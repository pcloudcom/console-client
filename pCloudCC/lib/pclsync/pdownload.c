/* Copyright (c) 2013 Anton Titov.
 * Copyright (c) 2013 pCloud Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of pCloud Ltd nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL pCloud Ltd BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pdownload.h"
#include "pstatus.h"
#include "ptimer.h"
#include "plibs.h"
#include "ptasks.h"
#include "pstatus.h"
#include "pssl.h"
#include "psettings.h"
#include "pnetlibs.h"
#include "pcallbacks.h"
#include "pfolder.h"
#include "psyncer.h"
#include "papi.h"
#include "pp2p.h"
#include "plist.h"
#include "plocalscan.h"
#include "pupload.h"
#include "pasyncnet.h"
#include "ppathstatus.h"

typedef struct {
  psync_list list;
  psync_fileid_t fileid;
  psync_syncid_t syncid;
  uint16_t stop;
  uint16_t started; // if set, means that real download is in progress (after P2P checks, checksum checks and so on)
  unsigned char schecksum[PSYNC_HASH_DIGEST_HEXLEN];
} download_list_t;

typedef struct {
  uint64_t taskid;
  download_list_t dwllist;
  char *localpath;
  char *localname;
  char *tmpname;
  psync_file_lock_t *lock;
  uint64_t size;
  uint64_t downloadedsize;
  uint64_t localsize;
  uint64_t hash;
  time_t crtime;
  time_t mtime;
  psync_folderid_t localfolderid;
  unsigned char checksum[PSYNC_HASH_DIGEST_HEXLEN];
  char indwllist;
  char localexists;
  char filename[];
} download_task_t;

static pthread_mutex_t download_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t download_cond=PTHREAD_COND_INITIALIZER;
static psync_uint_t download_wakes=0;
static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED),
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE)
};

static psync_uint_t started_downloads=0;
static psync_uint_t current_downloads_waiters=0;
static pthread_mutex_t current_downloads_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t current_downloads_cond=PTHREAD_COND_INITIALIZER;

static psync_list downloads=PSYNC_LIST_STATIC_INIT(downloads);

static void task_wait_no_downloads(){
  pthread_mutex_lock(&current_downloads_mutex);
  while (started_downloads){
    current_downloads_waiters++;
    pthread_cond_wait(&current_downloads_cond, &current_downloads_mutex);
    current_downloads_waiters--;
  }
  pthread_mutex_unlock(&current_downloads_mutex);
}

static int task_mkdir(const char *path){
  int err;
  while (1){
    if (likely(!psync_mkdir(path))){ // don't change to likely_log, as it may overwrite psync_fs_err;
      psync_set_local_full(0);
      return 0;
    }
    err=psync_fs_err();
    debug(D_WARNING, "mkdir of %s failed, errno=%d", path, (int)err);
    if (err==P_NOSPC || err==P_DQUOT){
      psync_set_local_full(1);
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
    }
    else {
      psync_set_local_full(0);
      if (err==P_NOENT)
        return 0; // do we have a choice? the user deleted the directory
      else if (err==P_EXIST){
        psync_stat_t st;
        if (psync_stat(path, &st)){
          debug(D_BUG, "mkdir failed with EEXIST, but stat returned error. race?");
          return -1;
        }
        if (psync_stat_isfolder(&st))
          return 0;
        if (psync_rename_conflicted_file(path))
          return -1;
      }
      else
        return -1;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  }
}

static int task_rmdir(const char *path){
  task_wait_no_downloads();
  if (likely_log(!psync_rmdir_with_trashes(path)))
    return 0;
  if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
    return -1;
  psync_wake_localscan();
  return 0;
//  if (psync_fs_err()==P_NOENT || psync_fs_err()==P_NOTDIR || psync_fs_err()==P_NOTEMPTY || psync_fs_err()==P_EXIST)
//    return 0;
}

/*static int task_rmdir_rec(const char *path){
  task_wait_no_downloads();
  if (likely_log(!psync_rmdir_recursive(path)))
    return 0;
  if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
    return -1;
  return 0;
}*/

static void do_move(void *ptr, psync_pstat *st){
  const char **arr;
  char *oldpath, *newpath;
  arr=(const char **)ptr;
  oldpath=psync_strcat(arr[0], st->name, NULL);
  newpath=psync_strcat(arr[1], st->name, NULL);
  if (psync_stat_isfolder(&st->stat))
    psync_rendir(oldpath, newpath);
  else
    psync_file_rename(oldpath, newpath);
  psync_free(newpath);
  psync_free(oldpath);
}

static int move_folder_contents(const char *oldpath, const char *newpath){
  const char *arr[2];
  arr[0]=oldpath;
  arr[1]=newpath;
  psync_list_dir(oldpath, do_move, (void *)arr);
  return psync_rmdir_with_trashes(oldpath);
}

static int task_renamedir(const char *oldpath, const char *newpath){
  while (1){
    if (likely_log(!psync_rendir(oldpath, newpath))){
      psync_set_local_full(0);
      return 0;
    }
    if (psync_fs_err()==P_NOSPC || psync_fs_err()==P_DQUOT){
      psync_set_local_full(1);
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
    }
    else {
      psync_set_local_full(0);
      if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
        return -1;
      if (psync_fs_err()==P_NOENT)
        return 0;
      else if (psync_fs_err()==P_EXIST || psync_fs_err()==P_NOTEMPTY || psync_fs_err()==P_NOTDIR){
        psync_stat_t st;
        if (psync_stat(newpath, &st)){
          debug(D_BUG, "rename failed with EEXIST, but stat returned error. race?");
          return -1;
        }
        if (psync_stat_isfolder(&st))
          return move_folder_contents(oldpath, newpath);
        if (psync_rename_conflicted_file(newpath))
          return -1;
      }
      else
        return -1;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  }
}

static void update_local_folder_mtime(const char *localpath, psync_folderid_t localfolderid){
  psync_stat_t st;
  psync_sql_res *res;
  if (psync_stat(localpath, &st)){
    debug(D_ERROR, "stat failed for %s", localpath);
    return;
  }
  res=psync_sql_prep_statement("UPDATE localfolder SET inode=?, deviceid=?, mtime=?, mtimenative=? WHERE id=?");
  psync_sql_bind_uint(res, 1, psync_stat_inode(&st));
  psync_sql_bind_uint(res, 2, psync_stat_device(&st));
  psync_sql_bind_uint(res, 3, psync_stat_mtime(&st));
  psync_sql_bind_uint(res, 4, psync_stat_mtime_native(&st));
  psync_sql_bind_uint(res, 5, localfolderid);
  psync_sql_run_free(res);
}

static int call_func_for_folder(psync_folderid_t localfolderid, psync_folderid_t folderid, psync_syncid_t syncid, psync_eventtype_t event,
                                int (*func)(const char *), int updatemtime, const char *debug){
  char *localpath;
  int res;
  localpath=psync_local_path_for_local_folder(localfolderid, syncid, NULL);
  if (likely(localpath)){
    res=func(localpath);
    if (!res){
      psync_send_event_by_id(event, syncid, localpath, folderid);
      if (updatemtime)
        update_local_folder_mtime(localpath, localfolderid);
      psync_decrease_local_folder_taskcnt(localfolderid);
      debug(D_NOTICE, "%s %s", debug, localpath);
    }
    psync_free(localpath);
  }
  else{
    debug(D_ERROR, "could not get path for local folder id %lu, syncid %u", (long unsigned)localfolderid, (unsigned)syncid);
    res=0;
  }
  return res;
}

static int call_func_for_folder_name(psync_folderid_t localfolderid, psync_folderid_t folderid, const char *name, psync_syncid_t syncid, psync_eventtype_t event,
                                int (*func)(const char *), int updatemtime, const char *debug){
  char *localpath;
  int res;
  localpath=psync_local_path_for_local_folder(localfolderid, syncid, NULL);
  if (likely(localpath)){
    res=func(localpath);
    if (!res){
      psync_send_event_by_path(event, syncid, localpath, folderid, name);
      if (updatemtime)
        update_local_folder_mtime(localpath, localfolderid);
      psync_decrease_local_folder_taskcnt(localfolderid);
      debug(D_NOTICE, "%s %s", debug, localpath);
    }
    psync_free(localpath);
  }
  else{
    debug(D_ERROR, "could not get path for local folder id %lu, syncid %u", (long unsigned)localfolderid, (unsigned)syncid);
    res=0;
  }
  return res;
}

static void delete_local_folder_from_db(psync_folderid_t localfolderid, psync_syncid_t syncid){
  psync_sql_res *res;
  psync_uint_row row;
  if (likely(localfolderid)){
    res=psync_sql_query("SELECT id, syncid FROM localfolder WHERE localparentfolderid=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    while ((row=psync_sql_fetch_rowint(res)))
      delete_local_folder_from_db(row[0], row[1]);
    psync_sql_free_result(res);
    res=psync_sql_query("SELECT id FROM localfile WHERE localparentfolderid=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    while ((row=psync_sql_fetch_rowint(res)))
      psync_delete_upload_tasks_for_file(row[0]);
    psync_sql_free_result(res);
    res=psync_sql_prep_statement("DELETE FROM localfile WHERE localparentfolderid=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run_free(res);
    res=psync_sql_prep_statement("DELETE FROM syncedfolder WHERE localfolderid=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run_free(res);
    res=psync_sql_prep_statement("DELETE FROM localfolder WHERE id=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run_free(res);
  }
  psync_path_status_sync_folder_deleted(syncid, localfolderid);
}

static int task_renamefolder(psync_syncid_t newsyncid, psync_folderid_t folderid, psync_folderid_t localfolderid,
                             psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  psync_variant_row row;
  psync_uint_row urow;
  char *oldpath, *newpath;
  psync_syncid_t oldsyncid;
  int ret;
  assert(newname!=NULL);
  task_wait_no_downloads();
  res=psync_sql_query("SELECT syncid, localparentfolderid, name FROM localfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  row=psync_sql_fetch_row(res);
  if (unlikely(!row)){
    psync_sql_free_result(res);
    debug(D_ERROR, "could not find local folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  oldsyncid=psync_get_number(row[0]);
  if (oldsyncid==newsyncid && psync_get_number(row[1])==newlocalparentfolderid && !psync_filename_cmp(psync_get_string(row[2]), newname)){
    psync_sql_free_result(res);
    debug(D_NOTICE, "folder %s already renamed locally, probably update initiated from this client", newname);
    return 0;
  }
  psync_sql_free_result(res);
  oldpath=psync_local_path_for_local_folder(localfolderid, oldsyncid, NULL);
  if (unlikely(!oldpath)){
    debug(D_ERROR, "could not get local path for folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  psync_sql_start_transaction();
  psync_restart_localscan();
  res=psync_sql_query_nolock("SELECT syncid, localparentfolderid FROM localfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  if ((urow=psync_sql_fetch_rowint(res))) {
    psync_path_status_sync_folder_moved(localfolderid, urow[0], urow[1], newsyncid, newlocalparentfolderid);
    psync_sql_free_result(res);
  } else {
    psync_sql_free_result(res);
    debug(D_NOTICE, "localfolderid %u not found in localfolder", (unsigned)localfolderid);
  }
  res=psync_sql_prep_statement("UPDATE localfolder SET syncid=?, localparentfolderid=?, name=? WHERE id=?");
  psync_sql_bind_uint(res, 1, newsyncid);
  psync_sql_bind_uint(res, 2, newlocalparentfolderid);
  psync_sql_bind_string(res, 3, newname);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_run_free(res);
  newpath=psync_local_path_for_local_folder(localfolderid, newsyncid, NULL);
  if (unlikely(!newpath)){
    psync_sql_rollback_transaction();
    psync_free(oldpath);
    debug(D_ERROR, "could not get local path for folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  ret=task_renamedir(oldpath, newpath);
  if (ret)
    psync_sql_rollback_transaction();
  else{
    psync_decrease_local_folder_taskcnt(localfolderid);
    psync_sql_commit_transaction();
    psync_send_event_by_id(PEVENT_LOCAL_FOLDER_RENAMED, newsyncid, newpath, folderid);
    debug(D_NOTICE, "local folder renamed from %s to %s", oldpath, newpath);
  }
  psync_free(newpath);
  psync_free(oldpath);
  return ret;
}

static int create_conflicted(const char *name, psync_folderid_t localfolderid, psync_syncid_t syncid, const char *filename){
  psync_sql_res *res;
  psync_stop_localscan();
  if (psync_rename_conflicted_file(name)){
    psync_resume_localscan();
    return -1;
  }
  res=psync_sql_prep_statement("DELETE FROM localfile WHERE syncid=? AND localparentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, localfolderid);
  psync_sql_bind_string(res, 3, filename);
  psync_sql_run_free(res);
  psync_resume_localscan();
  psync_wake_localscan();
  return 0;
}

static int rename_if_notex(const char *oldname, const char *newname, psync_fileid_t fileid, psync_folderid_t localfolderid,
                           psync_syncid_t syncid, const char *filename){
  uint64_t filesize;
  int ret, isrev;
  unsigned char localhashhex[PSYNC_HASH_DIGEST_HEXLEN];
  debug(D_NOTICE, "renaming %s to %s", oldname, newname);
  if (psync_get_local_file_checksum(newname, localhashhex, &filesize)==PSYNC_NET_OK){
    debug(D_NOTICE, "file %s already exists", newname);
    ret=psync_is_revision_of_file(localhashhex, filesize, fileid, &isrev);
    if (ret==PSYNC_NET_TEMPFAIL){
      debug(D_NOTICE, "got PSYNC_NET_TEMPFAIL for %s", newname);
      return -1;
    }
    if (ret==PSYNC_NET_OK && !isrev){
      if (create_conflicted(newname, localfolderid, syncid, filename)){
        debug(D_WARNING, "create_conflicted failed for %s", newname);
        return -1;
      }
    }
    else if (ret==PSYNC_NET_OK && isrev)
      debug(D_NOTICE, "file %s is found to be old revision of fileid %lu, overwriting", newname, (unsigned long)fileid);
  }
  return psync_file_rename_overwrite(oldname, newname);
}

static int stat_and_create_local(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *filename,
                                 const char *name, unsigned char *checksum, uint64_t serversize, uint64_t hash){
  psync_sql_res *sql;
  psync_stat_t st;
  psync_uint_row row;
  psync_fileid_t localfileid;
  if (unlikely_log(psync_stat(name, &st)) || unlikely_log(psync_stat_size(&st)!=serversize))
    return -1;
  localfileid=0;
  psync_sql_start_transaction();
  sql=psync_sql_query_nolock("SELECT id FROM localfile WHERE syncid=? AND localparentfolderid=? AND name=?");
  psync_sql_bind_uint(sql, 1, syncid);
  psync_sql_bind_uint(sql, 2, localfolderid);
  psync_sql_bind_string(sql, 3, filename);
  if ((row=psync_sql_fetch_rowint(sql)))
    localfileid=row[0];
  psync_sql_free_result(sql);

  sql=psync_sql_query_nolock("SELECT parentfolderid FROM file WHERE id=?");
  psync_sql_bind_uint(sql, 1, fileid);
  row=psync_sql_fetch_rowint(sql);
  if (!row || !psync_is_folder_in_downloadlist(row[0])){
    psync_sql_free_result(sql);
    if (localfileid){
      sql=psync_sql_prep_statement("DELETE FROM localfile WHERE id=?");
      psync_sql_bind_uint(sql, 1, localfileid);
      psync_sql_run_free(sql);
    }
    psync_sql_commit_transaction(sql);
    psync_file_delete(name);
    if (row)
      debug(D_NOTICE, "fileid %lu (%s) got moved out of download folder while finishing download, deleting %s", (unsigned long)fileid, filename, name);
    else
      debug(D_NOTICE, "fileid %lu (%s) got deleted while finishing download, deleting %s", (unsigned long)fileid, filename, name);
    return 0;
  }
  psync_sql_free_result(sql);

  if (localfileid){
    sql=psync_sql_prep_statement("UPDATE localfile SET localparentfolderid=?, fileid=?, hash=?, syncid=?, size=?, inode=?, mtime=?, mtimenative=?, "
                                                       "name=?, checksum=? WHERE id=?");
    psync_sql_bind_uint(sql, 1, localfolderid);
    psync_sql_bind_uint(sql, 2, fileid);
    psync_sql_bind_uint(sql, 3, hash);
    psync_sql_bind_uint(sql, 4, syncid);
    psync_sql_bind_uint(sql, 5, psync_stat_size(&st));
    psync_sql_bind_uint(sql, 6, psync_stat_inode(&st));
    psync_sql_bind_uint(sql, 7, psync_stat_mtime(&st));
    psync_sql_bind_uint(sql, 8, psync_stat_mtime_native(&st));
    psync_sql_bind_string(sql, 9, filename);
    psync_sql_bind_lstring(sql, 10, (char *)checksum, PSYNC_HASH_DIGEST_HEXLEN);
    psync_sql_bind_uint(sql, 11, localfileid);
    psync_sql_run_free(sql);
  }
  else{
    sql=psync_sql_prep_statement("REPLACE INTO localfile (localparentfolderid, fileid, hash, syncid, size, inode, mtime, mtimenative, name, checksum)"
                                                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    psync_sql_bind_uint(sql, 1, localfolderid);
    psync_sql_bind_uint(sql, 2, fileid);
    psync_sql_bind_uint(sql, 3, hash);
    psync_sql_bind_uint(sql, 4, syncid);
    psync_sql_bind_uint(sql, 5, psync_stat_size(&st));
    psync_sql_bind_uint(sql, 6, psync_stat_inode(&st));
    psync_sql_bind_uint(sql, 7, psync_stat_mtime(&st));
    psync_sql_bind_uint(sql, 8, psync_stat_mtime_native(&st));
    psync_sql_bind_string(sql, 9, filename);
    psync_sql_bind_lstring(sql, 10, (char *)checksum, PSYNC_HASH_DIGEST_HEXLEN);
    psync_sql_run_free(sql);
  }
  return psync_sql_commit_transaction();
}

// rename_and_create_local(dt->tmpname, dt->localname, dt->dwllist.syncid, dt->dwllist.fileid, dt->localfolderid, dt->filename, serverhashhex, serversize, hash))
//static int rename_and_create_local(const char *src, const char *dst, psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid,
//                                   const char *filename, unsigned char *checksum, uint64_t serversize, uint64_t hash){


static int rename_and_create_local(download_task_t *dt, unsigned char *checksum, uint64_t serversize, uint64_t hash){
  psync_stop_localscan();
  psync_set_crtime_mtime(dt->tmpname, dt->crtime, dt->mtime);
  if (rename_if_notex(dt->tmpname, dt->localname, dt->dwllist.fileid, dt->localfolderid, dt->dwllist.syncid, dt->filename)){
    psync_resume_localscan();
    debug(D_WARNING, "failed to rename %s to %s", dt->tmpname, dt->localname);
    psync_milisleep(1000);
    return -1;
  }
  if (stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid, dt->localfolderid, dt->filename, dt->localname, checksum, serversize, hash)){
    debug(D_WARNING, "stat_and_create_local failed for file %s", dt->localname);
    psync_resume_localscan();
    return -1;
  }
  psync_resume_localscan();
  return 0;
}

static int task_download_file(download_task_t *dt){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", dt->dwllist.fileid)};
  psync_stat_t st;
  psync_list ranges;
  psync_range_list_t *range;
  binresult *res;
  psync_sql_res *sql;
  const binresult *hosts;
  char *tmpold;
  char *oldfiles[2];
  uint32_t oldcnt;
  const char *requestpath;
  void *buff;
  psync_http_socket *http;
  uint64_t result, serversize, hash;
  psync_uint_row row;
  psync_hash_ctx hashctx;
  unsigned char serverhashhex[PSYNC_HASH_DIGEST_HEXLEN],
                localhashhex[PSYNC_HASH_DIGEST_HEXLEN],
                localhashbin[PSYNC_HASH_DIGEST_LEN];
  char cookie[128];
  uint32_t i;
  psync_file_t fd, ifd;
  int rd, rt;

  psync_list_init(&ranges);
  tmpold=NULL;

  rt=psync_get_remote_file_checksum(dt->dwllist.fileid, serverhashhex, &serversize, &hash);
  if (unlikely_log(rt!=PSYNC_NET_OK)){
    if (rt==PSYNC_NET_TEMPFAIL)
      return -1;
    else
      return 0;
  }
  memcpy(dt->dwllist.schecksum, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN);

  if (serversize!=dt->size){
    pthread_mutex_lock(&current_downloads_mutex);
    psync_status.bytestodownloadcurrent-=dt->size;
    psync_status.bytestodownloadcurrent+=serversize;
    pthread_mutex_unlock(&current_downloads_mutex);
    dt->size=serversize;
    psync_status_send_update();
  }

  sql=psync_sql_query_rdlock("SELECT fileid, id, hash FROM localfile WHERE size=? AND checksum=? AND localparentfolderid=? AND syncid=? AND name=?");
  psync_sql_bind_uint(sql, 1, serversize);
  psync_sql_bind_lstring(sql, 2, (char *)serverhashhex, PSYNC_HASH_DIGEST_HEXLEN);
  psync_sql_bind_uint(sql, 3, dt->localfolderid);
  psync_sql_bind_uint(sql, 4, dt->dwllist.syncid);
  psync_sql_bind_string(sql, 5, dt->filename);
  if ((row=psync_sql_fetch_rowint(sql))){
    rt=row[0]!=dt->dwllist.fileid || row[2]!=hash;
    result=row[1];
    psync_sql_free_result(sql);
    if (rt){
      sql=psync_sql_prep_statement("UPDATE localfile SET fileid=?, hash=? WHERE id=?");
      psync_sql_bind_uint(sql, 1, dt->dwllist.fileid);
      psync_sql_bind_uint(sql, 2, hash);
      psync_sql_bind_uint(sql, 3, result);
      psync_sql_run_free(sql);
    }
    return 0;
  }
  psync_sql_free_result(sql);

  if (dt->localexists && dt->localsize==serversize && !memcmp(dt->checksum, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN)){
    if (stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid, dt->localfolderid, dt->filename, dt->localname, serverhashhex, serversize, hash)){
      debug(D_NOTICE, "file %s, already exists but stat_and_create_local failed", dt->filename);
      return -1;
    }
    else{
      debug(D_NOTICE, "file already exists %s, not downloading", dt->filename);
      return 0;
    }
  }

  sql=psync_sql_query_rdlock("SELECT id FROM localfile WHERE size=? AND checksum=?");
  psync_sql_bind_uint(sql, 1, serversize);
  psync_sql_bind_lstring(sql, 2, (char *)serverhashhex, PSYNC_HASH_DIGEST_HEXLEN);
  while ((row=psync_sql_fetch_rowint(sql))){
    tmpold=psync_local_path_for_local_file(row[0], NULL);
    if (unlikely_log(!tmpold))
      continue;
    psync_sql_free_result(sql);
    sql=NULL;
    rt=psync_copy_local_file_if_checksum_matches(tmpold, dt->tmpname, serverhashhex, serversize);
    if (likely(rt==PSYNC_NET_OK)){
      if (rename_and_create_local(dt, serverhashhex, serversize, hash))
        rt=PSYNC_NET_TEMPFAIL;
      else
        debug(D_NOTICE, "file %s copied from %s", dt->localname, tmpold);
    }
    else
      debug(D_WARNING, "failed to copy %s from %s", dt->localname, tmpold);
    psync_free(tmpold);
    tmpold=NULL;
    if (likely_log(rt==PSYNC_NET_OK))
      return 0;
    else
      break;
  }
  if (sql)
    psync_sql_free_result(sql);

  if (dt->dwllist.stop)
    return 0;

//  psync_send_event_by_id(PEVENT_FILE_DOWNLOAD_STARTED, syncid, name, fileid);
  if (serversize>=PSYNC_MIN_SIZE_FOR_P2P){
    rt=psync_p2p_check_download(dt->dwllist.fileid, serverhashhex, serversize, dt->tmpname);
    if (rt==PSYNC_NET_OK){
      if (rename_and_create_local(dt, serverhashhex, serversize, hash))
        return -1;
      else
        return 0;
    }
    else if (rt==PSYNC_NET_TEMPFAIL)
      return -1;
  }
  res=psync_api_run_command("getfilelink", params);
  if (unlikely_log(!res))
    return -1;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    debug(D_WARNING, "got error %lu from getfilelink", (long unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL){
      psync_free(res);
      return -1;
    }
    else{
      psync_free(res);
      return 0;
    }
  }

  dt->dwllist.started=1;

  oldcnt=0;
  if (serversize>=PSYNC_MIN_SIZE_FOR_CHECKSUMS){
    if (!psync_stat(dt->tmpname, &st) && psync_stat_size(&st)>=PSYNC_MIN_SIZE_FOR_CHECKSUMS){
      tmpold=psync_strcat(dt->localpath, PSYNC_DIRECTORY_SEPARATOR, dt->filename, "-old", PSYNC_APPEND_PARTIAL_FILES, NULL);
      if (psync_file_rename_overwrite(dt->tmpname, tmpold)){
        psync_free(tmpold);
        tmpold=NULL;
      }
      else
        oldfiles[oldcnt++]=tmpold;
    }
    if (dt->localexists && dt->localsize>=PSYNC_MIN_SIZE_FOR_CHECKSUMS)
      oldfiles[oldcnt++]=dt->localname;
  }

  fd=psync_file_open(dt->tmpname, P_O_WRONLY, P_O_CREAT|P_O_TRUNC);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE))
    goto err0;

  rt=psync_net_download_ranges(&ranges, dt->dwllist.fileid, hash, serversize, oldfiles, oldcnt);
  if (rt==PSYNC_NET_TEMPFAIL)
    goto err1;

  hosts=psync_find_result(res, "hosts", PARAM_ARRAY);
  requestpath=psync_find_result(res, "path", PARAM_STR)->str;
  psync_slprintf(cookie, sizeof(cookie), "Cookie: dwltag=%s\015\012", psync_find_result(res, "dwltag", PARAM_STR)->str);
  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  http=NULL;
  psync_hash_init(&hashctx);
  psync_list_for_each_element(range, &ranges, psync_range_list_t, list){
    if (!range->len)
      continue;
    if (range->type==PSYNC_RANGE_TRANSFER){
      debug(D_NOTICE, "downloading %lu bytes from offset %lu of fileid %lu", (unsigned long)range->len, (unsigned long)range->off, (unsigned long)dt->dwllist.fileid);
      for (i=0; i<hosts->length; i++)
        if ((http=psync_http_connect(hosts->array[i]->str, requestpath, range->off, (range->len==serversize&&range->off==0)?0:(range->len+range->off-1), cookie)))
          break;
      if (unlikely_log(!http))
        goto err2;
      rd=0;
      while (!dt->dwllist.stop){
        rd=psync_http_readall(http, buff, PSYNC_COPY_BUFFER_SIZE);
        if (rd==0)
          break;
        if (unlikely_log(rd<0) ||
            unlikely_log(psync_file_writeall_checkoverquota(fd, buff, rd)))
          goto err2;
        psync_hash_update(&hashctx, buff, rd);
        pthread_mutex_lock(&current_downloads_mutex);
        psync_status.bytesdownloaded+=rd;
        if (current_downloads_waiters && psync_status.bytestodownloadcurrent-psync_status.bytesdownloaded<=PSYNC_START_NEW_DOWNLOADS_TRESHOLD)
          pthread_cond_signal(&current_downloads_cond);
        pthread_mutex_unlock(&current_downloads_mutex);
        psync_send_status_update();
        dt->downloadedsize+=rd;
        if (unlikely(!psync_statuses_ok_array(requiredstatuses, ARRAY_SIZE(requiredstatuses))))
          goto err2;
      }
      psync_http_close(http);
      http=NULL;
    }
    else{
      debug(D_NOTICE, "copying %lu bytes from %s offset %lu", (unsigned long)range->len, range->filename, (unsigned long)range->off);
      ifd=psync_file_open(range->filename, P_O_RDONLY, 0);
      if (unlikely_log(ifd==INVALID_HANDLE_VALUE))
        goto err2;
      if (unlikely_log(psync_file_seek(ifd, range->off, P_SEEK_SET)==-1)){
        psync_file_close(ifd);
        goto err2;
      }
      result=range->len;
      while (!dt->dwllist.stop && result){
        if (result>PSYNC_COPY_BUFFER_SIZE)
          rd=PSYNC_COPY_BUFFER_SIZE;
        else
          rd=result;
        rd=psync_file_read(ifd, buff, rd);
        if (unlikely_log(rd<=0) || unlikely_log(psync_file_writeall_checkoverquota(fd, buff, rd)) ||
            unlikely(!psync_statuses_ok_array(requiredstatuses, ARRAY_SIZE(requiredstatuses)))){
          psync_file_close(ifd);
          goto err2;
        }
        result-=rd;
        psync_hash_update(&hashctx, buff, rd);
        pthread_mutex_lock(&current_downloads_mutex);
        psync_status.bytesdownloaded+=rd;
        if (current_downloads_waiters && psync_status.bytestodownloadcurrent-psync_status.bytesdownloaded<=PSYNC_START_NEW_DOWNLOADS_TRESHOLD)
          pthread_cond_signal(&current_downloads_cond);
        pthread_mutex_unlock(&current_downloads_mutex);
        psync_send_status_update();
        dt->downloadedsize+=rd;
      }
      psync_file_close(ifd);
    }
    if (dt->dwllist.stop)
      break;
  }
  if (unlikely(dt->dwllist.stop)){
    if (dt->dwllist.stop==2){
      debug(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
      psync_file_delete(dt->tmpname);
    }
    goto err2;
  }
  if (unlikely_log(psync_file_sync(fd)))
    goto err2;
  psync_free(buff);
  psync_hash_final(localhashbin, &hashctx);
  if (unlikely_log(psync_file_close(fd)))
    goto err0;
  psync_binhex(localhashhex, localhashbin, PSYNC_HASH_DIGEST_LEN);
  if (unlikely_log(memcmp(localhashhex, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN))){
    debug(D_WARNING, "got wrong file checksum for file %s", dt->filename);
    if (dt->dwllist.stop==2){
      debug(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
      psync_file_delete(dt->tmpname);
    }
    goto err0;
  }
  if (dt->dwllist.stop==2){
    debug(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
    psync_file_delete(dt->tmpname);
    goto err0;
  }
  if (rename_and_create_local(dt, serverhashhex, serversize, hash))
    goto err0;
//  psync_send_event_by_id(PEVENT_FILE_DOWNLOAD_FINISHED, syncid, name, fileid);
  debug(D_NOTICE, "file downloaded %s", dt->localname);
  psync_list_for_each_element_call(&ranges, psync_range_list_t, list, psync_free);
  if (tmpold){
    psync_file_delete(tmpold);
    psync_free(tmpold);
  }
  psync_free(res);
  return 0;
err2:
  psync_hash_final(localhashbin, &hashctx); /* just in case */
  psync_free(buff);
  if (http)
    psync_http_close(http);
err1:
  psync_file_close(fd);
//  psync_send_event_by_id(PEVENT_FILE_DOWNLOAD_FAILED, syncid, name, fileid);
err0:
  psync_list_for_each_element_call(&ranges, psync_range_list_t, list, psync_free);
  if (tmpold){
    psync_file_delete(tmpold);
    psync_free(tmpold);
  }
  psync_free(res);
  return -1;
}

static int task_delete_file(psync_syncid_t syncid, psync_fileid_t fileid, const char *remotepath){
  psync_sql_res *res, *stmt;
  psync_uint_row row;
  char *name;
  int ret;
  ret=0;
  task_wait_no_downloads();
  if (syncid){
    res=psync_sql_query("SELECT id, syncid FROM localfile WHERE fileid=? AND syncid=?");
    psync_sql_bind_uint(res, 2, syncid);
  }
  else
    res=psync_sql_query("SELECT id, syncid FROM localfile WHERE fileid=?");
  psync_sql_bind_uint(res, 1, fileid);
  psync_restart_localscan();
  while ((row=psync_sql_fetch_rowint(res))){
    name=psync_local_path_for_local_file(row[0], NULL);
    if (likely_log(name)){
      if (unlikely(psync_file_delete(name))){
        debug(D_WARNING, "error deleting local file %s error %d", name, (int)psync_fs_err());
        if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS){
          ret=-1;
          psync_free(name);
          continue;
        }
      }
      else
        debug(D_NOTICE, "local file %s deleted", name);
//      threre are some reports about crashes here, comment out for now as events are not fully implemented anyway
//      psync_send_event_by_path(PEVENT_LOCAL_FILE_DELETED, row[1], name, fileid, remotepath);
      psync_free(name);
    }
    stmt=psync_sql_prep_statement("DELETE FROM localfile WHERE id=?");
    psync_sql_bind_uint(stmt, 1, row[0]);
    psync_sql_run_free(stmt);
  }
  psync_sql_free_result(res);
  return ret;
}

static int task_rename_file(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t fileid, psync_folderid_t oldlocalfolderid,
                                  psync_folderid_t newlocalfolderid, const char *newname){
  char *oldpath, *newfolder, *newpath;
  psync_sql_res *res;
  psync_variant_row row;
  psync_fileid_t lfileid;
  psync_stat_t st;
  psync_syncid_t syncid;
  int ret;
  task_wait_no_downloads();
  res=psync_sql_query("SELECT id, localparentfolderid, syncid, name FROM localfile WHERE fileid=?");
  psync_sql_bind_uint(res, 1, fileid);
  lfileid=0;
  while ((row=psync_sql_fetch_row(res))){
    syncid=psync_get_number(row[2]);
    if (psync_get_number(row[1])==newlocalfolderid && syncid==newsyncid && !psync_filename_cmp(psync_get_string(row[3]), newname)){
      debug(D_NOTICE, "file %s already renamed locally, probably update initiated from this client", newname);
      psync_sql_free_result(res);
      return 0;
    }
    else if (syncid==oldsyncid){
      lfileid=psync_get_number(row[0]);
      break;
    }
  }
  psync_sql_free_result(res);
  if (unlikely_log(!lfileid)){
    psync_task_download_file(newsyncid, fileid, newlocalfolderid, newname);
    return 0;
  }
  newfolder=psync_local_path_for_local_folder(newlocalfolderid, newsyncid, NULL);
  if (unlikely_log(!newfolder))
    return 0;
  oldpath=psync_local_path_for_local_file(lfileid, NULL);
  if (unlikely_log(!oldpath)){
    psync_free(newfolder);
    return 0;
  }
  newpath=psync_strcat(newfolder, PSYNC_DIRECTORY_SEPARATOR, newname, NULL);
  ret=0;
  psync_stop_localscan();
  if (psync_file_rename_overwrite(oldpath, newpath)){
    psync_resume_localscan();
    if (psync_fs_err()==P_NOENT){
      debug(D_WARNING, "renamed from %s to %s failed, downloading", oldpath, newpath);
      psync_task_download_file(newsyncid, fileid, newlocalfolderid, newname);
    }
    else
      ret=-1;
  }
  else{
    if (likely_log(!psync_stat(newpath, &st))){
      res=psync_sql_prep_statement("UPDATE OR REPLACE localfile SET localparentfolderid=?, syncid=?, name=?, inode=?, mtime=?, mtimenative=? WHERE id=?");
      psync_sql_bind_uint(res, 1, newlocalfolderid);
      psync_sql_bind_uint(res, 2, newsyncid);
      psync_sql_bind_string(res, 3, newname);
      psync_sql_bind_uint(res, 4, psync_stat_inode(&st));
      psync_sql_bind_uint(res, 5, psync_stat_mtime(&st));
      psync_sql_bind_uint(res, 6, psync_stat_mtime_native(&st));
      psync_sql_bind_uint(res, 7, lfileid);
      psync_sql_run_free(res);
      debug(D_NOTICE, "renamed %s to %s", oldpath, newpath);
    }
    psync_resume_localscan();
  }
  psync_free(newpath);
  psync_free(oldpath);
  psync_free(newfolder);
  return ret;
}

static void set_task_inprogress(uint64_t taskid, uint32_t val){
  psync_sql_res *res;
  res=psync_sql_prep_statement("UPDATE task SET inprogress=? WHERE id=?");
  psync_sql_bind_uint(res, 1, val);
  psync_sql_bind_uint(res, 2, taskid);
  psync_sql_run_free(res);
}

static void delete_task(uint64_t taskid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("DELETE FROM task WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_run_free(res);
}

static void free_download_task(download_task_t *dt){
  if (dt->indwllist){
    pthread_mutex_lock(&current_downloads_mutex);
    psync_list_del(&dt->dwllist.list);
    started_downloads--;
    psync_status.filesdownloading--;
    psync_status.bytestodownloadcurrent-=dt->size;
    psync_status.bytesdownloaded-=dt->downloadedsize;
    if (current_downloads_waiters)
      pthread_cond_broadcast(&current_downloads_cond);
    pthread_mutex_unlock(&current_downloads_mutex);
  }
  if (dt->lock)
    psync_unlock_file(dt->lock);
  psync_free(dt->localpath);
  psync_free(dt->localname);
  psync_free(dt->tmpname);
  psync_free(dt);
}

static void free_task_timer_thread(void *ptr){
  download_task_t *dt=(download_task_t *)ptr;
  set_task_inprogress(dt->taskid, 0);
  free_download_task(dt);
  psync_send_status_update();
  psync_wake_download();
}

static void free_task_timer(psync_timer_t timer, void *ptr){
  psync_timer_stop(timer);
  psync_run_thread1("free task", free_task_timer_thread, ptr);
}

static void handle_async_error(download_task_t *dt, psync_async_result_t *res){
  if (res->error==PSYNC_SERVER_ERROR_TOO_BIG){
    psync_sql_res *sres;
    assert(res->file.size>PSYNC_MAX_SIZE_FOR_ASYNC_DOWNLOAD);
    sres=psync_sql_prep_statement("UPDATE file SET size=?, hash=? WHERE id=?");
    psync_sql_bind_uint(sres, 1, res->file.size);
    psync_sql_bind_uint(sres, 2, res->file.hash);
    psync_sql_bind_uint(sres, 3, dt->dwllist.fileid);
    psync_sql_run_free(sres);
    set_task_inprogress(dt->taskid, 0);
    free_download_task(dt);
    psync_send_status_update();
    psync_wake_download();
  }
  else if ((res->errorflags&PSYNC_ASYNC_ERR_FLAG_PERM) || !(res->errorflags&PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS)){
    delete_task(dt->taskid);
    free_download_task(dt);
    psync_status_recalc_to_download_async();
  }
  else
    psync_timer_register(free_task_timer, 1, dt);
}

#if defined(P_OS_WINDOWS)

typedef struct {
  psync_async_result_t res;
  download_task_t *dt;
} async_res_dt_t;

static void rename_create_thread(void *ptr){
  async_res_dt_t *ard;
  ard=(async_res_dt_t *)ptr;
  if (rename_and_create_local(ard->dt, ard->res.file.sha1hex, ard->res.file.size, ard->res.file.hash)){
    set_task_inprogress(ard->dt->taskid, 0);
    free_download_task(ard->dt);
    psync_free(ard);
    psync_send_status_update();
    psync_wake_download();
  }
  else{
    delete_task(ard->dt->taskid);
    psync_path_status_sync_folder_task_completed(ard->dt->dwllist.syncid, ard->dt->localfolderid);
    free_download_task(ard->dt);
    psync_free(ard);
    psync_status_recalc_to_download_async();
  }
}

static void rename_create_timer(psync_timer_t timer, void *ptr){
  psync_timer_stop(timer);
  psync_run_thread1("small file dwl db ins", rename_create_thread, ptr);
}

#endif

static void finish_async_download(void *ptr, psync_async_result_t *res){
  download_task_t *dt=(download_task_t *)ptr;
  if (res->error)
    handle_async_error(dt, res);
  else{
    if (dt->dwllist.stop==2){
      debug(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
      psync_file_delete(dt->tmpname);
      return;
    }
#if defined(P_OS_WINDOWS)
    async_res_dt_t *ard;
    ard=psync_new(async_res_dt_t);
    memcpy(&ard->res, res, sizeof(psync_async_result_t));
    ard->dt=dt;
    psync_timer_register(rename_create_timer, 2, ard);
#else
    if (rename_and_create_local(dt, res->file.sha1hex, res->file.size, res->file.hash))
      psync_timer_register(free_task_timer, 1, dt);
    else{
      delete_task(dt->taskid);
      psync_path_status_sync_folder_task_completed(dt->dwllist.syncid, dt->localfolderid);
      free_download_task(dt);
      psync_status_recalc_to_download_async();
    }
#endif
  }
}

static void finish_async_download_existing_not_mod(download_task_t *dt, psync_async_result_t *res){
  debug(D_NOTICE, "file %s not modified", dt->localname);
  if (stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid, dt->localfolderid, dt->filename, dt->localname,
                            res->file.sha1hex, res->file.size, res->file.hash)){
    debug(D_WARNING, "stat_and_create_local failed for %s", dt->localname);
    psync_timer_register(free_task_timer, 1, dt);
  }
  else{
    delete_task(dt->taskid);
    psync_path_status_sync_folder_task_completed(dt->dwllist.syncid, dt->localfolderid);
    free_download_task(dt);
    psync_status_recalc_to_download_async();
  }
}

static void finish_async_download_existing(void *ptr, psync_async_result_t *res){
  if (res->error==PSYNC_SERVER_ERROR_NOT_MOD)
    finish_async_download_existing_not_mod((download_task_t *)ptr, res);
  else
    finish_async_download(ptr, res);
}

static void task_run_download_file_thread(void *ptr){
  download_task_t *dt;
  dt=(download_task_t *)ptr;
  if (task_download_file(dt)){
    psync_milisleep(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
    set_task_inprogress(dt->taskid, 0);
    psync_wake_download();
  }
  else{
    delete_task(dt->taskid);
    psync_path_status_sync_folder_task_completed(dt->dwllist.syncid, dt->localfolderid);
  }
  free_download_task(dt);
  psync_status_recalc_to_download_async();
}

static int task_run_download_file(uint64_t taskid, psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *filename){
  psync_sql_res *res;
  psync_uint_row row;
  psync_str_row srow;
  download_task_t *dt;
  char *localpath, *localname, *tmpname;
  psync_file_lock_t *lock;
  uint64_t size, minfree, hash, csize;
  time_t crtime, mtime;
  int64_t freespace;
  size_t len;
  unsigned char targetchecksum[PSYNC_HASH_DIGEST_HEXLEN];
  int hastargetchecksum, ret;
  res=psync_sql_query_rdlock("SELECT size, hash, ctime, mtime FROM file WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  row=psync_sql_fetch_rowint(res);
  if (row){
    size=row[0];
    hash=row[1];
    crtime=row[2];
    mtime=row[3];
  }
  else{
    // make compiler happy :)
    size=0;
    hash=0;
    crtime=0;
    mtime=0;
  }
  psync_sql_free_result(res);
  if (!row){
    debug(D_NOTICE, "possible race, fileid %lu not found in file table", (unsigned long)size);
    return 0; // this will delete the task
  }
  res=psync_sql_query_rdlock("SELECT checksum FROM hashchecksum WHERE hash=? AND size=?");
  psync_sql_bind_uint(res, 1, hash);
  psync_sql_bind_uint(res, 2, size);
  srow=psync_sql_fetch_rowstr(res);
  if (srow){
    memcpy(targetchecksum, srow[0], PSYNC_HASH_DIGEST_HEXLEN);
    hastargetchecksum=1;
  }
  else
    hastargetchecksum=0;
  psync_sql_free_result(res);
  localpath=psync_local_path_for_local_folder(localfolderid, syncid, NULL);
  if (unlikely_log(!localpath))
    return 0;
  localname=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, filename, NULL);
  tmpname=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, filename, PSYNC_APPEND_PARTIAL_FILES, NULL);
  len=strlen(filename);
  dt=(download_task_t *)psync_malloc(offsetof(download_task_t, filename)+len+1);
  memset(dt, 0, offsetof(download_task_t, filename));
  dt->taskid=taskid;
  dt->dwllist.fileid=fileid;
  dt->dwllist.syncid=syncid;
  dt->localpath=localpath;
  dt->localname=localname;
  dt->tmpname=tmpname;
  dt->size=size;
  dt->hash=hash;
  dt->crtime=crtime;
  dt->mtime=mtime;
  dt->localfolderid=localfolderid;
  memcpy(dt->filename, filename, len+1);
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_add_tail(&downloads, &dt->dwllist.list);
  while (!dt->dwllist.stop && (started_downloads>=PSYNC_MAX_PARALLEL_DOWNLOADS ||
          psync_status.bytestodownloadcurrent-psync_status.bytesdownloaded>PSYNC_START_NEW_DOWNLOADS_TRESHOLD)){
    current_downloads_waiters++;
    pthread_cond_wait(&current_downloads_cond, &current_downloads_mutex);
    current_downloads_waiters--;
  }
  if (unlikely(dt->dwllist.stop)){
    dt->indwllist=0;
    psync_list_del(&dt->dwllist.list);
  }
  else{
    dt->indwllist=1;
    psync_status.bytestodownloadcurrent+=size;
    psync_status.filesdownloading++;
    started_downloads++;
  }
  pthread_mutex_unlock(&current_downloads_mutex);
  if (unlikely(!dt->indwllist)){
    free_download_task(dt);
    return -1;
  }
  psync_send_status_update();
  if (hastargetchecksum && psync_get_local_file_checksum(tmpname, dt->checksum, &csize)==PSYNC_NET_OK && csize==size &&
      !memcmp(dt->checksum, targetchecksum, PSYNC_HASH_DIGEST_HEXLEN)){
    debug(D_NOTICE, "found file %s, candidate for %s with the right size and checksum", tmpname, localname);
    ret=rename_and_create_local(dt, targetchecksum, size, hash);
    free_download_task(dt);
    return ret;
  }
  if (psync_get_local_file_checksum(localname, dt->checksum, &dt->localsize)==PSYNC_NET_OK)
    dt->localexists=1;
  else
    dt->localexists=0;
  if (hastargetchecksum && dt->localexists && size==csize && !memcmp(dt->checksum, targetchecksum, PSYNC_HASH_DIGEST_HEXLEN)){
    debug(D_NOTICE, "file %s already exists and has correct checksum, not downloading", localname);
    ret=stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid, dt->localfolderid, dt->filename, dt->localname, targetchecksum, size, hash);
    free_download_task(dt);
    return ret;
  }
  minfree=psync_setting_get_uint(_PS(minlocalfreespace));
  freespace=psync_get_free_space_by_path(localpath);
  debug(D_NOTICE, "free space is %llu, needed %llu+%llu", (unsigned long long)freespace, (unsigned long long)minfree, (unsigned long long)size);
  if (likely(freespace!=-1)){
    if (freespace>=minfree+size)
      psync_set_local_full(0);
    else{
      free_download_task(dt);
      psync_set_local_full(1);
      debug(D_NOTICE, "disk is full, sleeping 10 seconds");
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
      return -1;
    }
  }
  else {
    debug(D_WARNING, "could not get free space for %s, maybe it is locally deleted, sleeping a bit and failing task", localpath);
    free_download_task(dt);
    psync_milisleep(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
    return -1;
  }
  lock=psync_lock_file(localname);
  if (!lock){
    debug(D_NOTICE, "file %s is currently locked, skipping for now", localname);
    free_download_task(dt);
    psync_milisleep(PSYNC_SLEEP_ON_LOCKED_FILE);
    return -1;
  }
  dt->lock=lock;
  set_task_inprogress(taskid, 1);
  if (size<=PSYNC_MAX_SIZE_FOR_ASYNC_DOWNLOAD){
    if (dt->localexists)
      ret=psync_async_download_file_if_changed(fileid, dt->tmpname, csize, dt->checksum, finish_async_download_existing, dt);
    else
      ret=psync_async_download_file(fileid, dt->tmpname, finish_async_download, dt);
    if (ret){
      debug(D_WARNING, "async download start failed for %s", dt->localname);
      free_download_task(dt);
      set_task_inprogress(taskid, 0);
      psync_milisleep(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
    }
  }
  else {
    psync_run_thread1("download file", task_run_download_file_thread, dt);
    psync_milisleep(25); // do not run downloads strictly in parallel so we reuse some API connections
  }
  return -1;
}

static void task_del_folder_rec_do(const char *localpath, psync_folderid_t localfolderid, psync_syncid_t syncid){
  psync_sql_res *res;
  psync_variant_row vrow;
  char *nm;
  res=psync_sql_query("SELECT id, name FROM localfile WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  while ((vrow=psync_sql_fetch_row(res))){
    psync_delete_upload_tasks_for_file(psync_get_number(vrow[0]));
    nm=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, psync_get_string(vrow[1]), NULL);
    debug(D_NOTICE, "deleting %s", nm);
    psync_file_delete(nm);
    psync_free(nm);
  }
  psync_sql_free_result(res);
  res=psync_sql_prep_statement("DELETE FROM localfile WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_run_free(res);
  res=psync_sql_query("SELECT id, name FROM localfolder WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  while ((vrow=psync_sql_fetch_row(res))){
    nm=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, psync_get_string(vrow[1]), NULL);
    task_del_folder_rec_do(nm, psync_get_number(vrow[0]), syncid);
    psync_free(nm);
  }
  psync_sql_free_result(res);
  res=psync_sql_prep_statement("DELETE FROM localfolder WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_run_free(res);
  if (psync_sql_affected_rows()){
    res=psync_sql_prep_statement("DELETE FROM syncedfolder WHERE localfolderid=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run_free(res);
  }
  psync_path_status_sync_folder_deleted(syncid, localfolderid);
}

static int task_del_folder_rec(psync_folderid_t localfolderid, psync_folderid_t folderid, psync_syncid_t syncid){
  char *localpath;
  psync_sql_res *res;
  task_wait_no_downloads();
  psync_stop_localscan();
  localpath=psync_local_path_for_local_folder(localfolderid, syncid, NULL);
  if (unlikely_log(!localpath)){
    psync_resume_localscan();
    return 0;
  }
  debug(D_NOTICE, "got recursive delete for localfolder %lu %s", (unsigned long)localfolderid, localpath);
  psync_sql_start_transaction();
  task_del_folder_rec_do(localpath, localfolderid, syncid);
  res=psync_sql_prep_statement("DELETE FROM localfolder WHERE id=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_run_free(res);
  if (psync_sql_affected_rows()){
    res=psync_sql_prep_statement("DELETE FROM syncedfolder WHERE localfolderid=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run_free(res);
  }
  psync_sql_commit_transaction();
  psync_rmdir_with_trashes(localpath);
  psync_resume_localscan();
  return 0;
}

static int download_task(uint64_t taskid, uint32_t type, psync_syncid_t syncid, uint64_t itemid, uint64_t localitemid, uint64_t newitemid, const char *name,
                         psync_syncid_t newsyncid){
  int res;
  const char *ptr;
  char *vname;
  vname=NULL;
  if (name && type!=PSYNC_DELETE_LOCAL_FILE && type!=PSYNC_DELETE_LOCAL_FOLDER)
    for (ptr=name; *ptr; ptr++)
      if (psync_invalid_filename_chars[(unsigned char)*ptr]){
        if (!vname)
          vname=psync_strdup(name);
        vname[ptr-name]=PSYNC_REPLACE_INV_CH_IN_FILENAMES;
      }
  if (vname){
    debug(D_NOTICE, "%u %s as %s", (unsigned)type, name, vname);
    name=vname;
  }
  switch (type) {
    case PSYNC_CREATE_LOCAL_FOLDER:
      res=call_func_for_folder(localitemid, itemid, syncid, PEVENT_LOCAL_FOLDER_CREATED, task_mkdir, 1, "local folder created");
      break;
    case PSYNC_DELETE_LOCAL_FOLDER:
      res=call_func_for_folder_name(localitemid, itemid, name, syncid, PEVENT_LOCAL_FOLDER_DELETED, task_rmdir, 0, "local folder deleted");
      if (!res){
        psync_sql_start_transaction();
        delete_local_folder_from_db(localitemid, syncid);
        psync_sql_commit_transaction();
      }
      break;
    case PSYNC_DELREC_LOCAL_FOLDER:
      res=task_del_folder_rec(localitemid, itemid, syncid);
      break;
    case PSYNC_RENAME_LOCAL_FOLDER:
      res=task_renamefolder(syncid, itemid, localitemid, newitemid, name);
      break;
    case PSYNC_DOWNLOAD_FILE:
      res=task_run_download_file(taskid, syncid, itemid, localitemid, name);
      break;
    case PSYNC_DELETE_LOCAL_FILE:
      res=task_delete_file(syncid, itemid, name);
      break;
    case PSYNC_RENAME_LOCAL_FILE:
      res=task_rename_file(syncid, newsyncid, itemid, localitemid, newitemid, name);
      break;
    default:
      debug(D_BUG, "invalid task type %u", (unsigned)type);
      res=0;
  }
  if (res && type!=PSYNC_DOWNLOAD_FILE)
    debug(D_WARNING, "task of type %u, syncid %u, id %lu localid %lu failed", (unsigned)type, (unsigned)syncid, (unsigned long)itemid, (unsigned long)localitemid);
  psync_free(vname);
  return res;
}

static void download_thread(){
  psync_variant *row;
  uint64_t taskid;
  uint32_t type;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));

    row=psync_sql_row("SELECT id, type, syncid, itemid, localitemid, newitemid, name, newsyncid FROM task WHERE "
                      "inprogress=0 AND type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_DOWNLOAD)" ORDER BY id LIMIT 1");
    if (row){
      taskid=psync_get_number(row[0]);
      type=psync_get_number(row[1]);
      if (!download_task(taskid, type,
                         psync_get_number_or_null(row[2]),
                         psync_get_number(row[3]),
                         psync_get_number(row[4]),
                         psync_get_number_or_null(row[5]),
                         psync_get_string_or_null(row[6]),
                         psync_get_number_or_null(row[7]))){
        delete_task(taskid);
        if (type==PSYNC_DOWNLOAD_FILE){
          psync_status_recalc_to_download_async();
          psync_path_status_sync_folder_task_completed(psync_get_number(row[2]), psync_get_number(row[4]));
        }
      }
      else if (type!=PSYNC_DOWNLOAD_FILE)
        psync_milisleep(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
      psync_free(row);
      continue;
    }

    pthread_mutex_lock(&download_mutex);
    if (!download_wakes)
      pthread_cond_wait(&download_cond, &download_mutex);
    download_wakes=0;
    pthread_mutex_unlock(&download_mutex);
  }
}

void psync_wake_download(){
  pthread_mutex_lock(&download_mutex);
  if (!download_wakes++)
    pthread_cond_signal(&download_cond);
  pthread_mutex_unlock(&download_mutex);
}

void psync_download_init(){
  psync_timer_exception_handler(psync_wake_download);
  psync_run_thread("download main", download_thread);
}

void psync_delete_download_tasks_for_file(psync_fileid_t fileid, psync_syncid_t syncid, int deltemp){
  psync_sql_res *res;
  download_list_t *dwl;
  uint32_t aff;
  if (syncid)
    res=psync_sql_prep_statement("DELETE FROM task WHERE type=? AND itemid=? AND syncid=?");
  else
    res=psync_sql_prep_statement("DELETE FROM task WHERE type=? AND itemid=?");
  psync_sql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  psync_sql_bind_uint(res, 2, fileid);
  if (syncid)
    psync_sql_bind_uint(res, 3, syncid);
  psync_sql_run(res);
  aff=psync_sql_affected_rows();
  psync_sql_free_result(res);
  if (aff)
    psync_status_recalc_to_download_async();
  if (deltemp)
    deltemp=2;
  else
    deltemp=1;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t, list)
    if (dwl->fileid==fileid && (syncid==0 || dwl->syncid==syncid))
      dwl->stop=deltemp;
  pthread_mutex_unlock(&current_downloads_mutex);
}

void psync_stop_file_download(psync_fileid_t fileid, psync_syncid_t syncid){
  download_list_t *dwl;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t, list)
    if (dwl->fileid==fileid && dwl->syncid==syncid)
      dwl->stop=1;
  pthread_mutex_unlock(&current_downloads_mutex);
}

void psync_stop_sync_download(psync_syncid_t syncid){
  download_list_t *dwl;
  psync_sql_res *res;
  res=psync_sql_prep_statement("DELETE FROM task WHERE syncid=? AND type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_DOWNLOAD));
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_run_free(res);
  psync_status_recalc_to_download_async();
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t, list)
    if (dwl->syncid==syncid)
      dwl->stop=1;
  pthread_mutex_unlock(&current_downloads_mutex);
}

void psync_stop_all_download(){
  download_list_t *dwl;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t, list)
    dwl->stop=1;
  pthread_mutex_unlock(&current_downloads_mutex);
}

downloading_files_hashes *psync_get_downloading_hashes(){
  download_list_t *dwl;
  downloading_files_hashes *ret;
  size_t cnt;
  cnt=0;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t, list)
    cnt++;
  ret=(downloading_files_hashes *)psync_malloc(offsetof(downloading_files_hashes, hashes)+sizeof(psync_hex_hash)*cnt);
  cnt=0;
  psync_list_for_each_element(dwl, &downloads, download_list_t, list)
    if (dwl->schecksum[0] && dwl->started){
      memcpy(ret->hashes[cnt], dwl->schecksum, PSYNC_HASH_DIGEST_HEXLEN);
      cnt++;
    }
  ret->hashcnt=cnt;
  pthread_mutex_unlock(&current_downloads_mutex);
  return ret;
}

