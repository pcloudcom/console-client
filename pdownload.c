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

static pthread_mutex_t download_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t download_cond=PTHREAD_COND_INITIALIZER;
static psync_uint_t download_wakes=0;
static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED),
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE)
};

static volatile psync_fileid_t downloadingfile=0, stopfile=0;
static volatile psync_syncid_t downloadingfilesyncid=0;

static int task_mkdir(const char *path){
  while (1){
    if (likely_log(!psync_mkdir(path))){
      psync_set_local_full(0);
      return 0;
    }
    if (psync_fs_err()==P_NOSPC || psync_fs_err()==P_DQUOT){
      psync_set_local_full(1);
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
    }
    else {
      psync_set_local_full(0);
      if (psync_fs_err()==P_NOENT)
        return 0; // do we have a choice? the user deleted the directory
      else if (psync_fs_err()==P_EXIST){
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
  if (likely_log(!psync_rmdir_with_trashes(path)))
    return 0;
  if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
    return -1;
  return 0;
//  if (psync_fs_err()==P_NOENT || psync_fs_err()==P_NOTDIR || psync_fs_err()==P_NOTEMPTY || psync_fs_err()==P_EXIST)
//    return 0;
}

static int task_rmdir_rec(const char *path){
  if (likely_log(!psync_rmdir_recursive(path)))
    return 0;
  if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
    return -1;
  return 0;
}

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
  res=psync_sql_prep_statement("UPDATE localfolder SET inode=?, mtime=?, mtimenative=? WHERE id=?");
  psync_sql_bind_uint(res, 1, psync_stat_inode(&st));
  psync_sql_bind_uint(res, 2, psync_stat_mtime(&st));
  psync_sql_bind_uint(res, 3, psync_stat_mtime_native(&st));
  psync_sql_bind_uint(res, 4, localfolderid);
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

static void delete_local_folder_from_db(psync_folderid_t localfolderid){
  psync_sql_res *res;
  if (likely(localfolderid)){
    res=psync_sql_prep_statement("DELETE FROM localfolder WHERE id=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run_free(res);
  }
}

static int task_renamefolder(psync_syncid_t newsyncid, psync_folderid_t folderid, psync_folderid_t localfolderid,
                             psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  psync_uint_row row;
  char *oldpath, *newpath;
  psync_syncid_t oldsyncid;
  int ret;
  assert(newname!=NULL);
  res=psync_sql_query("SELECT syncid FROM localfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  row=psync_sql_fetch_rowint(res);
  if (unlikely(!row)){
    psync_sql_free_result(res);
    debug(D_ERROR, "could not find local folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  oldsyncid=row[0];
  psync_sql_free_result(res);
  oldpath=psync_local_path_for_local_folder(localfolderid, oldsyncid, NULL);
  if (unlikely(!oldpath)){
    debug(D_ERROR, "could not get local path for folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  psync_sql_start_transaction();
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
    debug(D_NOTICE, "local folder renamed from %s ro %s", oldpath, newpath);
  }
  psync_free(newpath);
  psync_free(oldpath);
  return ret;
}

static int rename_if_notex(const char *oldname, const char *newname){
  return psync_file_rename_overwrite(oldname, newname);
}

static int stat_and_create_local(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *filename,
                                 const char *name, unsigned char *hash, uint64_t serversize){
  psync_sql_res *sql;
  psync_stat_t st;
  if (unlikely_log(psync_stat(name, &st)) || unlikely_log(psync_stat_size(&st)!=serversize))
    return -1;
  sql=psync_sql_prep_statement("REPLACE INTO localfile (localparentfolderid, fileid, syncid, size, inode, mtime, mtimenative, name, checksum)"
                                              " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_uint(sql, 1, localfolderid);
  psync_sql_bind_uint(sql, 2, fileid);
  psync_sql_bind_uint(sql, 3, syncid);
  psync_sql_bind_uint(sql, 4, psync_stat_size(&st));
  psync_sql_bind_uint(sql, 5, psync_stat_inode(&st));
  psync_sql_bind_uint(sql, 6, psync_stat_mtime(&st));
  psync_sql_bind_uint(sql, 7, psync_stat_mtime_native(&st));
  psync_sql_bind_string(sql, 8, filename);
  psync_sql_bind_lstring(sql, 9, (char *)hash, PSYNC_HASH_DIGEST_HEXLEN);
  psync_sql_run_free(sql);
  return 0;
}

static int task_download_file(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *filename){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid)};
  psync_socket *api;
  binresult *res;
  psync_sql_res *sql;
  const binresult *hosts;
  char *localpath, *tmpname, *name;
  const char *requestpath;
  void *buff;
  psync_http_socket *http;
  uint64_t result, serversize, localsize;
  int64_t freespace;
  psync_uint_row row;
  psync_hash_ctx hashctx;
  unsigned char serverhashhex[PSYNC_HASH_DIGEST_HEXLEN], 
                localhashhex[PSYNC_HASH_DIGEST_HEXLEN], 
                localhashbin[PSYNC_HASH_DIGEST_LEN];
  uint32_t i;
  psync_file_t fd;
  int rd, rt;
  downloadingfile=fileid;
  downloadingfilesyncid=syncid;
  localpath=psync_local_path_for_local_folder(localfolderid, syncid, NULL);
  name=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, filename, NULL);
  rt=psync_get_remote_file_checksum(fileid, serverhashhex, &serversize);
  if (unlikely_log(rt!=PSYNC_NET_OK)){
    if (rt==PSYNC_NET_TEMPFAIL)
      goto err_sl_ex;
    else
      goto ret0;
  }
  result=psync_setting_get_uint(_PS(minlocalfreespace));
  if (result){
    freespace=psync_get_free_space_by_path(localpath);
    if (likely_log(freespace!=-1)){
      if (freespace>=result+serversize)
        psync_set_local_full(0);
      else{
        psync_set_local_full(1);
        psync_free(localpath);
        psync_free(name);
        psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
        return -1;
      }
    }
  }
  sql=psync_sql_query("SELECT fileid, id FROM localfile WHERE size=? AND checksum=? AND localparentfolderid=? AND name=?");
  psync_sql_bind_uint(sql, 1, serversize);
  psync_sql_bind_lstring(sql, 2, (char *)serverhashhex, PSYNC_HASH_DIGEST_HEXLEN);
  psync_sql_bind_uint(sql, 3, localfolderid);
  psync_sql_bind_string(sql, 4, filename);
  if ((row=psync_sql_fetch_rowint(sql))){
    rt=row[0]!=fileid;
    result=row[1];
    psync_sql_free_result(sql);
    if (rt){
      sql=psync_sql_prep_statement("UPDATE localfile SET fileid=? WHERE id=?");
      psync_sql_bind_uint(sql, 1, fileid);
      psync_sql_bind_uint(sql, 2, result);
      psync_sql_run_free(sql);
    }
    goto ret0;
  }
  psync_sql_free_result(sql);
  if (psync_get_local_file_checksum(name, localhashhex, &localsize)==PSYNC_NET_OK){
    if (localsize==serversize && !memcmp(localhashhex, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN)){
      if (unlikely_log(stat_and_create_local(syncid, fileid, localfolderid, filename, name, serverhashhex, serversize)))
        goto err_sl_ex;
      else{
        debug(D_NOTICE, "file already exists %s, not downloading", name);
        goto ret0;
      }
    }
  }
  sql=psync_sql_query("SELECT id FROM localfile WHERE size=? AND checksum=?");
  psync_sql_bind_uint(sql, 1, serversize);
  psync_sql_bind_lstring(sql, 2, (char *)serverhashhex, PSYNC_HASH_DIGEST_HEXLEN);
  while ((row=psync_sql_fetch_rowint(sql))){
    tmpname=psync_local_path_for_local_file(row[0], NULL);
    rt=psync_copy_local_file_if_checksum_matches(tmpname, name, serverhashhex, serversize);
    if (likely(rt==PSYNC_NET_OK)){
      if (unlikely_log(stat_and_create_local(syncid, fileid, localfolderid, filename, name, serverhashhex, serversize)))
        rt=PSYNC_NET_TEMPFAIL;
      else
        debug(D_NOTICE, "file %s copied from %s", tmpname, name);
    }
    else
      debug(D_WARNING, "failed to copy %s from %s", tmpname, name);
    psync_free(tmpname);
    if (likely_log(rt==PSYNC_NET_OK)){
      psync_sql_free_result(sql);
      goto ret0;
    }
  }
  psync_sql_free_result(sql);
  api=psync_apipool_get();
  if (unlikely_log(!api))
    goto err_sl_ex;
  res=send_command(api, "getfilelink", params);
  psync_apipool_release(api);
  if (unlikely_log(!res))
    goto err_sl_ex;
  tmpname=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, filename, PSYNC_APPEND_PARTIAL_FILES, NULL);
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    debug(D_WARNING, "got error %lu from getfilelink", (long unsigned)result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      goto err0;
    else{
      psync_free(res);
      psync_free(tmpname);
      goto ret0;
    }
  }
  fd=psync_file_open(tmpname, P_O_WRONLY, P_O_CREAT);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE))
    goto err0;
  
  psync_send_event_by_id(PEVENT_FILE_DOWNLOAD_STARTED, syncid, name, fileid);
  psync_status.bytestodownloadcurrent=serversize;
  psync_status.bytesdownloaded=0;
  
  hosts=psync_find_result(res, "hosts", PARAM_ARRAY);
  requestpath=psync_find_result(res, "path", PARAM_STR)->str;
  http=NULL;
  for (i=0; i<hosts->length; i++)
    if ((http=psync_http_connect(hosts->array[i]->str, requestpath, 0, 0)))
      break;
  if (unlikely_log(!http))
    goto err1;
  psync_hash_init(&hashctx);
  rd=0;
  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (stopfile!=fileid && (rd=psync_http_readall(http, buff, PSYNC_COPY_BUFFER_SIZE))>0){
    if (unlikely_log(psync_file_writeall_checkoverquota(fd, buff, rd)))
      goto err2;
    psync_hash_update(&hashctx, buff, rd);
    psync_status.bytesdownloaded+=rd;
    psync_send_status_update();
    if (unlikely(!psync_statuses_ok_array(requiredstatuses, ARRAY_SIZE(requiredstatuses))))
      goto err2;
  }
  psync_status.bytestodownloadcurrent=0;
  psync_status.bytesdownloaded=0;
  downloadingfile=0;
  downloadingfilesyncid=0;
  if (unlikely(stopfile)){
    if (stopfile==fileid){
      psync_free(buff);
      psync_http_close(http);
      psync_file_close(fd);
      psync_hash_final(localhashbin, &hashctx);
      psync_file_delete(tmpname);
      goto err0;
    }
    stopfile=0;
  }
  if (unlikely_log(rd==-1) || unlikely_log(psync_file_sync(fd)))
    goto err2;
  psync_free(buff);
  psync_http_close(http);
  psync_hash_final(localhashbin, &hashctx);
  if (unlikely_log(psync_file_close(fd)))
    goto err0;
  psync_binhex(localhashhex, localhashbin, PSYNC_HASH_DIGEST_LEN);
  if (unlikely_log(memcmp(localhashhex, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN))){
    debug(D_WARNING, "got wrong file checksum for file %s", filename);
    goto err0;
  }
  if (unlikely_log(rename_if_notex(tmpname, name)) || unlikely_log(stat_and_create_local(syncid, fileid, localfolderid, filename, name, localhashhex, serversize)))
    goto err0;
  psync_send_event_by_id(PEVENT_FILE_DOWNLOAD_FINISHED, syncid, name, fileid);
  debug(D_NOTICE, "file downloaded %s", name);
  psync_free(name);
  psync_free(tmpname);
  psync_free(localpath);
  psync_free(res);
  return 0;
err2:
  psync_hash_final(localhashbin, &hashctx); /* just in case */
  psync_free(buff);
  psync_http_close(http);
err1:
  psync_status.bytestodownloadcurrent=0;
  psync_status.bytesdownloaded=0;
  psync_file_close(fd);
  psync_send_event_by_id(PEVENT_FILE_DOWNLOAD_FAILED, syncid, name, fileid);
err0:
  psync_free(tmpname);
  psync_free(localpath);
  psync_free(name);
  psync_free(res);
  downloadingfile=0;
  downloadingfilesyncid=0;
  return -1;
err_sl_ex:
  psync_free(localpath);
  psync_free(name);
  downloadingfile=0;
  downloadingfilesyncid=0;
  psync_timer_notify_exception();
  psync_milisleep(PSYNC_SOCK_TIMEOUT_ON_EXCEPTION*1000);
  return -1;
ret0:
  psync_free(localpath);
  psync_free(name);
  return 0;
}

static int task_delete_file(psync_syncid_t syncid, psync_fileid_t fileid, const char *remotepath){
  psync_sql_res *res, *stmt;
  psync_uint_row row;
  char *name;
  int ret;
  ret=0;
  if (syncid){
    res=psync_sql_query("SELECT id, syncid FROM localfile WHERE fileid=? AND syncid=?");
    psync_sql_bind_uint(res, 2, syncid);
  }
  else
    res=psync_sql_query("SELECT id, syncid FROM localfile WHERE fileid=?");
  psync_sql_bind_uint(res, 1, fileid);
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
      psync_send_event_by_path(PEVENT_LOCAL_FILE_DELETED, row[1], name, fileid, remotepath);
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
  psync_uint_row row;
  psync_fileid_t lfileid;
  psync_stat_t st;
  int ret;
  res=psync_sql_query("SELECT id FROM localfile WHERE syncid=? AND fileid=?");
  psync_sql_bind_uint(res, 1, oldsyncid);
  psync_sql_bind_uint(res, 2, fileid);
  row=psync_sql_fetch_rowint(res);
  if (row)
    lfileid=row[0];
  else
    lfileid=0;
  psync_sql_free_result(res);
  if (unlikely_log(!fileid)){
    psync_task_download_file(newsyncid, fileid, newlocalfolderid, newname);
    return 0;
  }
  newfolder=psync_local_path_for_local_folder(newlocalfolderid, newsyncid, NULL);
  if (unlikely_log(!newfolder)){
    psync_free(newfolder);
    return 0;
  }
  oldpath=psync_local_path_for_local_file(lfileid, NULL);
  newpath=psync_strcat(newfolder, PSYNC_DIRECTORY_SEPARATOR, newname, NULL);
  ret=0;
  if (psync_file_rename_overwrite(oldpath, newpath)){
    if (psync_fs_err()==P_NOENT){
      debug(D_WARNING, "renamed from %s to %s failed, downloading", oldpath, newpath);
      psync_task_download_file(newsyncid, fileid, newlocalfolderid, newname);
    }
    else
      ret=-1;
  }
  else{
    if (likely_log(!psync_stat(newpath, &st))){
      res=psync_sql_prep_statement("UPDATE localfile SET localparentfolderid=?, syncid=?, name=?, inode=?, mtime=?, mtimenative=? WHERE id=?");
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
  }
  psync_free(newpath);
  psync_free(oldpath);
  psync_free(newfolder);
  return ret;
}
  
static int download_task(uint32_t type, psync_syncid_t syncid, uint64_t itemid, uint64_t localitemid, uint64_t newitemid, const char *name,
                                        psync_syncid_t newsyncid){
  int res;
  switch (type) {
    case PSYNC_CREATE_LOCAL_FOLDER:
      res=call_func_for_folder(localitemid, itemid, syncid, PEVENT_LOCAL_FOLDER_CREATED, task_mkdir, 1, "local folder created");
      break;
    case PSYNC_DELETE_LOCAL_FOLDER:
      res=call_func_for_folder_name(localitemid, itemid, name, syncid, PEVENT_LOCAL_FOLDER_DELETED, task_rmdir, 0, "local folder deleted");
      if (!res)
        delete_local_folder_from_db(localitemid);
      break;
    case PSYNC_DELREC_LOCAL_FOLDER:
      res=call_func_for_folder(localitemid, itemid, syncid, PEVENT_LOCAL_FOLDER_DELETED, task_rmdir_rec, 0, "local folder deleted recursively");
      if (!res)
        delete_local_folder_from_db(localitemid);
      break;
    case PSYNC_RENAME_LOCAL_FOLDER:
      res=task_renamefolder(syncid, itemid, localitemid, newitemid, name);
      break;
    case PSYNC_DOWNLOAD_FILE:
      res=task_download_file(syncid, itemid, localitemid, name);
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
  if (res)
    debug(D_WARNING, "task of type %u, syncid %u, id %lu localid %lu failed", (unsigned)type, (unsigned)syncid, (unsigned long)itemid, (unsigned long)localitemid);
  return res;
}

static void download_thread(){
  psync_sql_res *res;
  psync_variant *row;
  uint32_t type;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    
    row=psync_sql_row("SELECT id, type, syncid, itemid, localitemid, newitemid, name, newsyncid FROM task WHERE type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_DOWNLOAD)" ORDER BY id LIMIT 1");
    if (row){
      type=psync_get_number(row[1]);
      if (!download_task(type, 
                         psync_get_number(row[2]), 
                         psync_get_number(row[3]), 
                         psync_get_number(row[4]), 
                         psync_get_number_or_null(row[5]),                          
                         psync_get_string_or_null(row[6]),
                         psync_get_number_or_null(row[7]))){
        res=psync_sql_prep_statement("DELETE FROM task WHERE id=?");
        psync_sql_bind_uint(res, 1, psync_get_number(row[0]));
        psync_sql_run_free(res);
        if (type==PSYNC_DOWNLOAD_FILE){
          psync_status_recalc_to_download();
          psync_send_status_update();
        }
      }
      else
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
  psync_run_thread(download_thread);
}

void psync_delete_download_tasks_for_file(psync_fileid_t fileid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("DELETE FROM task WHERE type=? AND itemid=?");
  psync_sql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  psync_sql_bind_uint(res, 2, fileid);
  psync_sql_run(res);
  if (psync_sql_affected_rows()){
    psync_status_recalc_to_download();
    psync_send_status_update();
  }
  psync_sql_free_result(res);
  if (fileid==downloadingfile)
    stopfile=fileid;
}

void psync_stop_file_download(psync_fileid_t fileid, psync_syncid_t syncid){
  if (fileid==downloadingfile && syncid==downloadingfilesyncid)
    stopfile=fileid;
}
