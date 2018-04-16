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

#include "pupload.h"
#include "pstatus.h"
#include "ptimer.h"
#include "plibs.h"
#include "ptasks.h"
#include "pssl.h"
#include "psettings.h"
#include "pnetlibs.h"
#include "papi.h"
#include "pfolder.h"
#include "pcallbacks.h"
#include "pdiff.h"
#include "plist.h"
#include "plocalscan.h"
#include "pfileops.h"
#include "ppathstatus.h"

typedef struct {
  psync_list list;
  psync_fileid_t localfileid;
  uint64_t filesize;
  uint64_t uploaded;
  uint64_t taskid;
  psync_syncid_t syncid;
  int stop;
  unsigned char hash[PSYNC_HASH_DIGEST_HEXLEN];
} upload_list_t;

typedef struct {
  upload_list_t upllist;
  char filename[];
} upload_task_t;

static pthread_mutex_t upload_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t upload_cond=PTHREAD_COND_INITIALIZER;
static uint32_t upload_wakes=0;

static psync_uint_t current_uploads_waiters=0;
static pthread_mutex_t current_uploads_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t current_uploads_cond=PTHREAD_COND_INITIALIZER;

static psync_list uploads=PSYNC_LIST_STATIC_INIT(uploads);

static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE),
  PSTATUS_COMBINE(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK)
};

void psync_upload_inc_uploads(){
  pthread_mutex_lock(&upload_mutex);
  psync_status.filesuploading++;
  pthread_mutex_unlock(&upload_mutex);
  psync_send_status_update();
}

void psync_upload_dec_uploads(){
  pthread_mutex_lock(&upload_mutex);
  psync_status.filesuploading--;
  if (psync_status.filesuploading==0 && current_uploads_waiters)
    pthread_cond_broadcast(&current_uploads_cond);
  pthread_mutex_unlock(&upload_mutex);
  psync_send_status_update();
}

void psync_upload_dec_uploads_cnt(uint32_t cnt){
  pthread_mutex_lock(&upload_mutex);
  psync_status.filesuploading-=cnt;
  if (psync_status.filesuploading==0 && current_uploads_waiters)
    pthread_cond_broadcast(&current_uploads_cond);
  pthread_mutex_unlock(&upload_mutex);
  psync_send_status_update();
}

void psync_upload_add_bytes_uploaded(uint64_t bytes){
  pthread_mutex_lock(&upload_mutex);
  psync_status.bytesuploaded+=bytes;
  pthread_mutex_unlock(&upload_mutex);
  psync_send_status_update();
}

void psync_upload_sub_bytes_uploaded(uint64_t bytes){
  pthread_mutex_lock(&upload_mutex);
  psync_status.bytesuploaded-=bytes;
  pthread_mutex_unlock(&upload_mutex);
  psync_send_status_update();
}

static int task_wait_no_uploads(uint64_t taskid){
  psync_sql_res *res;
  psync_uint_row row;
  uint64_t cnt;
  pthread_mutex_lock(&current_uploads_mutex);
  while (psync_status.filesuploading){
    current_uploads_waiters++;
    pthread_cond_wait(&current_uploads_cond, &current_uploads_mutex);
    current_uploads_waiters--;
    if (!psync_status.filesuploading)
      debug(D_NOTICE, "waited for uploads to finish");
  }
  pthread_mutex_unlock(&current_uploads_mutex);
  res=psync_sql_query("SELECT COUNT(*) FROM task WHERE id<? AND type=?");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_bind_uint(res, 2, PSYNC_UPLOAD_FILE);
  if ((row=psync_sql_fetch_rowint(res)))
    cnt=row[0];
  else
    cnt=0;
  psync_sql_free_result(res);
  if (cnt){
    debug(D_NOTICE, "all uploads stopped, but there are still %u upload tasks", (unsigned)cnt);
    return -1;
  }
  else
    return 0;
}

static int64_t do_run_command_res(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt){
  binresult *res;
  uint64_t result;
  res=psync_do_api_run_command(cmd, cmdlen, params, paramscnt);
  if (unlikely(!res))
    return -1;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  if (unlikely(result)){
    psync_process_api_error(result);
    debug(D_WARNING, "command %s returned code %u", cmd, (unsigned)result);
  }
  return result;
}

static int do_run_command(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt){
  uint64_t result;
  result=do_run_command_res(cmd, cmdlen, params, paramscnt);
  if (unlikely(result))
    return psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL?-1:0;
  else
    return 0;
}

#define run_command(cmd, params) do_run_command(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam))
#define run_command_res(cmd, params) do_run_command_res(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam))

static int task_createfolder(psync_syncid_t syncid, psync_folderid_t localfolderid, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t parentfolderid, folderid;
  binresult *bres;
  const binresult *meta;
  uint64_t result;
  int ret;
  res=psync_sql_query_rdlock("SELECT s.folderid FROM localfolder l, syncedfolder s WHERE l.id=? AND l.syncid=? AND l.localparentfolderid=s.localfolderid AND s.syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, syncid);
  if (likely_log(row=psync_sql_fetch_rowint(res)))
    parentfolderid=row[0];
  else
    parentfolderid=PSYNC_INVALID_FOLDERID;
  psync_sql_free_result(res);
  if (unlikely(parentfolderid==PSYNC_INVALID_FOLDERID))
    return 0;
  else{
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", parentfolderid), P_STR("name", name), P_STR("timeformat", "timestamp")};
    psync_diff_lock();
    bres=psync_api_run_command("createfolderifnotexists", params);
    if (unlikely(!bres)){
      psync_diff_unlock();
      return -1;
    }
    result=psync_find_result(bres, "result", PARAM_NUM)->num;
    if (unlikely(result)){
      psync_diff_unlock();
      debug(D_WARNING, "command createfolderifnotexists returned code %u: %s for creating folder in %lu with name %s",
            (unsigned)result, psync_find_result(bres, "error", PARAM_STR)->str, (unsigned long)parentfolderid, name);
      psync_process_api_error(result);
      psync_free(bres);
      if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
        return -1;
      else
        return 0;
    }
    meta=psync_find_result(bres, "metadata", PARAM_HASH);
    folderid=psync_find_result(meta, "folderid", PARAM_NUM)->num;
    debug(D_NOTICE, "remote folder %lu %lu/%s created", (long unsigned)folderid, (long unsigned)parentfolderid, name);
    psync_sql_start_transaction();
    psync_ops_create_folder_in_db(meta);
    res=psync_sql_prep_statement("UPDATE localfolder SET folderid=? WHERE id=? AND syncid=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_uint(res, 2, localfolderid);
    psync_sql_bind_uint(res, 3, syncid);
    psync_sql_run_free(res);
    res=psync_sql_prep_statement("UPDATE syncedfolder SET folderid=? WHERE localfolderid=? AND syncid=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_uint(res, 2, localfolderid);
    psync_sql_bind_uint(res, 3, syncid);
    psync_sql_run_free(res);
    ret=psync_sql_commit_transaction();
    psync_diff_unlock();
    if (psync_find_result(bres, "created", PARAM_BOOL)->num)
      psync_diff_wake();
    psync_free(bres);
    return ret;
  }
}

static int task_renameremotefile(psync_fileid_t fileid, psync_folderid_t newparentfolderid, const char *newname){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("tofolderid", newparentfolderid), P_STR("toname", newname),
                     P_STR("timeformat", "timestamp")};
  int ret;
  ret=run_command("renamefile", params);
  if (likely(!ret)){
    debug(D_NOTICE, "remote fileid %lu moved/renamed to (%lu)/%s", (long unsigned)fileid, (long unsigned)newparentfolderid, newname);
    psync_diff_wake();
  }
  return ret;
}

static int task_renamefile(uint64_t taskid, psync_syncid_t syncid, psync_fileid_t localfileid, psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fileid_t fileid;
  psync_folderid_t folderid;
  if (task_wait_no_uploads(taskid))
    return -1;
  res=psync_sql_query_rdlock("SELECT fileid FROM localfile WHERE id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res)))
    fileid=row[0];
  else
    fileid=0;
  psync_sql_free_result(res);
  res=psync_sql_query_rdlock("SELECT folderid FROM syncedfolder WHERE syncid=? AND localfolderid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, newlocalparentfolderid);
  if ((row=psync_sql_fetch_rowint(res)))
    folderid=row[0];
  else
    folderid=0;
  psync_sql_free_result(res);
  if (unlikely_log(!fileid) || unlikely_log(!folderid))
    return 0;
  else
    return task_renameremotefile(fileid, folderid, newname);
}

static int task_renameremotefolder(psync_folderid_t folderid, psync_folderid_t newparentfolderid, const char *newname){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_NUM("tofolderid", newparentfolderid), P_STR("toname", newname),
                     P_STR("timeformat", "timestamp")};
  binresult *res;
  uint64_t result;
  int ret;
  res=psync_api_run_command("renamefolder", params);
  if (unlikely(!res))
    return -1;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (likely(!result)){
    ret=0;
    debug(D_NOTICE, "remote folderid %lu moved/renamed to (%lu)/%s", (long unsigned)folderid, (long unsigned)newparentfolderid, newname);
    if (!psync_sql_start_transaction()){
      psync_ops_update_folder_in_db(psync_find_result(res, "metadata", PARAM_HASH));
      psync_sql_commit_transaction();
    }
    psync_diff_wake();
  }
  else{
    ret=-1;
    psync_process_api_error(result);
    debug(D_NOTICE, "command renamefolder returned %lu: %s", (unsigned long)result, psync_find_result(res, "error", PARAM_STR)->str);
  }
  psync_free(res);
  return ret;
}

static int task_renamefolder(uint64_t taskid, psync_syncid_t syncid, psync_fileid_t localfolderid, psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t folderid, parentfolderid;
  if (task_wait_no_uploads(taskid))
    return -1;
  res=psync_sql_query_rdlock("SELECT folderid FROM syncedfolder WHERE syncid=? AND localfolderid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, localfolderid);
  if ((row=psync_sql_fetch_rowint(res)))
    folderid=row[0];
  else
    folderid=0;
  psync_sql_free_result(res);
  res=psync_sql_query_rdlock("SELECT folderid FROM syncedfolder WHERE syncid=? AND localfolderid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, newlocalparentfolderid);
  if ((row=psync_sql_fetch_rowint(res)))
    parentfolderid=row[0];
  else
    parentfolderid=0;
  psync_sql_free_result(res);
  if (unlikely_log(!folderid) || unlikely_log(!parentfolderid))
    return 0;
  else
    return task_renameremotefolder(folderid, parentfolderid, newname);
}

static void set_local_file_remote_id(psync_fileid_t localfileid, psync_fileid_t fileid, uint64_t hash){
  psync_sql_res *res;
  res=psync_sql_prep_statement("UPDATE localfile SET fileid=?, hash=? WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  psync_sql_bind_uint(res, 2, hash);
  psync_sql_bind_uint(res, 3, localfileid);
  psync_sql_run_free(res);
}

static void set_local_file_conflicted(psync_fileid_t localfileid, psync_fileid_t fileid, uint64_t hash, const char *localpath, const char *newname,
                                      uint64_t taskid){
  psync_sql_res *res;
  char *newpath;
  debug(D_NOTICE, "conflict found, renaming %s to %s", localpath, newname);
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("UPDATE localfile SET fileid=?, hash=?, name=? WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  psync_sql_bind_uint(res, 2, hash);
  psync_sql_bind_string(res, 3, newname);
  psync_sql_bind_uint(res, 4, localfileid);
  psync_sql_run_free(res);
  res=psync_sql_prep_statement("UPDATE task SET name=? WHERE id=?");
  psync_sql_bind_string(res, 1, newname);
  psync_sql_bind_uint(res, 2, taskid);
  psync_sql_run_free(res);
  newpath=psync_local_path_for_local_file(localfileid, NULL);
  if (unlikely_log(psync_file_rename_overwrite(localpath, newpath)))
    psync_sql_rollback_transaction();
  else
    psync_sql_commit_transaction();
  psync_free(newpath);
}

static int copy_file(psync_fileid_t fileid, uint64_t hash, psync_folderid_t folderid, const char *name, psync_fileid_t localfileid, psync_stat_t *st){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("hash", hash), P_NUM("tofolderid", folderid), P_STR("toname", name),
#if defined(PSYNC_HAS_BIRTHTIME)
                     P_NUM("ctime", psync_stat_birthtime(st)),
#endif
                     P_NUM("mtime", psync_stat_mtime(st)), P_STR("timeformat", "timestamp")};
  binresult *res;
  const binresult *meta;
  uint64_t result;
  psync_diff_lock();
  res=psync_api_run_command("copyfile", params);
  if (unlikely(!res)){
    psync_diff_unlock();
    return -1;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    psync_diff_unlock();
    psync_free(res);
    debug(D_WARNING, "command copyfile returned code %u", (unsigned)result);
    psync_process_api_error(result);
    return 0;
  }
  meta=psync_find_result(res, "metadata", PARAM_HASH);
  set_local_file_remote_id(localfileid, psync_find_result(meta, "fileid", PARAM_NUM)->num, psync_find_result(meta, "hash", PARAM_NUM)->num);
  psync_diff_unlock();
  psync_free(res);
  psync_diff_wake();
  return 1;
}

static int check_file_if_exists(const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name, psync_fileid_t localfileid){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fileid_t fileid;
  uint64_t filesize, hash;
  unsigned char shashhex[PSYNC_HASH_DIGEST_HEXLEN];
  int ret;
  res=psync_sql_query_rdlock("SELECT id, size FROM file WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_string(res, 2, name);
  row=psync_sql_fetch_rowint(res);
  if (row && row[1]==fsize){
    fileid=row[0];
    psync_sql_free_result(res);
    ret=psync_get_remote_file_checksum(fileid, shashhex, &filesize, &hash);
    if (ret==PSYNC_NET_OK){
      if (filesize==fsize && !memcmp(hashhex, shashhex, PSYNC_HASH_DIGEST_HEXLEN)){
        debug(D_NOTICE, "file %lu/%s already exists and matches local checksum, not doing anything", (unsigned long)folderid, name);
        set_local_file_remote_id(localfileid, fileid, hash);
        return 1;
      }
      else
        return 0;
    }
    else if (ret==PSYNC_NET_TEMPFAIL)
      return -1;
    else if (ret==PSYNC_NET_PERMFAIL)
      return 0;
  }
  psync_sql_free_result(res);
  return 0;
}

static int copy_file_if_exists(const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name, psync_fileid_t localfileid,
                               psync_stat_t *st){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("size", fsize), P_LSTR(PSYNC_CHECKSUM, hashhex, PSYNC_HASH_DIGEST_HEXLEN), P_STR("timeformat", "timestamp")};
  binresult *res;
  const binresult *metas, *meta;
  uint64_t result;
  int ret;
  res=psync_api_run_command("getfilesbychecksum", params);
  if (!res)
    return -1;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    psync_free(res);
    debug(D_WARNING, "command getfilesbychecksum returned code %u", (unsigned)result);
    psync_process_api_error(result);
    return 0;
  }
  metas=psync_find_result(res, "metadata", PARAM_ARRAY);
  if (!metas->length){
    psync_free(res);
    return 0;
  }
  meta=metas->array[0];
  ret=copy_file(psync_find_result(meta, "fileid", PARAM_NUM)->num, psync_find_result(meta, "hash", PARAM_NUM)->num, folderid, name, localfileid, st);
  if (ret==1)
    debug(D_NOTICE, "file %lu/%s copied to %lu/%s instead of uploading due to matching checksum",
          (long unsigned)psync_find_result(meta, "parentfolderid", PARAM_NUM)->num, psync_find_result(meta, "name", PARAM_STR)->str,
          (long unsigned)folderid, name);
  psync_free(res);
  return ret;
}

static void wake_upload_when_ready(){
  if (current_uploads_waiters && psync_status.filesuploading<PSYNC_MAX_PARALLEL_UPLOADS &&
      psync_status.bytestouploadcurrent-psync_status.bytesuploaded<=PSYNC_START_NEW_UPLOADS_TRESHOLD)
    pthread_cond_signal(&current_uploads_cond);
}

static void add_bytes_uploaded(uint64_t bytes){
  pthread_mutex_lock(&current_uploads_mutex);
  psync_status.bytesuploaded+=bytes;
  wake_upload_when_ready();
  pthread_mutex_unlock(&current_uploads_mutex);
  psync_send_status_update();
}

static int upload_file(const char *localpath, const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name,
                       psync_fileid_t localfileid, psync_syncid_t syncid, upload_list_t *upload, psync_stat_t *st, binparam pr){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("filename", name), P_BOOL("nopartial", 1), P_STR("timeformat", "timestamp"),
#if defined(PSYNC_HAS_BIRTHTIME)
                     P_NUM("ctime", psync_stat_birthtime(st)),
#endif
                     P_NUM("mtime", psync_stat_mtime(st)), {pr.paramtype, pr.paramnamelen, pr.opts, pr.paramname, {pr.num}} /* specially for Visual Studio compiler */};
  psync_socket *api;
  void *buff;
  binresult *res;
  const binresult *meta;
  const char *hashhexsrv;
  psync_sql_res *sres;
  uint64_t bw, result, fileid, rsize, hash;
  size_t rd;
  ssize_t rrd;
  psync_file_t fd;
  fd=psync_file_open(localpath, P_O_RDONLY, 0);
  if (fd==INVALID_HANDLE_VALUE){
    debug(D_WARNING, "could not open local file %s", localpath);
    return -1;
  }
  api=psync_apipool_get();
  if (unlikely(!api))
    goto err0;
  if (unlikely_log(!do_send_command(api, "uploadfile", strlen("uploadfile"), params, ARRAY_SIZE(params), fsize, 0)))
    goto err1;
  bw=0;
  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (bw<fsize){
    if (unlikely(upload->stop)){
      debug(D_NOTICE, "upload of %s stopped", localpath);
      goto err2;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    if (fsize-bw>PSYNC_COPY_BUFFER_SIZE)
      rd=PSYNC_COPY_BUFFER_SIZE;
    else
      rd=fsize-bw;
    rrd=psync_file_read(fd, buff, rd);
    if (unlikely_log(rrd<=0))
      goto err2;
    if (unlikely_log(psync_socket_writeall_upload(api, buff, rrd)!=rrd))
      goto err2;
    bw+=rrd;
    if (bw==fsize && psync_file_read(fd, buff, 1)!=0){
      debug(D_WARNING, "file %s has grown while uploading, retrying", localpath);
      goto err2;
    }
    upload->uploaded+=rrd;
    add_bytes_uploaded(rrd);
  }
  psync_free(buff);
  psync_file_close(fd);
  psync_set_default_sendbuf(api);
  psync_diff_lock();
  res=get_result(api);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_apipool_release_bad(api);
    goto err00;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    psync_free(res);
    debug(D_WARNING, "command uploadfile returned code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      goto err00;
    else{
      psync_diff_unlock();
      return 0;
    }
  }
  meta=psync_find_result(res, "metadata", PARAM_ARRAY)->array[0];
  fileid=psync_find_result(meta, "fileid", PARAM_NUM)->num;
  hash=psync_find_result(meta, "hash", PARAM_NUM)->num;
  rsize=psync_find_result(meta, "size", PARAM_NUM)->num;
  hashhexsrv=psync_find_result(psync_find_result(res, "checksums", PARAM_ARRAY)->array[0], PSYNC_CHECKSUM, PARAM_STR)->str;
  psync_sql_start_transaction();
  sres=psync_sql_prep_statement("REPLACE INTO hashchecksum (hash, size, checksum) VALUES (?, ?, ?)");
  psync_sql_bind_uint(sres, 1, hash);
  psync_sql_bind_uint(sres, 2, rsize);
  psync_sql_bind_lstring(sres, 3, hashhexsrv, PSYNC_HASH_DIGEST_HEXLEN);
  psync_sql_run_free(sres);
  if (psync_check_result(meta, "conflicted", PARAM_BOOL)){
    psync_sql_commit_transaction();
    set_local_file_conflicted(localfileid, fileid, hash, localpath, psync_find_result(meta, "name", PARAM_STR)->str, upload->taskid);
  }
  else{
    set_local_file_remote_id(localfileid, fileid, hash);
    psync_sql_commit_transaction();
  }
  psync_diff_unlock();
  if (rsize!=fsize || memcmp(hashhexsrv, hashhex, PSYNC_HASH_DIGEST_HEXLEN)){
    debug(D_WARNING, "uploaded file differs localsize=%lu, remotesize=%lu, localhash=%s, remotehash=%s",
          (unsigned long)fsize, (unsigned long)rsize, hashhex, hashhexsrv);
    psync_free(res);
    return -1;
  }
  psync_free(res);
  psync_diff_wake();
  debug(D_NOTICE, "file %s uploaded to %lu/%s", localpath, (long unsigned)folderid, name);
  return 0;
err2:
  psync_free(buff);
err1:
  psync_apipool_release_bad(api);
err0:
  psync_file_close(fd);
return -1;
err00:
  psync_diff_unlock();
  return -1;
}

static int upload_range(psync_socket *api, psync_upload_range_list_t *r, upload_list_t *upload, psync_uploadid_t uploadid, psync_file_t fd){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", r->uploadoffset), P_NUM("id", r->id), P_NUM("uploadid", uploadid)};
  void *buff;
  uint64_t bw;
  size_t rd;
  ssize_t rrd;
  if (unlikely_log(psync_file_seek(fd, r->off, P_SEEK_SET)==-1) ||
      unlikely_log(!do_send_command(api, "upload_write", strlen("upload_write"), params, ARRAY_SIZE(params), r->len, 0)))
    return PSYNC_NET_TEMPFAIL;
  bw=0;

  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (bw<r->len){
    if (unlikely(upload->stop)){
      debug(D_NOTICE, "upload stopped");
      goto err0;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    if (r->len-bw>PSYNC_COPY_BUFFER_SIZE)
      rd=PSYNC_COPY_BUFFER_SIZE;
    else
      rd=r->len-bw;
    rrd=psync_file_read(fd, buff, rd);
    if (unlikely_log(rrd<=0))
      goto err0;
    bw+=rrd;
    if (unlikely_log(psync_socket_writeall_upload(api, buff, rrd)!=rrd))
      goto err0;
    upload->uploaded+=rrd;
    add_bytes_uploaded(rrd);
  }
  psync_free(buff);
  return PSYNC_NET_OK;
err0:
  psync_free(buff);
  return PSYNC_NET_TEMPFAIL;
}

static int upload_from_file(psync_socket *api, psync_upload_range_list_t *r, psync_uploadid_t uploadid, upload_list_t *upload){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", r->uploadoffset), P_NUM("id", r->id), P_NUM("uploadid", uploadid),
                     P_NUM("fileid", r->file.fileid), P_NUM("hash", r->file.hash), P_NUM("offset", r->off), P_NUM("count", r->len)};
  if (unlikely_log(!send_command_no_res(api, "upload_writefromfile", params)))
    return PSYNC_NET_TEMPFAIL;
  else{
    upload->uploaded+=r->len;
    add_bytes_uploaded(r->len);
    return PSYNC_NET_OK;
  }
}

static int upload_from_upload(psync_socket *api, psync_upload_range_list_t *r, psync_uploadid_t uploadid, upload_list_t *upload){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", r->uploadoffset), P_NUM("id", r->id), P_NUM("uploadid", uploadid),
                     P_NUM("readuploadid", r->uploadid), P_NUM("offset", r->off), P_NUM("count", r->len)};
  if (unlikely_log(!send_command_no_res(api, "upload_writefromupload", params)))
    return PSYNC_NET_TEMPFAIL;
  else{
    upload->uploaded+=r->len;
    add_bytes_uploaded(r->len);
    return PSYNC_NET_OK;
  }
}

static int upload_get_checksum(psync_socket *api, psync_uploadid_t uploadid, uint32_t id){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadid", uploadid), P_NUM("id", id)};
  if (unlikely_log(!send_command_no_res(api, "upload_info", params)))
    return PSYNC_NET_TEMPFAIL;
  else
    return PSYNC_NET_OK;
}

static int upload_save(psync_socket *api, psync_fileid_t localfileid, const char *localpath, const unsigned char *hashhex, uint64_t size,
                       psync_uploadid_t uploadid, psync_folderid_t folderid, const char *name, uint64_t taskid, psync_stat_t *st, binparam pr){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_NUM("uploadid", uploadid), P_STR("timeformat", "timestamp"),
#if defined(PSYNC_HAS_BIRTHTIME)
                     P_NUM("ctime", psync_stat_birthtime(st)),
#endif
                     P_NUM("mtime", psync_stat_mtime(st)), {pr.paramtype, pr.paramnamelen, pr.opts, pr.paramname, {pr.num}} /* specially for Visual Studio compiler */};
  psync_sql_res *sres;
  binresult *res;
  const binresult *meta;
  psync_fileid_t fileid;
  uint64_t result, hash;
  int ret;
  psync_diff_lock();
  res=send_command(api, "upload_save", params);
  if (res){
    result=psync_find_result(res, "result", PARAM_NUM)->num;
    if (unlikely(result)){
      debug(D_WARNING, "command upload_save returned code %u", (unsigned)result);
      psync_process_api_error(result);
      ret=psync_handle_api_result(result);
    }
    else{
      meta=psync_find_result(res, "metadata", PARAM_HASH);
      fileid=psync_find_result(meta, "fileid", PARAM_NUM)->num;
      hash=psync_find_result(meta, "hash", PARAM_NUM)->num;
      psync_sql_start_transaction();
      sres=psync_sql_prep_statement("REPLACE INTO hashchecksum (hash, size, checksum) VALUES (?, ?, ?)");
      psync_sql_bind_uint(sres, 1, hash);
      psync_sql_bind_uint(sres, 2, size);
      psync_sql_bind_lstring(sres, 3, (const char *)hashhex, PSYNC_HASH_DIGEST_HEXLEN);
      psync_sql_run_free(sres);
      if (psync_check_result(meta, "conflicted", PARAM_BOOL)){
        psync_sql_commit_transaction();
        set_local_file_conflicted(localfileid, fileid, hash, localpath, psync_find_result(meta, "name", PARAM_STR)->str, taskid);
      }
      else{
        set_local_file_remote_id(localfileid, fileid, hash);
        psync_sql_commit_transaction();
      }
      ret=PSYNC_NET_OK;
      psync_diff_wake();
    }
    psync_free(res);
  }
  else
    ret=PSYNC_NET_TEMPFAIL;
  psync_diff_unlock();
  return ret;
}

static int upload_big_file(const char *localpath, const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name,
                           psync_fileid_t localfileid, psync_syncid_t syncid, upload_list_t *upload, psync_uploadid_t uploadid, uint64_t uploadoffset,
                           psync_stat_t *st, binparam pr){
  psync_socket *api;
  binresult *res;
  psync_sql_res *sql;
  psync_uint_row row;
  psync_str_row srow;
  psync_full_result_int *fr;
  psync_upload_range_list_t *le, *le2;
  psync_list rlist;
  uint64_t result;
  uint32_t rid, respwait, id;
  psync_file_t fd;
  int ret;
  debug(D_NOTICE, "uploading file %s with repeating block inspection", localpath);
  if (uploadoffset){
    debug(D_NOTICE, "resuming from position %lu", (unsigned long)uploadoffset);
    upload->uploaded+=uploadoffset;
    add_bytes_uploaded(uploadoffset);
  }
  api=psync_apipool_get();
  if (unlikely(!api))
    return -1;
  if (!uploadid){
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("filesize", fsize)};
    res=send_command(api, "upload_create", params);
    if (!res)
      goto err0;
    result=psync_find_result(res, "result", PARAM_NUM)->num;
    if (unlikely(result)){
      psync_free(res);
      psync_apipool_release(api);
      psync_process_api_error(result);
      debug(D_WARNING, "upload_create returned %lu", (unsigned long)result);
      if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
        return -1;
      else
        return 0;
    }
    uploadid=psync_find_result(res, "uploadid", PARAM_NUM)->num;
    psync_free(res);
    psync_sql_start_transaction();
    sql=psync_sql_query_nolock("SELECT id FROM localfile WHERE id=?");
    psync_sql_bind_uint(sql, 1, localfileid);
    row=psync_sql_fetch_rowint(sql);
    psync_sql_free_result(sql);
    if (!row){
      psync_sql_rollback_transaction();
      debug(D_NOTICE, "local file %s (%lu) disappeard from localfile while creating upload, failing task", localpath, (unsigned long)localfileid);
      return -1;
    }
    sql=psync_sql_prep_statement("INSERT INTO localfileupload (localfileid, uploadid) VALUES (?, ?)");
    psync_sql_bind_uint(sql, 1, localfileid);
    psync_sql_bind_uint(sql, 2, uploadid);
    psync_sql_run_free(sql);
    psync_sql_commit_transaction();
  }
  psync_list_init(&rlist);
  if (likely(uploadoffset<fsize)){
    le=psync_new(psync_upload_range_list_t);
    le->uploadoffset=uploadoffset;
    le->off=uploadoffset;
    le->len=fsize-uploadoffset;
    le->type=PSYNC_URANGE_UPLOAD;
    psync_list_add_tail(&rlist, &le->list);
  }
  fd=psync_file_open(localpath, P_O_RDONLY, 0);
  if (unlikely(fd==INVALID_HANDLE_VALUE)){
    debug(D_WARNING, "could not open local file %s", localpath);
    psync_apipool_release(api);
    psync_list_for_each_element_call(&rlist, psync_upload_range_list_t, list, psync_free);
    return -1;
  }
  if (likely(uploadoffset<fsize)){
    uint64_t fileid, hash;
    fileid=0;
    sql=psync_sql_query_rdlock("SELECT fileid, hash FROM localfile WHERE id=?");
    psync_sql_bind_uint(sql, 1, localfileid);
    if ((row=psync_sql_fetch_rowint(sql))){
      fileid=row[0];
      hash=row[1];
      psync_sql_free_result(sql);
      debug(D_NOTICE, "fileid(local)=%lu", (unsigned long)fileid);
      if (fileid && psync_net_scan_file_for_blocks(api, &rlist, fileid, hash, fd)==PSYNC_NET_TEMPFAIL)
        goto err1;
    }
    else
      psync_sql_free_result(sql);
    if (!fileid) {
      debug(D_NOTICE, "looking for folderid=%lu and name=%s in file", (unsigned long)folderid, name);
      sql=psync_sql_query_rdlock("SELECT id, hash FROM file WHERE parentfolderid=? AND name=?");
      psync_sql_bind_uint(sql, 1, folderid);
      psync_sql_bind_string(sql, 2, name);
      if ((row=psync_sql_fetch_rowint(sql))){
        fileid=row[0];
        hash=row[1];
        psync_sql_free_result(sql);
        debug(D_NOTICE, "fileid(file)=%lu", (unsigned long)fileid);
        if (fileid && psync_net_scan_file_for_blocks(api, &rlist, fileid, hash, fd)==PSYNC_NET_TEMPFAIL)
          goto err1;
      }
      else
        psync_sql_free_result(sql);

    }
    if (!fileid) {
      sql=psync_sql_query_rdlock("SELECT name FROM localfile WHERE id=?");
      psync_sql_bind_uint(sql, 1, localfileid);
      if ((srow=psync_sql_fetch_rowstr(sql))){
        char *nname=psync_strdup(srow[0]);
        psync_sql_free_result(sql);
        debug(D_NOTICE, "looking for folderid=%lu and name=%s in file", (unsigned long)folderid, nname);
        sql=psync_sql_query_rdlock("SELECT id, hash FROM file WHERE parentfolderid=? AND name=?");
        psync_sql_bind_uint(sql, 1, folderid);
        psync_sql_bind_string(sql, 2, nname);
        if ((row=psync_sql_fetch_rowint(sql))){
          fileid=row[0];
          hash=row[1];
          psync_sql_free_result(sql);
          debug(D_NOTICE, "fileid(file, local name)=%lu", (unsigned long)fileid);
          if (fileid && psync_net_scan_file_for_blocks(api, &rlist, fileid, hash, fd)==PSYNC_NET_TEMPFAIL){
            psync_free(nname);
            goto err1;
          }
        }
        else
          psync_sql_free_result(sql);
        psync_free(nname);
      }
      else
        psync_sql_free_result(sql);
    }
    sql=psync_sql_query_rdlock("SELECT uploadid FROM localfileupload WHERE localfileid=? ORDER BY uploadid DESC LIMIT 5");
    psync_sql_bind_uint(sql, 1, localfileid);
    fr=psync_sql_fetchall_int(sql);
    for (id=0; id<fr->rows; id++)
      if (psync_get_result_cell(fr, id, 0)!=uploadid && psync_net_scan_upload_for_blocks(api, &rlist, psync_get_result_cell(fr, id, 0), fd)==PSYNC_NET_TEMPFAIL){
        psync_free(fr);
        goto err1;
      }
    psync_free(fr);
  }
  rid=0;
  respwait=0;
  psync_list_for_each_element(le, &rlist, psync_upload_range_list_t, list)
    if ((le->type==PSYNC_URANGE_COPY_FILE || le->type==PSYNC_URANGE_COPY_UPLOAD) && le->len>PSYNC_MAX_COPY_FROM_REQ) {
      le2=psync_new(psync_upload_range_list_t);
      *le2=*le;
      le->len=PSYNC_MAX_COPY_FROM_REQ;
      le2->off+=PSYNC_MAX_COPY_FROM_REQ;
      le2->len-=PSYNC_MAX_COPY_FROM_REQ;
      psync_list_add_after(&le->list, &le2->list);
    }
  le=psync_new(psync_upload_range_list_t);
  le->type=PSYNC_URANGE_LAST;
  psync_list_add_tail(&rlist, &le->list);
  psync_list_for_each_element(le, &rlist, psync_upload_range_list_t, list){
    if (upload->stop)
      goto err1;
    le->uploadoffset=uploadoffset;
    le->id=++rid;
    if (le->type==PSYNC_URANGE_LAST){
      if (upload_get_checksum(api, uploadid, le->id))
        goto err1;
      else
        respwait++;
    }
    while (respwait && (le->type==PSYNC_URANGE_LAST || psync_socket_pendingdata(api) ||
                        psync_select_in(&api->sock, 1, respwait>=PSYNC_MAX_PENDING_UPLOAD_REQS?PSYNC_SOCK_READ_TIMEOUT*1000:0)!=SOCKET_ERROR)){
      res=get_result(api);
      if (unlikely_log(!res))
        goto err1;
      respwait--;
      result=psync_find_result(res, "result", PARAM_NUM)->num;
      if (unlikely(result)){
        id=psync_find_result(res, "id", PARAM_NUM)->num;
        psync_free(res);
        psync_process_api_error(result);
        if (unlikely_log(!id))
          goto err1;
        while (respwait){
          res=get_result(api);
          if (unlikely_log(!res))
            goto err1;
          respwait--;
          psync_free(res);
        }
        psync_list_for_each_element(le2, &rlist, psync_upload_range_list_t, list)
          if (le2->id==id){
            if (le2->type==PSYNC_URANGE_LAST || le2->type==PSYNC_URANGE_UPLOAD){
              debug(D_ERROR, "range of type %u failed with error %lu", (unsigned)le2->type, (unsigned long)result);
              goto err1;
            }
            else{
              debug(D_WARNING, "range of type %u failed with error %lu, restarting as upload range", (unsigned)le2->type, (unsigned long)result);
              le2->type=PSYNC_URANGE_UPLOAD;
              uploadoffset=le2->uploadoffset;
              le2->off=le2->uploadoffset;
              le=le2;
              goto restart;
            }
          }
        debug(D_BUG, "could not find id %u", (unsigned)id);
        goto err1;
      }
      else if (le->type==PSYNC_URANGE_LAST && le->id==psync_find_result(res, "id", PARAM_NUM)->num){
        if (unlikely(psync_find_result(res, "size", PARAM_NUM)->num!=fsize)){
          debug(D_WARNING, "file size mismatch after upload, expected: %lu, got: %lu", (unsigned long)fsize,
                (unsigned long)psync_find_result(res, "size", PARAM_NUM)->num);
          psync_free(res);
          goto err1;
        }
        else if (unlikely(memcmp(psync_find_result(res, PSYNC_CHECKSUM, PARAM_STR)->str, hashhex, PSYNC_HASH_DIGEST_HEXLEN))){
          debug(D_WARNING, "hash mismatch after upload, expected: %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)
                           "s, got: %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)"s", hashhex,
                           psync_find_result(res, PSYNC_CHECKSUM, PARAM_STR)->str);
          psync_free(res);
          goto err1;
        }
        else
          assert(respwait==0);
      }
      psync_free(res);
    }
restart:
    if (le->type==PSYNC_URANGE_UPLOAD){
      debug(D_NOTICE, "uploading %lu bytes to offset %lu", (unsigned long)le->len, (unsigned long)le->uploadoffset);
      ret=upload_range(api, le, upload, uploadid, fd);
    }
    else if (le->type==PSYNC_URANGE_COPY_FILE){
      debug(D_NOTICE, "copying %lu bytes to offset %lu from fileid %lu hash %lu offset %lu", (unsigned long)le->len, (unsigned long)le->uploadoffset,
                                                                                             (unsigned long)le->file.fileid, (unsigned long)le->file.hash,
                                                                                             (unsigned long)le->off);
      ret=upload_from_file(api, le, uploadid, upload);
    }
    else if (le->type==PSYNC_URANGE_COPY_UPLOAD){
      debug(D_NOTICE, "copying %lu bytes to offset %lu from uploadid %lu offset %lu", (unsigned long)le->len, (unsigned long)le->uploadoffset,
                                                                                      (unsigned long)le->uploadid, (unsigned long)le->off);
      ret=upload_from_upload(api, le, uploadid, upload);
    }
    else if (le->type==PSYNC_URANGE_LAST)
      break;
    else {
      debug(D_BUG, "Invalid range type %u", (unsigned)le->type);
      goto err1;
    }
    if (unlikely_log(ret!=PSYNC_NET_OK)){
      if (ret==PSYNC_NET_TEMPFAIL)
        goto err1;
      else
        goto errp;
    }
    respwait++;
    uploadoffset+=le->len;
  }
  psync_list_for_each_element_call(&rlist, psync_upload_range_list_t, list, psync_free);
  if (psync_file_size(fd)!=fsize){
    debug(D_NOTICE, "file %s changed filesize while uploading, restarting task", localpath);
    ret=PSYNC_NET_TEMPFAIL;
  }
  else
    ret=PSYNC_NET_OK;
  psync_file_close(fd);
  if (ret==PSYNC_NET_OK)
    ret=upload_save(api, localfileid, localpath, hashhex, fsize, uploadid, folderid, name, upload->taskid, st, pr);
  if (ret==PSYNC_NET_TEMPFAIL){
    psync_apipool_release_bad(api);
    return -1;
  }
  else{
    psync_apipool_release(api);
    return 0;
  }
err1:
  psync_file_close(fd);
  psync_list_for_each_element_call(&rlist, psync_upload_range_list_t, list, psync_free);
err0:
  psync_apipool_release_bad(api);
  return -1;
errp:
  psync_file_close(fd);
  psync_list_for_each_element_call(&rlist, psync_upload_range_list_t, list, psync_free);
  psync_apipool_release_bad(api);
  return 0;
}

static void delete_uploadid(psync_uploadid_t uploadid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadid", uploadid)};
  binresult *res;
  res=psync_api_run_command("upload_delete", params);
  psync_free(res);
}

static void delete_uploadids(psync_fileid_t localfileid){
  psync_sql_res *res;
  psync_full_result_int *rows;
  uint32_t i;
  res=psync_sql_query_rdlock("SELECT uploadid FROM localfileupload WHERE localfileid=?");
  psync_sql_bind_uint(res, 1, localfileid);
  rows=psync_sql_fetchall_int(res);
  if (rows->rows){
    for (i=0; i<rows->rows; i++)
      delete_uploadid(psync_get_result_cell(rows, i, 0));
    res=psync_sql_prep_statement("DELETE FROM localfileupload WHERE localfileid=?");
    psync_sql_bind_uint(res, 1, localfileid);
    psync_sql_run_free(res);
  }
  psync_free(rows);
}

static void delete_from_localfile(psync_fileid_t localfileid){
  psync_sql_res *res;
  psync_uint_row row;
  res=psync_sql_query("SELECT syncid, localparentfolderid FROM localfile WHERE id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res))){
    psync_syncid_t syncid=row[0];
    psync_folderid_t folderid=row[1];
    psync_sql_free_result(res);
    res=psync_sql_prep_statement("DELETE FROM localfile WHERE id=?");
    psync_sql_bind_uint(res, 1, localfileid);
    psync_sql_run_free(res);
    psync_path_status_sync_folder_task_completed(syncid, folderid);
  }
  else
    psync_sql_free_result(res);
}

static int task_uploadfile(psync_syncid_t syncid, psync_folderid_t localfileid, const char *name, upload_list_t *upload){
  psync_sql_res *res;
  psync_uint_row row;
  psync_str_row srow;
  char *localpath, *nname;
  psync_file_lock_t *lock;
  psync_folderid_t folderid;
  psync_uploadid_t uploadid;
  uint64_t fsize, ufsize;
  psync_stat_t st;
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN], uhashhex[PSYNC_HASH_DIGEST_HEXLEN], phashhex[PSYNC_HASH_DIGEST_HEXLEN];
  binparam pr;
  int ret;
  psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  if (upload->stop)
    return -1;
  localpath=psync_local_path_for_local_file(localfileid, NULL);
  if (unlikely(!localpath)){
    debug(D_WARNING, "could not find local file %s (id %lu)", name, (unsigned long)localfileid);
    return 0;
  }
  if (!psync_stat(localpath, &st) && psync_stat_mtime(&st)>=psync_timer_time()-PSYNC_UPLOAD_OLDER_THAN_SEC){
    time_t ctime;
    debug(D_NOTICE, "file %s is too new, waiting for upload", localpath);
    ctime=psync_timer_time();
    psync_apipool_prepare();
    if (ctime<psync_stat_mtime(&st)-2)
      debug(D_NOTICE, "file %s has a modification time in the future, skipping waits", localpath);
    else{
      ret=0;
      do {
        if (ctime<psync_stat_mtime(&st))
          ctime=psync_stat_mtime(&st);
        if (psync_stat_mtime(&st)+PSYNC_UPLOAD_OLDER_THAN_SEC>ctime)
          psync_milisleep((psync_stat_mtime(&st)+PSYNC_UPLOAD_OLDER_THAN_SEC-ctime)*1000+500);
        else
          psync_milisleep(500);
        if (psync_stat(localpath, &st)){
          debug(D_NOTICE, "can not stat %s anymore, failing for now", localpath);
          psync_free(localpath);
          return -1;
        }
        ctime=psync_timer_time();
      } while (psync_stat_mtime(&st)>=ctime-PSYNC_UPLOAD_OLDER_THAN_SEC && ++ret<=10);
      if (ret==10){
        debug(D_NOTICE, "file %s kept changing %d times, skipping for now", localpath, ret);
        psync_free(localpath);
        return -1;
      }
      debug(D_NOTICE, "file %s got old enough", localpath);
    }
  }
  lock=psync_lock_file(localpath);
  if (!lock){
    debug(D_NOTICE, "file %s is currently locked, skipping for now", localpath);
    psync_free(localpath);
    psync_milisleep(PSYNC_SLEEP_ON_LOCKED_FILE);
    return -1;
  }
  res=psync_sql_query_rdlock("SELECT uploadid FROM localfileupload WHERE localfileid=? ORDER BY uploadid DESC LIMIT 1");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res)))
    uploadid=row[0];
  else
    uploadid=0;
  psync_sql_free_result(res);
  ufsize=0;
  if (uploadid){
    ret=psync_get_upload_checksum(uploadid, uhashhex, &ufsize);
    if (ret==PSYNC_NET_TEMPFAIL){
      psync_unlock_file(lock);
      psync_free(localpath);
      return -1;
    }
    else if (ret==PSYNC_NET_PERMFAIL)
      uploadid=0;
  }
  if (uploadid)
    ret=psync_get_local_file_checksum_part(localpath, hashhex, &fsize, phashhex, ufsize);
  else
    ret=psync_get_local_file_checksum(localpath, hashhex, &fsize);
  if (unlikely(ret)){
    debug(D_WARNING, "could not open local file %s, deleting it from localfile", localpath);
    psync_unlock_file(lock);
    psync_free(localpath);
    delete_from_localfile(localfileid);
    return 0;
  }
  if (fsize!=upload->filesize){
    pthread_mutex_lock(&current_uploads_mutex);
    psync_status.bytestouploadcurrent-=upload->filesize;
    psync_status.bytestouploadcurrent+=fsize;
    pthread_mutex_unlock(&current_uploads_mutex);
    upload->filesize=fsize;
  }
  res=psync_sql_prep_statement("UPDATE localfile SET size=?, checksum=? WHERE id=?");
  psync_sql_bind_uint(res, 1, fsize);
  psync_sql_bind_lstring(res, 2, (char *)hashhex, PSYNC_HASH_DIGEST_HEXLEN);
  psync_sql_bind_uint(res, 3, localfileid);
  psync_sql_run_free(res);
  res=psync_sql_query_rdlock("SELECT s.folderid FROM localfile f, syncedfolder s WHERE f.id=? AND f.localparentfolderid=s.localfolderid AND s.syncid=?");
  psync_sql_bind_uint(res, 1, localfileid);
  psync_sql_bind_uint(res, 2, syncid);
  if (likely_log(row=psync_sql_fetch_rowint(res)))
    folderid=row[0];
  else{
    debug(D_WARNING, "could not get remote folderid for local file %lu", (unsigned long)localfileid);
    psync_sql_free_result(res);
    psync_unlock_file(lock);
    psync_free(localpath);
    return 0;
  }
  psync_sql_free_result(res);
  nname=NULL;
  if (strchr(name, PSYNC_REPLACE_INV_CH_IN_FILENAMES)){
    res=psync_sql_query_rdlock("SELECT f.name FROM localfile lf, file f WHERE lf.id=? AND lf.fileid=f.id");
    psync_sql_bind_uint(res, 1, localfileid);
    srow=psync_sql_fetch_rowstr(res);
    if (srow && strcmp(srow[0], name)){
      const char *s1=srow[0], *s2=name;
      while (*s1 && *s2 && (*s1==*s2 || (psync_invalid_filename_chars[(unsigned char)*s1] && *s2==PSYNC_REPLACE_INV_CH_IN_FILENAMES))){
        s1++;
        s2++;
      }
      if (*s1==*s2){ //==0
        debug(D_NOTICE, "uploading %s as %s", name, srow[0]);
        nname=psync_strdup(srow[0]);
        name=nname;
      }
    }
    psync_sql_free_result(res);
  }
  ret=check_file_if_exists(hashhex, fsize, folderid, name, localfileid);
  /* PSYNC_MIN_SIZE_FOR_EXISTS_CHECK should be low enough not to waste bandwidth and high enough
   * not to waste a roundtrip to the server. Few kilos should be fine
   */
  if (ret==0 && fsize>=PSYNC_MIN_SIZE_FOR_EXISTS_CHECK)
    ret=copy_file_if_exists(hashhex, fsize, folderid, name, localfileid, &st);
  if (ret==1 || ret==-1){
    psync_unlock_file(lock);
    psync_free(nname);
    psync_free(localpath);
    return ret==1?0:-1;
  }
  memcpy(upload->hash, hashhex, PSYNC_HASH_DIGEST_HEXLEN);
  res=psync_sql_query_rdlock("SELECT hash FROM localfile WHERE hash IS NOT NULL AND id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res))){
    pr.paramtype=PARAM_NUM;
    pr.paramnamelen=6;
    pr.paramname="ifhash";
    pr.num=row[0];
  }
  else{
    pr.paramtype=PARAM_STR;
    pr.paramnamelen=6;
    pr.paramname="ifhash";
    pr.opts=3;
    pr.str="new";
  }
  psync_sql_free_result(res);
  debug(D_NOTICE, "uploading file %s", localpath);
  if (fsize<=PSYNC_MIN_SIZE_FOR_CHECKSUMS)
    ret=upload_file(localpath, hashhex, fsize, folderid, name, localfileid, syncid, upload, &st, pr);
  else{
    if (uploadid && !memcmp(phashhex, uhashhex, PSYNC_HASH_DIGEST_HEXLEN))
      ret=upload_big_file(localpath, hashhex, fsize, folderid, name, localfileid, syncid, upload, uploadid, ufsize, &st, pr);
    else{
      if (uploadid && memcmp(phashhex, uhashhex, PSYNC_HASH_DIGEST_HEXLEN))
        debug(D_WARNING, "restarting upload due to checksum mismatch up to offset %lu, expected: %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)
                          "s, got: %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)"s", (unsigned long)ufsize, phashhex, uhashhex);
      ret=upload_big_file(localpath, hashhex, fsize, folderid, name, localfileid, syncid, upload, 0, 0, &st, pr);
    }
  }
  psync_unlock_file(lock);
  psync_free(nname);
  psync_free(localpath);
  if (!ret)
    delete_uploadids(localfileid);
  return ret;
}

static void delete_upload_task(uint64_t taskid, psync_fileid_t localfileid) {
  psync_sql_res *res;
  psync_uint_row row;
  psync_sql_lock();
  res=psync_sql_prep_statement("DELETE FROM task WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_run_free(res);
  res=psync_sql_query_nolock("SELECT syncid, localparentfolderid FROM localfile WHERE id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res)))
    psync_path_status_sync_folder_task_completed(row[0], row[1]);
  psync_sql_free_result(res);
  psync_sql_unlock();
}

static void task_run_upload_file_thread(void *ptr){
  upload_task_t *ut;
  psync_sql_res *res;
  ut=(upload_task_t *)ptr;
  if (task_uploadfile(ut->upllist.syncid, ut->upllist.localfileid, ut->filename, &ut->upllist)){
    psync_milisleep(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
    res=psync_sql_prep_statement("UPDATE task SET inprogress=0 WHERE id=?");
    psync_sql_bind_uint(res, 1, ut->upllist.taskid);
    psync_sql_run_free(res);
    psync_wake_upload();
  }
  else
    delete_upload_task(ut->upllist.taskid, ut->upllist.localfileid);
  pthread_mutex_lock(&current_uploads_mutex);
  psync_status.bytestouploadcurrent-=ut->upllist.filesize;
  psync_status.bytesuploaded-=ut->upllist.uploaded;
  psync_status.filesuploading--;
  if (!psync_status.filesuploading){
    psync_status.bytesuploaded=0;
    psync_status.bytestouploadcurrent=0;
  }
  psync_list_del(&ut->upllist.list);
  wake_upload_when_ready();
  pthread_mutex_unlock(&current_uploads_mutex);
  psync_status_recalc_to_upload_async();
  psync_free(ut);
}

static int task_run_uploadfile(uint64_t taskid, psync_syncid_t syncid, psync_folderid_t localfileid, const char *filename){
  psync_sql_res *res;
  upload_task_t *ut;
  psync_uint_row row;
  uint64_t filesize;
  size_t len;
  int stop;
  res=psync_sql_query_rdlock("SELECT size FROM localfile WHERE id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  row=psync_sql_fetch_rowint(res);
  if (likely(row)){
    filesize=row[0];
    psync_sql_free_result(res);
  }
  else{
    psync_sql_free_result(res);
    debug(D_WARNING, "could not get size for local file %s (localfileid %lu)", filename, (unsigned long)localfileid);
    return 0;
  }
  res=psync_sql_prep_statement("UPDATE task SET inprogress=1 WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_run_free(res);
  len=strlen(filename);
  ut=(upload_task_t *)psync_malloc(offsetof(upload_task_t, filename)+len+1);
  ut->upllist.taskid=taskid;
  ut->upllist.localfileid=localfileid;
  ut->upllist.filesize=filesize;
  ut->upllist.uploaded=0;
  ut->upllist.syncid=syncid;
  ut->upllist.stop=0;
  ut->upllist.hash[0]=0;
  memcpy(ut->filename, filename, len+1);
  stop=0;
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_add_tail(&uploads, &ut->upllist.list);
  while (!ut->upllist.stop && (psync_status.filesuploading>=PSYNC_MAX_PARALLEL_UPLOADS ||
         psync_status.bytestouploadcurrent-psync_status.bytesuploaded>PSYNC_START_NEW_UPLOADS_TRESHOLD)){
    current_uploads_waiters++;
    pthread_cond_wait(&current_uploads_cond, &current_uploads_mutex);
    current_uploads_waiters--;
  }
  if (unlikely(ut->upllist.stop)){
    psync_list_del(&ut->upllist.list);
    stop=1;
  }
  else{
    psync_status.bytestouploadcurrent+=filesize;
    psync_status.filesuploading++;
  }
  pthread_mutex_unlock(&current_uploads_mutex);
  if (stop){
    psync_free(ut);
    res=psync_sql_prep_statement("UPDATE task SET inprogress=0 WHERE id=?");
    psync_sql_bind_uint(res, 1, taskid);
    psync_sql_run_free(res);
  }
  else{
    psync_status_send_update();
    psync_run_thread1("upload file", task_run_upload_file_thread, ut);
  }
  return -1;
}

static int task_deletefile(uint64_t taskid, psync_fileid_t fileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid)};
  int ret;
  if (task_wait_no_uploads(taskid))
    return -1;
  ret=run_command("deletefile", params);
  if (likely(!ret)){
    debug(D_NOTICE, "remote fileid %lu deleted", (long unsigned)fileid);
    psync_diff_wake();
  }
  return ret;
}

static int task_deletefolderrec(uint64_t taskid, psync_folderid_t folderid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid)};
  int ret;
  if (task_wait_no_uploads(taskid))
    return -1;
  ret=run_command("deletefolderrecursive", params);
  if (likely(!ret)){
    debug(D_NOTICE, "remote folder %lu deleted", (long unsigned)folderid);
    psync_diff_wake();
  }
  return ret;
}

static int upload_task(uint64_t taskid, uint32_t type, psync_syncid_t syncid, uint64_t itemid, uint64_t localitemid,
                       uint64_t newitemid, const char *name, psync_syncid_t newsyncid){
  int res;
  switch (type){
    case PSYNC_CREATE_REMOTE_FOLDER:
      res=task_createfolder(syncid, localitemid, name);
      break;
    case PSYNC_RENAME_REMOTE_FILE:
      res=task_renamefile(taskid, newsyncid, localitemid, newitemid, name);
      break;
    case PSYNC_RENAME_REMOTE_FOLDER:
      res=task_renamefolder(taskid, newsyncid, localitemid, newitemid, name);
      break;
    case PSYNC_UPLOAD_FILE:
      res=task_run_uploadfile(taskid, syncid, localitemid, name);
      break;
    case PSYNC_DELETE_REMOTE_FILE:
      res=task_deletefile(taskid, itemid);
      break;
    case PSYNC_DELREC_REMOTE_FOLDER:
      res=task_deletefolderrec(taskid, itemid);
      break;
    default:
      debug(D_BUG, "invalid task type %u", (unsigned)type);
      res=0;
      break;
  }
  if (res && type!=PSYNC_UPLOAD_FILE)
    debug(D_WARNING, "task of type %u, syncid %u, id %lu localid %lu failed", (unsigned)type, (unsigned)syncid, (unsigned long)itemid, (unsigned long)localitemid);
  return res;
}

static void upload_thread(){
  psync_sql_res *res;
  psync_variant *row;
  uint64_t taskid;
  uint32_t type;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));

    row=psync_sql_row("SELECT id, type, syncid, itemid, localitemid, newitemid, name, newsyncid FROM task WHERE type&"
                       NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_UPLOAD)" AND inprogress=0 ORDER BY id LIMIT 1");
    if (row){
      taskid=psync_get_number(row[0]);
      type=psync_get_number(row[1]);
      if (!upload_task(taskid, type,
                         psync_get_number(row[2]),
                         psync_get_number(row[3]),
                         psync_get_number(row[4]),
                         psync_get_number_or_null(row[5]),
                         psync_get_string_or_null(row[6]),
                         psync_get_number_or_null(row[7]))){
        if (type==PSYNC_UPLOAD_FILE){
          delete_upload_task(taskid, psync_get_number(row[3]));
          psync_status_recalc_to_upload_async();
        }
        else{
          res=psync_sql_prep_statement("DELETE FROM task WHERE id=?");
          psync_sql_bind_uint(res, 1, taskid);
          psync_sql_run_free(res);
        }
      }
      else if (type!=PSYNC_UPLOAD_FILE)
        psync_milisleep(PSYNC_SLEEP_ON_FAILED_UPLOAD);
      psync_free(row);
      continue;
    }

    pthread_mutex_lock(&upload_mutex);
    if (!upload_wakes)
      pthread_cond_wait(&upload_cond, &upload_mutex);
    upload_wakes=0;
    pthread_mutex_unlock(&upload_mutex);
  }
}

void psync_wake_upload(){
  pthread_mutex_lock(&upload_mutex);
  if (!upload_wakes++)
    pthread_cond_signal(&upload_cond);
  pthread_mutex_unlock(&upload_mutex);
}

void psync_upload_init(){
  psync_timer_exception_handler(psync_wake_upload);
  psync_run_thread("upload main", upload_thread);
}

void psync_delete_upload_tasks_for_file(psync_fileid_t localfileid){
  psync_sql_res *res;
  upload_list_t *upl;
  res=psync_sql_prep_statement("DELETE FROM task WHERE type=? AND localitemid=?");
  psync_sql_bind_uint(res, 1, PSYNC_UPLOAD_FILE);
  psync_sql_bind_uint(res, 2, localfileid);
  psync_sql_run(res);
  if (psync_sql_affected_rows())
    psync_status_recalc_to_upload_async();
  psync_sql_free_result(res);
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_for_each_element(upl, &uploads, upload_list_t, list)
    if (upl->localfileid==localfileid)
      upl->stop=1;
  pthread_mutex_unlock(&current_uploads_mutex);
}

void psync_stop_sync_upload(psync_syncid_t syncid){
  upload_list_t *upl;
  psync_sql_res *res;
  res=psync_sql_prep_statement("DELETE FROM task WHERE syncid=? AND type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_UPLOAD));
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_run_free(res);
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_for_each_element(upl, &uploads, upload_list_t, list)
    if (upl->syncid==syncid)
      upl->stop=1;
  pthread_mutex_unlock(&current_uploads_mutex);
  psync_status_recalc_to_upload_async();
}

void psync_stop_all_upload(){
  upload_list_t *upl;
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_for_each_element(upl, &uploads, upload_list_t, list)
    upl->stop=1;
  pthread_mutex_unlock(&current_uploads_mutex);
}
