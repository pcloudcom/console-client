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

static pthread_mutex_t upload_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t upload_cond=PTHREAD_COND_INITIALIZER;
static uint32_t upload_wakes=0;

static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE),
  PSTATUS_COMBINE(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK)
};

static int64_t do_run_command_res(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt){
  psync_socket *api;
  binresult *res;
  uint64_t result;
  api=psync_apipool_get();
  if (unlikely(!api))
    return -1;
  res=do_send_command(api, cmd, cmdlen, params, paramscnt, -1, 1);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_apipool_release_bad(api);
    return -1;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  if (unlikely(result))
    debug(D_WARNING, "command %s returned code %u", cmd, (unsigned)result);
  return result;
}

static int do_run_command(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt){
  uint64_t result;
  result=do_run_command_res(cmd, cmdlen, params, paramscnt);
  if (unlikely(result)){
    debug(D_WARNING, "command %s returned code %u", cmd, (unsigned)result);
    return psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL?-1:0;
  }
  else
    return 0;
}

#define run_command(cmd, params) do_run_command(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam))
#define run_command_res(cmd, params) do_run_command_res(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam))

static int task_createfolder(psync_syncid_t syncid, psync_folderid_t localfolderid, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t parentfolderid, folderid;
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  int ret;
  res=psync_sql_query("SELECT s.folderid FROM localfolder l, syncedfolder s WHERE l.id=? AND l.syncid=? AND l.localparentfolderid=s.localfolderid AND s.syncid=?");
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
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", parentfolderid), P_STR("name", name)};
    api=psync_apipool_get();
    if (unlikely(!api))
      return -1;
    psync_diff_lock();
    bres=send_command(api, "createfolderifnotexists", params);
    if (likely(bres))
      psync_apipool_release(api);
    else{
      psync_diff_unlock();
      psync_apipool_release_bad(api);
      return -1;
    }
    result=psync_find_result(bres, "result", PARAM_NUM)->num;
    if (unlikely(result)){
      psync_diff_unlock();
      debug(D_WARNING, "command createfolderifnotexists returned code %u", (unsigned)result);
      if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
        return -1;
      else
        return 0;
    }
    folderid=psync_find_result(psync_find_result(bres, "metadata", PARAM_HASH), "folderid", PARAM_NUM)->num;
    psync_free(bres);
    debug(D_NOTICE, "remote folder %lu %lu/%s created", (long unsigned)folderid, (long unsigned)parentfolderid, name);
    psync_sql_start_transaction();
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
    return ret;
  }  
}

static int task_renameremotefile(psync_fileid_t fileid, psync_folderid_t newparentfolderid, const char *newname){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("tofolderid", newparentfolderid), P_STR("toname", newname)};
  int ret;
  ret=run_command("renamefile", params);
  if (likely(!ret))
    debug(D_NOTICE, "remote fileid %lu moved/renamed to (%lu)/%s", (long unsigned)fileid, (long unsigned)newparentfolderid, newname);
  return ret;
}

static int task_renamefile(psync_syncid_t syncid, psync_fileid_t localfileid, psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fileid_t fileid;
  psync_folderid_t folderid;
  res=psync_sql_query("SELECT fileid FROM localfile WHERE id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res)))
    fileid=row[0];
  else
    fileid=0;
  psync_sql_free_result(res);
  res=psync_sql_query("SELECT folderid FROM syncedfolder WHERE syncid=? AND localfolderid=?");
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
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_NUM("tofolderid", newparentfolderid), P_STR("toname", newname)};
  int ret;
  ret=run_command("renamefolder", params);
  if (likely(!ret))
    debug(D_NOTICE, "remote folderid %lu moved/renamed to (%lu)/%s", (long unsigned)folderid, (long unsigned)newparentfolderid, newname);
  return ret;
}

static int task_renamefolder(psync_syncid_t syncid, psync_fileid_t localfolderid, psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t folderid, parentfolderid;
  res=psync_sql_query("SELECT folderid FROM syncedfolder WHERE syncid=? AND localfolderid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, localfolderid);
  if ((row=psync_sql_fetch_rowint(res)))
    folderid=row[0];
  else
    folderid=0;
  psync_sql_free_result(res);
  res=psync_sql_query("SELECT folderid FROM syncedfolder WHERE syncid=? AND localfolderid=?");
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

static void set_local_file_remote_id(psync_fileid_t localfileid, psync_fileid_t fileid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("UPDATE localfile SET fileid=? WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  psync_sql_bind_uint(res, 1, localfileid);
  psync_sql_run_free(res);
}

static int copy_file(psync_fileid_t fileid, uint64_t hash, psync_folderid_t folderid, const char *name, psync_fileid_t localfileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("hash", hash), P_NUM("tofolderid", folderid), P_STR("toname", name)};
  psync_socket *api;
  binresult *res;
  uint64_t result;
  api=psync_apipool_get();
  if (unlikely(!api))
    return -1;
  res=send_command(api, "copyfile", params);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_apipool_release_bad(api);
    return -1;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    psync_free(res);
    debug(D_WARNING, "command copyfile returned code %u", (unsigned)result);
    return 0;
  }
  set_local_file_remote_id(localfileid, psync_find_result(psync_find_result(res, "metadata", PARAM_HASH), "fileid", PARAM_NUM)->num);
  psync_free(res);
  return 1;
}

static int copy_file_if_exists(const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name, psync_fileid_t localfileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("size", fsize), P_LSTR(PSYNC_CHECKSUM, hashhex, PSYNC_HASH_DIGEST_HEXLEN)};
  psync_socket *api;
  binresult *res;
  const binresult *metas, *meta;
  uint64_t result;
  int ret;
  api=psync_apipool_get();
  if (unlikely(!api))
    return -1;
  res=send_command(api, "getfilesbychecksum", params);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_apipool_release_bad(api);
    return -1;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    psync_free(res);
    debug(D_WARNING, "command getfilesbychecksum returned code %u", (unsigned)result);
    return 0;
  }
  metas=psync_find_result(res, "metadata", PARAM_ARRAY);
  if (!metas->length){
    psync_free(res);
    return 0;
  }
  meta=metas->array[0];
  ret=copy_file(psync_find_result(meta, "fileid", PARAM_NUM)->num, psync_find_result(meta, "hash", PARAM_NUM)->num, folderid, name, localfileid);
  if (ret==1)
    debug(D_NOTICE, "file %lu/%s copied to %lu/%s instead of uploading due to matching checksum", 
          (long unsigned)psync_find_result(meta, "parentfolderid", PARAM_NUM)->num, psync_find_result(meta, "name", PARAM_STR)->str,
          (long unsigned)folderid, name);
  psync_free(res);
  return ret;
}

static int upload_file(const char *localpath, const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name, psync_fileid_t localfileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("filename", name), P_BOOL("nopartial", 1)};
  psync_socket *api;
  void *buff;
  binresult *res;
  uint64_t bw, result, fileid, rsize;
  size_t rd;
  ssize_t rrd;
  psync_file_t fd;
  unsigned char hashhexsrv[PSYNC_HASH_DIGEST_HEXLEN];
  fd=psync_file_open(localpath, P_O_RDONLY, 0);
  if (fd==INVALID_HANDLE_VALUE){
    debug(D_WARNING, "could not open local file %s", localpath);
    return 0;
  }
  psync_status.bytestouploadcurrent=fsize;
  psync_status.bytesuploaded=0;
  psync_status_inc_uploads_count();
  api=psync_apipool_get();
  if (unlikely(!api))
    goto err0;
  if (unlikely_log(!do_send_command(api, "uploadfile", strlen("uploadfile"), params, ARRAY_SIZE(params), fsize, 0)))
    goto err1;
  bw=0;
  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (bw<fsize){
    if (fsize-bw>PSYNC_COPY_BUFFER_SIZE)
      rd=PSYNC_COPY_BUFFER_SIZE;
    else
      rd=fsize-bw;
    rrd=psync_file_read(fd, buff, rd);
    if (unlikely_log(rrd<=0))
      goto err2;
    bw+=rrd;
    if (bw==fsize && psync_file_read(fd, buff, 1)!=0){
      debug(D_WARNING, "file %s has grown while uploading, retrying", localpath);
      goto err2;
    }
    if (unlikely_log(psync_socket_writeall_upload(api, buff, rrd)!=rrd))
      goto err2;
    psync_status.bytesuploaded+=rrd;
    psync_send_status_update();
  }
  psync_free(buff);
  psync_file_close(fd);
  res=get_result(api);
  psync_set_default_sendbuf(api);
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
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      goto err00;
    else{
      psync_status_dec_uploads_count();
      return 0;
    }
  }
  fileid=psync_find_result(res, "fileids", PARAM_ARRAY)->array[0]->num;
  psync_free(res);
  if (unlikely_log(psync_get_remote_file_checksum(fileid, hashhexsrv, &rsize)))
    goto err00;
  if (unlikely_log(rsize!=fsize) || unlikely_log(memcmp(hashhexsrv, hashhex, PSYNC_HASH_DIGEST_HEXLEN)))
    goto err00;
  set_local_file_remote_id(localfileid, fileid);
  psync_status_dec_uploads_count();
  debug(D_NOTICE, "file %s uploaded to %lu/%s", localpath, (long unsigned)folderid, name);
  return 0;
err2:
  psync_free(buff);
err1:
  psync_apipool_release_bad(api);
err0:
  psync_file_close(fd);
err00:
  psync_status_dec_uploads_count();
  return -1;
}

static int task_uploadfile(psync_syncid_t syncid, psync_folderid_t localfileid, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  char *localpath;
  psync_folderid_t folderid;
  uint64_t fsize;
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  int ret;
  localpath=psync_local_path_for_local_file(localfileid, NULL);
  if (unlikely_log(!localpath))
    return 0;
  if (psync_get_local_file_checksum(localpath, hashhex, &fsize)){
    debug(D_WARNING, "could not open local file %s", localpath);
    psync_free(localpath);
    return 0;
  }
  res=psync_sql_prep_statement("UPDATE localfile SET size=?, checksum=? WHERE id=?");
  psync_sql_bind_uint(res, 1, fsize);
  psync_sql_bind_lstring(res, 2, (char *)hashhex, PSYNC_HASH_DIGEST_HEXLEN);
  psync_sql_bind_uint(res, 3, localfileid);
  psync_sql_run_free(res);
  res=psync_sql_query("SELECT s.folderid FROM localfile f, syncedfolder s WHERE f.id=? AND f.localparentfolderid=s.localfolderid AND s.syncid=?");
  psync_sql_bind_uint(res, 1, localfileid);
  psync_sql_bind_uint(res, 2, syncid);
  if (likely_log(row=psync_sql_fetch_rowint(res)))
    folderid=row[0];
  else{
    debug(D_WARNING, "could not get remote folderid for local file %lu", (unsigned long)localfileid);
    psync_sql_free_result(res);
    psync_free(localpath);
    return 0;    
  }
  psync_sql_free_result(res);
  ret=copy_file_if_exists(hashhex, fsize, folderid, name, localfileid);
  if (ret==-1){
    psync_free(localpath);
    return -1;
  }
  else if (ret==1){
    psync_free(localpath);
    return 0;
  }
  ret=upload_file(localpath, hashhex, fsize, folderid, name, localfileid);
  psync_free(localpath);
  return ret;
}

static int task_deletefile(psync_fileid_t fileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid)};
  int ret;
  ret=run_command("deletefile", params);
  if (likely(!ret))
    debug(D_NOTICE, "remote fileid %lu deleted", (long unsigned)fileid);
  return ret;
}

static int task_deletefolderrec(psync_folderid_t folderid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid)};
  int ret;
  ret=run_command("deletefolderrecursive", params);
  if (likely(!ret))
    debug(D_NOTICE, "remote folder %lu deleted", (long unsigned)folderid);
  return ret;
}

static int upload_task(uint32_t type, psync_syncid_t syncid, uint64_t itemid, uint64_t localitemid, uint64_t newitemid, const char *name,
                                        psync_syncid_t newsyncid){
  int res;
  switch (type){
    case PSYNC_CREATE_REMOTE_FOLDER:
      res=task_createfolder(syncid, localitemid, name);
      break;
    case PSYNC_RENAME_REMOTE_FILE:
      res=task_renamefile(newsyncid, localitemid, newitemid, name);
      break;    
    case PSYNC_RENAME_REMOTE_FOLDER:
      res=task_renamefolder(newsyncid, localitemid, newitemid, name);
      break;
    case PSYNC_UPLOAD_FILE:
      res=task_uploadfile(syncid, localitemid, name);
      break;
    case PSYNC_DELETE_REMOTE_FILE:
      res=task_deletefile(itemid);
      break;
    case PSYNC_DELREC_REMOTE_FOLDER:
      res=task_deletefolderrec(itemid);
      break;
    default:
      debug(D_BUG, "invalid task type %u", (unsigned)type);
      res=0;
      break;
  }
  if (res)
    debug(D_WARNING, "task of type %u, syncid %u, id %lu localid %lu failed", (unsigned)type, (unsigned)syncid, (unsigned long)itemid, (unsigned long)localitemid);
  return res;
}

static void upload_thread(){
  psync_sql_res *res;
  psync_variant *row;
  uint32_t type;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    
    row=psync_sql_row("SELECT id, type, syncid, itemid, localitemid, newitemid, name, newsyncid FROM task WHERE type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_UPLOAD)" ORDER BY id LIMIT 1");
    if (row){
      type=psync_get_number(row[1]);
      if (!upload_task(type, 
                         psync_get_number(row[2]), 
                         psync_get_number(row[3]), 
                         psync_get_number(row[4]), 
                         psync_get_number_or_null(row[5]),                          
                         psync_get_string_or_null(row[6]),
                         psync_get_number_or_null(row[7]))){
        res=psync_sql_prep_statement("DELETE FROM task WHERE id=?");
        psync_sql_bind_uint(res, 1, psync_get_number(row[0]));
        psync_sql_run_free(res);
        if (type==PSYNC_UPLOAD_FILE){
          psync_status_recalc_to_upload();
          psync_send_status_update();
        }
      }
      else
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
  psync_run_thread(upload_thread);
}

void psync_delete_upload_tasks_for_file(psync_fileid_t localfileid){
}
