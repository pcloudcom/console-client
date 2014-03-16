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

typedef struct {
  psync_list list;
  psync_fileid_t localfileid;
  psync_syncid_t syncid;
  int stop;
  unsigned char hash[PSYNC_HASH_DIGEST_HEXLEN];
} upload_list_t;

static pthread_mutex_t upload_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t upload_cond=PTHREAD_COND_INITIALIZER;
static uint32_t upload_wakes=0;

static pthread_mutex_t current_uploads_mutex=PTHREAD_MUTEX_INITIALIZER;

static psync_list uploads=PSYNC_LIST_STATIC_INIT(uploads);

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
  char *nname;
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
  nname=psync_strnormalize_filename(name);
  if (unlikely(parentfolderid==PSYNC_INVALID_FOLDERID)){
    psync_free(nname);
    return 0;
  }
  else{
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", parentfolderid), P_STR("name", nname)};
    api=psync_apipool_get();
    if (unlikely(!api)){
      psync_free(nname);
      return -1;
    }
    psync_diff_lock();
    bres=send_command(api, "createfolderifnotexists", params);
    psync_free(nname);
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
  char *nname;
  int ret;
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
  else{
    nname=psync_strnormalize_filename(newname);
    ret=task_renameremotefile(fileid, folderid, nname);
    psync_free(nname);
    return ret;
  }
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
  char *nname;
  int ret;
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
  else{
    nname=psync_strnormalize_filename(newname);
    ret=task_renameremotefolder(folderid, parentfolderid, nname);
    psync_free(nname);
    return ret;
  }
}

static void set_local_file_remote_id(psync_fileid_t localfileid, psync_fileid_t fileid, uint64_t hash){
  psync_sql_res *res;
  res=psync_sql_prep_statement("UPDATE localfile SET fileid=?, hash=? WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  psync_sql_bind_uint(res, 2, hash);
  psync_sql_bind_uint(res, 3, localfileid);
  psync_sql_run_free(res);
}

static int copy_file(psync_fileid_t fileid, uint64_t hash, psync_folderid_t folderid, const char *name, psync_fileid_t localfileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("hash", hash), P_NUM("tofolderid", folderid), P_STR("toname", name)};
  psync_socket *api;
  binresult *res;
  const binresult *meta;
  uint64_t result;
  api=psync_apipool_get();
  if (unlikely(!api))
    return -1;
  psync_diff_lock();
  res=send_command(api, "copyfile", params);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_diff_unlock();
    psync_apipool_release_bad(api);
    return -1;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    psync_diff_unlock();
    psync_free(res);
    debug(D_WARNING, "command copyfile returned code %u", (unsigned)result);
    return 0;
  }
  meta=psync_find_result(res, "metadata", PARAM_HASH);
  set_local_file_remote_id(localfileid, psync_find_result(meta, "fileid", PARAM_NUM)->num, psync_find_result(meta, "hash", PARAM_NUM)->num);
  psync_diff_unlock();
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

static int upload_file(const char *localpath, const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name, 
                       psync_fileid_t localfileid, psync_syncid_t syncid, upload_list_t *upload){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("filename", name), P_BOOL("nopartial", 1)};
  psync_socket *api;
  void *buff;
  binresult *res;
  uint64_t bw, result, fileid, rsize, hash;
  size_t rd;
  ssize_t rrd;
  psync_file_t fd;
  unsigned char hashhexsrv[PSYNC_HASH_DIGEST_HEXLEN];
  fd=psync_file_open(localpath, P_O_RDONLY, 0);
  if (fd==INVALID_HANDLE_VALUE){
    debug(D_WARNING, "could not open local file %s", localpath);
    return 0;
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
  psync_diff_lock();
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
      psync_diff_unlock();
      return 0;
    }
  }
  fileid=psync_find_result(res, "fileids", PARAM_ARRAY)->array[0]->num;
  hash=psync_find_result(psync_find_result(res, "metadata", PARAM_ARRAY)->array[0], "hash", PARAM_NUM)->num;
  psync_free(res);
  if (unlikely_log(psync_get_remote_file_checksum(fileid, hashhexsrv, &rsize, NULL)))
    goto err00;
  if (unlikely_log(rsize!=fsize) || unlikely_log(memcmp(hashhexsrv, hashhex, PSYNC_HASH_DIGEST_HEXLEN)))
    goto err00;
  set_local_file_remote_id(localfileid, fileid, hash);
  psync_diff_unlock();
  debug(D_NOTICE, "file %s uploaded to %lu/%s", localpath, (long unsigned)folderid, name);
  return 0;
err2:
  psync_free(buff);
err1:
  psync_apipool_release_bad(api);
err0:
  psync_file_close(fd);
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
    psync_status.bytesuploaded+=rrd;
    psync_send_status_update();
  }
  psync_free(buff);
  return PSYNC_NET_OK;
err0:
  psync_free(buff);
  return PSYNC_NET_TEMPFAIL;
}

static int upload_from_file(psync_socket *api, psync_upload_range_list_t *r, psync_uploadid_t uploadid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", r->uploadoffset), P_NUM("id", r->id), P_NUM("uploadid", uploadid),
                     P_NUM("fileid", r->file.fileid), P_NUM("hash", r->file.hash), P_NUM("offset", r->off), P_NUM("count", r->len)};
  if (unlikely_log(!send_command_no_res(api, "upload_writefromfile", params)))
    return PSYNC_NET_TEMPFAIL;
  else{
    psync_status.bytesuploaded+=r->len;
    psync_send_status_update();
    return PSYNC_NET_OK;
  }
}

static int upload_from_upload(psync_socket *api, psync_upload_range_list_t *r, psync_uploadid_t uploadid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", r->uploadoffset), P_NUM("id", r->id), P_NUM("uploadid", uploadid),
                     P_NUM("readuploadid", r->uploadid), P_NUM("offset", r->off), P_NUM("count", r->len)};
  if (unlikely_log(!send_command_no_res(api, "upload_writefromupload", params)))
    return PSYNC_NET_TEMPFAIL;
  else{
    psync_status.bytesuploaded+=r->len;
    psync_send_status_update();
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

static int upload_save(psync_socket *api, psync_fileid_t localfileid, psync_uploadid_t uploadid, psync_folderid_t folderid, const char *name){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_NUM("uploadid", uploadid)};
  binresult *res;
  const binresult *meta;
  uint64_t result;
  int ret;
  psync_diff_lock();
  res=send_command(api, "upload_save", params);
  if (res){
    result=psync_find_result(res, "result", PARAM_NUM)->num;
    if (unlikely(result)){
      debug(D_WARNING, "command upload_save returned code %u", (unsigned)result);
      ret=psync_handle_api_result(result);
    }
    else{
      meta=psync_find_result(res, "metadata", PARAM_HASH);
      set_local_file_remote_id(localfileid, psync_find_result(meta, "fileid", PARAM_NUM)->num, psync_find_result(meta, "hash", PARAM_NUM)->num);
      ret=PSYNC_NET_OK;
    }
    psync_free(res);
  }
  else
    ret=PSYNC_NET_TEMPFAIL;
  psync_diff_unlock();
  return ret;
}

static int upload_big_file(const char *localpath, const unsigned char *hashhex, uint64_t fsize, psync_folderid_t folderid, const char *name, 
                       psync_fileid_t localfileid, psync_syncid_t syncid, upload_list_t *upload, psync_uploadid_t uploadid, uint64_t uploadoffset){
  psync_socket *api;
  binresult *res;
  psync_sql_res *sql;
  psync_uint_row row;
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
    psync_status.bytesuploaded=uploadoffset;
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
      debug(D_WARNING, "upload_create returned %lu", (unsigned long)result);
      if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
        return -1;
      else
        return 0;
    }
    uploadid=psync_find_result(res, "uploadid", PARAM_NUM)->num;
    psync_free(res);
    sql=psync_sql_prep_statement("INSERT INTO localfileupload (localfileid, uploadid) VALUES (?, ?)");
    psync_sql_bind_uint(sql, 1, localfileid);
    psync_sql_bind_uint(sql, 2, uploadid);
    psync_sql_run_free(sql);
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
    return 0;
  }
  if (likely(uploadoffset<fsize)){
    sql=psync_sql_query("SELECT fileid, hash FROM localfile WHERE id=?");
    psync_sql_bind_uint(sql, 1, localfileid);
    if ((row=psync_sql_fetch_rowint(sql))){
      uint64_t fileid, hash;
      fileid=row[0];
      hash=row[1];
      psync_sql_free_result(sql);
      if (fileid && psync_net_scan_file_for_blocks(api, &rlist, fileid, hash, fd)==PSYNC_NET_TEMPFAIL)
        goto err1;
    }
    else
      psync_sql_free_result(sql);
    sql=psync_sql_query("SELECT uploadid FROM localfileupload WHERE localfileid=? ORDER BY uploadid LIMIT 5");
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
    while (respwait && (le->type==PSYNC_URANGE_LAST || psync_socket_pendingdata(api) || psync_select_in(&api->sock, 1, 0)!=SOCKET_ERROR)){
      res=get_result(api);
      if (unlikely_log(!res))
        goto err1;
      respwait--;
      result=psync_find_result(res, "result", PARAM_NUM)->num;
      if (unlikely(result)){
        id=psync_find_result(res, "id", PARAM_NUM)->num;
        psync_free(res);
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
              le=le2;
              goto restart;
            }
          }
        debug(D_BUG, "could not find id %u", (unsigned)id);
        goto err1;
      }
      else if (le->type==PSYNC_URANGE_LAST && le->id==psync_find_result(res, "id", PARAM_NUM)->num){
        if (unlikely(psync_find_result(res, "size", PARAM_NUM)->num!=fsize)){
          debug(D_WARNING, "file size mismach after upload, expected: %lu, got: %lu", (unsigned long)fsize, 
                (unsigned long)psync_find_result(res, "size", PARAM_NUM)->num);
          psync_free(res);
          goto err1;
        }
        else if (unlikely(memcmp(psync_find_result(res, PSYNC_CHECKSUM, PARAM_STR)->str, hashhex, PSYNC_HASH_DIGEST_HEXLEN))){
          debug(D_WARNING, "hash mismach after upload, expected: %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)
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
      debug(D_NOTICE, "uploading %lu bytes", (unsigned long)le->len);
      ret=upload_range(api, le, upload, uploadid, fd);
    }
    else if (le->type==PSYNC_URANGE_COPY_FILE){
      debug(D_NOTICE, "copying %lu bytes from fileid %lu hash %lu offset %lu", (unsigned long)le->len, (unsigned long)le->file.fileid,
                                                                               (unsigned long)le->file.hash, le->off);
      ret=upload_from_file(api, le, uploadid);
    }
    else if (le->type==PSYNC_URANGE_COPY_UPLOAD){
      debug(D_NOTICE, "copying %lu bytes from uploadid %lu offset %lu", (unsigned long)le->len, (unsigned long)le->uploadid, le->off);
      ret=upload_from_upload(api, le, uploadid);
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
  psync_file_close(fd);
  ret=upload_save(api, localfileid, uploadid, folderid, name);
  psync_apipool_release(api);
  if (ret==PSYNC_NET_TEMPFAIL)
    return -1;
  else
    return 0;
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
  psync_socket *api;
  binresult *res;
  api=psync_apipool_get();
  if (unlikely(!api))
    return;
  res=send_command(api, "upload_delete", params);
  psync_apipool_release(api);
  psync_free(res);
}

static void delete_uploadids(psync_fileid_t localfileid){
  psync_sql_res *res;
  psync_uint_row row;
  int hasuploadids;
  hasuploadids=0;
  res=psync_sql_query("SELECT uploadid FROM localfileupload WHERE localfileid=?");
  psync_sql_bind_uint(res, 1, localfileid);
  while ((row=psync_sql_fetch_rowint(res))){
    hasuploadids=1;
    delete_uploadid(row[0]);
  }
  psync_sql_free_result(res);
  if (hasuploadids){
    res=psync_sql_prep_statement("DELETE FROM localfileupload WHERE localfileid=?");
    psync_sql_bind_uint(res, 1, localfileid);
    psync_sql_run_free(res);
  }
}

static int get_upload_checksum(psync_uploadid_t uploadid, unsigned char *uhash, uint64_t *usize){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadid", uploadid)};
  psync_socket *api;
  binresult *res;
  api=psync_apipool_get();
  if (unlikely(!api))
    return PSYNC_NET_TEMPFAIL;
  res=send_command(api, "upload_info", params);
  psync_apipool_release(api);
  if (unlikely(!res))
    return PSYNC_NET_TEMPFAIL;
  if (psync_find_result(res, "result", PARAM_NUM)->num){
    psync_free(res);
    return PSYNC_NET_PERMFAIL;
  }
  *usize=psync_find_result(res, "size", PARAM_NUM)->num;
  memcpy(uhash, psync_find_result(res, PSYNC_CHECKSUM, PARAM_STR)->str, PSYNC_HASH_DIGEST_HEXLEN);
  psync_free(res);
  return PSYNC_NET_OK;
}
  
static int task_uploadfile(psync_syncid_t syncid, psync_folderid_t localfileid, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  char *localpath, *nname;
  psync_folderid_t folderid;
  psync_uploadid_t uploadid;
  uint64_t fsize, ufsize;
  upload_list_t upload;
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN], uhashhex[PSYNC_HASH_DIGEST_HEXLEN], phashhex[PSYNC_HASH_DIGEST_HEXLEN];
  int ret;
  res=psync_sql_query("SELECT uploadid FROM localfileupload WHERE localfileid=? ORDER BY uploadid DESC LIMIT 1");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res)))
    uploadid=row[0];
  else
    uploadid=0;
  psync_sql_free_result(res);
  ufsize=0;
  if (uploadid){
    ret=get_upload_checksum(uploadid, uhashhex, &ufsize);
    if (ret==PSYNC_NET_TEMPFAIL)
      return -1;
    else if (ret==PSYNC_NET_PERMFAIL)
      uploadid=0;
  }
  localpath=psync_local_path_for_local_file(localfileid, NULL);
  nname=psync_strnormalize_filename(name);
  if (unlikely_log(!localpath))
    return 0;

  if (uploadid){
    if (psync_get_local_file_checksum_part(localpath, hashhex, &fsize, phashhex, ufsize)){
      debug(D_WARNING, "could not open local file %s", localpath);
      psync_free(nname);
      psync_free(localpath);
      return 0;
    }
  }
  else{
    if (psync_get_local_file_checksum(localpath, hashhex, &fsize)){
      debug(D_WARNING, "could not open local file %s", localpath);
      psync_free(nname);
      psync_free(localpath);
      return 0;
    }
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
    psync_free(nname);
    psync_free(localpath);
    return 0;    
  }
  psync_sql_free_result(res);
  ret=copy_file_if_exists(hashhex, fsize, folderid, nname, localfileid);
  if (ret==-1){
    psync_free(nname);
    psync_free(localpath);
    return -1;
  }
  else if (ret==1){
    psync_free(nname);
    psync_free(localpath);
    return 0;
  }
  psync_status.bytestouploadcurrent=fsize;
  psync_status.bytesuploaded=0;
  psync_status_inc_uploads_count();
  upload.localfileid=localfileid;
  upload.syncid=syncid;
  upload.stop=0;
  memcpy(upload.hash, hashhex, PSYNC_HASH_DIGEST_HEXLEN);
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_add_tail(&uploads, &upload.list);
  pthread_mutex_unlock(&current_uploads_mutex); 
  if (fsize<=PSYNC_MIN_SIZE_FOR_CHECKSUMS)
    ret=upload_file(localpath, hashhex, fsize, folderid, nname, localfileid, syncid, &upload);
  else{
    if (uploadid && !memcmp(phashhex, uhashhex, PSYNC_HASH_DIGEST_HEXLEN))
      ret=upload_big_file(localpath, hashhex, fsize, folderid, nname, localfileid, syncid, &upload, uploadid, ufsize);
    else{
      if (uploadid && memcmp(phashhex, uhashhex, PSYNC_HASH_DIGEST_HEXLEN))
        debug(D_WARNING, "restarting upload due to checksum mismatch up to offset %lu, expected: %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)
                          "s, got: %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)"s", ufsize, phashhex, uhashhex);
      ret=upload_big_file(localpath, hashhex, fsize, folderid, nname, localfileid, syncid, &upload, 0, 0);
    }
  }
  psync_status_dec_uploads_count();
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_del(&upload.list);
  pthread_mutex_unlock(&current_uploads_mutex);
  psync_free(nname);
  psync_free(localpath);
  if (!ret)
    delete_uploadids(localfileid);
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
  psync_sql_res *res;
  upload_list_t *upl;
  res=psync_sql_prep_statement("DELETE FROM task WHERE type=? AND localitemid=?");
  psync_sql_bind_uint(res, 1, PSYNC_UPLOAD_FILE);
  psync_sql_bind_uint(res, 2, localfileid);
  psync_sql_run(res);
  if (psync_sql_affected_rows()){
    psync_status_recalc_to_upload();
    psync_send_status_update();
  }
  psync_sql_free_result(res);
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_for_each_element(upl, &uploads, upload_list_t, list)
    if (upl->localfileid==localfileid)
      upl->stop=1;
  pthread_mutex_unlock(&current_uploads_mutex);
}

void psync_stop_sync_upload(psync_syncid_t syncid){
  upload_list_t *upl;
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_for_each_element(upl, &uploads, upload_list_t, list)
    if (upl->syncid==syncid)
      upl->stop=1;
  pthread_mutex_unlock(&current_uploads_mutex);
}

void psync_stop_all_upload(){
  upload_list_t *upl;
  pthread_mutex_lock(&current_uploads_mutex);
  psync_list_for_each_element(upl, &uploads, upload_list_t, list)
    upl->stop=1;
  pthread_mutex_unlock(&current_uploads_mutex);
}
