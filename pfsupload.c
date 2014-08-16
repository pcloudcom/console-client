/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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

#include "plibs.h"
#include "pstatus.h"
#include "ptimer.h"
#include "psettings.h"
#include "pfsupload.h"
#include "plist.h"
#include "pnetlibs.h"
#include "pfstasks.h"
#include "pfileops.h"
#include "ppagecache.h"
#include "pssl.h"
#include "pfsxattr.h"
#include <string.h>

typedef struct {
  psync_list list;
  binresult *res;
  uint64_t id;
  uint64_t type;
  psync_folderid_t folderid;
  psync_folderid_t sfolderid;
  psync_fileid_t fileid;
  const char *text1;
  const char *text2;
  int64_t int1;
  int64_t int2;
} fsupload_task_t;

static pthread_mutex_t upload_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t upload_cond=PTHREAD_COND_INITIALIZER;
static uint64_t current_upload_taskid=0;
static uint32_t upload_wakes=0;
static int large_upload_running=0;
static int stop_current_upload=0;

static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED),
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE),
  PSTATUS_COMBINE(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK)
};

static void delete_task(uint64_t id){
  psync_sql_res *res;
  res=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, id);
  psync_sql_run_free(res);
}

static int psync_send_task_mkdir(psync_socket *api, fsupload_task_t *task){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", task->folderid), P_STR("name", task->text1), P_STR("timeformat", "timestamp")};
  if (likely_log(send_command_no_res(api, "createfolderifnotexists", params)==PTR_OK))
    return 0;
  else
    return -1;
}

static void handle_mkdir_api_error(uint64_t result, fsupload_task_t *task){
  psync_sql_res *res;
  debug(D_ERROR, "createfolderifnotexists returned error %u", (unsigned)result);
  switch (result){
    case 2002: /* parent does not exists */
    case 2003: /* access denied */
      res=psync_sql_prep_statement("UPDATE fstask SET folderid=0 WHERE id=?");
      psync_sql_bind_uint(res, 1, task->id);
      psync_sql_run_free(res);
      break;
    case 2001: /* invalid name */
      res=psync_sql_prep_statement("UPDATE fstask SET text1=\"Invalid Name Requested\" WHERE id=?");
      psync_sql_bind_uint(res, 1, task->id);
      psync_sql_run_free(res);
      break;
    default:
      break;
  }
}

static int psync_process_task_mkdir(fsupload_task_t *task){
  const binresult *meta;
  uint64_t result;
  psync_folderid_t folderid;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result){
    handle_mkdir_api_error(result, task);
    return -1;
  }
  meta=psync_find_result(task->res, "metadata", PARAM_HASH);
  folderid=psync_find_result(meta, "folderid", PARAM_NUM)->num;
  task->int2=folderid;
  psync_ops_create_folder_in_db(meta);
  psync_fstask_folder_created(task->folderid, task->id, folderid, task->text1);
  psync_fs_task_to_folder(task->id, folderid);
  debug(D_NOTICE, "folder %lu/%s created", (unsigned long)task->folderid, task->text1);
  return 0;
}

static int psync_send_task_rmdir(psync_socket *api, fsupload_task_t *task){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", task->int1)};
  if (likely_log(send_command_no_res(api, "deletefolder", params)==PTR_OK))
    return 0;
  else
    return -1;
}

static int handle_rmdir_api_error(uint64_t result, fsupload_task_t *task){
  debug(D_ERROR, "deletefolder returned error %u", (unsigned)result);
  switch (result){
    case 2005: /* folder does not exist, kind of success */
      psync_ops_delete_folder_from_db(task->int1);
      psync_fstask_folder_deleted(task->folderid, task->id, task->text1);
      return 0;
    case 2003: /* access denied, skip*/
    case 2006: /* not empty */
    case 2028: /* folder is shared */
      psync_fstask_folder_deleted(task->folderid, task->id, task->text1);
      return 0;
    default:
      return -1;
  }
}

static int psync_process_task_rmdir(fsupload_task_t *task){
  uint64_t result;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result)
    return handle_rmdir_api_error(result, task);
  psync_ops_delete_folder_from_db(task->int1);
  psync_fstask_folder_deleted(task->folderid, task->id, task->text1);
  debug(D_NOTICE, "folder %lu/%s deleted", (unsigned long)task->folderid, task->text1);
  return 0;
}

static int psync_send_task_creat_upload_small(psync_socket *api, fsupload_task_t *task, psync_file_t fd, uint64_t size){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", task->folderid), P_STR("filename", task->text1), 
                      P_BOOL("nopartial", 1), P_STR("ifhash", "new"), P_STR("timeformat", "timestamp")};
  void *buff;
  buff=psync_malloc(size);
  if (unlikely_log(psync_file_read(fd, buff, size)!=size) || unlikely_log(psync_fs_get_file_writeid(task->id)!=task->int1) ||
      unlikely_log(!do_send_command(api, "uploadfile", strlen("uploadfile"), params, ARRAY_SIZE(params), size, 0)) ||
      unlikely_log(psync_socket_writeall_upload(api, buff, size)!=size)){
    psync_free(buff);
    return -1;
  }
  else{
    psync_free(buff);
    return 0;
  }
}

static int large_upload_creat_send_write(psync_socket *api, psync_uploadid_t uploadid, uint64_t offset, uint64_t length){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", offset), P_NUM("uploadid", uploadid)};
  if (unlikely_log(!do_send_command(api, "upload_write", strlen("upload_write"), params, ARRAY_SIZE(params), length, 0)))
    return -1;
  else
    return 0;
}

static int clean_uploads_for_task(psync_socket *api, psync_uploadid_t taskid){
  psync_sql_res *sql;
  psync_full_result_int *fr;
  binresult *res;
  uint32_t i;
  int ret;
  ret=0;
  sql=psync_sql_query("SELECT uploadid FROM fstaskupload WHERE fstaskid=?");
  psync_sql_bind_uint(sql, 1, taskid);
  fr=psync_sql_fetchall_int(sql);
  for (i=0; i<fr->rows; i++){
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadid", psync_get_result_cell(fr, i, 0))};
    res=send_command(api, "upload_delete", params);
    if (!res){
      ret=-1;
      break;
    }
    else
      psync_free(res);
  }
  sql=psync_sql_prep_statement("DELETE FROM fstaskupload WHERE fstaskid=?");
  psync_sql_bind_uint(sql, 1, taskid);
  psync_sql_run_free(sql);
  return ret;
}

static int large_upload_check_checksum(psync_socket *api, uint64_t uploadid, const unsigned char *filehash){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadid", uploadid)};
  binresult *res;
  res=send_command(api, "upload_info", params);
  if (unlikely_log(!res)){
    psync_apipool_release_bad(api);
    return -1;
  }
  if (unlikely(psync_find_result(res, "result", PARAM_NUM)->num)){
    debug(D_WARNING, "upload_info returned %lu", (long unsigned)psync_find_result(res, "result", PARAM_NUM)->num);
    psync_free(res);
    psync_apipool_release(api);
    return -1;
  }
  if (memcmp(filehash, psync_find_result(res, PSYNC_CHECKSUM, PARAM_STR)->str, PSYNC_HASH_DIGEST_HEXLEN)){
    debug(D_WARNING, "upload_info returned different checksum");
    psync_free(res);
    psync_apipool_release(api);
    return -1;
  }
  psync_free(res);
  return 0;
}

static int handle_upload_api_error_taskid(uint64_t result, uint64_t taskid){
  psync_sql_res *res;
  switch (result){
    case 2005: /* folder does not exists */
    case 2003: /* access denied */
      res=psync_sql_prep_statement("UPDATE fstask SET folderid=0 WHERE id=?");
      psync_sql_bind_uint(res, 1, taskid);
      psync_sql_run_free(res);
      return -1;
    case 2001: /* invalid filename */
      res=psync_sql_prep_statement("UPDATE fstask SET text1=\"Invalid Name Requested\" WHERE id=?");
      psync_sql_bind_uint(res, 1, taskid);
      psync_sql_run_free(res);
      return -1;
    case 2008: /* overquota */
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
      return -1;
    default:
      return -1;
  }
}

static int handle_upload_api_error(uint64_t result, fsupload_task_t *task){
  debug(D_ERROR, "uploadfile returned error %u", (unsigned)result);
  return handle_upload_api_error_taskid(result, task->id);
}

static int large_upload_save(psync_socket *api, uint64_t uploadid, psync_folderid_t folderid, const char *name, uint64_t taskid, uint64_t writeid, int newfile){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_NUM("uploadid", uploadid), 
                     /*P_STR("ifhash", "new"), */P_STR("timeformat", "timestamp")};
  binresult *res;
  const binresult *meta;
  psync_sql_res *sql;
  uint64_t result, hash;
  psync_fileid_t fileid;
  res=send_command(api, "upload_save", params);
  if (unlikely_log(!res)){
    psync_apipool_release_bad(api);
    return -1;
  }
  psync_apipool_release(api);
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    debug(D_WARNING, "upload_save returned %lu", (long unsigned)result);
    psync_free(res);
    handle_upload_api_error_taskid(result, taskid);
    return -1;
  }
  meta=psync_find_result(res, "metadata", PARAM_HASH);
  fileid=psync_find_result(meta, "fileid", PARAM_NUM)->num;
  hash=psync_find_result(meta, "hash", PARAM_NUM)->num;
  psync_sql_start_transaction();
  if (psync_fs_update_openfile(taskid, writeid, fileid, hash, psync_find_result(meta, "size", PARAM_NUM)->num)){
    psync_sql_rollback_transaction();
    psync_free(res);
    return -1;
  }
  if (newfile){
    psync_ops_create_file_in_db(meta);
    psync_pagecache_creat_to_pagecache(taskid, hash);
    psync_fstask_file_created(folderid, taskid, name, fileid);
    psync_fs_task_to_file(taskid, fileid);
  }
  else{
    psync_ops_update_file_in_db(meta);
    psync_pagecache_modify_to_pagecache(taskid, hash);
    psync_fstask_file_modified(folderid, taskid, name, fileid);
  }
  sql=psync_sql_prep_statement("DELETE FROM fstaskdepend WHERE dependfstaskid=?");
  psync_sql_bind_uint(sql, 1, taskid);
  psync_sql_run_free(sql);
  sql=psync_sql_prep_statement("UPDATE fstask SET fileid=? WHERE fileid=?");
  psync_sql_bind_uint(sql, 1, fileid);
  psync_sql_bind_int(sql, 2, -taskid);
  psync_sql_run_free(sql);
  sql=psync_sql_prep_statement("DELETE FROM fstask WHERE id=? AND int1=?");
  psync_sql_bind_uint(sql, 1, taskid);
  psync_sql_bind_uint(sql, 2, writeid);
  psync_sql_run_free(sql);
  if (!psync_sql_affected_rows()){
    psync_sql_rollback_transaction();
    psync_free(res);
    return -1;
  }
  psync_sql_commit_transaction(); 
  psync_free(res);
  debug(D_NOTICE, "file %lu/%s uploaded", (unsigned long)folderid, name);
  return 0;
}

static void perm_fail_upload_task(uint64_t taskid){
  psync_sql_res *sql;
  debug(D_WARNING, "failed task %lu", (unsigned long)taskid);
  psync_sql_start_transaction();
  sql=psync_sql_prep_statement("DELETE FROM fstaskdepend WHERE dependfstaskid=?");
  psync_sql_bind_uint(sql, 1, taskid);
  psync_sql_run_free(sql);
  sql=psync_sql_prep_statement("DELETE FROM fstask WHERE fileid=?");
  psync_sql_bind_int(sql, 1, -taskid);
  psync_sql_run_free(sql);
  sql=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
  psync_sql_bind_uint(sql, 1, taskid);
  psync_sql_run_free(sql);
  psync_fs_task_deleted(taskid);
  psync_sql_commit_transaction();
}

static int large_upload_creat(uint64_t taskid, psync_folderid_t folderid, const char *name, const char *filename, psync_uploadid_t uploadid, uint64_t writeid){
  psync_sql_res *sql;
  psync_socket *api;
  binresult *res;
  void *buff;
  uint64_t usize, fsize, result;
  size_t rd;
  ssize_t rrd;
  psync_file_t fd;
  int ret;
  unsigned char uploadhash[PSYNC_HASH_DIGEST_HEXLEN], filehash[PSYNC_HASH_DIGEST_HEXLEN], fileparthash[PSYNC_HASH_DIGEST_HEXLEN];
  debug(D_NOTICE, "uploading %s as %lu/%s", filename, (unsigned long)folderid, name);
  if (uploadid){
    ret=psync_get_upload_checksum(uploadid, uploadhash, &usize);
    if (ret!=PSYNC_NET_OK){
      if (ret==PSYNC_NET_TEMPFAIL)
        return -1;
      else
        uploadid=0;
    }
  }
  if (uploadid)
    ret=psync_get_local_file_checksum_part(filename, filehash, &fsize, fileparthash, usize);
  else
    ret=psync_get_local_file_checksum(filename, filehash, &fsize);
  if (ret){
    perm_fail_upload_task(taskid);
    debug(D_WARNING, "could not open local file %s, skipping task", filename);
    return 0;
  }
  //TODO: check if file exists on the remote
  if (uploadid && memcmp(fileparthash, uploadhash, PSYNC_HASH_DIGEST_HEXLEN))
    uploadid=0;
  api=psync_apipool_get();
  if (unlikely(!api))
    return -1;
  if (!uploadid || usize>fsize){
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("filesize", fsize)};
    usize=0;
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
    sql=psync_sql_prep_statement("INSERT INTO fstaskupload (fstaskid, uploadid) VALUES (?, ?)");
    psync_sql_bind_uint(sql, 1, taskid);
    psync_sql_bind_uint(sql, 2, uploadid);
    psync_sql_run_free(sql);
  }
  fd=psync_file_open(filename, P_O_RDONLY, 0);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE))
    goto ret0;
  if (usize){
    debug(D_NOTICE, "resuming from offset %lu", (unsigned long)usize);
    if (unlikely_log(psync_file_seek(fd, usize, P_SEEK_SET)==-1))
      goto ret01;
  }
  if (large_upload_creat_send_write(api, uploadid, usize, fsize-usize))
    goto err1;
  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (usize<fsize){
    if (unlikely(stop_current_upload)){
      debug(D_NOTICE, "got stop for file %s", name);
      goto err2;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    if (fsize-usize>PSYNC_COPY_BUFFER_SIZE)
      rd=PSYNC_COPY_BUFFER_SIZE;
    else
      rd=fsize-usize;
    rrd=psync_file_read(fd, buff, rd);
    if (unlikely_log(rrd<=0))
      goto err2;
    usize+=rrd;
    if (unlikely_log(psync_socket_writeall_upload(api, buff, rrd)!=rrd))
      goto err2;
  }
  psync_free(buff);
  psync_file_close(fd);
  res=get_result(api);
  if (unlikely_log(!res))
    goto err0;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  if (result){
    debug(D_WARNING, "upload_write returned error %lu", (long unsigned)result);
    if (result==2068){
      if (clean_uploads_for_task(api, taskid))
        psync_apipool_release_bad(api);
      else
        psync_apipool_release(api);
      return -1;
    }
  }
  // large_upload_check_checksum releases api on failure
  if (large_upload_check_checksum(api, uploadid, filehash))
    return -1;
  if (psync_fs_get_file_writeid(taskid)!=writeid){
    debug(D_NOTICE, "%s changed while uploading as %lu/%s", filename, (unsigned long)folderid, name);
    psync_apipool_release(api);
    return -1;
  }
  return large_upload_save(api, uploadid, folderid, name, taskid, writeid, 1);
ret01:
  psync_file_close(fd);
ret0:
  psync_apipool_release(api);
  perm_fail_upload_task(taskid);
  return 0;
err2:
  psync_free(buff);
err1:
  psync_file_close(fd);
err0:
  psync_apipool_release_bad(api);
  return -1;
}

static int64_t i64min(int64_t a, int64_t b){
  return a<b?a:b;
}

static int upload_modify_send_copy_from(psync_socket *api, psync_uploadid_t uploadid, uint64_t offset, uint64_t length, 
                                        psync_fileid_t fileid, uint64_t hash){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", offset), P_NUM("uploadid", uploadid),
                     P_NUM("fileid", fileid), P_NUM("hash", hash), P_NUM("offset", offset), P_NUM("count", length)};
  debug(D_NOTICE, "copying %lu byte from fileid %lu hash %lu at offset %lu", (unsigned long)length, (unsigned long)fileid, (unsigned long) hash, (unsigned long)offset);
  if (unlikely_log(!send_command_no_res(api, "upload_writefromfile", params)))
    return PSYNC_NET_TEMPFAIL;
  else
    return PSYNC_NET_OK;
}

static int upload_modify_send_local(psync_socket *api, psync_uploadid_t uploadid, uint64_t offset, uint64_t length, psync_file_t fd){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("uploadoffset", offset), P_NUM("uploadid", uploadid)};
  void *buff;
  uint64_t bw;
  size_t rd;
  ssize_t rrd;
  debug(D_NOTICE, "uploading %lu byte from local file at offset %lu", (unsigned long)length, (unsigned long)offset);
  if (unlikely_log(psync_file_seek(fd, offset, P_SEEK_SET)==-1) ||
      unlikely_log(!do_send_command(api, "upload_write", strlen("upload_write"), params, ARRAY_SIZE(params), length, 0)))
    return PSYNC_NET_TEMPFAIL;
  bw=0;
    
  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (bw<length){
    if (unlikely(stop_current_upload)){
      debug(D_NOTICE, "got stop");
      goto err0;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    if (length-bw>PSYNC_COPY_BUFFER_SIZE)
      rd=PSYNC_COPY_BUFFER_SIZE;
    else
      rd=length-bw;
    rrd=psync_file_read(fd, buff, rd);
    if (unlikely_log(rrd<=0)){
      if (rrd==0)
        goto errp;
      else
        goto err0;
    }
    bw+=rrd;
    if (unlikely_log(psync_socket_writeall_upload(api, buff, rrd)!=rrd))
      goto err0;
  }
  psync_free(buff);
  return PSYNC_NET_OK;
err0:
  psync_free(buff);
  return PSYNC_NET_TEMPFAIL;
errp:
  psync_free(buff);
  return PSYNC_NET_PERMFAIL;
}

static int upload_modify_read_req(psync_socket *api){
  binresult *res;
  uint64_t result;
  res=get_result(api);
  if (!res)
    return PSYNC_NET_TEMPFAIL;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  if (result)
    return psync_handle_api_result(result);
  else
    return PSYNC_NET_OK;
}

int upload_modify(uint64_t taskid, psync_folderid_t folderid, const char *name, const char *filename, const char *indexname, psync_fileid_t fileid, 
              uint64_t hash, uint64_t writeid){
  binparam aparams[]={P_STR("auth", psync_my_auth)};
  psync_interval_tree_t *tree, *cinterval;
  psync_socket *api;
  binresult *res;
  psync_sql_res *sql;
  int64_t fsize, coff, len;
  uint64_t result;
  psync_uploadid_t uploadid;
  psync_uint_t reqs;
  psync_file_t fd;
  psync_fs_err_t err;
  int ret;
  debug(D_NOTICE, "uploading modified file %s as %lu/%s", filename, (unsigned long)folderid, name);
  fd=psync_file_open(indexname, P_O_RDONLY, 0);
  if (unlikely(fd==INVALID_HANDLE_VALUE)){
    err=psync_fs_err();
    debug(D_WARNING, "can not open %s", indexname);
    if (err==P_NOENT)
      return 0;
    else
      return -1;
  }
  tree=NULL;
  if (unlikely_log((fsize=psync_file_size(fd))==-1 || psync_fs_load_interval_tree(fd, fsize, &tree)==-1)){
    psync_interval_tree_free(tree);
    psync_file_close(fd);
    return -1;
  }
  psync_file_close(fd);
  api=psync_apipool_get();
  if (unlikely_log(!api))
    goto err1;
  if (unlikely_log(clean_uploads_for_task(api, taskid)))
    goto err2;
  res=send_command(api, "upload_create", aparams);
  if (unlikely_log(!res))
    goto err2;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (unlikely(result)){
    psync_free(res);
    psync_apipool_release(api);
    psync_interval_tree_free(tree);
    debug(D_WARNING, "upload_create returned %lu", (unsigned long)result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -1;
    else
      return 0;
  }
  uploadid=psync_find_result(res, "uploadid", PARAM_NUM)->num;
  psync_free(res);
  sql=psync_sql_prep_statement("INSERT INTO fstaskupload (fstaskid, uploadid) VALUES (?, ?)");
  psync_sql_bind_uint(sql, 1, taskid);
  psync_sql_bind_uint(sql, 2, uploadid);
  psync_sql_run_free(sql);
  fd=psync_file_open(filename, P_O_RDONLY, 0);
  if (unlikely(fd==INVALID_HANDLE_VALUE)){
    err=psync_fs_err();
    debug(D_WARNING, "can not open %s", filename);
    psync_apipool_release(api);
    psync_interval_tree_free(tree);
    if (err==P_NOENT)
      return 0;
    else
      return -1;
  }
  fsize=psync_file_size(fd);
  if (unlikely_log(fsize==-1))
    goto err3;
  coff=0;
  reqs=0;
  cinterval=psync_interval_tree_get_first(tree);
  while (coff<fsize){
    if (reqs && (psync_socket_pendingdata(api) || psync_select_in(&api->sock, 1, 0)!=SOCKET_ERROR)){
      if ((ret=upload_modify_read_req(api))){
        if (unlikely_log(ret==PSYNC_NET_PERMFAIL))
          perm_fail_upload_task(taskid);
        goto err3;
      }
      else
        reqs--;
    }
    if (cinterval){
      if (cinterval->from>coff){
        len=i64min(cinterval->from, fsize)-coff;
        ret=upload_modify_send_copy_from(api, uploadid, coff, len, fileid, hash);
        reqs++;
        coff+=len;
      }
      else if (cinterval->from<=coff && cinterval->to>coff){
        ret=upload_modify_send_local(api, uploadid, coff, i64min(cinterval->to, fsize)-coff, fd);
        reqs++;
        coff=cinterval->to;
        cinterval=psync_interval_tree_get_next(cinterval);
      }
      else{
        debug(D_BUG, "broken interval tree");
        break;
      }
    }
    else{
      ret=upload_modify_send_copy_from(api, uploadid, coff, fsize-coff, fileid, hash);
      reqs++;
      coff=fsize;
    }
    if (ret){
      if (unlikely_log(ret==PSYNC_NET_PERMFAIL))
        perm_fail_upload_task(taskid);
      goto err3;
    }
    if (unlikely(stop_current_upload)){
      debug(D_NOTICE, "got stop for file %s", name);
      goto err3;
    }
  }
  psync_file_close(fd);
  while (reqs--)
    if ((ret=upload_modify_read_req(api))){
      if (unlikely_log(ret==PSYNC_NET_PERMFAIL))
        perm_fail_upload_task(taskid);
      goto err2;
    }
  psync_interval_tree_free(tree);
  if (psync_fs_get_file_writeid(taskid)!=writeid){
    debug(D_NOTICE, "%s changed while uploading as %lu/%s", filename, (unsigned long)folderid, name);
    psync_apipool_release(api);
    return -1;
  }
  return large_upload_save(api, uploadid, folderid, name, taskid, writeid, 0);
err3:
  psync_file_close(fd);
err2:
  psync_apipool_release_bad(api);
err1:
  psync_interval_tree_free(tree);
  return -1;
}

static void large_upload(){
  uint64_t taskid, type, writeid;
  psync_uploadid_t uploadid;
  psync_folderid_t folderid;
  const char *cname;
  char *name, *filename, *indexname;
  size_t len;
  psync_sql_res *res;
  psync_variant_row row;
  psync_uint_row urow;
  int ret;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  debug(D_NOTICE, "started");
  while (1){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    res=psync_sql_query("SELECT id, type, folderid, text1, int1, fileid, int2 FROM fstask WHERE status=2 AND \
type IN ("NTO_STR(PSYNC_FS_TASK_CREAT)", "NTO_STR(PSYNC_FS_TASK_MODIFY)") ORDER BY id LIMIT 1");
    row=psync_sql_fetch_row(res);
    if (!row){
      large_upload_running=0;
      current_upload_taskid=0;
      psync_sql_free_result(res);
      break;
    }
    taskid=psync_get_number(row[0]);
    type=psync_get_number(row[1]);
    folderid=psync_get_number(row[2]);
    cname=psync_get_lstring(row[3], &len);
    writeid=psync_get_number(row[4]);
    len++;
    name=psync_new_cnt(char, len);
    memcpy(name, cname, len);
    current_upload_taskid=taskid;
    stop_current_upload=0;
    psync_sql_free_result(res);
    psync_binhex(fileidhex, &taskid, sizeof(psync_fsfileid_t));
    fileidhex[sizeof(psync_fsfileid_t)]='d';
    fileidhex[sizeof(psync_fsfileid_t)+1]=0;
    cname=psync_setting_get_string(_PS(fscachepath));
    filename=psync_strcat(cname, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    fileidhex[sizeof(psync_fsfileid_t)]='i';
    indexname=psync_strcat(cname, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    res=psync_sql_query("SELECT uploadid FROM fstaskupload WHERE fstaskid=? ORDER BY uploadid DESC LIMIT 1");
    if ((urow=psync_sql_fetch_rowint(res)))
      uploadid=urow[0];
    else
      uploadid=0;
    psync_sql_free_result(res);
    if (type==PSYNC_FS_TASK_CREAT)
      ret=large_upload_creat(taskid, folderid, name, filename, uploadid, writeid);
    else if (type==PSYNC_FS_TASK_MODIFY)
      ret=upload_modify(taskid, folderid, name, filename, indexname, psync_get_number(row[5]), psync_get_number(row[6]), writeid);
    else{
      ret=0;
      debug(D_BUG, "wrong type %lu for task %lu", (unsigned long)type, (unsigned long)taskid);
      res=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
      psync_sql_bind_uint(res, 1, taskid);
      psync_sql_run_free(res);
    }
    if (ret)
      psync_milisleep(PSYNC_SLEEP_ON_FAILED_UPLOAD);
    psync_free(indexname);
    psync_free(filename);
    psync_free(name);
  }
  debug(D_NOTICE, "exited");
}

static int psync_sent_task_creat_upload_large(fsupload_task_t *task){
  psync_sql_res *res;
  res=psync_sql_prep_statement("UPDATE fstask SET status=2 WHERE id=?");
  psync_sql_bind_uint(res, 1, task->id);
  //psync_fs_uploading_openfile(task->id);
  if (!large_upload_running){
    large_upload_running=1;
    psync_run_thread("large file fs upload", large_upload);
  }
  psync_sql_run_free(res);
  return 0;
}

void psync_fsupload_stop_upload_locked(uint64_t taskid){
  psync_sql_res *res;
  if (current_upload_taskid==taskid)
    stop_current_upload=1;
  res=psync_sql_prep_statement("UPDATE fstask SET status=1 WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_run_free(res);
  assertw(psync_sql_affected_rows());
}

static int psync_send_task_creat(psync_socket *api, fsupload_task_t *task){
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  char *filename;
  psync_stat_t st;
  uint64_t size;
  psync_file_t fd;
  int ret;
  psync_binhex(fileidhex, &task->id, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)]='d';
  fileidhex[sizeof(psync_fsfileid_t)+1]=0;
  filename=psync_strcat(psync_setting_get_string(_PS(fscachepath)), PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
  fd=psync_file_open(filename, P_O_RDONLY, 0);
  psync_free(filename);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE) || unlikely_log(psync_fstat(fd, &st))){
    if (fd!=INVALID_HANDLE_VALUE)
      psync_file_close(fd);
    delete_task(task->id);
    return -1;
  }
  size=psync_stat_size(&st);
  if (api){
    if (size>PSYNC_FS_DIRECT_UPLOAD_LIMIT){
      psync_file_close(fd);
      debug(D_NOTICE, "defering upload of %lu/%s due to size of %lu", (unsigned long)task->folderid, task->text1, (unsigned long)size);
      return -2;
    }
    else{
      debug(D_NOTICE, "uploading file %lu/%s pipelined due to size of %lu", (unsigned long)task->folderid, task->text1, (unsigned long)size);
      ret=psync_send_task_creat_upload_small(api, task, fd, size);
      psync_file_close(fd);
      return ret;
    }
  }
  else{
    debug(D_NOTICE, "uploading file %lu/%s separately due to size of %lu", (unsigned long)task->folderid, task->text1, (unsigned long)size);
    psync_file_close(fd);
    return psync_sent_task_creat_upload_large(task);
  }
}

static int psync_send_task_modify(psync_socket *api, fsupload_task_t *task){
  if (api)
    return -2;
  else
    return psync_sent_task_creat_upload_large(task);
}

static int psync_process_task_creat(fsupload_task_t *task){
  uint64_t result;
  const binresult *meta;
  psync_fileid_t fileid;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result)
    return handle_upload_api_error(result, task);
  meta=psync_find_result(task->res, "metadata", PARAM_ARRAY)->array[0];
  fileid=psync_find_result(meta, "fileid", PARAM_NUM)->num;
  if (psync_fs_update_openfile(task->id, task->int1, fileid, psync_find_result(meta, "hash", PARAM_NUM)->num, psync_find_result(meta, "size", PARAM_NUM)->num))
    return -1;
  psync_ops_create_file_in_db(meta);
  psync_fstask_file_created(task->folderid, task->id, task->text1, fileid);
  psync_pagecache_creat_to_pagecache(task->id, psync_find_result(meta, "hash", PARAM_NUM)->num);
  psync_fs_task_to_file(task->id, fileid);
  task->int2=fileid;
  debug(D_NOTICE, "file %lu/%s uploaded", (unsigned long)task->folderid, task->text1);
  return 0;
}

static int psync_send_task_unlink(psync_socket *api, fsupload_task_t *task){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", task->fileid)};
  if (likely_log(send_command_no_res(api, "deletefile", params)==PTR_OK))
    return 0;
  else
    return -1;
}

static int handle_unlink_api_error(uint64_t result, fsupload_task_t *task){
  debug(D_ERROR, "deletefile returned error %u", (unsigned)result);
  switch (result){
    case 2009: /* file does not exist, kind of success */
      psync_ops_delete_file_from_db(task->fileid);
      psync_fstask_file_deleted(task->folderid, task->id, task->text1);
      return 0;
    case 2003: /* access denied, skip*/
      psync_fstask_file_deleted(task->folderid, task->id, task->text1);
      return 0;
    default:
      return -1;
  }
}

static int psync_process_task_unlink(fsupload_task_t *task){
  uint64_t result;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result)
    return handle_unlink_api_error(result, task);
  psync_ops_delete_file_from_db(task->fileid);
  psync_fstask_file_deleted(task->folderid, task->id, task->text1);
  debug(D_NOTICE, "file %lu/%s deleted", (unsigned long)task->folderid, task->text1);
  return 0;
}

static int psync_send_task_rename_file(psync_socket *api, fsupload_task_t *task){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", task->fileid), P_NUM("tofolderid", task->folderid), 
                     P_STR("toname", task->text1), P_STR("timeformat", "timestamp")};
  if (likely_log(send_command_no_res(api, "renamefile", params)==PTR_OK))
    return 0;
  else
    return -1;
}

static int psync_send_task_rename_folder(psync_socket *api, fsupload_task_t *task){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", task->sfolderid), P_NUM("tofolderid", task->folderid), 
                     P_STR("toname", task->text1), P_STR("timeformat", "timestamp")};
  if (likely_log(send_command_no_res(api, "renamefolder", params)==PTR_OK))
    return 0;
  else
    return -1;
}

/*static fsupload_task_t *load_task(uint64_t id){
  fsupload_task_t *task;
  psync_sql_res *res;
  psync_variant_row row;
  char *end;
  size_t size;
  res=psync_sql_query("SELECT id, type, folderid, fileid, text1, text2, int1, int2, sfolderid FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, id);
  task=NULL;
  if ((row=psync_sql_fetch_row(res))){
    size=sizeof(fsupload_task_t);
    if (row[4].type==PSYNC_TSTRING)
      size+=row[4].length+1;
    if (row[5].type==PSYNC_TSTRING)
      size+=row[5].length+1;
    task=(fsupload_task_t *)psync_malloc(size);
    end=(char *)(task+1);
    task->res=NULL;
    task->id=psync_get_number(row[0]);
    task->type=psync_get_number(row[1]);
    task->folderid=psync_get_number(row[2]);
    task->fileid=psync_get_number_or_null(row[3]);
    task->sfolderid=psync_get_number_or_null(row[8]);
    if (row[4].type==PSYNC_TSTRING){
      memcpy(end, row[4].str, row[4].length+1);
      task->text1=end;
      end+=row[4].length+1;
    }
    else
      task->text1=NULL;
    if (row[5].type==PSYNC_TSTRING){
      memcpy(end, row[5].str, row[5].length+1);
      task->text2=end;
    }
    else
      task->text2=NULL;
    task->int1=psync_get_snumber_or_null(row[6]);
    task->int2=psync_get_snumber_or_null(row[7]);
  }
  psync_sql_free_result(res);
  return task;  
}*/

static int handle_rename_file_api_error(uint64_t result, fsupload_task_t *task){
  debug(D_ERROR, "renamefile returned error %u", (unsigned)result);
  switch (result){
    case 2009: /* file does not exist, skip */
    case 2005: /* destination does not exist, skip */
    case 2003: /* access denied, skip */
    case 2001: /* invalid name, should not happen */
    case 2008: /* overquota */
    case 2049: /* Source and target are the same file */
      psync_fstask_file_renamed(task->folderid, task->id, task->text1, task->int1);
      return 0;
  }
  return -1;
}

static int psync_process_task_rename_file(fsupload_task_t *task){
  uint64_t result;
  const binresult *meta;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result && result!=2049)
    return handle_rename_file_api_error(result, task);
  meta=psync_find_result(task->res, "metadata", PARAM_HASH);
  psync_ops_update_file_in_db(meta);
  psync_fstask_file_renamed(task->folderid, task->id, task->text1, task->int1);
  debug(D_NOTICE, "file %lu/%s renamed", (unsigned long)task->folderid, task->text1);
  return 0;
}

static int handle_rename_folder_api_error(uint64_t result, fsupload_task_t *task){
  debug(D_ERROR, "renamefolder returned error %u", (unsigned)result);
  switch (result){
    case 2005: /* folder does not exist, skip */
    case 2042: /* moving root, should not happen */
    case 2003: /* access denied, skip */
    case 2001: /* invalid name, should not happen */
    case 2008: /* overquota */
    case 2023: /* moving into shared folder */
      psync_fstask_folder_renamed(task->folderid, task->id, task->text1, task->int1);
      return 0;
  }
  return -1;
}

static int psync_process_task_rename_folder(fsupload_task_t *task){
  uint64_t result;
  const binresult *meta;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result)
    return handle_rename_folder_api_error(result, task);
  meta=psync_find_result(task->res, "metadata", PARAM_HASH);
  psync_ops_update_folder_in_db(meta);
  psync_fstask_folder_renamed(task->folderid, task->id, task->text1, task->int1);
  debug(D_NOTICE, "folder %lu/%s renamed", (unsigned long)task->folderid, task->text1);
  return 0;
}

typedef int (*psync_send_task_ptr)(psync_socket *, fsupload_task_t *);
typedef int (*psync_process_task_ptr)(fsupload_task_t *);

static psync_send_task_ptr psync_send_task_func[]={
  NULL,
  psync_send_task_mkdir,
  psync_send_task_rmdir,
  psync_send_task_creat,
  psync_send_task_unlink,
  NULL,
  psync_send_task_rename_file,
  NULL,
  psync_send_task_rename_folder,
  psync_send_task_modify
};

static psync_process_task_ptr psync_process_task_func[]={
  NULL,
  psync_process_task_mkdir,
  psync_process_task_rmdir,
  psync_process_task_creat,
  psync_process_task_unlink,
  NULL,
  psync_process_task_rename_file,
  NULL,
  psync_process_task_rename_folder,
  NULL
};

static void psync_fsupload_process_tasks(psync_list *tasks){
  fsupload_task_t *task;
  psync_sql_res *del, *dep, *fol, *sfol, *fil;
  psync_sql_start_transaction();
  del=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
  dep=psync_sql_prep_statement("DELETE FROM fstaskdepend WHERE dependfstaskid=?");
  fol=psync_sql_prep_statement("UPDATE fstask SET folderid=? WHERE folderid=?");
  sfol=psync_sql_prep_statement("UPDATE fstask SET sfolderid=? WHERE sfolderid=?");
  fil=psync_sql_prep_statement("UPDATE fstask SET fileid=? WHERE fileid=?");
  psync_list_for_each_element (task, tasks, fsupload_task_t, list)
    if (task->res){
      if (psync_process_task_func[task->type](task))
        debug(D_WARNING, "processing task %lu of type %lu failed", (unsigned long)task->id, (unsigned long)task->type);
      else{
        if (task->type==PSYNC_FS_TASK_MKDIR){
          psync_sql_bind_uint(fol, 1, task->int2);
          psync_sql_bind_int(fol, 2, -task->id);
          psync_sql_run(fol);
          psync_sql_bind_uint(sfol, 1, task->int2);
          psync_sql_bind_int(sfol, 2, -task->id);
          psync_sql_run(sfol);
        }
        if (task->type==PSYNC_FS_TASK_CREAT){
          psync_sql_bind_uint(fil, 1, task->int2);
          psync_sql_bind_int(fil, 2, -task->id);
          psync_sql_run(fil);
        }
        psync_sql_bind_uint(dep, 1, task->id);
        psync_sql_run(dep);
        if (psync_sql_affected_rows())
          upload_wakes++;
        psync_sql_bind_uint(del, 1, task->id);
        psync_sql_run(del);
      }
      psync_free(task->res);
    }
  psync_sql_free_result(fil);
  psync_sql_free_result(sfol);
  psync_sql_free_result(fol);
  psync_sql_free_result(dep);
  psync_sql_free_result(del);
  psync_sql_commit_transaction();
}

static void psync_fsupload_run_tasks(psync_list *tasks){
  psync_socket *api;
  fsupload_task_t *task, *rtask;
  int ret;
  api=psync_apipool_get();
  if (!api)
    goto err;
  rtask=psync_list_element(tasks->next, fsupload_task_t, list);
  ret=0;
  psync_list_for_each_element (task, tasks, fsupload_task_t, list){
    if (!task->type || task->type>=ARRAY_SIZE(psync_send_task_func)){
      debug(D_BUG, "bad task type %lu", (unsigned long)task->type);
      continue;
    }
    ret=psync_send_task_func[task->type](api, task);
    if (ret==-1)
      goto err0;
    else if (ret==-2)
      break;
    while (psync_select_in(&api->sock, 1, 0)==0){
      rtask->res=get_result(api);
      if (unlikely_log(!rtask->res))
        goto err0;
      rtask=psync_list_element(rtask->list.next, fsupload_task_t, list);
    }
  }
  while (rtask!=task){
    rtask->res=get_result(api);
    if (unlikely_log(!rtask->res))
      goto err0;
    rtask=psync_list_element(rtask->list.next, fsupload_task_t, list);
  }
  psync_apipool_release(api);
  psync_fsupload_process_tasks(tasks);
  if (ret==-2)
    psync_send_task_func[task->type](NULL, task);
  return;
err0:
  psync_apipool_release_bad(api);
  psync_fsupload_process_tasks(tasks);
err:
  psync_timer_notify_exception();
  upload_wakes++;
  psync_milisleep(PSYNC_SLEEP_ON_FAILED_UPLOAD);
}

static void psync_fsupload_check_tasks(){
  fsupload_task_t *task;
  psync_sql_res *res;
  psync_variant_row row;
  char *end;
  psync_list tasks;
  size_t size;
  psync_list_init(&tasks);
  res=psync_sql_query("SELECT f.id, f.type, f.folderid, f.fileid, f.text1, f.text2, f.int1, f.int2, f.sfolderid FROM fstask f LEFT JOIN fstaskdepend d ON f.id=d.fstaskid"
                      " WHERE d.fstaskid IS NULL AND status=0 ORDER BY id LIMIT "NTO_STR(PSYNC_FSUPLOAD_NUM_TASKS_PER_RUN));
  while ((row=psync_sql_fetch_row(res))){
    size=sizeof(fsupload_task_t);
    if (row[4].type==PSYNC_TSTRING)
      size+=row[4].length+1;
    if (row[5].type==PSYNC_TSTRING)
      size+=row[5].length+1;
    task=(fsupload_task_t *)psync_malloc(size);
    end=(char *)(task+1);
    task->res=NULL;
    task->id=psync_get_number(row[0]);
    task->type=psync_get_number(row[1]);
    task->folderid=psync_get_number(row[2]);
    task->fileid=psync_get_number_or_null(row[3]);
    task->sfolderid=psync_get_number_or_null(row[8]);
    if (row[4].type==PSYNC_TSTRING){
      memcpy(end, row[4].str, row[4].length+1);
      task->text1=end;
      end+=row[4].length+1;
    }
    else
      task->text1=NULL;
    if (row[5].type==PSYNC_TSTRING){
      memcpy(end, row[5].str, row[5].length+1);
      task->text2=end;
    }
    else
      task->text2=NULL;
    task->int1=psync_get_snumber_or_null(row[6]);
    task->int2=psync_get_snumber_or_null(row[7]);
    psync_list_add_tail(&tasks, &task->list);
  }
  psync_sql_free_result(res);
  if (!psync_list_isempty(&tasks))
    psync_fsupload_run_tasks(&tasks);
  psync_list_for_each_element_call(&tasks, fsupload_task_t, list, psync_free);
}

static void psync_fsupload_thread(){
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    psync_fsupload_check_tasks();
    pthread_mutex_lock(&upload_mutex);
    if (!upload_wakes)
      pthread_cond_wait(&upload_cond, &upload_mutex);
    upload_wakes=0;
    pthread_mutex_unlock(&upload_mutex);
  }
}

void psync_fsupload_init(){
  psync_timer_exception_handler(psync_fsupload_wake);
  psync_run_thread("fsupload main", psync_fsupload_thread);
}

void psync_fsupload_wake(){
  pthread_mutex_lock(&upload_mutex);
  if (!upload_wakes++)
    pthread_cond_signal(&upload_cond);
  pthread_mutex_unlock(&upload_mutex); 
}
