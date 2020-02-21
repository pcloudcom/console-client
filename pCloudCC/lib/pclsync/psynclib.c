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

#include "gitcommit.h"
#include "plibs.h"
#include "pcompat.h"
#include "psynclib.h"
#include "pcallbacks.h"
#include "pstatus.h"
#include "pdiff.h"
#include "pssl.h"
#include "ptimer.h"
#include "pupload.h"
#include "pdownload.h"
#include "pfolder.h"
#include "psettings.h"
#include "psyncer.h"
#include "ptasks.h"
#include "papi.h"
#include "pnetlibs.h"
#include "pscanner.h"
#include "plocalscan.h"
#include "plist.h"
#include "pp2p.h"
#include "plocalnotify.h"
#include "pcache.h"
#include "pfileops.h"
#include "pcloudcrypto.h"
#include "ppagecache.h"
#include "ppassword.h"
#include "pnotifications.h"
#include "pmemlock.h"
#include "pexternalstatus.h"
#include "publiclinks.h"
#include "pbusinessaccount.h"
#include "pcontacts.h"
#include "poverlay.h"
#include "pasyncnet.h"
#include "ppathstatus.h"
//#include "pdevice_monitor.h"

#include <string.h>
#include <ctype.h>
#include <stddef.h>

typedef struct {
  psync_list list;
  char str[];
} string_list;

static psync_malloc_t psync_real_malloc=malloc;
static psync_realloc_t psync_real_realloc=realloc;
static psync_free_t psync_real_free=free;

const char *psync_database=NULL;

static int psync_libstate=0;
static pthread_mutex_t psync_libstate_mutex=PTHREAD_MUTEX_INITIALIZER;

#define return_error(err) do {psync_error=err; return -1;} while (0)
#define return_isyncid(err) do {psync_error=err; return PSYNC_INVALID_SYNCID;} while (0)

PSYNC_NOINLINE void *psync_emergency_malloc(size_t size){
  void *ret;
  debug(D_WARNING, "could not allocate %lu bytes", (unsigned long)size);
  psync_try_free_memory();
  ret=psync_real_malloc(size);
  if (likely(ret))
#if IS_DEBUG
    return memset(ret, 0xfa, size);
#else
    return ret;
#endif
  else{
    debug(D_CRITICAL, "could not allocate %lu bytes even after freeing some memory, aborting", (unsigned long)size);
    abort();
    return NULL;
  }
}

void *psync_malloc(size_t size){
  void *ret;
  ret=psync_real_malloc(size);
  if (likely(ret))
#if IS_DEBUG
    return memset(ret, 0xfa, size);
#else
    return ret;
#endif
  else
    return psync_emergency_malloc(size);
}

PSYNC_NOINLINE void *psync_emergency_realloc(void *ptr, size_t size){
  void *ret;
  debug(D_WARNING, "could not reallocate %lu bytes", (unsigned long)size);
  psync_try_free_memory();
  ret=psync_real_realloc(ptr, size);
  if (likely(ret))
    return ret;
  else{
    debug(D_CRITICAL, "could not reallocate %lu bytes even after freeing some memory, aborting", (unsigned long)size);
    abort();
    return NULL;
  }
}

void *psync_realloc(void *ptr, size_t size){
  void *ret;
  ret=psync_real_realloc(ptr, size);
  if (likely(ret))
    return ret;
  else
    return psync_emergency_realloc(ptr, size);
}

void psync_free(void *ptr){
  psync_real_free(ptr);
}

uint32_t psync_get_last_error(){
  return psync_error;
}

void psync_set_database_path(const char *databasepath){
  psync_database=psync_strdup(databasepath);
}

void psync_set_alloc(psync_malloc_t malloc_call, psync_realloc_t realloc_call, psync_free_t free_call){
  psync_real_malloc=malloc_call;
  psync_real_realloc=realloc_call;
  psync_real_free=free_call;
}

void psync_set_software_string(const char *str){
  debug(D_NOTICE, "setting software name to %s", str);
  psync_set_software_name(str);
}

static void psync_stop_crypto_on_sleep(){
  if (psync_setting_get_bool(_PS(sleepstopcrypto)) && psync_crypto_isstarted()){
    psync_cloud_crypto_stop();
    debug(D_NOTICE, "stopped crypto due to sleep");
  }
}

int psync_init(){
  psync_thread_name="main app thread";
  debug(D_NOTICE, "initializing library version "PSYNC_LIB_VERSION);
  debug(D_NOTICE, "last commit time "GIT_COMMIT_DATE);
  debug(D_NOTICE, "previous commit time "GIT_PREV_COMMIT_DATE);
  debug(D_NOTICE, "previous commit id "GIT_PREV_COMMIT_ID);
  if (IS_DEBUG){
    pthread_mutex_lock(&psync_libstate_mutex);
    if (psync_libstate!=0){
      pthread_mutex_unlock(&psync_libstate_mutex);
      debug(D_BUG, "you are not supposed to call psync_init for a second time");
      return 0;
    }
  }
  psync_locked_init();
  psync_cache_init();
  psync_compat_init();
  if (!psync_database){
    psync_database=psync_get_default_database_path();
    if (unlikely_log(!psync_database)){
      if (IS_DEBUG)
        pthread_mutex_unlock(&psync_libstate_mutex);
      return_error(PERROR_NO_HOMEDIR);
    }
  }
  if (psync_sql_connect(psync_database)){
    if (IS_DEBUG)
      pthread_mutex_unlock(&psync_libstate_mutex);
    return_error(PERROR_DATABASE_OPEN);
  }
  psync_sql_statement("UPDATE task SET inprogress=0 WHERE inprogress=1");
  psync_timer_init();
  if (unlikely_log(psync_ssl_init())){
    if (IS_DEBUG)
      pthread_mutex_unlock(&psync_libstate_mutex);
    return_error(PERROR_SSL_INIT_FAILED);
  }

  psync_libs_init();
  psync_settings_init();
  psync_status_init();
  psync_timer_sleep_handler(psync_stop_crypto_on_sleep);
  psync_path_status_init();
  if (IS_DEBUG){
    psync_libstate=1;
    pthread_mutex_unlock(&psync_libstate_mutex);
  }

  psync_run_thread("Overlay main thread", overlay_main_loop);
  init_overlay_callbacks();
  //psync_run_thread("Device monitor main thread", pinit_device_monitor);

  return 0;
}

void psync_start_sync(pstatus_change_callback_t status_callback, pevent_callback_t event_callback){
  debug(D_NOTICE, "starting sync");
  if (IS_DEBUG){
    pthread_mutex_lock(&psync_libstate_mutex);
    if (psync_libstate==0){
      pthread_mutex_unlock(&psync_libstate_mutex);
      debug(D_BUG, "you are calling psync_start_sync before psync_init");
      return;
    }
    else if (psync_libstate==2){
      pthread_mutex_unlock(&psync_libstate_mutex);
      debug(D_BUG, "you are calling psync_start_sync for a second time");
      return;
    }
    else
      psync_libstate=2;
    pthread_mutex_unlock(&psync_libstate_mutex);
  }
  if (status_callback)
    psync_set_status_callback(status_callback);
  if (event_callback)
    psync_set_event_callback(event_callback);
  psync_syncer_init();
  psync_diff_init();
  psync_upload_init();
  psync_download_init();
  psync_netlibs_init();
  psync_localscan_init();
  psync_p2p_init();
  if (psync_setting_get_bool(_PS(autostartfs)))
    psync_fs_start();
}

void psync_set_notification_callback(pnotification_callback_t notification_callback, const char *thumbsize){
  psync_notifications_set_callback(notification_callback, thumbsize);
}

psync_notification_list_t *psync_get_notifications(){
  return psync_notifications_get();
}

uint32_t psync_download_state(){
  return 0;
}

void psync_destroy(){
  psync_do_run=0;
  psync_fs_stop();
  psync_terminate_status_waiters();
  psync_send_status_update();
  psync_async_stop();
  psync_timer_wake();
  psync_timer_notify_exception();
  psync_sql_sync();
  psync_milisleep(20);
  psync_sql_lock();
  psync_cache_clean_all();
  psync_sql_close();
}

void psync_get_status(pstatus_t *status){
  psync_callbacks_get_status(status);
}

char *psync_get_username(){
  return psync_sql_cellstr("SELECT value FROM setting WHERE id='username'");
}

static void clear_db(int save){
  psync_sql_statement("DELETE FROM setting WHERE id IN ('pass', 'auth')");
  psync_setting_set_bool(_PS(saveauth), save);
}

void psync_set_user_pass(const char *username, const char *password, int save){
  clear_db(save);
  if (save){
    psync_set_string_value("user", username);
    if (password && password[0])
      psync_set_string_value("pass", password);
  }
  else{
    pthread_mutex_lock(&psync_my_auth_mutex);
    psync_free(psync_my_user);
    psync_my_user=psync_strdup(username);
    psync_free(psync_my_pass);
    if (password && password[0])
      psync_my_pass=psync_strdup(password);
    pthread_mutex_unlock(&psync_my_auth_mutex);
  }
  psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
  psync_recache_contacts=1;
}

void psync_set_pass(const char *password, int save){
  clear_db(save);
  if (save)
    psync_set_string_value("pass", password);
  else{
    pthread_mutex_lock(&psync_my_auth_mutex);
    psync_free(psync_my_pass);
    psync_my_pass=psync_strdup(password);
    pthread_mutex_unlock(&psync_my_auth_mutex);
  }
  psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
}

void psync_set_auth(const char *auth, int save){
  clear_db(save);
  if (save)
    psync_set_string_value("auth", auth);
  else
    psync_strlcpy(psync_my_auth, auth, sizeof(psync_my_auth));
  psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
}

void psync_set_tfa_pin(const char *tfa_pin){
    psync_strlcpy(psync_my_tfa_pin, tfa_pin, sizeof(psync_my_tfa_pin));
    psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
}

int psync_mark_notificaitons_read(uint32_t notificationid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("notificationid", notificationid)};
  return psync_run_command("readnotifications", params, NULL)?-1:0;
}

static void psync_invalidate_auth(const char *auth){
  binparam params[]={P_STR("auth", auth)};
  psync_run_command("logout", params, NULL);
}

void psync_logout2(uint32_t auth_status, int doinvauth){
  debug(D_NOTICE, "logout");
  psync_sql_statement("DELETE FROM setting WHERE id IN ('pass', 'auth', 'saveauth')");
  if (doinvauth)
    psync_invalidate_auth(psync_my_auth);
  memset(psync_my_auth, 0, sizeof(psync_my_auth));
  psync_cloud_crypto_stop();
  pthread_mutex_lock(&psync_my_auth_mutex);
  psync_free(psync_my_pass);
  psync_my_pass=NULL;
  pthread_mutex_unlock(&psync_my_auth_mutex);
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  psync_set_status(PSTATUS_TYPE_AUTH, auth_status);
  psync_fs_pause_until_login();
  psync_stop_all_download();
  psync_stop_all_upload();
  psync_async_stop();
  psync_cache_clean_all();
  psync_restart_localscan();
  psync_timer_notify_exception();
  if (psync_fs_need_per_folder_refresh())
    psync_fs_refresh_folder(0);
}

void psync_logout(){
  psync_logout2(PSTATUS_AUTH_REQUIRED, 1);
}

void psync_unlink(){
  int ret;
  debug(D_NOTICE, "unlink");
  psync_diff_lock();
  psync_stop_all_download();
  psync_stop_all_upload();
  psync_status_recalc_to_download();
  psync_status_recalc_to_upload();
  psync_invalidate_auth(psync_my_auth);
  psync_cloud_crypto_stop();
  psync_milisleep(20);
  psync_stop_localscan();
  psync_sql_checkpoint_lock();
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_REQUIRED);
  psync_set_status(PSTATUS_TYPE_RUN, PSTATUS_RUN_STOP);
  psync_timer_notify_exception();
  psync_sql_lock();
  debug(D_NOTICE, "clearing database, locked");
  psync_cache_clean_all();
  ret=psync_sql_close();
  psync_file_delete(psync_database);
  if (ret){
    debug(D_ERROR, "failed to close database, exiting");
    exit(1);
  }
  psync_pagecache_clean_cache();
  psync_sql_connect(psync_database);
  /*
    psync_sql_res *res;
    psync_variant_row row;
    char *sql;
    const char *str;
    size_t len;
    psync_list list;
    string_list *le;
    psync_list_init(&list);
    res=psync_sql_query("SELECT name FROM sqlite_master WHERE type='index'");
    while ((row=psync_sql_fetch_row(res))){
      str=psync_get_lstring(row[0], &len);
      le=(string_list *)psync_malloc(offsetof(string_list, str)+len+1);
      memcpy(le->str, str, len+1);
      psync_list_add_tail(&list, &le->list);
    }
    psync_sql_free_result(res);
    psync_list_for_each_element(le, &list, string_list, list){
      sql=psync_strcat("DROP INDEX ", le->str, NULL);
      psync_sql_statement(sql);
      psync_free(sql);
    }
    psync_list_for_each_element_call(&list, string_list, list, psync_free);
    psync_list_init(&list);
    res=psync_sql_query("SELECT name FROM sqlite_master WHERE type='table'");
    while ((row=psync_sql_fetch_row(res))){
      str=psync_get_lstring(row[0], &len);
      le=(string_list *)psync_malloc(offsetof(string_list, str)+len+1);
      memcpy(le->str, str, len+1);
      psync_list_add_tail(&list, &le->list);
    }
    psync_sql_free_result(res);
    psync_list_for_each_element(le, &list, string_list, list){
      sql=psync_strcat("DROP TABLE ", le->str, NULL);
      psync_sql_statement(sql);
      psync_free(sql);
    }
    psync_list_for_each_element_call(&list, string_list, list, psync_free);
    psync_sql_statement("VACUUM");
  */
  pthread_mutex_lock(&psync_my_auth_mutex);
  memset(psync_my_auth, 0, sizeof(psync_my_auth));
  psync_my_user=NULL;
  psync_my_pass=NULL;
  psync_my_userid=0;
  pthread_mutex_unlock(&psync_my_auth_mutex);
  debug(D_NOTICE, "clearing database, finished");
  psync_fs_pause_until_login();
  psync_fs_clean_tasks();
  psync_path_status_init();
  psync_clear_downloadlist();
  psync_sql_unlock();
  psync_sql_checkpoint_unlock();
  psync_settings_reset();
  psync_cache_clean_all();
  psync_notifications_clean();
  psync_pagecache_reopen_read_cache();
  psync_diff_unlock();
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  psync_set_status(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK);
  psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_REQUIRED);
  psync_set_status(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN);
  psync_resume_localscan();
  if (psync_fs_need_per_folder_refresh())
    psync_fs_refresh_folder(0);
}

psync_syncid_t psync_add_sync_by_path(const char *localpath, const char *remotepath, psync_synctype_t synctype){
  psync_folderid_t folderid=psync_get_folderid_by_path(remotepath);
  if (likely_log(folderid!=PSYNC_INVALID_FOLDERID))
    return psync_add_sync_by_folderid(localpath, folderid, synctype);
  else
    return PSYNC_INVALID_SYNCID;
}

psync_syncid_t psync_add_sync_by_folderid(const char *localpath, psync_folderid_t folderid, psync_synctype_t synctype){
  psync_sql_res *res;
  char *syncmp;
  psync_uint_row row;
  psync_str_row srow;
  uint64_t perms;
  psync_stat_t st;
  psync_syncid_t ret;
  int unsigned md;
  if (unlikely_log(synctype<PSYNC_SYNCTYPE_MIN || synctype>PSYNC_SYNCTYPE_MAX))
    return_isyncid(PERROR_INVALID_SYNCTYPE);
  if (unlikely_log(psync_stat(localpath, &st)) || unlikely_log(!psync_stat_isfolder(&st)))
    return_isyncid(PERROR_LOCAL_FOLDER_NOT_FOUND);
  if (synctype&PSYNC_DOWNLOAD_ONLY)
    md=7;
  else
    md=5;
  if (unlikely_log(!psync_stat_mode_ok(&st, md)))
    return_isyncid(PERROR_LOCAL_FOLDER_ACC_DENIED);
  syncmp=psync_fs_getmountpoint();
  if (syncmp){
    size_t len=strlen(syncmp);
    if (!psync_filename_cmpn(syncmp, localpath, len) && (localpath[len]==0 || localpath[len]=='/' || localpath[len]=='\\')){
      debug(D_NOTICE, "local path %s is on pCloudDrive mounted as %s, rejecting sync", localpath, syncmp);
      psync_free(syncmp);
      return_isyncid(PERROR_LOCAL_IS_ON_PDRIVE);
    }
    psync_free(syncmp);
  }
  res=psync_sql_query("SELECT localpath FROM syncfolder");
  if (unlikely_log(!res))
    return_isyncid(PERROR_DATABASE_ERROR);
  while ((srow=psync_sql_fetch_rowstr(res)))
    if (psync_str_is_prefix(srow[0], localpath)){
      psync_sql_free_result(res);
      return_isyncid(PERROR_PARENT_OR_SUBFOLDER_ALREADY_SYNCING);
    }
    else if (!psync_filename_cmp(srow[0], localpath)){
      psync_sql_free_result(res);
      return_isyncid(PERROR_FOLDER_ALREADY_SYNCING);
    }
  psync_sql_free_result(res);
  if (folderid){
    res=psync_sql_query("SELECT permissions FROM folder WHERE id=?");
    if (unlikely_log(!res))
      return_isyncid(PERROR_DATABASE_ERROR);
    psync_sql_bind_uint(res, 1, folderid);
    row=psync_sql_fetch_rowint(res);
    if (unlikely_log(!row)){
      psync_sql_free_result(res);
      return_isyncid(PERROR_REMOTE_FOLDER_NOT_FOUND);
    }
    perms=row[0];
    psync_sql_free_result(res);
  }
  else
    perms=PSYNC_PERM_ALL;
  if (unlikely_log((synctype&PSYNC_DOWNLOAD_ONLY && (perms&PSYNC_PERM_READ)!=PSYNC_PERM_READ) ||
      (synctype&PSYNC_UPLOAD_ONLY && (perms&PSYNC_PERM_WRITE)!=PSYNC_PERM_WRITE)))
    return_isyncid(PERROR_REMOTE_FOLDER_ACC_DENIED);
  res=psync_sql_prep_statement("INSERT OR IGNORE INTO syncfolder (folderid, localpath, synctype, flags, inode, deviceid) VALUES (?, ?, ?, 0, ?, ?)");
  if (unlikely_log(!res))
    return_isyncid(PERROR_DATABASE_ERROR);
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_string(res, 2, localpath);
  psync_sql_bind_uint(res, 3, synctype);
  psync_sql_bind_uint(res, 4, psync_stat_inode(&st));
  psync_sql_bind_uint(res, 5, psync_stat_device(&st));
  psync_sql_run(res);
  if (likely_log(psync_sql_affected_rows()))
    ret=psync_sql_insertid();
  else
    ret=PSYNC_INVALID_SYNCID;
  psync_sql_free_result(res);
  if (ret==PSYNC_INVALID_SYNCID)
    return_isyncid(PERROR_FOLDER_ALREADY_SYNCING);
  psync_sql_sync();
  psync_path_status_reload_syncs();
  psync_syncer_new(ret);
  return ret;
}

int psync_add_sync_by_path_delayed(const char *localpath, const char *remotepath, psync_synctype_t synctype){
  psync_sql_res *res;
  psync_stat_t st;
  int unsigned md;
  if (unlikely_log(synctype<PSYNC_SYNCTYPE_MIN || synctype>PSYNC_SYNCTYPE_MAX))
    return_error(PERROR_INVALID_SYNCTYPE);
  if (unlikely_log(psync_stat(localpath, &st)) || unlikely_log(!psync_stat_isfolder(&st)))
    return_error(PERROR_LOCAL_FOLDER_NOT_FOUND);
  if (synctype&PSYNC_DOWNLOAD_ONLY)
    md=7;
  else
    md=5;
  if (unlikely_log(!psync_stat_mode_ok(&st, md)))
    return_error(PERROR_LOCAL_FOLDER_ACC_DENIED);
  res=psync_sql_prep_statement("INSERT INTO syncfolderdelayed (localpath, remotepath, synctype) VALUES (?, ?, ?)");
  psync_sql_bind_string(res, 1, localpath);
  psync_sql_bind_string(res, 2, remotepath);
  psync_sql_bind_uint(res, 3, synctype);
  psync_sql_run_free(res);
  psync_sql_sync();
  if (psync_status_get(PSTATUS_TYPE_ONLINE)==PSTATUS_ONLINE_ONLINE)
    psync_run_thread("check delayed syncs", psync_syncer_check_delayed_syncs);
  return 0;
}

int psync_change_synctype(psync_syncid_t syncid, psync_synctype_t synctype){
  psync_sql_res *res;
  psync_variant_row row;
  psync_uint_row urow;
  psync_folderid_t folderid;
  uint64_t perms;
  psync_stat_t st;
  int unsigned md;
  psync_synctype_t oldsynctype;
  if (unlikely_log(synctype<PSYNC_SYNCTYPE_MIN || synctype>PSYNC_SYNCTYPE_MAX))
    return_isyncid(PERROR_INVALID_SYNCTYPE);
  psync_sql_start_transaction();
  res=psync_sql_query("SELECT folderid, localpath, synctype FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  row=psync_sql_fetch_row(res);
  if (unlikely_log(!row)){
    psync_sql_free_result(res);
    psync_sql_rollback_transaction();
    return_error(PERROR_INVALID_SYNCID);
  }
  folderid=psync_get_number(row[0]);
  oldsynctype=psync_get_number(row[2]);
  if (oldsynctype==synctype){
    psync_sql_free_result(res);
    psync_sql_rollback_transaction();
    return 0;
  }
  if (unlikely_log(psync_stat(psync_get_string(row[1]), &st)) || unlikely_log(!psync_stat_isfolder(&st))){
    psync_sql_free_result(res);
    psync_sql_rollback_transaction();
    return_isyncid(PERROR_LOCAL_FOLDER_NOT_FOUND);
  }
  psync_sql_free_result(res);
  if (synctype&PSYNC_DOWNLOAD_ONLY)
    md=7;
  else
    md=5;
  if (unlikely_log(!psync_stat_mode_ok(&st, md))){
    psync_sql_rollback_transaction();
    return_isyncid(PERROR_LOCAL_FOLDER_ACC_DENIED);
  }
  if (folderid){
    res=psync_sql_query("SELECT permissions FROM folder WHERE id=?");
    if (unlikely_log(!res))
      return_isyncid(PERROR_DATABASE_ERROR);
    psync_sql_bind_uint(res, 1, folderid);
    urow=psync_sql_fetch_rowint(res);
    if (unlikely_log(!urow)){
      psync_sql_free_result(res);
      psync_sql_rollback_transaction();
      return_isyncid(PERROR_REMOTE_FOLDER_NOT_FOUND);
    }
    perms=urow[0];
    psync_sql_free_result(res);
  }
  else
    perms=PSYNC_PERM_ALL;
  if (unlikely_log((synctype&PSYNC_DOWNLOAD_ONLY && (perms&PSYNC_PERM_READ)!=PSYNC_PERM_READ) ||
      (synctype&PSYNC_UPLOAD_ONLY && (perms&PSYNC_PERM_WRITE)!=PSYNC_PERM_WRITE))){
    psync_sql_rollback_transaction();
    return_isyncid(PERROR_REMOTE_FOLDER_ACC_DENIED);
  }
  res=psync_sql_prep_statement("UPDATE syncfolder SET synctype=?, flags=0 WHERE id=?");
  psync_sql_bind_uint(res, 1, synctype);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_run_free(res);
  res=psync_sql_query("SELECT folderid FROM syncedfolder WHERE syncid=?");
  psync_sql_bind_uint(res, 1, syncid);
  while ((urow=psync_sql_fetch_rowint(res)))
    psync_del_folder_from_downloadlist(urow[0]);
  psync_sql_free_result(res);
  res=psync_sql_prep_statement("DELETE FROM syncedfolder WHERE syncid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_run_free(res);
  res=psync_sql_prep_statement("DELETE FROM localfile WHERE syncid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_run_free(res);
  res=psync_sql_prep_statement("DELETE FROM localfolder WHERE syncid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_run_free(res);
  psync_path_status_sync_delete(syncid);
  psync_sql_commit_transaction();
  psync_localnotify_del_sync(syncid);
  psync_stop_sync_download(syncid);
  psync_stop_sync_upload(syncid);
  psync_sql_sync();
  psync_path_status_reload_syncs();
  psync_syncer_new(syncid);
  return 0;
}

static void psync_delete_local_recursive(psync_syncid_t syncid, psync_folderid_t localfolderid){
  psync_sql_res *res;
  psync_uint_row row;
  res=psync_sql_query("SELECT id FROM localfolder WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  while ((row=psync_sql_fetch_rowint(res)))
    psync_delete_local_recursive(syncid, row[0]);
  psync_sql_free_result(res);
  res=psync_sql_prep_statement("DELETE FROM localfile WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_run_free(res);
  res=psync_sql_prep_statement("DELETE FROM localfolder WHERE id=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_run_free(res);
  if (psync_sql_affected_rows()){
    res=psync_sql_prep_statement("DELETE FROM syncedfolder WHERE localfolderid=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run_free(res);
  }
}

int psync_delete_sync(psync_syncid_t syncid){
  psync_sql_res *res;
  psync_sql_start_transaction();
/* this is slow and unneeded:
  psync_uint_row row;
  res=psync_sql_query("SELECT type, itemid, localitemid FROM task WHERE syncid=?");
  psync_sql_bind_uint(res, 1, syncid);
  while ((row=psync_sql_fetch_rowint(res)))
    if (row[0]==PSYNC_DOWNLOAD_FILE)
      psync_stop_file_download(row[1], syncid);
    else if (row[0]==PSYNC_UPLOAD_FILE)
      psync_delete_upload_tasks_for_file(row[2]);
  psync_sql_free_result(res);
  */
  psync_delete_local_recursive(syncid, 0);
  res=psync_sql_prep_statement("DELETE FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_run_free(res);
  if (psync_sql_commit_transaction())
    return -1;
  else{
    psync_stop_sync_download(syncid);
    psync_stop_sync_upload(syncid);
    psync_localnotify_del_sync(syncid);
    psync_restart_localscan();
    psync_sql_sync();
    psync_path_status_sync_delete(syncid);
    psync_path_status_reload_syncs();
    return 0;
  }
}

psync_folder_list_t *psync_get_sync_list(){
  return psync_list_get_list();
}

psuggested_folders_t *psync_get_sync_suggestions(){
  char *home;
  psuggested_folders_t *ret;
  home=psync_get_home_dir();
  if (likely_log(home)){
    ret=psync_scanner_scan_folder(home);
    psync_free(home);
    return ret;
  }
  else{
    psync_error=PERROR_NO_HOMEDIR;
    return NULL;
  }
}

pfolder_list_t *psync_list_local_folder_by_path(const char *localpath, psync_listtype_t listtype){
  return psync_list_local_folder(localpath, listtype);
}

pfolder_list_t *psync_list_remote_folder_by_path(const char *remotepath, psync_listtype_t listtype){
  psync_folderid_t folderid=psync_get_folderid_by_path(remotepath);
  if (folderid!=PSYNC_INVALID_FOLDERID)
    return psync_list_remote_folder(folderid, listtype);
  else
    return NULL;
}

pfolder_list_t *psync_list_remote_folder_by_folderid(psync_folderid_t folderid, psync_listtype_t listtype){
  return psync_list_remote_folder(folderid, listtype);
}

pentry_t *psync_stat_path(const char *remotepath){
  return psync_folder_stat_path(remotepath);
}

int psync_is_lname_to_ignore(const char *name, size_t namelen){
  const char *ign, *sc, *pt;
  char *namelower;
  unsigned char *lp;
  size_t ilen, off, pl;
  char buff[120];
  if (namelen>=sizeof(buff))
    namelower=(char *)psync_malloc(namelen+1);
  else
    namelower=buff;
  memcpy(namelower, name, namelen);
  namelower[namelen]=0;
  lp=(unsigned char *)namelower;
  while (*lp){
    *lp=tolower(*lp);
    lp++;
  }
  ign=psync_setting_get_string(_PS(ignorepatterns));
  ilen=strlen(ign);
  off=0;
  do {
    sc=(const char *)memchr(ign+off, ';', ilen-off);
    if (sc)
      pl=sc-ign-off;
    else
      pl=ilen-off;
    pt=ign+off;
    off+=pl+1;
    while (pl && isspace((unsigned char)*pt)){
      pt++;
      pl--;
    }
    while (pl && isspace((unsigned char)pt[pl-1]))
      pl--;
    if (psync_match_pattern(namelower, pt, pl)){
      if (namelower!=buff)
        psync_free(namelower);
      debug(D_NOTICE, "ignoring file/folder %s", name);
      return 1;
    }
  } while (sc);
  if (namelower!=buff)
    psync_free(namelower);
  return 0;
}

int psync_is_name_to_ignore(const char *name){
  return psync_is_lname_to_ignore(name, strlen(name));
}

static void psync_set_run_status(uint32_t status){
  psync_set_status(PSTATUS_TYPE_RUN, status);
  psync_set_uint_value("runstatus", status);
  psync_rebuild_icons();
}

int psync_pause(){
  psync_set_run_status(PSTATUS_RUN_PAUSE);
  return 0;
}

int psync_stop(){
  psync_set_run_status(PSTATUS_RUN_STOP);
  psync_timer_notify_exception();
  return 0;
}

int psync_resume(){
  psync_set_run_status(PSTATUS_RUN_RUN);
  return 0;
}

void psync_run_localscan(){
  psync_wake_localscan();
}

#define run_command_get_res(cmd, params, err, res) do_run_command_get_res(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam), err, res)

static int do_run_command_get_res(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt, char **err, binresult **pres){
  psync_socket *api;
  binresult *res;
  uint64_t result;
  api=psync_apipool_get();
  if (unlikely(!api))
    goto neterr;
  res=do_send_command(api, cmd, cmdlen, params, paramscnt, -1, 1);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_apipool_release_bad(api);
    goto neterr;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    debug(D_WARNING, "command %s returned code %u", cmd, (unsigned)result);
    if (err)
      *err=psync_strdup(psync_find_result(res, "error", PARAM_STR)->str);
    psync_process_api_error(result);
  }
  if (result)
    psync_free(res);
  else
    *pres=res;
  return (int)result;
neterr:
  if (err)
    *err=psync_strdup("Could not connect to the server.");
  return -1;
}

int psync_register(const char *email, const char *password, int termsaccepted, char **err){
  binparam params[]={P_STR("mail", email), P_STR("password", password), P_STR("termsaccepted", termsaccepted?"yes":"0"), P_NUM("os", P_OS_ID)};
  return psync_run_command("register", params, err);
}

int psync_verify_email(char **err){
  binparam params[]={P_STR("auth", psync_my_auth)};
  return psync_run_command("sendverificationemail", params, err);
}

int psync_lost_password(const char *email, char **err){
  binparam params[]={P_STR("mail", email)};
  return psync_run_command("lostpassword", params, err);
}

int psync_change_password(const char *currentpass, const char *newpass, char **err){
  char * device; int ret;binresult *res;
  device=psync_deviceid();
  {
    binparam params[]={P_STR("auth", psync_my_auth), P_STR("oldpassword", currentpass), P_STR("newpassword", newpass), P_STR("device", device), P_BOOL("regetauth", 1)};
    ret = run_command_get_res("changepassword", params, err, &res);
  }
  psync_free(device);
  if (ret)
    return ret;
  psync_strlcpy(psync_my_auth, psync_find_result(res, "auth", PARAM_STR)->str, sizeof(psync_my_auth));
  psync_free(res);
  return 0;
}

int psync_create_remote_folder_by_path(const char *path, char **err){
  binparam params[]={P_STR("auth", psync_my_auth), P_STR("path", path), P_STR("timeformat", "timestamp")};
  binresult *res;
  int ret;
  ret=run_command_get_res("createfolder", params, err, &res);
  if (ret)
    return ret;
  psync_ops_create_folder_in_db(psync_find_result(res, "metadata", PARAM_HASH));
  psync_free(res);
  psync_diff_wake();
  return 0;
}

int psync_create_remote_folder(psync_folderid_t parentfolderid, const char *name, char **err){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", parentfolderid), P_STR("name", name), P_STR("timeformat", "timestamp")};
  binresult *res;
  int ret;
  ret=run_command_get_res("createfolder", params, err, &res);
  if (ret)
    return ret;
  psync_ops_create_folder_in_db(psync_find_result(res, "metadata", PARAM_HASH));
  psync_free(res);
  psync_diff_wake();
  return 0;
}

const char *psync_get_auth_string(){
  return psync_my_auth;
}

int psync_get_bool_setting(const char *settingname){
  return psync_setting_get_bool(psync_setting_getid(settingname));
}

int psync_set_bool_setting(const char *settingname, int value){
  return psync_setting_set_bool(psync_setting_getid(settingname), value);
}

int64_t psync_get_int_setting(const char *settingname){
  return psync_setting_get_int(psync_setting_getid(settingname));
}

int psync_set_int_setting(const char *settingname, int64_t value){
  return psync_setting_set_int(psync_setting_getid(settingname), value);
}

uint64_t psync_get_uint_setting(const char *settingname){
  return psync_setting_get_uint(psync_setting_getid(settingname));
}

int psync_set_uint_setting(const char *settingname, uint64_t value){
  return psync_setting_set_uint(psync_setting_getid(settingname), value);
}

const char *psync_get_string_setting(const char *settingname){
  return psync_setting_get_string(psync_setting_getid(settingname));
}

int psync_set_string_setting(const char *settingname, const char *value){
  return psync_setting_set_string(psync_setting_getid(settingname), value);
}

int psync_has_value(const char *valuename){
  psync_sql_res *res;
  psync_uint_row row;
  int ret;
  res=psync_sql_query_rdlock("SELECT COUNT(*) FROM setting WHERE id=?");
  psync_sql_bind_string(res, 1, valuename);
  row=psync_sql_fetch_rowint(res);
  if (row)
    ret=row[0];
  else
    ret=0;
  psync_sql_free_result(res);
  return ret;
}

int psync_get_bool_value(const char *valuename){
  return !!psync_get_uint_value(valuename);
}

void psync_set_bool_value(const char *valuename, int value){
  psync_set_uint_value(valuename, (uint64_t)(!!value));
}

int64_t psync_get_int_value(const char *valuename){
  return (int64_t)psync_get_uint_value(valuename);
}

void psync_set_int_value(const char *valuename, int64_t value){
  psync_set_uint_value(valuename, (uint64_t)value);
}

uint64_t psync_get_uint_value(const char *valuename){
  psync_sql_res *res;
  psync_uint_row row;
  uint64_t ret;
  res=psync_sql_query_rdlock("SELECT value FROM setting WHERE id=?");
  psync_sql_bind_string(res, 1, valuename);
  row=psync_sql_fetch_rowint(res);
  if (row)
    ret=row[0];
  else
    ret=0;
  psync_sql_free_result(res);
  return ret;
}

void psync_set_uint_value(const char *valuename, uint64_t value){
  psync_sql_res *res;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_string(res, 1, valuename);
  psync_sql_bind_uint(res, 2, value);
  psync_sql_run_free(res);
}

char *psync_get_string_value(const char *valuename){
  psync_sql_res *res;
  psync_str_row row;
  char *ret;
  res=psync_sql_query_rdlock("SELECT value FROM setting WHERE id=?");
  psync_sql_bind_string(res, 1, valuename);
  row=psync_sql_fetch_rowstr(res);
  if (row)
    ret=psync_strdup(row[0]);
  else
    ret=NULL;
  psync_sql_free_result(res);
  return ret;
}

void psync_set_string_value(const char *valuename, const char *value){
  psync_sql_res *res;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_string(res, 1, valuename);
  psync_sql_bind_string(res, 2, value);
  psync_sql_run_free(res);
}

void psync_network_exception(){
  psync_timer_notify_exception();
}

static int create_request(psync_list_builder_t *builder, void *element, psync_variant_row row){
  psync_sharerequest_t *request;
  const char *str;
  uint32_t perms;
  size_t len;
  request=(psync_sharerequest_t *)element;
  request->sharerequestid=psync_get_number(row[0]);
  request->folderid=psync_get_number(row[1]);
  request->created=psync_get_number(row[2]);
  perms=psync_get_number(row[3]);
  request->userid=psync_get_number_or_null(row[4]);
  str=psync_get_lstring(row[5], &len);
  request->email=str;
  psync_list_add_lstring_offset(builder, offsetof(psync_sharerequest_t, email), len);
  str=psync_get_lstring(row[6], &len);
  request->sharename=str;
  psync_list_add_lstring_offset(builder, offsetof(psync_sharerequest_t, sharename), len);
  str=psync_get_lstring_or_null(row[7], &len);
  if (str){
    request->message=str;
    psync_list_add_lstring_offset(builder, offsetof(psync_sharerequest_t, message), len);
  }
  else{
    request->message="";
  }
  request->permissions=perms;
  request->canread=(perms&PSYNC_PERM_READ)/PSYNC_PERM_READ;
  request->cancreate=(perms&PSYNC_PERM_CREATE)/PSYNC_PERM_CREATE;
  request->canmodify=(perms&PSYNC_PERM_MODIFY)/PSYNC_PERM_MODIFY;
  request->candelete=(perms&PSYNC_PERM_DELETE)/PSYNC_PERM_DELETE;
  request->isba=psync_get_number(row[8]);
  return 0;
}

psync_sharerequest_list_t *psync_list_sharerequests(int incoming){
  psync_list_builder_t *builder;
  psync_sql_res *res;
  builder=psync_list_builder_create(sizeof(psync_sharerequest_t), offsetof(psync_sharerequest_list_t, sharerequests));
  incoming=!!incoming;
  res=psync_sql_query_rdlock("SELECT id, folderid, ctime, permissions, userid, mail, name, message, ifnull(isba, 0) FROM sharerequest WHERE isincoming=? ORDER BY name");
  psync_sql_bind_uint(res, 1, incoming);
  psync_list_bulder_add_sql(builder, res, create_request);
  return (psync_sharerequest_list_t *)psync_list_builder_finalize(builder);
}

static int create_share(psync_list_builder_t *builder, void *element, psync_variant_row row){
  psync_share_t *share;
  const char *str;
  uint32_t perms;
  size_t len;
  share=(psync_share_t *)element;
  share->shareid=psync_get_number(row[0]);
  share->folderid=psync_get_number(row[1]);
  share->created=psync_get_number(row[2]);
  perms=psync_get_number(row[3]);
  share->userid=psync_get_number(row[4]);
  if (row[5].type != PSYNC_TNULL) {
    str=psync_get_lstring(row[5], &len);
    share->toemail=str;
    psync_list_add_lstring_offset(builder, offsetof(psync_share_t, toemail), len);
  } else
    share->toemail = "";
  if (row[6].type != PSYNC_TNULL) {
    str=psync_get_lstring(row[6], &len);
    share->fromemail=str;
    psync_list_add_lstring_offset(builder, offsetof(psync_share_t, fromemail), len);
  } else
    share->fromemail = "";
  if (row[7].type != PSYNC_TNULL) {
    str=psync_get_lstring(row[7], &len);
    share->sharename=str;
    psync_list_add_lstring_offset(builder, offsetof(psync_share_t, sharename), len);
   } else
    share->sharename = "";
  share->permissions=perms;
  share->canread=(perms&PSYNC_PERM_READ)/PSYNC_PERM_READ;
  share->cancreate=(perms&PSYNC_PERM_CREATE)/PSYNC_PERM_CREATE;
  share->canmodify=(perms&PSYNC_PERM_MODIFY)/PSYNC_PERM_MODIFY;
  share->candelete=(perms&PSYNC_PERM_DELETE)/PSYNC_PERM_DELETE;
  share->canmanage=(perms&PSYNC_PERM_MANAGE)/PSYNC_PERM_MANAGE;
  if(psync_get_number(row[8]))
    share->isba = 1;
  else
    share->isba = 0;
  share->isteam = psync_get_number(row[9]);
  return 0;
}

psync_share_list_t *psync_list_shares(int incoming){
  psync_list_builder_t *builder;
  psync_sql_res *res;
  builder=psync_list_builder_create(sizeof(psync_share_t), offsetof(psync_share_list_t, shares));
  incoming=!!incoming;
  if (incoming) {
    res=psync_sql_query_rdlock("SELECT id, folderid, ctime, permissions, userid, ifnull(mail, ''), ifnull(mail, '') as frommail,name, ifnull(bsharedfolderid, 0), 0 FROM sharedfolder WHERE isincoming=1 AND id >= 0 "
                                " UNION ALL "
                                " select id, folderid, ctime, permissions, fromuserid as userid , "
                                " case when isteam = 1 then (select name from baccountteam where id = toteamid) "
                                "  else (select mail from baccountemail where id = touserid) end as mail, "
                                " (select mail from baccountemail where id = fromuserid) as frommail,"
                                " name, id as bsharedfolderid, 0 from bsharedfolder where isincoming = 1 "
                                " ORDER BY name;");
  psync_list_bulder_add_sql(builder, res, create_share);

  } else {
    res=psync_sql_query_rdlock("SELECT sf.id, sf.folderid, sf.ctime, sf.permissions, sf.userid, ifnull(sf.mail, ''), ifnull(sf.mail, '') as frommail, f.name as fname, ifnull(sf.bsharedfolderid, 0), 0 "
                                " FROM sharedfolder sf, folder f WHERE sf.isincoming=0 AND sf.id >= 0 and sf.folderid = f.id "
                                " UNION ALL "
                                " select bsf.id, bsf.folderid, bsf.ctime,  bsf.permissions, "
                                " case when bsf.isincoming = 0 and bsf.isteam = 1 then bsf.toteamid else bsf.touserid end as userid , "
                                " case when bsf.isincoming = 0 and bsf.isteam = 1 then (select name from baccountteam where id = bsf.toteamid) "
                                " else (select mail from baccountemail where id = bsf.touserid) end as mail, "
                                " (select mail from baccountemail where id = bsf.fromuserid) as frommail, "
                                " f.name as fname, bsf.id, bsf.isteam from bsharedfolder bsf, folder f where bsf.isincoming = 0 "
                                " and bsf.folderid = f.id ORDER BY fname ");
    psync_list_bulder_add_sql(builder, res, create_share);
  }

  return (psync_share_list_t *)psync_list_builder_finalize(builder);
}

static uint32_t convert_perms(uint32_t permissions){
  return
    (permissions&PSYNC_PERM_CREATE)/PSYNC_PERM_CREATE*1+
    (permissions&PSYNC_PERM_MODIFY)/PSYNC_PERM_MODIFY*2+
    (permissions&PSYNC_PERM_DELETE)/PSYNC_PERM_DELETE*4+
    (permissions&PSYNC_PERM_MANAGE)/PSYNC_PERM_MANAGE*8;
}

int psync_share_folder(psync_folderid_t folderid, const char *name, const char *mail, const char *message, uint32_t permissions, char **err){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_STR("mail", mail),
                     P_STR("message", message), P_NUM("permissions", convert_perms(permissions))};
  return psync_run_command("sharefolder", params, err);
}

int psync_account_teamshare(psync_folderid_t folderid, const char *name, psync_teamid_t teamid, const char *message, uint32_t permissions, char **err){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_NUM("teamid", teamid),
                     P_STR("message", message), P_NUM("permissions", convert_perms(permissions))};
  return psync_run_command("account_teamshare", params, err);
}

int psync_cancel_share_request(psync_sharerequestid_t requestid, char **err){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("sharerequestid", requestid)};
  return psync_run_command("cancelsharerequest", params, err);
}

int psync_decline_share_request(psync_sharerequestid_t requestid, char **err){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("sharerequestid", requestid)};
  return psync_run_command("declineshare", params, err);
}

int psync_accept_share_request(psync_sharerequestid_t requestid, psync_folderid_t tofolderid, const char *name, char **err){
  if (name){
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("sharerequestid", requestid), P_NUM("folderid", tofolderid), P_STR("name", name)};
    return psync_run_command("acceptshare", params, err);
  }
  else{
    binparam params[]={P_STR("auth", psync_my_auth), P_NUM("sharerequestid", requestid), P_NUM("folderid", tofolderid)};
    return psync_run_command("acceptshare", params, err);
  }
}

int psync_account_stopshare(psync_shareid_t shareid, char **err) {
  psync_shareid_t shareidarr[] = {shareid};
  debug(D_NOTICE, "shareidarr %lld", (long long)shareidarr[0]);
  int result =  do_psync_account_stopshare(shareidarr, 1, shareidarr, 1, err);
  return result;
}

int psync_remove_share(psync_shareid_t shareid, char **err){
  int result;
  char *err1 = NULL;
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("shareid", shareid)};
  result = psync_run_command("removeshare", params, err);
  if (result == 2025) {
    result = psync_account_stopshare(shareid, &err1);
    if(result == 2075) {
      result = 2025;
      psync_free(err1);
    } else {
      psync_free(*err);
      *err = err1;
    }
    debug(D_NOTICE, "erroris  %s", *err);
  }
  return result;
}

static int psync_account_modifyshare(psync_shareid_t shareid, uint32_t permissions, char **err) {
  psync_shareid_t shareidarr[] = {shareid};
  uint32_t permsarr[] = {permissions};
  debug(D_NOTICE, "shareidarr %lld", (long long)shareidarr[0]);
  int result =  do_psync_account_modifyshare(shareidarr, permsarr, 1, shareidarr, permsarr, 1, err);
  return result;
}

int psync_modify_share(psync_shareid_t shareid, uint32_t permissions, char **err){
  int result;
  char *err1 = NULL;
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("shareid", shareid), P_NUM("permissions", convert_perms(permissions))};
  result =  psync_run_command("changeshare", params, err);
  if (result == 2025) {
    result = psync_account_modifyshare(shareid, convert_perms(permissions), &err1);
    if(result == 2075) {
      result = 2025;
      psync_free(err1);
    } else {
      psync_free(*err);
      *err = err1;
    }
     debug(D_NOTICE, "erroris  %s", *err);
  }
  return result;
}

static unsigned long psync_parse_version(const char *currentversion){
  unsigned long cv, cm;
  cv=cm=0;
  while (1){
    if (*currentversion=='.'){
      cv=(cv+cm)*100;
      cm=0;
    }
    else if (*currentversion==0)
      return cv+cm;
    else if (*currentversion>='0' && *currentversion<='9')
      cm=cm*10+*currentversion-'0';
    else
      debug(D_WARNING, "invalid characters in version string: %s", currentversion);
    currentversion++;
  }
}

psync_new_version_t *psync_check_new_version_str(const char *os, const char *currentversion){
  return psync_check_new_version(os, psync_parse_version(currentversion));
}

static psync_new_version_t *psync_res_to_ver(const binresult *res, char *localpath){
  psync_new_version_t *ver;
  const char *notes, *versionstr;
  size_t lurl, lnotes, lversion, llpath, llocalpath;
  const binresult *cres, *pres, *hres;
  char *ptr;
  unsigned long usize;
  cres=psync_find_result(res, "download", PARAM_HASH);
  lurl=sizeof("https://")-1;
  pres=psync_find_result(cres, "path", PARAM_STR);
  lurl+=pres->length;
  hres=psync_find_result(cres, "hosts", PARAM_ARRAY)->array[0];
  lurl+=hres->length;
  lurl=(lurl+sizeof(void *))/sizeof(void *)*sizeof(void *);
  usize=psync_find_result(cres, "size", PARAM_NUM)->num;
  cres=psync_find_result(res, "notes", PARAM_STR);
  notes=cres->str;
  lnotes=(cres->length+sizeof(void *))/sizeof(void *)*sizeof(void *);
  cres=psync_find_result(res, "versionstr", PARAM_STR);
  versionstr=cres->str;
  lversion=(cres->length+sizeof(void *))/sizeof(void *)*sizeof(void *);
  if (localpath){
    llpath=strlen(localpath);
    llocalpath=(llpath+sizeof(void *))/sizeof(void *)*sizeof(void *);
  }
  else
    llpath=llocalpath=0;
  ver=(psync_new_version_t *)psync_malloc(sizeof(psync_new_version_t)+lurl+lnotes+lversion+llocalpath);
  ptr=(char *)(ver+1);
  ver->url=ptr;
  memcpy(ptr, "https://", sizeof("https://")-1);
  ptr+=sizeof("https://")-1;
  memcpy(ptr, hres->str, hres->length);
  ptr+=hres->length;
  memcpy(ptr, pres->str, pres->length+1);
  ptr=(char *)ver->url+lurl;
  memcpy(ptr, notes, lnotes);
  ver->notes=ptr;
  ptr+=lnotes;
  memcpy(ptr, versionstr, lversion);
  ver->versionstr=ptr;
  if (localpath){
    ptr+=lversion;
    memcpy(ptr, localpath, llpath+1);
    ver->localpath=ptr;
  }
  else
    ver->localpath=NULL;
  ver->version=psync_find_result(res, "version", PARAM_NUM)->num;
  ver->updatesize=usize;
  return ver;
}

psync_new_version_t *psync_check_new_version(const char *os, unsigned long currentversion){
  binparam params[]={P_STR("os", os), P_NUM("version", currentversion)};
  psync_new_version_t *ver;
  binresult *res;
  int ret;
  ret=run_command_get_res("getlastversion", params, NULL, &res);
  if (ret){
    debug(D_WARNING, "getlastversion returned %d", ret);
    return NULL;
  }
  if (!psync_find_result(res, "newversion", PARAM_BOOL)->num){
    psync_free(res);
    return NULL;
  }
  ver=psync_res_to_ver(res, NULL);
  psync_free(res);
  return ver;
}

static void psync_del_all_except(void *ptr, psync_pstat_fast *st){
  const char **nmarr;
  char *fp;
  nmarr=(const char **)ptr;
  if (!psync_filename_cmp(st->name, nmarr[1]) || st->isfolder)
    return;
  fp=psync_strcat(nmarr[0], PSYNC_DIRECTORY_SEPARATOR, st->name, NULL);
  debug(D_NOTICE, "deleting old update file %s", fp);
  if (psync_file_delete(fp))
    debug(D_WARNING, "could not delete %s", fp);
  psync_free(fp);
}

static char *psync_filename_from_res(const binresult *res){
  const char *nm;
  char *nmd, *path, *ret;
  const char *nmarr[2];
  nm=strrchr(psync_find_result(res, "path", PARAM_STR)->str, '/');
  if (unlikely_log(!nm))
    return NULL;
  path=psync_get_private_tmp_dir();
  if (unlikely_log(!path))
    return NULL;
  nmd=psync_url_decode(nm+1);
  nmarr[0]=path;
  nmarr[1]=nmd;
  psync_list_dir_fast(path, psync_del_all_except, (void *)nmarr);
  ret=psync_strcat(path, PSYNC_DIRECTORY_SEPARATOR, nmd, NULL);
  psync_free(nmd);
  psync_free(path);
  return ret;
}

static int psync_download_new_version(const binresult *res, char **lpath){
  const char *host;
  psync_http_socket *sock;
  char *buff, *filename;
  uint64_t size;
  psync_stat_t st;
  psync_file_t fd;
  int rd;
  char cookie[128];
  sock=psync_http_connect_multihost(psync_find_result(res, "hosts", PARAM_ARRAY), &host);
  if (unlikely_log(!sock))
    return -1;
  psync_slprintf(cookie, sizeof(cookie), "Cookie: dwltag=%s\015\012", psync_find_result(res, "dwltag", PARAM_STR)->str);
  if (unlikely_log(psync_http_request(sock, host, psync_find_result(res, "path", PARAM_STR)->str, 0, 0, cookie))){
    psync_http_close(sock);
    return -1;
  }
  if (unlikely_log(psync_http_next_request(sock))){
    psync_http_close(sock);
    return 1;
  }
  size=psync_find_result(res, "size", PARAM_NUM)->num;
  filename=psync_filename_from_res(res);
  if (unlikely_log(!filename)){
    psync_http_close(sock);
    return 1;
  }
  if (!psync_stat(filename, &st) && psync_stat_size(&st)==size){
    *lpath=filename;
    psync_http_close(sock);
    return 0;
  }
  if (unlikely_log((fd=psync_file_open(filename, P_O_WRONLY, P_O_CREAT|P_O_TRUNC))==INVALID_HANDLE_VALUE)){
    psync_free(filename);
    psync_http_close(sock);
    return 1;
  }
  buff=(char *)psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (size){
    rd=psync_http_request_readall(sock, buff, PSYNC_COPY_BUFFER_SIZE);
    if (unlikely_log(rd<=0 || psync_file_write(fd, buff, rd)!=rd))
      break;
    size-=rd;
  }
  psync_free(buff);
  psync_file_close(fd);
  psync_http_close(sock);
  if (unlikely_log(size)){
    psync_free(filename);
    return -1;
  }
  *lpath=filename;
  return 0;
}

psync_new_version_t *psync_check_new_version_download_str(const char *os, const char *currentversion){
  return psync_check_new_version_download(os, psync_parse_version(currentversion));
}

psync_new_version_t *psync_check_new_version_download(const char *os, unsigned long currentversion){
  binparam params[]={P_STR("os", os), P_NUM("version", currentversion)};
  psync_new_version_t *ver;
  binresult *res;
  char *lfilename;
  int ret;
  ret=run_command_get_res("getlastversion", params, NULL, &res);
  if (unlikely(ret==-1))
    do{
      debug(D_WARNING, "could not connect to server, sleeping");
      psync_milisleep(10000);
      ret=run_command_get_res("getlastversion", params, NULL, &res);
    } while (ret==-1);
  if (ret){
    debug(D_WARNING, "getlastversion returned %d", ret);
    return NULL;
  }
  if (!psync_find_result(res, "newversion", PARAM_BOOL)->num){
    psync_free(res);
    return NULL;
  }
  ret=psync_download_new_version(psync_find_result(res, "download", PARAM_HASH), &lfilename);
  if (unlikely(ret==-1))
    do{
      debug(D_WARNING, "could not download update, sleeping");
      psync_milisleep(10000);
      ret=psync_download_new_version(psync_find_result(res, "download", PARAM_HASH), &lfilename);
    } while (ret==-1);
  if (unlikely_log(ret)){
    psync_free(res);
    return NULL;
  }
  debug(D_NOTICE, "update downloaded to %s", lfilename);
  ver=psync_res_to_ver(res, lfilename);
  psync_free(lfilename);
  psync_free(res);
  return ver;
}

void psync_run_new_version(psync_new_version_t *ver){
  debug(D_NOTICE, "running %s", ver->localpath);
  if (psync_run_update_file(ver->localpath))
    return;
  psync_destroy();
  exit(0);
}

static int psync_upload_result(binresult *res, psync_fileid_t *fileid){
  uint64_t result;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (likely(!result)){
    const binresult *meta=psync_find_result(res, "metadata", PARAM_ARRAY)->array[0];
    *fileid=psync_find_result(meta, "fileid", PARAM_NUM)->num;
    psync_free(res);
    psync_diff_wake();
    return 0;
  }
  else{
    debug(D_WARNING, "uploadfile returned error %u: %s", (unsigned)result, psync_find_result(res, "error", PARAM_STR)->str);
    psync_free(res);
    psync_process_api_error(result);
    return result;
  }
}

static int psync_upload_params(binparam *params, size_t paramcnt, const void *data, size_t length, psync_fileid_t *fileid){
  psync_socket *api;
  binresult *res;
  int tries;
  tries=0;
  do {
    api=psync_apipool_get();
    if (unlikely(!api))
      break;
    if (likely(do_send_command(api, "uploadfile", strlen("uploadfile"), params, paramcnt, length, 0))){
      if (psync_socket_writeall(api, data, length)==length){
        res=get_result(api);
        if (likely(res)){
          psync_apipool_release(api);
          return psync_upload_result(res, fileid);
        }
      }
    }
    psync_apipool_release_bad(api);
  } while (++tries<=PSYNC_RETRY_REQUEST);
  psync_timer_notify_exception();
  return -1;
}

int psync_upload_data(psync_folderid_t folderid, const char *remote_filename, const void *data, size_t length, psync_fileid_t *fileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("filename", remote_filename), P_BOOL("nopartial", 1)};
  return psync_upload_params(params, ARRAY_SIZE(params), data, length, fileid);
}

int psync_upload_data_as(const char *remote_path, const char *remote_filename, const void *data, size_t length, psync_fileid_t *fileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_STR("path", remote_path), P_STR("filename", remote_filename), P_BOOL("nopartial", 1)};
  return psync_upload_params(params, ARRAY_SIZE(params), data, length, fileid);
}

static int psync_load_file(const char *local_path, char **data, size_t *length){
  psync_file_t fd;
  psync_stat_t st1, st2;
  char *buff;
  size_t len, off;
  ssize_t rd;
  int tries;
  for (tries=0; tries<15; tries++){
    fd=psync_file_open(local_path, P_O_RDONLY, 0);
    if (fd==INVALID_HANDLE_VALUE)
      goto err0;
    if (psync_fstat(fd, &st1))
      goto err1;
    len=psync_stat_size(&st1);
    buff=psync_malloc(len);
    if (!buff)
      goto err1;
    off=0;
    while (off<len){
      rd=psync_file_pread(fd, buff+off, len-off, off);
      if (rd<0)
        break;
      off+=rd;
    }
    psync_file_close(fd);
    if (off==len && !psync_stat(local_path, &st2) && psync_stat_size(&st2)==len && psync_stat_mtime_native(&st1)==psync_stat_mtime_native(&st2)){
      *data=buff;
      *length=len;
      return 0;
    }
    psync_free(buff);
  }
  return -1;
err1:
  psync_file_close(fd);
err0:
  return -1;
}

int psync_upload_file(psync_folderid_t folderid, const char *remote_filename, const char *local_path, psync_fileid_t *fileid){
  char *data;
  size_t length;
  int ret;
  if (psync_load_file(local_path, &data, &length))
    return -2;
  ret=psync_upload_data(folderid, remote_filename, data, length, fileid);
  psync_free(data);
  return ret;
}

int psync_upload_file_as(const char *remote_path, const char *remote_filename, const char *local_path, psync_fileid_t *fileid){
  char *data;
  size_t length;
  int ret;
  if (psync_load_file(local_path, &data, &length))
    return -2;
  ret=psync_upload_data_as(remote_path, remote_filename, data, length, fileid);
  psync_free(data);
  return ret;
}


int psync_password_quality(const char *password){
  uint64_t score=psync_password_score(password);
  if (score<(uint64_t)1<<30)
    return 0;
  if (score<(uint64_t)1<<40)
    return 1;
  else
    return 2;
}

int psync_password_quality10000(const char *password){
  uint64_t score=psync_password_score(password);
  if (score<(uint64_t)1<<30)
    return score/(((uint64_t)1<<30)/10000+1);
  if (score<(uint64_t)1<<40)
    return (score-((uint64_t)1<<30))/((((uint64_t)1<<40)-((uint64_t)1<<30))/10000+1)+10000;
  else{
    if (score>=((uint64_t)1<<45)-((uint64_t)1<<40))
      return 29999;
    else
      return (score-((uint64_t)1<<40))/((((uint64_t)1<<45)-((uint64_t)1<<40))/10000+1)+20000;
  }
}

char *psync_derive_password_from_passphrase(const char *username, const char *passphrase){
  return psync_ssl_derive_password_from_passphrase(username, passphrase);
}

int psync_crypto_setup(const char *password, const char *hint){
  if (psync_status_is_offline())
    return PSYNC_CRYPTO_SETUP_CANT_CONNECT;
  else
    return psync_cloud_crypto_setup(password, hint);
}

int psync_crypto_get_hint(char **hint){
  if (psync_status_is_offline())
    return PSYNC_CRYPTO_HINT_CANT_CONNECT;
  else
    return psync_cloud_crypto_get_hint(hint);
}

int psync_crypto_start(const char *password){
  return psync_cloud_crypto_start(password);
}

int psync_crypto_stop(){
  return psync_cloud_crypto_stop();
}

int psync_crypto_isstarted(){
  return psync_cloud_crypto_isstarted();
}

int psync_crypto_mkdir(psync_folderid_t folderid, const char *name, const char **err, psync_folderid_t *newfolderid){
  if (psync_status_is_offline())
    return PSYNC_CRYPTO_CANT_CONNECT;
  else
    return psync_cloud_crypto_mkdir(folderid, name, err, newfolderid);
}

int psync_crypto_issetup(){
  return psync_sql_cellint("SELECT value FROM setting WHERE id='cryptosetup'", 0);
}

int psync_crypto_hassubscription(){
  return psync_sql_cellint("SELECT value FROM setting WHERE id='cryptosubscription'", 0);
}

int psync_crypto_isexpired(){
  int64_t ce;
  ce=psync_sql_cellint("SELECT value FROM setting WHERE id='cryptoexpires'", 0);
  return ce?(ce<psync_timer_time()):0;
}

time_t psync_crypto_expires(){
  return psync_sql_cellint("SELECT value FROM setting WHERE id='cryptoexpires'", 0);
}

int psync_crypto_reset(){
  if (psync_status_is_offline())
    return PSYNC_CRYPTO_RESET_CANT_CONNECT;
  else
    return psync_cloud_crypto_reset();
}

psync_folderid_t psync_crypto_folderid(){
  int64_t id;
  id=psync_sql_cellint("SELECT id FROM folder WHERE parentfolderid=0 AND flags&"NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)"="NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)" LIMIT 1", 0);
  if (id)
    return id;
  id=psync_sql_cellint("SELECT f1.id FROM folder f1, folder f2 WHERE f1.parentfolderid=f2.id AND "
                       "f1.flags&"NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)"="NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)" AND "
                       "f2.flags&"NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)"=0 LIMIT 1", 0);
  if (id)
    return id;
  else
    return PSYNC_CRYPTO_INVALID_FOLDERID;
}

psync_folderid_t *psync_crypto_folderids(){
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t *ret;
  size_t alloc, l;
  alloc=2;
  l=0;
  ret=psync_new_cnt(psync_folderid_t, alloc);
  res=psync_sql_query_rdlock("SELECT f1.id FROM folder f1, folder f2 WHERE f1.parentfolderid=f2.id AND "
                             "f1.flags&"NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)"="NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)" AND "
                             "f2.flags&"NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)"=0");
  while ((row=psync_sql_fetch_rowint(res))){
    ret[l]=row[0];
    if (++l==alloc){
      alloc*=2;
      ret=(psync_folderid_t *)psync_realloc(ret, sizeof(psync_folderid_t)*alloc);
    }
  }
  psync_sql_free_result(res);
  ret[l]=PSYNC_CRYPTO_INVALID_FOLDERID;
  return ret;
}

external_status psync_filesystem_status(const char *path) {
  switch (psync_path_status_get_status(psync_path_status_get(path))) {
    case PSYNC_PATH_STATUS_IN_SYNC:
      return INSYNC;
    case PSYNC_PATH_STATUS_IN_PROG:
      return INPROG;
    case PSYNC_PATH_STATUS_PAUSED:
    case PSYNC_PATH_STATUS_REMOTE_FULL:
    case PSYNC_PATH_STATUS_LOCAL_FULL:
      return NOSYNC;
    default:
      return INVSYNC;
  }
}

external_status psync_status_file(const char *path) {
  return psync_filesystem_status(path);
}

external_status psync_status_folder(const char *path) {
  return psync_filesystem_status(path);
}

int64_t psync_file_public_link(const char *path, char **code /*OUT*/, char **err /*OUT*/) {
  int64_t ret = 0;
  do_psync_file_public_link(path, &ret, code, err, 0, 0, 0);
  return ret;
}

int64_t psync_screenshot_public_link(const char *path, int hasdelay, int64_t delay, char **code /*OUT*/, char **err /*OUT*/) {
  return do_psync_screenshot_public_link(path, hasdelay, delay, code, err);
}

int64_t psync_folder_public_link(const char *path, char **code /*OUT*/, char **err /*OUT*/) {
  return do_psync_folder_public_link(path, code, err, 0, 0, 0);
}

int64_t psync_tree_public_link(const char *linkname, const char *root, char **folders, int numfolders, char **files, int numfiles, char **code /*OUT*/, char **err /*OUT*/) {
  return do_psync_tree_public_link(linkname, root, folders, numfolders, files, numfiles, code, err,  0, 0, 0);
}

plink_info_list_t *psync_list_links(char **err /*OUT*/) {
  return do_psync_list_links(err);
}

plink_contents_t *psync_show_link(const char *code, char **err /*OUT*/) {
  return do_show_link(code, err);
}

int psync_delete_link(int64_t linkid, char **err /*OUT*/) {
  return do_psync_delete_link(linkid, err);
}

int64_t psync_upload_link(const char *path, const char *comment, char **code /*OUT*/, char **err /*OUT*/) {
  return do_psync_upload_link(path, comment, code, err, 0, 0, 0);
}

int psync_delete_upload_link(int64_t uploadlinkid, char **err /*OUT*/) {
  return do_psync_delete_upload_link(uploadlinkid, err);
}

int psync_delete_all_links_folder(psync_folderid_t folderid, char**err) {
  return do_delete_all_folder_links(folderid, err);
}
int psync_delete_all_links_file(psync_fileid_t fileid, char**err){
  return do_delete_all_file_links(fileid, err);
}


pcontacts_list_t *psync_list_contacts() {
  return do_psync_list_contacts();
}

pcontacts_list_t *psync_list_myteams() {
  return do_psync_list_myteams();
}

void psync_register_account_events_callback(paccount_cache_callback_t callback)
{
  do_register_account_events_callback(callback);
}

void psync_get_current_userid(psync_userid_t *ret) {
  psync_sql_res *res;
  psync_uint_row row;

  res = psync_sql_query_rdlock("SELECT value FROM setting WHERE id= 'userid' ");
  while ((row = psync_sql_fetch_rowint(res)))
    *ret = row[0];
  psync_sql_free_result(res);
}

void psync_get_folder_ownerid(psync_folderid_t folderid, psync_userid_t *ret) {
  psync_sql_res *res;
  psync_uint_row row;

  res=psync_sql_query_rdlock("SELECT userid FROM folder WHERE id=?");
  psync_sql_bind_uint(res, 1, folderid);
  while ((row=psync_sql_fetch_rowint(res)))
    *ret = row[0];
  psync_sql_free_result(res);
}

int psync_setlanguage(const char *language, char **err){
  binparam params[]={P_STR("language", language)};
  return psync_run_command("setlanguage", params, err);
}

void psync_fs_clean_read_cache(){
  psync_pagecache_clean_read_cache();
}

int psync_fs_move_cache(const char *path){
  return  psync_pagecache_move_cache(path);
}

char * psync_get_token()
{
  if (psync_my_auth[0])
    return psync_strdup(psync_my_auth);
  else return NULL;
}