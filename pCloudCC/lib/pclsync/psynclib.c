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
#include "pdevice_monitor.h"
#include "pfsfolder.h"
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include "ptools.h"
#include "papi.h"

//Variable containing UNIX time of the last backup file deleted event 
time_t lastBupDelEventTime = 0;
time_t bupNotifDelay = 300;

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
static time_t links_last_refresh_time;

extern int unlinked;
extern int tfa;

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

void psync_set_os_string(const char *str){
  debug(D_NOTICE, "setting os name to %s", str);
  psync_set_os_name(str);
}

static void psync_stop_crypto_on_sleep(){
  if (psync_setting_get_bool(_PS(sleepstopcrypto)) && psync_crypto_isstarted()){
    psync_cloud_crypto_stop();
    debug(D_NOTICE, "stopped crypto due to sleep");
  }
}

static void ssl_debug_cb(void *ctx, int level, const char *msg){
  debug(D_NOTICE, "%s", msg);
}

void psync_set_ssl_debug_callback(psync_ssl_debug_callback_t cb){
  if (cb){
    psync_ssl_set_log_threshold(PSYNC_SSL_DEBUG_LEVEL);
    psync_ssl_set_debug_callback(cb, NULL);
  }
  else{
    psync_ssl_set_log_threshold(0);
    psync_ssl_set_debug_callback(NULL, NULL);
  }
}

void psync_set_apiserver(const char* binapi, uint32_t locationid)
{
  if (binapi)
  {
  	psync_apipool_set_server(binapi);
  	psync_set_string_setting("api_server", binapi);
  	psync_set_int_setting("location_id", locationid);
  }
}

void psync_apiserver_init(){
  if (psync_setting_get_bool(_PS(saveauth)))
  {
    psync_set_apiserver(psync_setting_get_string(_PS(api_server)), psync_setting_get_uint(_PS(location_id)));
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
  if (PSYNC_SSL_DEBUG_LEVEL)
    psync_set_ssl_debug_callback(ssl_debug_cb);

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
  psync_apiserver_init();
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
  psync_devmon_init();
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

int psync_mark_notificaitons_read(uint32_t notificationid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("notificationid", notificationid)};
  return psync_run_command("readnotifications", params, NULL)?-1:0;
}

static void psync_invalidate_auth(const char *auth){
  binparam params[]={P_STR("auth", auth)};
  psync_run_command("logout", params, NULL);
}

void psync_logout2(uint32_t auth_status, int doinvauth){
  tfa=0;
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
  psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
  psync_restart_localscan();
  psync_timer_notify_exception();
  if (psync_fs_need_per_folder_refresh())
    psync_fs_refresh_folder(0);
}

void psync_logout(){
  psync_logout2(PSTATUS_AUTH_REQUIRED, 1);
}

apiservers_list_t *psync_get_apiservers(char **err)
{
	psync_socket *api;
	binresult *bres;
	psync_list_builder_t *builder;
	const binresult *locations = 0, *location, *br;
	const char *errorret;
	apiservers_list_t *ret;
	apiserver_info_t *plocation;
	uint64_t result;
	int i, locationscnt, usessl;
	binparam params[] = { P_STR("timeformat", "timestamp") };
	usessl = psync_setting_get_bool(_PS(usessl));
	api = psync_socket_connect(PSYNC_API_HOST, usessl ? PSYNC_API_PORT_SSL : PSYNC_API_PORT, usessl);

	if (unlikely(!api)) {
		debug(D_WARNING, "Can't get api from the pool. No pool ?\n");
		*err = psync_strndup("Can't get api from the pool.", 29);
		return NULL;
	}
	bres = send_command(api, "getlocationapi", params);
	if (likely(bres))
		psync_apipool_release(api);
	else {
		psync_apipool_release_bad(api);
		debug(D_WARNING, "Send command returned invalid result.\n");
		*err = psync_strndup("Connection error.", 17);
		return NULL;
	}
	result = psync_find_result(bres, "result", PARAM_NUM)->num;
	if (unlikely(result)) {
		errorret = psync_find_result(bres, "error", PARAM_STR)->str;
		*err = psync_strndup(errorret, strlen(errorret));
		debug(D_WARNING, "command getlocationapi returned error code %u", (unsigned)result);
		return NULL;
	}

	locations = psync_find_result(bres, "locations", PARAM_ARRAY);
	locationscnt = locations->length;
	if (!locationscnt){
		psync_free(bres);
		return NULL;
	}
	builder = psync_list_builder_create(sizeof(apiserver_info_t), offsetof(apiservers_list_t, entries));

	for (i = 0; i < locationscnt; ++i) {
		location = locations->array[i];
		plocation = (apiserver_info_t *)psync_list_bulder_add_element(builder);
		br = psync_find_result(location, "label", PARAM_STR);
		plocation->label = br->str;
		psync_list_add_lstring_offset(builder, offsetof(apiserver_info_t, label), br->length);
		br = psync_find_result(location, "api", PARAM_STR);
		plocation->api = br->str;
		psync_list_add_lstring_offset(builder, offsetof(apiserver_info_t, api), br->length);
		br = psync_find_result(location, "binapi", PARAM_STR);
		plocation->binapi = br->str;
		psync_list_add_lstring_offset(builder, offsetof(apiserver_info_t, binapi), br->length);
		plocation->locationid = psync_find_result(location, "id", PARAM_NUM)->num;
	}
	ret = (apiservers_list_t *)psync_list_builder_finalize(builder);
	ret->serverscnt = locationscnt;
	return ret;
}

void psync_reset_apiserver()
{
  psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
}

void psync_unlink(){
  psync_sql_res *res;
  char *deviceid;
  int ret;
  char* errMsg;

  deviceid=psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");
  debug(D_NOTICE, "unlink");

  psync_diff_lock();
  unlinked=1;
  tfa=0;
  psync_stop_all_download();
  psync_stop_all_upload();
  //Stop the root backup folder before unlinking the database. 0 means fetch the deviceid from local DB.
  psync_stop_device(0, &errMsg);

  psync_status_recalc_to_download();
  psync_status_recalc_to_upload();
  psync_invalidate_auth(psync_my_auth);
  psync_cloud_crypto_stop();
  psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
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
    psync_free(deviceid);
    debug(D_ERROR, "failed to close database, exiting");
    exit(1);
  }
  psync_pagecache_clean_cache();
  psync_sql_connect(psync_database);
  if (deviceid){
    res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES ('deviceid', ?)");
    psync_sql_bind_string(res, 1, deviceid);
    psync_sql_run_free(res);
    psync_free(deviceid);
  }
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

int psync_tfa_has_devices() {
  return psync_my_2fa_has_devices;
}

int psync_tfa_type() {
	return psync_my_2fa_type;
}

static void check_tfa_result(uint64_t result){
  if (result==2064){
    if (psync_status_get(PSTATUS_TYPE_AUTH)==PSTATUS_AUTH_TFAREQ){
      psync_free(psync_my_2fa_token);
      psync_my_2fa_token=NULL;
      psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
    }
  }
}

static char *binresult_to_str(const binresult *res){
  if (!res)
    return psync_strdup("field not found");
  if (res->type==PARAM_STR)
    return psync_strdup(res->str);
  else if (res->type==PARAM_NUM){
    char buff[32], *ptr;
    uint64_t n;
    ptr=buff+sizeof(buff);
    *--ptr=0;
    n=res->num;
    do {
      *--ptr='0'+n%10;
      n/=10;
    } while (n);
    return psync_strdup(ptr);
  }
  else{
    return psync_strdup("bad field type");
  }
}

int psync_tfa_send_sms(char **country_code, char **phone_number){
  if (country_code)
    *country_code=NULL;
  if (phone_number)
    *phone_number=NULL;
  if (!psync_my_2fa_token){
    return -2;
  }
  else{
    binresult *res;
    uint64_t code;
    binparam params[]={P_STR("token", psync_my_2fa_token)};
    res=psync_api_run_command("tfa_sendcodeviasms", params);
    if (!res)
      return -1;
    code=psync_find_result(res, "result", PARAM_NUM)->num;
    if (code){
      free(res);
      check_tfa_result(code);
      return code;
    }
    if (country_code || phone_number) {
      const binresult *cres=psync_find_result(res, "phonedata", PARAM_HASH);
      if (country_code)
        *country_code=binresult_to_str(psync_get_result(cres, "countrycode"));
      if (phone_number)
        *phone_number=binresult_to_str(psync_get_result(cres, "msisdn"));
    }
    free(res);
    return 0;
  }
}

int psync_tfa_send_nofification(plogged_device_list_t **devices_list){
  if (devices_list)
    *devices_list=NULL;
  if (!psync_my_2fa_token){
    return -2;
  }
  else{
    binresult *res;
    uint64_t code;
    binparam params[]={P_STR("token", psync_my_2fa_token)};
    res=psync_api_run_command("tfa_sendcodeviasysnotification", params);
    if (!res)
      return -1;
    code=psync_find_result(res, "result", PARAM_NUM)->num;
    if (code){
      free(res);
      check_tfa_result(code);
      return code;
    }
    if (devices_list){
      const binresult *cres=psync_find_result(res, "devices", PARAM_ARRAY);
      psync_list_builder_t *builder;
      uint32_t i;
      builder=psync_list_builder_create(sizeof(plogged_device_t), offsetof(plogged_device_list_t, devices));
      for (i=0; i<cres->length; i++){
        plogged_device_t *dev=(plogged_device_t *)psync_list_bulder_add_element(builder);
        const binresult *str=psync_find_result(cres->array[i], "name", PARAM_STR);
        dev->type=psync_find_result(cres->array[i], "type", PARAM_NUM)->num;
        dev->name=str->str;
        psync_list_add_lstring_offset(builder, offsetof(plogged_device_t, name), str->length);
      }
      *devices_list=(plogged_device_list_t *)psync_list_builder_finalize(builder);
    }
    free(res);
    return 0;
  }
}

plogged_device_list_t *psync_tfa_send_nofification_res(){
  plogged_device_list_t *devices_list;
  if (psync_tfa_send_nofification(&devices_list))
    return NULL;
  else
    return devices_list;
}

void psync_tfa_set_code(const char *code, int trusted, int is_recovery){
  strncpy(psync_my_2fa_code, code, sizeof(psync_my_2fa_code));
  psync_my_2fa_code[sizeof(psync_my_2fa_code)-1]=0;
  psync_my_2fa_trust=trusted;
  psync_my_2fa_code_type=is_recovery?2:1;
  psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
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

  debug(D_NOTICE, "Add sync by folder id localpath: [%s]", localpath);

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
  psync_restat_sync_folders_del(syncid);
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
    psync_restat_sync_folders_del(syncid);
    psync_restart_localscan();
    psync_sql_sync();
    psync_path_status_sync_delete(syncid);
    psync_path_status_reload_syncs();

    return 0;
  }
}

psync_folder_list_t *psync_get_sync_list(){
  return psync_list_get_list(PSYNC_STR_ALLSYNCS);
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

int psync_register(const char *email, const char *password, int termsaccepted, const char* binapi, unsigned int locationid, char **err){
  binresult *res;
  psync_socket *sock;
  uint64_t result;
  binparam params[]={P_STR("mail", email), P_STR("password", password), P_STR("termsaccepted", termsaccepted?"yes":"0"), P_NUM("os", P_OS_ID)};
  if (binapi)
    psync_set_apiserver(binapi, locationid);
  else {
    if (err)
      *err = psync_strdup("Could not connect to the server.");
	psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
    return -1;
  }
  sock = psync_api_connect(binapi, psync_setting_get_bool(_PS(usessl)));
  if (unlikely_log(!sock)){
	  if (err)
		  *err = psync_strdup("Could not connect to the server.");
	  psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
	  return -1;
  }
  res = send_command(sock, "register", params);
  if (unlikely_log(!res)){
	psync_socket_close(sock);
	if (err)
	  *err = psync_strdup("Could not connect to the server.");
	psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
	return -1;
  }
  result = psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
	debug(D_WARNING, "command register returned code %u", (unsigned)result);
    if (err)
	  *err = psync_strdup(psync_find_result(res, "error", PARAM_STR)->str);
	psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
  }
  psync_socket_close(sock);
  psync_free(res);
  return result;
}

int psync_verify_email(char **err){
  binparam params[]={P_STR("auth", psync_my_auth)};
  return psync_run_command("sendverificationemail", params, err);
}

int psync_verify_email_restricted(char **err){
	binparam params[] = { P_STR("verifytoken", psync_my_verify_token) };
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

int psync_reset_setting(const char *settingname){
  return psync_setting_reset(psync_setting_getid(settingname));
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
    res=psync_sql_query_rdlock("SELECT id, folderid, ctime, permissions, userid, ifnull(mail, ''), ifnull(mail, '') as frommail, name, ifnull(bsharedfolderid, 0), 0 FROM sharedfolder WHERE isincoming=1 AND id >= 0 "
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
                                " bsf.name as fname, bsf.id, bsf.isteam from bsharedfolder bsf, folder f where bsf.isincoming = 0 "
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
	  P_STR("message", message), P_NUM("permissions", convert_perms(permissions)), P_NUM("strictmode", 1)};
  return psync_run_command("sharefolder", params, err);
}

int psync_crypto_share_folder(psync_folderid_t folderid, const char *name, const char *mail, const char *message, uint32_t permissions, char *hint, char *temppass,  char **err){
  char *priv_key=NULL;
  char *signature=NULL;
  int change_err;

  if (!temppass){
  	binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_STR("mail", mail),
  		P_STR("message", message), P_NUM("permissions", convert_perms(permissions)), P_STR("hint", hint), P_NUM("strictmode", 1) };
  	return psync_run_command("sharefolder", params, err);
  }
  if ((change_err = psync_crypto_change_passphrase_unlocked(temppass, PSYNC_CRYPTO_FLAG_TEMP_PASS, &priv_key, &signature))){
	  return change_err;
  }
  {
    binparam params[] = { P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_STR("mail", mail),
      P_STR("message", message), P_NUM("permissions", convert_perms(permissions)), P_STR("hint", hint), P_STR("privatekey", priv_key),
      P_STR("signature", signature), P_NUM("strictmode", 1) };
    return psync_run_command("sharefolder", params, err);
  }
}

int psync_account_teamshare(psync_folderid_t folderid, const char *name, psync_teamid_t teamid, const char *message, uint32_t permissions, char **err){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_NUM("teamid", teamid),
                     P_STR("message", message), P_NUM("permissions", convert_perms(permissions))};
  return psync_run_command("account_teamshare", params, err);
}

int psync_crypto_account_teamshare(psync_folderid_t folderid, const char *name, psync_teamid_t teamid, const char *message, uint32_t permissions, char* hint, char *temppass, char **err){
	char *priv_key=NULL;
	char *signature=NULL;
	int change_err;

    if (!temppass){
		binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_NUM("teamid", teamid),
											 P_STR("message", message), P_NUM("permissions", convert_perms(permissions)), P_STR("hint", hint)};
		return psync_run_command("account_teamshare", params, err);
	}

	if ((change_err = psync_crypto_change_passphrase_unlocked(temppass, PSYNC_CRYPTO_FLAG_TEMP_PASS, &priv_key, &signature))){
	  return change_err;
	}

	{
		binparam params[] = { P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_NUM("teamid", teamid),
			P_STR("message", message), P_NUM("permissions", convert_perms(permissions)), P_STR("hint", hint),
			P_STR("privatekey", priv_key), P_STR("signature", signature) };
		return psync_run_command("account_teamshare", params, err);
	}
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

int check_new_version_on_us_socket(binresult **pres, const char *os, unsigned long currentversion){
	binparam params[] = { P_STR("os", os), P_NUM("version", currentversion) };
	psync_socket *api;
	binresult *res;
	int usessl;
	uint64_t result;

	usessl = psync_setting_get_bool(_PS(usessl));
	api = psync_socket_connect("binapi.pcloud.com", usessl ? PSYNC_API_PORT_SSL : PSYNC_API_PORT, usessl);
	if (unlikely(!api)) {
		return -1;
	}
	res = send_command(api, "getlastversion", params);
	if (likely(res))
		psync_apipool_release(api);
	else {
		psync_apipool_release_bad(api);
		return -1;
	}
	result = psync_find_result(res, "result", PARAM_NUM)->num;
	if (result){
		debug(D_WARNING, "command %s returned code %u", "getlastversion", (unsigned)result);
		psync_process_api_error(result);
	}
	if (result)
		psync_free(res);
	else
		*pres = res;
	return (int)result;
}

psync_new_version_t *psync_check_new_version(const char *os, unsigned long currentversion){
  binparam params[]={P_STR("os", os), P_NUM("version", currentversion)};
  psync_new_version_t *ver;
  binresult *res;
  int ret;
  ret = check_new_version_on_us_socket(&res,os,currentversion);
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
  if (!psync_filename_cmp(st->name, nmarr[1]) || psync_stat_fast_isfolder(st))
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
  psync_new_version_t *ver;
  binresult *res;
  char *lfilename;
  int ret;
  ret = check_new_version_on_us_socket(&res, os, currentversion);
  if (unlikely(ret==-1))
    do{
      debug(D_WARNING, "could not connect to server, sleeping");
      psync_milisleep(10000);
	  ret = check_new_version_on_us_socket(&res, os, currentversion);
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

int psync_crypto_change_crypto_pass(const char *oldpass, const char *newpass, const char *hint, const char *code){
  psync_socket *api;
  binresult *res;
  uint64_t result;
  int tries=0, err;
  char *priv_key=NULL;
  char *signature=NULL;

  if ((err = psync_crypto_change_passphrase(oldpass, newpass, 0, &priv_key, &signature))){
    return err;
  }
  {
    binparam params[] = { P_STR("auth", psync_my_auth), P_STR("privatekey", priv_key), P_STR("signature", signature), P_STR("hint", hint), P_STR("code", code) };
    debug(D_NOTICE, "uploading re-encoded private key");
    while (1){
    	api = psync_apipool_get();
    	if (!api)
    	  return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
    	res = send_command(api, "crypto_changeuserprivate", params);
    	if (unlikely_log(!res)){
    	  psync_apipool_release_bad(api);
    	  if (++tries > 5)
    	  	return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
    	}
    	else{
    	  psync_apipool_release(api);
    	  break;
    	}
    }
    result = psync_find_result(res, "result", PARAM_NUM)->num;
    psync_free(res);
    if (result != 0)
    	debug(D_WARNING, "crypto_changeuserprivate returned %u", (unsigned)result);
    if (result == 0){
    	psync_delete_cached_crypto_keys();
    	return PSYNC_CRYPTO_SETUP_SUCCESS;
    }
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_UNKNOWN_ERROR);
  }
}

int psync_crypto_change_crypto_pass_unlocked(const char *newpass, const char *hint, const char *code){
  psync_socket *api;
  binresult *res;
  uint64_t result;
  int tries = 0, err;
  char *priv_key = NULL;
  char *signature = NULL;


  if ((err = psync_crypto_change_passphrase_unlocked(newpass, 0, &priv_key, &signature))){
  	return err;
  }
  {
	binparam params[] = { P_STR("auth", psync_my_auth), P_STR("privatekey", priv_key), P_STR("signature", signature), P_STR("hint", hint), P_STR("code", code) };
	debug(D_NOTICE, "uploading re-encoded private key");
	while (1){
	  api = psync_apipool_get();
	  if (!api)
	  	return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
	  res = send_command(api, "crypto_changeuserprivate", params);
	  if (unlikely_log(!res)){
	  	psync_apipool_release_bad(api);
	  	if (++tries > 5)
	  	  return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
	  }
	  else{
	  	psync_apipool_release(api);
	  	break;
	  }
	}
	result = psync_find_result(res, "result", PARAM_NUM)->num;
	psync_free(res);
	if (result != 0)
		debug(D_WARNING, "crypto_changeuserprivate returned %u", (unsigned)result);
	if (result == 0){
		psync_delete_cached_crypto_keys();
		return PSYNC_CRYPTO_SETUP_SUCCESS;
	}
	return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_UNKNOWN_ERROR);
  }
}

int psync_crypto_crypto_send_change_user_private(){
  psync_socket *api;
  binresult *res;
  uint64_t result;
	binparam params[] = { P_STR("auth", psync_my_auth) };
	debug(D_NOTICE, "Requesting code for changing the private key password");
	api=psync_apipool_get();
	if (!api)
		return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
	res=send_command(api, "crypto_sendchangeuserprivate", params);
	if (unlikely_log(!res)){
		psync_apipool_release_bad(api);
		return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
	}
	else{
		psync_apipool_release(api);
	}
	result=psync_find_result(res, "result", PARAM_NUM)->num;
	psync_free(res);
	if (result!=0)
		debug(D_WARNING, "crypto_sendchangeuserprivate returned %u", (unsigned)result);
	if (result==0)
		return PSYNC_CRYPTO_SETUP_SUCCESS;
	return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_UNKNOWN_ERROR);
}

external_status psync_filesystem_status(const char *path){
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

int64_t psync_file_public_link(const char *path, char **link /*OUT*/, char **err /*OUT*/) {
  int64_t ret = 0;
  do_psync_file_public_link(path, &ret, link, err, 0, 0, 0);
  return ret;
}

int64_t psync_screenshot_public_link(const char *path, int hasdelay, int64_t delay, char **link /*OUT*/, char **err /*OUT*/) {
  return do_psync_screenshot_public_link(path, hasdelay, delay, link, err);
}

int64_t psync_folder_public_link(const char *path, char **link /*OUT*/, char **err /*OUT*/) {
  return do_psync_folder_public_link(path, link, err, 0, 0, 0);
}

int64_t psync_folder_public_link_full(const char *path, char **link /*OUT*/, char **err /*OUT*/,unsigned long long expire, int maxdownloads, int maxtraffic, const char* password) {
	return do_psync_folder_public_link_full(path, link, err, expire, maxdownloads, maxtraffic, password);
}

int psync_change_link(unsigned long long linkid, unsigned long long expire, int delete_expire,
  const char* linkpassword, int delete_password, unsigned long long maxtraffic, unsigned long long maxdownloads,
  int enableuploadforeveryone, int enableuploadforchosenusers, int disableupload, char** err)
{
	return do_psync_change_link(linkid,expire,delete_expire,
    linkpassword,delete_password,maxtraffic,maxdownloads,
    enableuploadforeveryone,enableuploadforchosenusers,disableupload,err);
}

int64_t psync_folder_updownlink_link(int canupload, unsigned long long folderid, const char* mail, char **err /*OUT*/) {
	return do_psync_folder_updownlink_link(canupload, folderid, mail, err);
}

int64_t psync_tree_public_link(const char *linkname, const char *root, char **folders, int numfolders, char **files, int numfiles, char **link /*OUT*/, char **err /*OUT*/) {
  return do_psync_tree_public_link(linkname, root, folders, numfolders, files, numfiles, link, err,  0, 0, 0);
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

int64_t psync_upload_link(const char *path, const char *comment, char **link /*OUT*/, char **err /*OUT*/) {
  return do_psync_upload_link(path, comment, link, err, 0, 0, 0);
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

void psync_cache_links_all()
{
	if (psync_current_time - links_last_refresh_time >= PSYNC_LINKS_REFRESH_INTERVAL){
	  links_last_refresh_time=psync_current_time;
	  cache_links_all();
	}
	else
		debug(D_WARNING, "refreshing link too early %u", (unsigned)psync_current_time - links_last_refresh_time);
}

preciever_list_t* psync_list_email_with_access(unsigned long long linkid, char** err)
{
  return do_list_email_with_access(linkid, err);
}

int psync_link_add_access(unsigned long long linkid, const char* mail, char** err)
{
  return do_link_add_access(linkid, mail, err);
}

int psync_link_remove_access(unsigned long long linkid, unsigned long long receiverid, char** err)
{
  return do_link_remove_access(linkid, receiverid, err);
}

bookmarks_list_t* psync_cache_bookmarks(char** err)
{
  return do_cache_bookmarks(err);
}

int psync_remove_bookmark(const char* code, int locationid, char** err)
{
  return do_remove_bookmark(code, locationid, err);
}

int psync_change_bookmark(const char* code, int locationid, const char* name, const char* description, char** err)
{
  return do_change_bookmark(code, locationid, name, description, err);
}

int psync_psync_change_link(unsigned long long linkid, unsigned long long expire, int delete_expire,
  const char* linkpassword, int delete_password, unsigned long long maxtraffic, unsigned long long maxdownloads,
  int enableuploadforeveryone, int enableuploadforchosenusers, int disableupload, char** err)
{
  return do_psync_change_link(linkid, expire, delete_expire, linkpassword, delete_password,
    maxtraffic, maxdownloads, enableuploadforeveryone, enableuploadforchosenusers, disableupload, err);
}
int psync_change_link_expire(unsigned long long linkid, unsigned long long expire, char** err)
{
  return do_change_link_expire(linkid, expire, err);
}

int psync_change_link_password(unsigned long long linkid, const char* password, char** err)
{
  return do_change_link_password(linkid, password, err);
}

int psync_change_link_enable_upload(unsigned long long linkid, int enableuploadforeveryone, int enableuploadforchosenusers, char** err)
{
  return do_change_link_enable_upload(linkid, enableuploadforeveryone, enableuploadforchosenusers, err);
}

pcontacts_list_t *psync_list_contacts() {
  return do_psync_list_contacts();
}

pcontacts_list_t *psync_list_myteams() {
  return do_psync_list_myteams();
}

void psync_register_account_events_callback(paccount_cache_callback_t callback){
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

char * psync_get_token(){
  if (psync_my_auth[0])
    return psync_strdup(psync_my_auth);
  else return NULL;
}

int psync_get_promo(char **url, uint64_t *width, uint64_t *height) {
  uint64_t result;
  binresult *res;
  binparam params[]={ P_STR("auth", psync_my_auth), P_NUM("os", P_OS_ID) };
  *url = 0;

  res = psync_api_run_command("getpromourl", params);

  if (unlikely_log(!res)){
	  return -1;
  }

  result = psync_find_result(res, "result", PARAM_NUM)->num;

  if (result){
    debug(D_WARNING, "getpromourl returned %d", (int)result);
    psync_free(res);
    return result;
  }

  if (!psync_find_result(res, "haspromo", PARAM_BOOL)->num) {
    psync_free(res);

    return result;
  }

  *url = psync_strdup(psync_find_result(res, "url", PARAM_STR)->str);

  if (!psync_find_result(res, "width", PARAM_NUM)->num) {
    debug(D_NOTICE, "Parameter width not found.");

    psync_free(res);
    return result;
  }

  *width = psync_find_result(res, "width", PARAM_NUM)->num;
  debug(D_NOTICE, "Promo window Width: [%llu]", *width);


  if (!psync_find_result(res, "height", PARAM_NUM)->num) {
    debug(D_NOTICE, "Parameter height not found.");

    psync_free(res);
    return result;
  }

  *height = psync_find_result(res, "height", PARAM_NUM)->num;
  debug(D_NOTICE, "Promo window Height: [%llu]", *height);

  psync_free(res);

  return 0;
}

psync_folderid_t psync_get_fsfolderid_by_path(const char *path, uint32_t *pflags, uint32_t *pPerm){
	return psync_fsfolderidperm_by_path(path, pflags, pPerm);
}

uint32_t psync_get_fsfolderflags_by_id(psync_folderid_t folderid, uint32_t *pPerm){
	return psync_fsfolderflags_by_id(folderid, pPerm);
}

uint64_t psync_crypto_priv_key_flags(){
  psync_sql_res *res;
  psync_uint_row row;
  uint64_t ret=0;
  res=psync_sql_query_rdlock_nocache("SELECT value FROM setting WHERE id='crypto_private_flags'");
  if((row=psync_sql_fetch_rowint(res))){
  	ret=row[0];
  	psync_sql_free_result(res);
  	return ret;
  }
  else
  	debug(D_NOTICE, "Can't read private key flags from the DB");
  psync_sql_free_result(res);
  return ret;
}

int psync_has_crypto_folders(){
  psync_sql_res *res;
  psync_uint_row row;
  uint64_t cnt=0;
  res=psync_sql_query_rdlock_nocache("SELECT count(*) FROM folder WHERE flags&"NTO_STR(PSYNC_FOLDER_FLAG_ENCRYPTED)"");
  if((row=psync_sql_fetch_rowint(res))){
  	cnt=row[0];
  }
  else
  	debug(D_NOTICE, "There are no crypto folders in the DB");
  psync_sql_free_result(res);
  return cnt>0;
}

void set_tfa_flag(int value){
  debug(D_NOTICE, "set tfa %u", value);
  tfa=value;
}

int psync_send_publink(const char *code, const char *mail, const char *message, char **err){
	binparam params[] = { P_STR("auth", psync_my_auth), P_STR("code", code), P_STR("mails", mail), P_STR("message", message), P_NUM("source", 1) };
	return psync_run_command("sendpublink", params, err);
}
/***********************************************************************************************************************************************/
int psync_is_folder_syncable(char*  localPath, 
                             char** errMsg) {
  psync_sql_res* sql;
  psync_str_row  srow;
  folderPath     folders;

  char* syncmp;
  const char* ignorePaths;

  int i;

  debug(D_NOTICE, "Check if folder is already synced. LocalPath [%s]", localPath);

  sql = psync_sql_query("SELECT localpath FROM syncfolder");

  if (unlikely_log(!sql)) {
    return_isyncid(PERROR_DATABASE_ERROR);
  }

  while ((srow = psync_sql_fetch_rowstr(sql))) {
    if (psync_str_is_prefix(srow[0], localPath)) {
      psync_sql_free_result(sql);

      *errMsg = psync_strdup("There is already an active sync or backup for a parent of this folder.");
      return PERROR_PARENT_OR_SUBFOLDER_ALREADY_SYNCING;
    }
    else if (!psync_filename_cmp(srow[0], localPath)) {
      psync_sql_free_result(sql);

      *errMsg = psync_strdup("There is already an active sync or backup for this folder.");
      return PERROR_FOLDER_ALREADY_SYNCING;
    }
  }
  psync_sql_free_result(sql);

  debug(D_NOTICE, "Check if folder is not on the Drive.");

  syncmp = psync_fs_getmountpoint();

  debug(D_NOTICE, "Mount point: [%s].", syncmp);
  if (syncmp) {
    size_t len = strlen(syncmp);

    debug(D_NOTICE, "Do check.");
    if (!psync_filename_cmpn(syncmp, localPath, len) && (localPath[len] == 0 || localPath[len] == '/' || localPath[len] == '\\')) {
      psync_free(syncmp);

      *errMsg = psync_strdup("Folder is located on pCloud drive.");
      return PERROR_LOCAL_IS_ON_PDRIVE;
    }
    psync_free(syncmp);
  }

  //Check if folder is not a child of an igrnored folder
  ignorePaths = psync_setting_get_string(_PS(ignorepaths));
  parse_os_path(ignorePaths, &folders, DELIM_SEMICOLON, 0);

  for (i = 0; i < folders.cnt; i++) {
    debug(D_NOTICE, "Check ignored folder: [%s]=[%s]", folders.folders[i], localPath);

    if (psync_left_str_is_prefix(folders.folders[i], localPath)) {
      *errMsg = psync_strdup("This folder is a child  of a folder in your ignore folders list.");
      return PERROR_PARENT_IS_IGNORED;
    }
  }

  return 0;
}
/***********************************************************************************************************************************************/
psync_folder_list_t* psync_get_syncs_bytype(const char* syncType) {
  debug(D_NOTICE, "Get syncs type: [%s]", syncType);

  return psync_list_get_list(syncType);
}
/***********************************************************************************************************************************************/
psync_folderid_t create_bup_mach_folder(char** msgErr) {
  binresult* rootFolIdObj;
  binresult* retData;

  psync_sql_res* sql;

  char  bRootFoName[64];
  char* tmpBuff;
  int   res = 0;

  tmpBuff = get_pc_name();
  psync_strlcpy(bRootFoName, tmpBuff, 64);

  free(tmpBuff);

  eventParams requiredParams = {
    3, //Number of parameters we are passing below.
    {
      P_STR("auth", psync_my_auth),
      P_STR("name", bRootFoName),
      P_NUM("os", P_OS_ID)
    }
  };

  eventParams optionalParams = {
    0
  };

  debug(D_NOTICE, "Call backend [backup/createdevice].");
  res = backend_call(apiserver,
                     "backup/createdevice",
                     FOLDER_META,
                     &requiredParams,
                     &optionalParams,
                     &retData,
                     msgErr);

  if (res == 0) {
    rootFolIdObj = psync_find_result(retData, "folderid", PARAM_NUM);

    //Store the root folder id in the local DB
    sql = psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES ('BackupRootFoId', ?)");
    psync_sql_bind_uint(sql, 1, rootFolIdObj->num);
    psync_sql_run_free(sql);

    free(retData);
  }

  return rootFolIdObj->num;
}
/***********************************************************************************************************************************************/
int psync_create_backup(char*  path, 
                        char** errMsg) {
  psync_folderid_t bFId;
  psync_syncid_t   syncFId;
  binresult*       folId;
  binresult*       retData;
  folderPath       folders;

  char*            optFolName;
  int   res = 0, oParCnt = 0;

  if (path[0] == 0) {
    *errMsg = strdup(PSYNC_BACKUP_PATH_EMPTY_MSG);

    return PSYNC_BACKUP_PATH_EMPTY_ERR;
  }

  res = psync_is_folder_syncable(path, errMsg);

  if (res != 0) {
    return res;
  }

  bFId = psync_sql_cellint("SELECT value FROM setting WHERE id='BackupRootFoId'", 0);

  if (bFId == 0) {
    retryRootCrt:
    bFId = create_bup_mach_folder(errMsg);
  }

  parse_os_path(path, &folders, DELIM_DIR, 1);

  if (folders.cnt > 1) {
    oParCnt = 1;
    optFolName = psync_strdup(folders.folders[folders.cnt - 2]);
  }
  else {
    oParCnt = 0;
    optFolName = psync_strdup("");
  }

  eventParams reqPar = {
    4, //Number of parameters we are passing below.
    {
      P_STR("auth", psync_my_auth),
      P_STR("name", folders.folders[folders.cnt - 1]),
      P_NUM("folderid", bFId),
      P_STR("timeformat", "timestamp")
    }
  };

  eventParams optPar = {
    oParCnt,
    {
      P_STR(PARENT_FOLDER_NAME, optFolName)
    }
  };

  debug(D_NOTICE, "Call backend [backup/createbackup].");

  res = backend_call(apiserver,
                     "backup/createbackup",
                     FOLDER_META,
                     &reqPar,
                     &optPar,
                     &retData,
                     errMsg);

  if (res == 0) {
    psync_diff_update_folder(retData);

    folId = psync_find_result(retData, FOLDER_ID, PARAM_NUM);

    syncFId = psync_add_sync_by_folderid(path, folId->num, PSYNC_BACKUPS);

    free(retData);

    if (syncFId < 0) {
      *errMsg = psync_strdup("Error creating backup.");
      return syncFId;
    }

    debug(D_NOTICE, "Created sync with id[%d].", syncFId);
  }
  else if(res == 2002) {
  // The backup folder for the machine was deleted for wathever reason. Delete the id stored in DB and create the new one.
    debug(D_NOTICE, "Backup folder id is not valid. Delete it and create a new one.");

    psync_sql_start_transaction();
    psync_sql_statement("DELETE FROM setting WHERE id='BackupRootFoId'");
    psync_sql_commit_transaction();

    goto retryRootCrt;
  }

  return res;
}
/***********************************************************************************************************************************************/
int psync_delete_backup(psync_syncid_t syncId,
                        char** errMsg) {
  binresult* retData;
  psync_sql_res* sqlRes;
  psync_uint_row row;
  psync_folderid_t folderId;

  int   res = 0;

  sqlRes = psync_sql_query_rdlock("SELECT folderid FROM syncfolder WHERE id = ?");

  psync_sql_bind_uint(sqlRes, 1, syncId);
  row = psync_sql_fetch_rowint(sqlRes);

  if (unlikely(!row)) {
    debug(D_ERROR, "Failed to find folder id for syncId: [%lld]", syncId);
    psync_sql_free_result(sqlRes);

    res = -1;
  }
  else{
    folderId = row[0];

    psync_sql_free_result(sqlRes);
  }
 
  if(res == 0) {
    eventParams reqPar = {
      2, //Number of parameters we are passing below.
      {
        P_STR("auth", psync_my_auth),
        P_NUM("folderid", folderId)
      }
    };

    eventParams optPar = {
      0
    };

    debug(D_NOTICE, "Call backend [backup/stopbackup].");

    res = backend_call(apiserver,
                       "backup/stopbackup",
                       NO_PAYLOAD,
                       &reqPar,
                       &optPar,
                       &retData,
                       errMsg);

    if (res == 0) {
      res = psync_delete_sync(syncId);
    }
  }

  debug(D_NOTICE, "Stop sync result: [%d].", res);
  
  return res;
}
/***********************************************************************************************************************************************/
void psync_stop_device(psync_folderid_t folderId,
                      char**           errMsg) {
  binresult* retData;
  psync_folderid_t bFId;
  int   res = 0;

  if (folderId == 0) {
    bFId = psync_sql_cellint("SELECT value FROM setting WHERE id='BackupRootFoId'", 0);
  }
  else {
    bFId = folderId;
  }

  if(bFId > 0) {
    eventParams reqPar = {
      2, //Number of parameters we are passing below.
      {
        P_STR("auth", psync_my_auth),
        P_NUM("folderid", bFId)
      }
    };

    eventParams optPar = {
      0
    };

    debug(D_NOTICE, "Call backend [backup/stopdevice].");

    res = backend_call(apiserver,
                       "backup/stopdevice",
                       NO_PAYLOAD,
                       &reqPar,
                       &optPar,
                       &retData,
                       errMsg);

    if (res != 0) {
      debug(D_ERROR, "Failed to stop device in the backend Message: [%s].", *errMsg);
    }
  }
  else {
    debug(D_ERROR, "Can't find device id in local DB.");
  }
}
/***********************************************************************************************************************************************/
char* get_backup_root_name() {
  return psync_sql_cellstr("SELECT name FROM setting s JOIN folder f ON s.value = f.id AND s.id = 'BackupRootFoId'");
}
/***********************************************************************************************************************************************/
char* get_pc_name() {
  return get_machine_name();
}
/***********************************************************************************************************************************************/
void psync_async_delete_sync(void* ptr) {
  psync_syncid_t syncId = (psync_syncid_t*)ptr;
  int res;

  res = psync_delete_sync(syncId);

  debug(D_NOTICE, "Backup stopped on the Web.");

  if (res == 0) {
    psync_send_eventid(PEVENT_BACKUP_STOP);
  }
}
/***********************************************************************************************************************************************/
void psync_async_ui_callback(void* ptr) {
  int eventId = (int*)ptr;
  time_t currTime = psync_time();

  if (((currTime - lastBupDelEventTime) > bupNotifDelay) || (lastBupDelEventTime == 0)) {
    debug(D_NOTICE, "Send event to UI. Event id: [%d]", eventId);

    psync_send_eventid(eventId);

    lastBupDelEventTime = currTime;
  }
}
/***********************************************************************************************************************************************/
int psync_delete_sync_by_folderid(psync_folderid_t fId) {
  psync_sql_res* sqlRes;
  psync_uint_row row;

  psync_syncid_t* syncId;
  psync_syncid_t* syncIdT;

  sqlRes = psync_sql_query_nolock("SELECT id FROM syncfolder WHERE folderid = ?");
  psync_sql_bind_uint(sqlRes, 1, fId);
  row = psync_sql_fetch_rowint(sqlRes);

  if (unlikely(!row)) {
    debug(D_ERROR, "Sync to delete not found!");
    psync_sql_free_result(sqlRes);

    return -1;
  }

  syncId = row[0];
  
  psync_sql_free_result(sqlRes);

  syncIdT = psync_new(psync_syncid_t);
  syncIdT = syncId;

  psync_run_thread1("psync_async_sync_delete", psync_async_delete_sync, syncIdT);

  return 0;
}
/***********************************************************************************************************************************************/
int psync_delete_backup_device(psync_folderid_t fId) {
  psync_folderid_t bFId;

  debug(D_NOTICE, "Check if the local device was stopped. Id: [%lld]", fId);

  bFId = psync_sql_cellint("SELECT value FROM setting WHERE id='BackupRootFoId'", 0);

  if (bFId == fId) {
    psync_sql_start_transaction();

    psync_sql_statement("DELETE FROM setting WHERE id='BackupRootFoId'");

    psync_sql_commit_transaction();
  }
  else {
    debug(D_NOTICE, "Stop for different device. Id: [%lld]", bFId);
  }

  return 1;
}
/***********************************************************************************************************************************************/
void psync_send_backup_del_event(psync_fileorfolderid_t remoteFId) {
  time_t currTime = psync_time();
  
  if (((currTime - lastBupDelEventTime) > bupNotifDelay) || (lastBupDelEventTime == 0)) {
    if (remoteFId == 0) {
      psync_send_eventid(PEVENT_BKUP_F_DEL_NOTSYNCED);
    }
    else {
      psync_send_eventid(PEVENT_BKUP_F_DEL_SYNCED);
    }

    lastBupDelEventTime = currTime;
  }
}
/***********************************************************************************************************************************************/
userinfo_t* psync_get_userinfo()
{
  if (psync_my_auth[0]) {
    size_t lemail, lcurrency, llanguage;
    const char* email, * currency, * language;
    const binresult* cres;
    char* ptr;
    binresult* res;
    uint64_t err;
    userinfo_t *info;
    binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp") };
    res = psync_api_run_command("userinfo", params);
    if (!res) {
      psync_free(res);
      return NULL;
    }
    err = psync_find_result(res, "result", PARAM_NUM)->num;
    if (err)
    {
      psync_free(res);
      return NULL;
    }

    cres = psync_find_result(res, "email", PARAM_STR);
    email = cres->str;
    lemail = (cres->length + sizeof(void*)) / sizeof(void*) * sizeof(void*);
    cres = psync_find_result(res, "currency", PARAM_STR);
    currency = cres->str;
    lcurrency = (cres->length + sizeof(void*)) / sizeof(void*) * sizeof(void*);
    cres = psync_find_result(res, "language", PARAM_STR);
    language = cres->str;
    llanguage = (cres->length + sizeof(void*)) / sizeof(void*) * sizeof(void*);
    info = (userinfo_t*)psync_malloc(sizeof(userinfo_t) + lemail + lcurrency + llanguage);
    ptr = (char*)(info + 1);
    memcpy(ptr, email, lemail);
    info->email = ptr;
    ptr += lemail;
    memcpy(ptr, currency, lcurrency);
    info->currency = ptr;
    ptr += lcurrency;
    memcpy(ptr, language, llanguage);
    info->language = ptr;

    info->cryptosetup = psync_find_result(res, "cryptosetup", PARAM_BOOL)->num;
    info->cryptosubscription = psync_find_result(res, "cryptosubscription", PARAM_BOOL)->num;
    info->cryptolifetime = psync_find_result(res, "cryptolifetime", PARAM_BOOL)->num;
    info->emailverified = psync_find_result(res, "emailverified", PARAM_BOOL)->num;
    info->usedpublinkbranding = psync_find_result(res, "usedpublinkbranding", PARAM_BOOL)->num;
    info->haspassword = psync_find_result(res, "haspassword", PARAM_BOOL)->num;
    info->premium = psync_find_result(res, "premium", PARAM_BOOL)->num;
    info->premiumlifetime = psync_find_result(res, "premiumlifetime", PARAM_BOOL)->num;
    info->business = psync_find_result(res, "business", PARAM_BOOL)->num;
    info->haspaidrelocation = psync_find_result(res, "haspaidrelocation", PARAM_BOOL)->num;
    cres = psync_check_result(res, "efh", PARAM_BOOL);
    if (cres) info->efh = cres->num;
    else info->efh = 0;
    cres = psync_check_result(res, "premiumexpires", PARAM_NUM);
    if (cres) info->premiumexpires = cres->num;
    else info->premiumexpires = 0;
    info->trashrevretentiondays = psync_find_result(res, "trashrevretentiondays", PARAM_NUM)->num;
    info->plan = psync_find_result(res, "plan", PARAM_NUM)->num;
    info->publiclinkquota = psync_find_result(res, "publiclinkquota", PARAM_NUM)->num;
    info->userid = psync_find_result(res, "userid", PARAM_NUM)->num;
    info->quota = psync_find_result(res, "quota", PARAM_NUM)->num;
    info->usedquota = psync_find_result(res, "usedquota", PARAM_NUM)->num;
    info->freequota = psync_find_result(res, "freequota", PARAM_NUM)->num;
    info->registered = psync_find_result(res, "registered", PARAM_NUM)->num;
    psync_free(res);
    return info;
  }

  return NULL;
}

int psync_create_backend_event(const char* category, const char* action, const char* label, eventParams params, char *err)
{
  time_t rawtime;
  time(&rawtime);
  return create_backend_event(apiserver, category, action, label, psync_my_auth, P_OS_ID, rawtime, &params, &err);
}
/******************************************************************************************************************/
void psync_init_data_event_handler(void* ptr) {
  psync_init_data_event(ptr);
}
/******************************************************************************************************************/