/* Copyright (c) 2015 Anton Titov.
 * Copyright (c) 2015 pCloud Ltd.
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

#include "pnotifications.h"
#include "psettings.h"
#include "ptimer.h"
#include "plibs.h"
#include "pnetlibs.h"

static char *ntf_thumb_size=NULL;
static pnotification_callback_t ntf_callback=NULL;
static pthread_mutex_t ntf_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ntf_cond=PTHREAD_COND_INITIALIZER;
static int ntf_thread_running=0;
static binresult *ntf_result=NULL;
static binresult *ntf_processed_result=NULL;

int psync_notifications_running(){
  return ntf_thread_running;
}

const char *psync_notifications_get_thumb_size(){
  return ntf_thumb_size;
}

void psync_notifications_notify(binresult *res){
  pthread_mutex_lock(&ntf_mutex);
  if (ntf_result)
    psync_free(ntf_result);
  ntf_result=res;
  pthread_cond_signal(&ntf_cond);
  pthread_mutex_unlock(&ntf_mutex);
}

static void psync_notifications_download_thumb(const binresult *thumb, const char *thumbpath){
  const char *path, *filename, *host;
  char *filepath, *tmpfilepath, *buff;
  psync_http_socket *sock;
  psync_stat_t st;
  psync_file_t fd;
  int rd;
  rd=-1;
  path=psync_find_result(thumb, "path", PARAM_STR)->str;
  filename=strrchr(path, '/');
  if (unlikely_log(!filename++))
    return;
  filepath=psync_strcat(thumbpath, PSYNC_DIRECTORY_SEPARATOR, filename, NULL);
  if (!psync_stat(filepath, &st)){
    debug(D_NOTICE, "skipping download of %s as it already exists", filename);
    goto err0;
  }
  tmpfilepath=psync_strcat(filepath, ".part", NULL);
  debug(D_NOTICE, "downloading thumbnail %s", filename);
  if (unlikely_log((fd=psync_file_open(tmpfilepath, P_O_WRONLY, P_O_CREAT|P_O_TRUNC))==INVALID_HANDLE_VALUE))
    goto err1;
  sock=psync_http_connect_multihost(psync_find_result(thumb, "hosts", PARAM_ARRAY), &host);
  if (unlikely_log(!sock))
    goto err2;
  if (unlikely_log(psync_http_request(sock, host, path, 0, 0)))
    goto err3;
  if (unlikely_log(psync_http_next_request(sock)))
    goto err3;
  buff=(char *)psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (1){
    rd=psync_http_request_readall(sock, buff, PSYNC_COPY_BUFFER_SIZE);
    if (rd<=0)
      break;
    if (psync_file_write(fd, buff, rd)!=rd)
      break;
  }
  psync_free(buff);
err3:
  psync_http_close(sock);
err2:
  psync_file_close(fd);
err1:
  if (rd==0 && !psync_file_rename_overwrite(tmpfilepath, filepath))
    debug(D_NOTICE, "downloaded thumbnail %s", filename);
  else
    debug(D_WARNING, "downloading of thumbnail %s failed", filename);
  psync_free(tmpfilepath);
err0:
  psync_free(filepath);
}

static void psync_notifications_set_current_list(binresult *res, const char *thumbpath){
  binresult *ores;
  const binresult *notifications, *thumb;
  pnotification_callback_t cb;
  uint32_t cntnew, cnttotal, i;
  notifications=psync_find_result(res, "notifications", PARAM_ARRAY);
  cnttotal=notifications->length;
  debug(D_NOTICE, "got list with %u notifications", (unsigned)cnttotal);
  cntnew=0;
  for (i=0; i<cnttotal; i++){
    if (psync_find_result(notifications->array[i], "isnew", PARAM_BOOL)->num)
      cntnew++;
    thumb=psync_check_result(notifications->array[i], "thumb", PARAM_HASH);
    if (thumb && thumbpath)
      psync_notifications_download_thumb(thumb, thumbpath);
  }
  pthread_mutex_lock(&ntf_mutex);
  ores=ntf_processed_result;
  ntf_processed_result=res;
  cb=ntf_callback;
  pthread_mutex_unlock(&ntf_mutex);
  psync_free(ores);
  if (cb){
    debug(D_NOTICE, "calling notification callback, cnt=%u, newcnt=%u", (unsigned)cnttotal, (unsigned)cntnew);
    cb(cnttotal, cntnew);
  }
}

static void psync_notifications_thread(){
  char *thumbpath;
  binresult *res;
  time_t ctime, lastnotify, mininterval;
  lastnotify=0;
  mininterval=30;
  thumbpath=psync_get_private_dir(PSYNC_DEFAULT_NTF_THUMB_DIR);
  while (psync_do_run){
    pthread_mutex_lock(&ntf_mutex);
    if (unlikely(!ntf_callback)){
      ntf_thread_running=0;
      pthread_mutex_unlock(&ntf_mutex);
      break;
    }
    while (!ntf_result)
      pthread_cond_wait(&ntf_cond, &ntf_mutex);
    ctime=psync_timer_time();
    if (ctime<lastnotify+mininterval){
      pthread_mutex_unlock(&ntf_mutex);
      debug(D_NOTICE, "sleeping %u seconds to throttle notifications", (unsigned)(lastnotify+mininterval-ctime+1));
      psync_milisleep((lastnotify+mininterval-ctime+1)*1000);
      if (mininterval<5*60)
        mininterval*=2;
      pthread_mutex_lock(&ntf_mutex);
    }
    else
      mininterval=30;
    res=ntf_result;
    ntf_result=NULL;
    pthread_mutex_unlock(&ntf_mutex);
    lastnotify=ctime;
    psync_notifications_set_current_list(res, thumbpath);
  }
  psync_free(thumbpath);
}

void psync_notifications_set_callback(pnotification_callback_t notification_callback, const char *thumbsize){
  char *ts;
  pthread_mutex_lock(&ntf_mutex);
  ts=ntf_thumb_size;
  if (thumbsize)
    ntf_thumb_size=psync_strdup(thumbsize);
  else
    ntf_thumb_size=NULL;
  if (ts)
    psync_free_after_sec(ts, 10);
  ntf_callback=notification_callback;
  if (!ntf_thread_running && notification_callback){
    ntf_thread_running=1;
    psync_run_thread("notifications", psync_notifications_thread);
  }
  pthread_mutex_unlock(&ntf_mutex);
}

static void fill_actionid(const binresult *ntf, psync_notification_t *pntf){
  const char *action;
  action=psync_find_result(ntf, "action", PARAM_STR)->str;
  if (!strcmp(action, "gotofolder")){
    pntf->actionid=PNOTIFICATION_ACTION_GO_TO_FOLDER;
    pntf->actiondata.folderid=psync_find_result(ntf, "folderid", PARAM_NUM)->num;
  }
  else
    pntf->actionid=PNOTIFICATION_ACTION_NONE;
}

psync_notification_list_t *psync_notifications_get(){
  psync_list_builder_t *builder;
  psync_notification_list_t *res;
  const binresult *ntf_res, *notifications, *ntf, *br;
  const char *filename;
  char *thumbpath, *filepath;
  psync_notification_t *pntf;
  psync_stat_t st;
  uint32_t cntnew, cnttotal, i;
  cntnew=0;
  thumbpath=NULL;
  thumbpath=psync_get_private_dir(PSYNC_DEFAULT_NTF_THUMB_DIR);
  builder=psync_list_builder_create(sizeof(psync_notification_t), offsetof(psync_notification_list_t, notifications));
  pthread_mutex_lock(&ntf_mutex);
  if (ntf_processed_result)
    ntf_res=ntf_processed_result;
  else if (ntf_result){
    ntf_res=ntf_result;
    debug(D_NOTICE, "using not processed result for now");
  }
  else
    ntf_res=NULL;
  if (ntf_res){
    notifications=psync_find_result(ntf_res, "notifications", PARAM_ARRAY);
    cnttotal=notifications->length;
    for (i=0; i<cnttotal; i++){
      ntf=notifications->array[i];
      pntf=(psync_notification_t *)psync_list_bulder_add_element(builder);
      br=psync_find_result(ntf, "notification", PARAM_STR);
      pntf->text=br->str;
      psync_list_add_lstring_offset(builder, offsetof(psync_notification_t, text), br->length);
      pntf->thumb=NULL;
      br=psync_check_result(ntf, "thumb", PARAM_HASH);
      if (br && thumbpath){
        filename=strrchr(psync_find_result(br, "path", PARAM_STR)->str, '/');
        if (filename++){
          filepath=psync_strcat(thumbpath, PSYNC_DIRECTORY_SEPARATOR, filename, NULL);
          if (!psync_stat(filepath, &st)){
            pntf->thumb=filepath;
            psync_list_add_string_offset(builder, offsetof(psync_notification_t, thumb));
          }
          else
            debug(D_WARNING, "could not stat thumb %s which supposed to be downloaded", filename);
          psync_free(filepath);
        }
      }
      pntf->mtime=psync_find_result(ntf, "mtime", PARAM_NUM)->num;
      pntf->notificationid=psync_find_result(ntf, "notificationid", PARAM_NUM)->num;
      pntf->isnew=psync_find_result(ntf, "isnew", PARAM_BOOL)->num;
      if (pntf->isnew)
        cntnew++;
      pntf->iconid=psync_find_result(ntf, "iconid", PARAM_NUM)->num;
      fill_actionid(ntf, pntf);
    }
  }
  pthread_mutex_unlock(&ntf_mutex);
  psync_free(thumbpath);
  res=(psync_notification_list_t *)psync_list_builder_finalize(builder);
  res->newnotificationcnt=cntnew;
  return res;
}
