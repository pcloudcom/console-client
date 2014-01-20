/* Copyright (c) 2013-2014 Anton Titov.
 * Copyright (c) 2013-2014 pCloud Ltd.
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

#include <string.h>
#include "pcallbacks.h"
#include "pcompat.h"
#include "plibs.h"
#include "plist.h"
#include "pfolder.h"

static pthread_mutex_t statusmutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t statuscond=PTHREAD_COND_INITIALIZER;
static uint32_t statuschanges=0;
static int statusthreadrunning=0;

static pthread_mutex_t eventmutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t eventcond=PTHREAD_COND_INITIALIZER;
static psync_list eventlist;
static int eventthreadrunning=0;

typedef struct {
  psync_list list;
  char *localpath;
  char *remotepath;
  char *name;
  psync_fileorfolderid_t remoteid;
  psync_eventtype_t event;
  psync_syncid_t syncid;
} event_list_t;

static void status_change_thread(void *ptr){
  pstatus_change_callback_t callback=(pstatus_change_callback_t)ptr;
  while (1){
    psync_milisleep(5);
    pthread_mutex_lock(&statusmutex);
    while (!statuschanges)
      pthread_cond_wait(&statuscond, &statusmutex);
    statuschanges=0;
    pthread_mutex_unlock(&statusmutex);
    if (!psync_do_run)
      break;
    callback(&psync_status);
  }
}

void psync_set_status_callback(pstatus_change_callback_t callback){
  psync_run_thread1(status_change_thread, callback);
  statusthreadrunning=1;
}

void psync_send_status_update(){
  if (statusthreadrunning){
    pthread_mutex_lock(&statusmutex);
    statuschanges++;
    pthread_mutex_unlock(&statusmutex);
    pthread_cond_signal(&statuscond);
  }
}

static void event_thread(void *ptr){
  pevent_callback_t callback=(pevent_callback_t)ptr;
  event_list_t *event;
  while (1){
    pthread_mutex_lock(&eventmutex);
    while (psync_list_isempty(&eventlist))
      pthread_cond_wait(&eventcond, &eventmutex);
    event=psync_list_remove_head_element(&eventlist, event_list_t, list);
    pthread_mutex_unlock(&eventmutex);
    if (!psync_do_run)
      break;
    callback(event->event, event->syncid, event->remoteid, event->name, event->localpath, event->remotepath);
    psync_free(event->localpath);
    psync_free(event->remotepath);
    psync_free(event);
  }
}

void psync_set_event_callback(pevent_callback_t callback){
  psync_list_init(&eventlist);
  psync_run_thread1(event_thread, callback);
  eventthreadrunning=1;
}

void psync_send_event_by_id(psync_eventtype_t eventid, psync_syncid_t syncid, const char *localpath, psync_fileorfolderid_t remoteid){
  if (eventthreadrunning){
    event_list_t *event;
    char *remotepath;
    if (eventid&PEVENT_TYPE_FOLDER)
      remotepath=psync_get_path_by_folderid(remoteid, NULL);
    else
      remotepath=psync_get_path_by_fileid(remoteid, NULL);
    if (unlikely_log(!remotepath))
      return;
    event=psync_new(event_list_t);
    event->localpath=psync_strdup(localpath);
    event->remotepath=remotepath;
    event->name=strrchr(remotepath, '/')+1;
    event->remoteid=remoteid;
    event->event=eventid;
    event->syncid=syncid;
    pthread_mutex_lock(&eventmutex);
    psync_list_add_head(&eventlist, &event->list);
    pthread_mutex_unlock(&eventmutex);
    pthread_cond_signal(&eventcond);
  }
}