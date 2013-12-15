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

#include "pcallbacks.h"
#include "pcompat.h"
#include "plibs.h"
#include <pthread.h>

static pthread_mutex_t statusmutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t statuscond=PTHREAD_COND_INITIALIZER;
static uint32_t statuschanges=0;

static int statusthreadrunning=0;

static void status_change_thread(void *ptr){
  pstatus_change_callback_t callback=(pstatus_change_callback_t)ptr;
  psync_milisleep(5);
  while (1){
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
    /* I don't see a race or any kind of problem here even without lock */
    statuschanges++;
    pthread_cond_signal(&statuscond);
  }
}

void psync_set_event_callback(pevent_callback_t callback){
}