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

#include <string.h>
#include <pthread.h>
#include "pstatus.h"
#include "pcallbacks.h"
#include "plibs.h"

#define TO_STR(s) #s

static uint32_t statuses[PSTATUS_NUM_STATUSES];
static pthread_mutex_t statusmutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t statuscond=PTHREAD_COND_INITIALIZER;
static uint32_t status_waiters=0;

static uint32_t psync_calc_status(){
  if (statuses[PSTATUS_TYPE_RUN]!=PSTATUS_RUN_RUN){
    if (statuses[PSTATUS_TYPE_RUN]==PSTATUS_RUN_PAUSE)
      return PSTATUS_PAUSED;
    else if (statuses[PSTATUS_TYPE_RUN]==PSTATUS_RUN_STOP)
      return PSTATUS_STOPPED;
    else {
      debug(D_BUG, "invalid PSTATUS_TYPE_RUN %d", statuses[PSTATUS_TYPE_RUN]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_AUTH]!=PSTATUS_AUTH_PROVIDED){
    if (statuses[PSTATUS_TYPE_AUTH]==PSTATUS_AUTH_REQURED)
      return PSTATUS_LOGIN_REQUIRED;
    else if (statuses[PSTATUS_TYPE_AUTH]==PSTATUS_AUTH_MISMATCH)
      return PSTATUS_USER_MISMATCH;
    else if (statuses[PSTATUS_TYPE_AUTH]==PSTATUS_AUTH_BADLOGIN)
      return PSTATUS_BAD_LOGIN_DATA;
    else {
      debug(D_BUG, "invalid PSTATUS_TYPE_AUTH %d", statuses[PSTATUS_TYPE_AUTH]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_ONLINE]!=PSTATUS_ONLINE_ONLINE){
    if (statuses[PSTATUS_TYPE_ONLINE]==PSTATUS_ONLINE_CONNECTING)
      return PSTATUS_CONNECTING;
    else if (statuses[PSTATUS_TYPE_ONLINE]==PSTATUS_ONLINE_SCANNING)
      return PSTATUS_SCANNING;
    else if (statuses[PSTATUS_TYPE_ONLINE]==PSTATUS_ONLINE_OFFLINE)
      return PSTATUS_OFFLINE;
    else {
      debug(D_BUG, "invalid PSTATUS_TYPE_ONLINE %d", statuses[PSTATUS_TYPE_ONLINE]);
      return -1;
    }
  }
  
  return PSTATUS_READY;
}

void psync_status_init(){
  memset(&psync_status, 0, sizeof(psync_status));
  statuses[PSTATUS_TYPE_RUN]=psync_sql_cellint("SELECT value FROM settings WHERE id='runstatus'", 0);
  if (statuses[PSTATUS_TYPE_RUN]<PSTATUS_RUN_RUN || statuses[PSTATUS_TYPE_RUN]>PSTATUS_RUN_STOP){
    statuses[PSTATUS_TYPE_RUN]=PSTATUS_RUN_RUN;
    psync_sql_statement("REPLACE INTO settings (id, value) VALUES ('runstatus', " TO_STR(PSTATUS_RUN_RUN) ")");
  }
  statuses[PSTATUS_TYPE_ONLINE]=PSTATUS_ONLINE_OFFLINE;
  psync_status.status=psync_calc_status();
}

void psync_set_status(uint32_t statusid, uint32_t status){
  pthread_mutex_lock(&statusmutex);
  statuses[statusid]=status;
  if (status_waiters)
    pthread_cond_broadcast(&statuscond);
  pthread_mutex_unlock(&statusmutex);
  status=psync_calc_status();
  if (psync_status.status!=status){
    psync_status.status=status;
    psync_send_status_update();
  }
}

void psync_wait_status(uint32_t statusid, uint32_t status){
  pthread_mutex_lock(&statusmutex);
  while ((statuses[statusid]&status)==0){
    status_waiters++;
    pthread_cond_wait(&statuscond, &statusmutex);
    status_waiters--;
  }
  pthread_mutex_unlock(&statusmutex);
}

