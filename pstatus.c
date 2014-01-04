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

#include "pstatus.h"
#include "pcallbacks.h"
#include "plibs.h"
#include <string.h>
#include <stdarg.h>

static uint32_t statuses[PSTATUS_NUM_STATUSES]={
  PSTATUS_INVALID, 
  PSTATUS_ONLINE_OFFLINE, 
  PSTATUS_AUTH_PROVIDED, 
  PSTATUS_ACCFULL_QUOTAOK,
  PSTATUS_DISKFULL_OK
};

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
    if (statuses[PSTATUS_TYPE_AUTH]==PSTATUS_AUTH_REQUIRED)
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
  if (statuses[PSTATUS_TYPE_ACCFULL]!=PSTATUS_ACCFULL_QUOTAOK){
    if (statuses[PSTATUS_TYPE_ACCFULL]==PSTATUS_ACCFULL_OVERQUOTA)
      return PSTATUS_ACCOUNT_FULL;
    else {
      debug(D_BUG, "invalid PSTATUS_TYPE_ACCFULL %d", statuses[PSTATUS_TYPE_ACCFULL]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_DISKFULL]!=PSTATUS_DISKFULL_OK){
    if (statuses[PSTATUS_TYPE_DISKFULL]==PSTATUS_DISKFULL_FULL)
      return PSTATUS_DISK_FULL;
    else {
      debug(D_BUG, "invalid PSTATUS_TYPE_DISKFULL %d", statuses[PSTATUS_TYPE_DISKFULL]);
      return -1;
    }
  }
  
  /* This will work quite as well probably:
   * return (!!psync_status.filesdownloading)+(!!psync_status.filesuploading)<<1;
   */
  if (psync_status.filesdownloading && psync_status.filesuploading)
    return PSTATUS_DOWNLOADINGANDUPLOADING;
  else if (psync_status.filesdownloading)
    return PSTATUS_DOWNLOADING;
  else if (psync_status.filesuploading)
    return PSTATUS_UPLOADING;
  else
    return PSTATUS_READY;
}

void psync_status_init(){
  memset(&psync_status, 0, sizeof(psync_status));
  statuses[PSTATUS_TYPE_RUN]=psync_sql_cellint("SELECT value FROM setting WHERE id='runstatus'", 0);
  if (statuses[PSTATUS_TYPE_RUN]<PSTATUS_RUN_RUN || statuses[PSTATUS_TYPE_RUN]>PSTATUS_RUN_STOP){
    statuses[PSTATUS_TYPE_RUN]=PSTATUS_RUN_RUN;
    psync_sql_statement("REPLACE INTO setting (id, value) VALUES ('runstatus', " NTO_STR(PSTATUS_RUN_RUN) ")");
  }
  psync_status.status=psync_calc_status();
}

uint32_t psync_status_get(uint32_t statusid){
  pthread_mutex_lock(&statusmutex);
  statusid=statuses[statusid];
  pthread_mutex_unlock(&statusmutex);
  return statusid;
}


void psync_set_status(uint32_t statusid, uint32_t status){
  pthread_mutex_lock(&statusmutex);
  statuses[statusid]=status;
  if (status_waiters)
    pthread_cond_broadcast(&statuscond);
  pthread_mutex_unlock(&statusmutex);
  psync_status.remoteisfull=(statuses[PSTATUS_TYPE_ACCFULL]==PSTATUS_ACCFULL_OVERQUOTA);
  psync_status.localisfull=(statuses[PSTATUS_TYPE_DISKFULL]==PSTATUS_DISK_FULL);
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

void psync_wait_statuses_array(const uint32_t *combinedstatuses, uint32_t cnt){
  uint32_t waited, i, statusid, status;
  pthread_mutex_lock(&statusmutex);
  do {
    waited=0;
    for (i=0; i<cnt; i++){
      statusid=combinedstatuses[i]>>24;
      status=combinedstatuses[i]&0x00ffffff;
      while ((statuses[statusid]&status)==0){
        waited=1;
        status_waiters++;
        pthread_cond_wait(&statuscond, &statusmutex);
        status_waiters--;
      }
    }
  } while (waited);
  pthread_mutex_unlock(&statusmutex);
}

void psync_wait_statuses(uint32_t first, ...){
  uint32_t arr[PSTATUS_NUM_STATUSES];
  uint32_t cnt;
  va_list ap;
  cnt=0;
  va_start(ap, first);
  do {
    arr[cnt++]=first;
  } while ((first=va_arg(ap, uint32_t)));
  va_end(ap);
  psync_wait_statuses_array(arr, cnt);
}

void psync_status_set_download_speed(uint32_t speed){
  if (psync_status.downloadspeed!=speed){
    psync_status.downloadspeed=speed;
    psync_send_status_update();
  }
}

void psync_status_inc_downloads_count(){
  psync_status.filesdownloading++;
  psync_send_status_update();
}

void psync_status_dec_downloads_count(){
  psync_status.filesdownloading++;
  psync_send_status_update();
}

