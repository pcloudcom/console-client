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

