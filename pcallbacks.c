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