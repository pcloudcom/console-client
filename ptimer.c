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

#include "psynclib.h"
#include "ptimer.h"
#include "pcompat.h"
#include "plibs.h"
#include "pcache.h"

/* Maximum timeout possible is TIMER_ARRAY_SIZE^TIMER_LEVELS seconds, in the worst case
 * TIMER_LEVELS operations will be preformed for each timer to service it
 * (it is log TIMER_ARRAY_SIZE(timer_seconds_after_now)). So servicing a timer is
 * generally constant time task with a maximum constant of TIMER_LEVELS and increasing
 * TIMER_ARRAY_SIZE will trade memory for less processing for each timer.
 *
 * TIMER_ARRAY_SIZE should be a power of two.
 */

#define TIMER_ARRAY_SIZE_SHIFT 6 /* 64 */
#define TIMER_ARRAY_SIZE (1<<TIMER_ARRAY_SIZE_SHIFT)
#define TIMER_LEVELS 3

#define PTIMER_IS_RUNNING     1
#define PTIMER_STOP_AFTER_RUN 2

time_t psync_current_time;

struct exception_list {
  struct exception_list *next;
  psync_exception_callback func;
  pthread_t threadid;
};

static psync_list timerlists[TIMER_LEVELS][TIMER_ARRAY_SIZE];
static struct exception_list *excepions=NULL;
static struct exception_list *sleeplist=NULL;
static pthread_mutex_t timer_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t timer_ex_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t timer_cond=PTHREAD_COND_INITIALIZER;
static uint32_t nextsecwaiters=0;
static int timer_running=0;

PSYNC_NOINLINE static void timer_sleep_detected(time_t lt){
  struct exception_list *e;
  debug(D_NOTICE, "sleep detected, current_time=%lu, last_current_time=%lu", (unsigned long)psync_current_time, (unsigned long)lt);
  pthread_mutex_lock(&timer_ex_mutex);
  e=sleeplist;
  while (e){
    e->func();
    e=e->next;
  }
  pthread_mutex_unlock(&timer_ex_mutex);
  psync_cache_clean_all();
  psync_timer_notify_exception();
}

static void timer_check_upper_levels(time_t tmdiv, psync_uint_t level, psync_uint_t sh){
  psync_list *l1, *l2, *l;
  time_t m;
  m=tmdiv%TIMER_ARRAY_SIZE;
  if (m==0 && level<TIMER_LEVELS-2)
    timer_check_upper_levels(tmdiv/TIMER_ARRAY_SIZE, level+1, sh+TIMER_ARRAY_SIZE_SHIFT);
  l=&timerlists[level+1][m];
  psync_list_for_each_safe(l1, l2, l)
    psync_list_add_tail(&timerlists[level][(psync_list_element(l1, psync_timer_structure_t, list)->runat>>sh)%TIMER_ARRAY_SIZE], l1);
  psync_list_init(&timerlists[level+1][m]);
}

static void timer_prepare_timers(time_t from, time_t to, psync_list *list){
  time_t i, m;
  psync_list *l1, *l2;
  for (i=from+1; i<=to; i++){
    m=i%TIMER_ARRAY_SIZE;
    if (m==0)
      timer_check_upper_levels(i/TIMER_ARRAY_SIZE, 0, 0);
    psync_list_for_each_safe(l1, l2, &timerlists[0][m]){
      psync_list_element(l1, psync_timer_structure_t, list)->opts|=PTIMER_IS_RUNNING;
      psync_list_add_tail(list, l1);
    }
    psync_list_init(&timerlists[0][m]);
  }
}

PSYNC_NOINLINE static void timer_process_timers(psync_list *timers){
  psync_timer_t timer;
  psync_list *l1, *l2;
  psync_list_for_each_element(timer, timers, psync_timer_structure_t, list)
    timer->call(timer, timer->param);
  pthread_mutex_lock(&timer_mutex);
  psync_list_for_each_safe(l1, l2, timers){
    timer=psync_list_element(l1, psync_timer_structure_t, list);
    if (!(timer->opts&PTIMER_STOP_AFTER_RUN)){
      timer->opts=0;
      psync_list_del(l1);
      timer->runat=psync_current_time+timer->numsec;
      psync_list_add_tail(&timerlists[timer->level][(timer->runat>>(timer->level*TIMER_ARRAY_SIZE_SHIFT))%TIMER_ARRAY_SIZE], &timer->list);
    }
  }
  pthread_mutex_unlock(&timer_mutex);
  psync_list_for_each_element_call(timers, psync_timer_structure_t, list, psync_free);
}

static void timer_thread(){
  psync_list timers;
  time_t lt;
  lt=psync_current_time;
  while (psync_do_run){
    psync_list_init(&timers);
    psync_milisleep(1000);
    psync_current_time=psync_time();
    pthread_mutex_lock(&timer_mutex);
    timer_prepare_timers(lt, psync_current_time, &timers);
    if (nextsecwaiters)
      pthread_cond_broadcast(&timer_cond);
    pthread_mutex_unlock(&timer_mutex);
    if (unlikely(!psync_list_isempty(&timers)))
      timer_process_timers(&timers);
    if (unlikely(psync_current_time-lt>=25))
      timer_sleep_detected(lt);
    else if (unlikely_log(psync_current_time==lt)){
      if (!psync_do_run)
        break;
      psync_milisleep(1000);
    }
    lt=psync_current_time;
  }
}

void psync_timer_init(){
  psync_uint_t i, j;
  for (i=0; i<TIMER_LEVELS; i++)
    for (j=0; j<TIMER_ARRAY_SIZE; j++)
      psync_list_init(&timerlists[i][j]);
  psync_current_time=psync_time();
  psync_run_thread("timer", timer_thread);
  timer_running=1;
}

time_t psync_timer_time(){
  if (timer_running)
    return psync_current_time;
  else
    return psync_time(NULL);
}

void psync_timer_wake(){
  pthread_cond_signal(&timer_cond);
}

psync_timer_t psync_timer_register(psync_timer_callback func, time_t numsec, void *param){
  psync_timer_t timer;
  uint32_t i;
  time_t n;
  timer=psync_new(psync_timer_structure_t);
  timer->call=func;
  timer->param=param;
  n=TIMER_ARRAY_SIZE;
  for (i=0; i<TIMER_LEVELS; i++){
    if (numsec<=n)
      break;
    else
      n*=TIMER_ARRAY_SIZE;
  }
  if (unlikely(i==TIMER_LEVELS)){
    n/=TIMER_ARRAY_SIZE;
    debug(D_ERROR, "requested timeout %lu is larger than the maximum of %lu", (unsigned long)numsec, (unsigned long)n);
    numsec=n;
    i--;
  }
  timer->numsec=numsec;
  timer->level=i;
  timer->opts=0;
  pthread_mutex_lock(&timer_mutex);
  timer->runat=psync_current_time+numsec;
  psync_list_add_tail(&timerlists[i][(timer->runat>>(i*TIMER_ARRAY_SIZE_SHIFT))%TIMER_ARRAY_SIZE], &timer->list);
  pthread_mutex_unlock(&timer_mutex);
  return timer;
}

int psync_timer_stop(psync_timer_t timer){
  int needfree=0;
  pthread_mutex_lock(&timer_mutex);
  if (timer->opts&PTIMER_IS_RUNNING)
    timer->opts|=PTIMER_STOP_AFTER_RUN;
  else{
    psync_list_del(&timer->list);
    needfree=1;
  }
  pthread_mutex_unlock(&timer_mutex);
  if (needfree){
    psync_free(timer);
    return 0;
  }
  else
    return 1;
}

void psync_timer_exception_handler(psync_exception_callback func){
  struct exception_list *t;
  t=psync_new(struct exception_list);
  t->next=NULL;
  t->func=func;
  t->threadid=pthread_self();
  pthread_mutex_lock(&timer_ex_mutex);
  t->next=excepions;
  excepions=t;
  pthread_mutex_unlock(&timer_ex_mutex);
}

void psync_timer_sleep_handler(psync_exception_callback func){
  struct exception_list *t;
  t=psync_new(struct exception_list);
  t->next=NULL;
  t->func=func;
  t->threadid=pthread_self();
  pthread_mutex_lock(&timer_ex_mutex);
  t->next=sleeplist;
  sleeplist=t;
  pthread_mutex_unlock(&timer_ex_mutex);
}

void psync_timer_do_notify_exception(){
  struct exception_list *e;
  pthread_t threadid;
  e=excepions;
  threadid=pthread_self();
  pthread_mutex_lock(&timer_ex_mutex);
  while (e){
    if (!pthread_equal(threadid, e->threadid))
      e->func();
    e=e->next;
  }
  pthread_mutex_unlock(&timer_ex_mutex);
}

void psync_timer_wait_next_sec(){
  time_t ctime;
  pthread_mutex_lock(&timer_mutex);
  ctime=psync_current_time;
  do {
    nextsecwaiters++;
    pthread_cond_wait(&timer_cond, &timer_mutex);
    nextsecwaiters--;
  } while (ctime==psync_current_time);
  pthread_mutex_unlock(&timer_mutex);
}
