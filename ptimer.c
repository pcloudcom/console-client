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

#include "psynclib.h"
#include "ptimer.h"
#include "pcompat.h"
#include "plibs.h"

time_t psync_current_time;

struct exception_list {
  struct exception_list *next;
  timer_callback func;
};

struct timer_list {
  struct timer_list *next;
  timer_callback func;
  time_t nextrun;
  time_t runevery;
};

static struct exception_list *excepions=NULL;
static struct timer_list *timers=NULL;
static pthread_mutex_t timer_mutex=PTHREAD_MUTEX_INITIALIZER;

static void timer_thread(){
  struct exception_list *e;
  struct timer_list *t;
  time_t lt;
  lt=psync_current_time;
  while (psync_do_run){
    psync_milisleep(1000);
    time(&psync_current_time);
    if (psync_current_time-lt>=5){
      e=excepions;
      while (e){
        e->func();
        e=e->next;
      }
    }
    lt=psync_current_time;
    t=timers;
    while (t){
      if (t->nextrun<=psync_current_time){
        t->nextrun=psync_current_time+t->runevery;
        t->func();
      }
      t=t->next;
    }
  }
}

void psync_timer_init(){
  time(&psync_current_time);
  psync_run_thread(timer_thread);
}

void psync_timer_register(timer_callback func, time_t numsec){
  struct timer_list *t;
  t=(struct timer_list *)psync_malloc(sizeof(struct timer_list));
  t->next=NULL; /* this is needed as in the timer there is no lock and the two operations between lock and unlock can be reordered*/
  t->func=func;
  t->nextrun=0;
  t->runevery=numsec;
  pthread_mutex_lock(&timer_mutex);
  t->next=timers;
  timers=t->next;
  pthread_mutex_unlock(&timer_mutex);
}

void psync_timer_exception_handler(timer_callback func){
  struct exception_list *t;
  t=(struct exception_list *)psync_malloc(sizeof(struct exception_list));
  t->next=NULL;
  t->func=func;
  pthread_mutex_lock(&timer_mutex);
  t->next=excepions;
  excepions=t->next;
  pthread_mutex_unlock(&timer_mutex);
}
