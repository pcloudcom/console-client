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

#include "pcompat.h"
#include "plibs.h"
#include "psynclib.h"
#include "ptimer.h"
#include "ppool.h"
#include <stdlib.h>
#include <string.h>

static void psync_clean_old_locked(psync_pool *pl){
  psync_def_var_arr(resources, void *, pl->curfree);
  time_t maxage;
  int i, cnt;
  cnt=0;
  maxage=psync_timer_time()-pl->maxage;
  for (i=pl->curfree-1; i>=0; i--)
    if (pl->freeres[i].lastuse<=maxage){
      resources[cnt++]=pl->freeres[i].resource;
      if (i!=pl->curfree-1)
        memcpy(&pl->freeres[i], &pl->freeres[pl->curfree-1], sizeof(psync_res_and_time));
      pl->curfree--;
      pl->inuse--;
    }
  if (cnt){
    pthread_mutex_unlock(&pl->lock);
    for (i=0; i<cnt; i++){
      pl->rd(resources[i]);
      debug(D_NOTICE, "freeing old item from cache");
    }
    pthread_mutex_lock(&pl->lock);
  }
}

static void psync_pool_timer(void *ptr){
  psync_pool *pl=(psync_pool *)ptr;
  pthread_mutex_lock(&pl->lock);
  psync_clean_old_locked(pl);
  pthread_mutex_unlock(&pl->lock);
}

psync_pool *psync_pool_create(resourceinit ri, resourcedestroy rd, int maxfree, int maxused, int maxage){
  psync_pool *pl;
  pl=(psync_pool *)psync_malloc(sizeof(psync_pool)+sizeof(psync_res_and_time)*maxfree);
  pl->ri=ri;
  pl->rd=rd;
  pl->inuse=0;
  pl->maxfree=maxfree;
  pl->maxused=maxused;
  pl->maxage=maxage;
  pl->curfree=0;
  pl->sleepers=0;
  pthread_mutex_init(&pl->lock, NULL);
  pthread_cond_init(&pl->cond, NULL);
  if (maxage>0){
    maxage/=8;
    if (!maxage)
      maxage++;
    psync_timer_register(psync_pool_timer, maxage, pl);
  }
  return pl;
}

void *psync_pool_get(psync_pool *pl){
  void *ret;
  time_t maxage;
  int i;
  pthread_mutex_lock(&pl->lock);
  while (pl->maxused && pl->inuse>=pl->maxused && !pl->curfree){
    pl->sleepers++;
    debug(D_NOTICE, "waiting for item");
    pthread_cond_wait(&pl->cond, &pl->lock);
    debug(D_NOTICE, "woke up");
    pl->sleepers--;
  }
  maxage=psync_timer_time()-pl->maxage;
  for (i=0; i<pl->curfree; i++)
    if (pl->freeres[i].lastuse>maxage){
      ret=pl->freeres[i].resource;
      if (i!=pl->curfree-1)
        memcpy(&pl->freeres[i], &pl->freeres[pl->curfree-1], sizeof(psync_res_and_time));
      pl->curfree--;
      pthread_mutex_unlock(&pl->lock);
      debug(D_NOTICE, "got item from cache");
      return ret;
    }
  pl->inuse++;
  pthread_mutex_unlock(&pl->lock);
  ret=pl->ri();
  debug(D_NOTICE, "allocating new item");
  if (unlikely_log(!ret)){
    pthread_mutex_lock(&pl->lock);
    pl->inuse--;
    pthread_mutex_unlock(&pl->lock);
  }
  return ret;
}

void psync_pool_release(psync_pool *pl, void *resource){
  pthread_mutex_lock(&pl->lock);
  if (pl->curfree>=pl->maxfree && pl->maxage>0)
    psync_clean_old_locked(pl);
  if (pl->sleepers)
    pthread_cond_signal(&pl->cond);
  if (pl->curfree>=pl->maxfree){
    pl->inuse--;
    pthread_mutex_unlock(&pl->lock);
    debug(D_NOTICE, "freeing item");
    pl->rd(resource);
  }
  else {
    pl->freeres[pl->curfree].resource=resource;
    pl->freeres[pl->curfree].lastuse=psync_timer_time();
    pl->curfree++;
    pthread_mutex_unlock(&pl->lock);
    debug(D_NOTICE, "put item to cache");
  }
}

void psync_pool_release_bad(psync_pool *pl, void *resource){
  pthread_mutex_lock(&pl->lock);
  pl->inuse--;
  if (pl->sleepers)
    pthread_cond_signal(&pl->cond);
  pthread_mutex_unlock(&pl->lock);
  debug(D_NOTICE, "freeing item");
  pl->rd(resource);
}
