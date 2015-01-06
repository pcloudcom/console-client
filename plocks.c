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

#include "plocks.h"
#include "plibs.h"

#define PSYNC_RW_OPT_PREFER_READ 1U
#define PSYNC_RW_OPT_RESERVED    2U

void psync_rwlock_init(psync_rwlock_t *rw){
  rw->rcount=0;
  rw->rwait=0;
  rw->wcount=0;
  rw->wwait=0;
  rw->opts=0;
  pthread_mutex_init(&rw->mutex, NULL);
  pthread_cond_init(&rw->rcond, NULL);
  pthread_cond_init(&rw->wcond, NULL);
}

void psync_rwlock_destroy(psync_rwlock_t *rw){
  pthread_mutex_destroy(&rw->mutex);
  pthread_cond_destroy(&rw->rcond);
  pthread_cond_destroy(&rw->wcond);
}

void psync_rwlock_rdlock(psync_rwlock_t *rw){
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount && pthread_equal(pthread_self(), rw->wthread))
    rw->wcount++; // we are holding write lock
  else{
    while (rw->wcount || rw->wwait){
      rw->rwait++;
      pthread_cond_wait(&rw->rcond, &rw->mutex);
      rw->rwait--;
    }
    rw->rcount++;
  }
  pthread_mutex_unlock(&rw->mutex);
}

int psync_rwlock_tryrdlock(psync_rwlock_t *rw){
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount && pthread_equal(pthread_self(), rw->wthread))
    rw->wcount++; // we are holding write lock
  else{
    if (rw->wcount || rw->wwait){
      pthread_mutex_unlock(&rw->mutex);
      return -1;
    }
    rw->rcount++;
  }
  pthread_mutex_unlock(&rw->mutex);
  return 0;
}

int psync_rwlock_timedrdlock(psync_rwlock_t *rw, const struct timespec *abstime){
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount && pthread_equal(pthread_self(), rw->wthread))
    rw->wcount++; // we are holding write lock
  else{
    while (rw->wcount || rw->wwait){
      rw->rwait++;
      if (unlikely(pthread_cond_timedwait(&rw->rcond, &rw->mutex, abstime))){
        rw->rwait--;
        pthread_mutex_unlock(&rw->mutex);
        return -1;
      }
      rw->rwait--;
    }
    rw->rcount++;
  }
  pthread_mutex_unlock(&rw->mutex);
  return 0;
}

void psync_rwlock_rdlock_starvewr(psync_rwlock_t *rw){
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount && pthread_equal(pthread_self(), rw->wthread))
    rw->wcount++; // we are holding write lock
  else{
    while (rw->wcount){
      rw->rwait++;
      rw->opts|=PSYNC_RW_OPT_PREFER_READ;
      pthread_cond_wait(&rw->rcond, &rw->mutex);
      rw->rwait--;
    }
    rw->rcount++;
  }
  pthread_mutex_unlock(&rw->mutex);
}

void psync_rwlock_wrlock(psync_rwlock_t *rw){
  pthread_t self;
  self=pthread_self();
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount && pthread_equal(self, rw->wthread))
    goto ex;
  while (rw->rcount || rw->wcount || (rw->opts&PSYNC_RW_OPT_RESERVED)){
    rw->wwait++;
    pthread_cond_wait(&rw->wcond, &rw->mutex);
    rw->wwait--;
  }
  rw->wthread=self;
ex:
  rw->wcount++;
  pthread_mutex_unlock(&rw->mutex);
}

int psync_rwlock_trywrlock(psync_rwlock_t *rw){
  pthread_t self;
  self=pthread_self();
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount && pthread_equal(self, rw->wthread))
    goto ex;
  if (rw->rcount || rw->wcount){
    pthread_mutex_unlock(&rw->mutex);
    return -1;
  }
  rw->wthread=self;
ex:
  rw->wcount++;
  pthread_mutex_unlock(&rw->mutex);
  return 0;
}

int psync_rwlock_timedwrlock(psync_rwlock_t *rw, const struct timespec *abstime){
  pthread_t self;
  self=pthread_self();
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount && pthread_equal(self, rw->wthread))
    goto ex;
  while (rw->rcount || rw->wcount || (rw->opts&PSYNC_RW_OPT_RESERVED)){
    rw->wwait++;
    if (unlikely(pthread_cond_timedwait(&rw->wcond, &rw->mutex, abstime))){
      rw->wwait--;
      pthread_mutex_unlock(&rw->mutex);
      return -1;
    }
    rw->wwait--;
  }
  rw->wthread=self;
ex:
  rw->wcount++;
  pthread_mutex_unlock(&rw->mutex);
  return 0;
}

void psync_rwlock_rslock(psync_rwlock_t *rw){
  pthread_t self;
  self=pthread_self();
  pthread_mutex_lock(&rw->mutex);
  while (rw->wcount || (rw->opts&PSYNC_RW_OPT_RESERVED)){
    rw->wwait++;
    pthread_cond_wait(&rw->wcond, &rw->mutex);
    rw->wwait--;
  }
  rw->rcount++;
  rw->wthread=self;
  rw->opts|=PSYNC_RW_OPT_RESERVED;
  pthread_mutex_unlock(&rw->mutex);
}

int psync_rwlock_towrlock(psync_rwlock_t *rw){
  pthread_t self;
  self=pthread_self();
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount){
    assert(pthread_equal(self, rw->wthread));
    debug(D_NOTICE, "we already have write lock, not doing anything");
    pthread_mutex_unlock(&rw->mutex);
    return 0;
  }
  assert(rw->rcount);
  if (rw->opts&PSYNC_RW_OPT_RESERVED){
    if (!pthread_equal(self, rw->wthread)){
      pthread_mutex_unlock(&rw->mutex);
      debug(D_NOTICE, "could not upgrade to write lock, consider using reserved locks instead");
      return -1;
    }
  }
  else{
    rw->opts|=PSYNC_RW_OPT_RESERVED;
    rw->wthread=self;
  }
  rw->rcount--;
  while (rw->rcount){
    rw->wwait++;
    pthread_cond_wait(&rw->wcond, &rw->mutex);
    rw->wwait--;
  }
  assert(!rw->wcount);
  rw->wcount++;
  rw->opts&=~PSYNC_RW_OPT_RESERVED;
  pthread_mutex_unlock(&rw->mutex);
  return 0;
}

void psync_rwlock_unlock(psync_rwlock_t *rw){
  pthread_mutex_lock(&rw->mutex);
  if (rw->rcount){
    if ((rw->opts&PSYNC_RW_OPT_RESERVED) && pthread_equal(pthread_self(), rw->wthread))
      rw->opts&=~PSYNC_RW_OPT_RESERVED;
    if (--rw->rcount==0){
      rw->opts&=~PSYNC_RW_OPT_PREFER_READ;
      if (rw->wwait){
        if (rw->opts&PSYNC_RW_OPT_RESERVED)
          pthread_cond_broadcast(&rw->wcond);
        else
          pthread_cond_signal(&rw->wcond);
      }
    }
  }
  else{
    assert(rw->wcount);
    assert(pthread_equal(pthread_self(), rw->wthread));
    if (--rw->wcount==0){
      if (rw->opts&PSYNC_RW_OPT_RESERVED){
        assert(rw->wwait);
        // this could create some small thundering herd, but is probably better than using one more condition variable
        pthread_cond_broadcast(&rw->wcond);
      }
      else if (rw->opts&PSYNC_RW_OPT_PREFER_READ){
        if (rw->rwait)
          pthread_cond_broadcast(&rw->rcond);
        else if (rw->wwait)
          pthread_cond_signal(&rw->wcond);
      }
      else{
        if (rw->wwait)
          pthread_cond_signal(&rw->wcond);
        else if (rw->rwait)
          pthread_cond_broadcast(&rw->rcond);
      }
    }
  }
  pthread_mutex_unlock(&rw->mutex);
}

unsigned psync_rwlock_num_waiters(psync_rwlock_t *rw){
  unsigned ret;
  pthread_mutex_lock(&rw->mutex);
  ret=rw->rwait+rw->wwait;
  pthread_mutex_unlock(&rw->mutex);
  return ret;
}

