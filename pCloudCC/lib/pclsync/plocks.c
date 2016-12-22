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

#if defined(_WIN64) || defined(__x86_64__)
typedef uint32_t uint_halfptr_t;
#else
typedef uint16_t uint_halfptr_t;
#endif

#define PSYNC_WR_RESERVED ((uint_halfptr_t)-1)

typedef union {
  void *ptr;
  uint_halfptr_t cnt[2];
} psync_rwlock_lockcnt_t;

void psync_rwlock_init(psync_rwlock_t *rw){
  assert(sizeof(void *)==sizeof(psync_rwlock_lockcnt_t));
  rw->rcount=0;
  rw->rwait=0;
  rw->wcount=0;
  rw->wwait=0;
  rw->opts=0;
  pthread_key_create(&rw->cntkey, NULL);
  pthread_mutex_init(&rw->mutex, NULL);
  pthread_cond_init(&rw->rcond, NULL);
  pthread_cond_init(&rw->wcond, NULL);
}

void psync_rwlock_destroy(psync_rwlock_t *rw){
  pthread_key_delete(rw->cntkey);
  pthread_mutex_destroy(&rw->mutex);
  pthread_cond_destroy(&rw->rcond);
  pthread_cond_destroy(&rw->wcond);
}

static psync_rwlock_lockcnt_t psync_rwlock_get_count(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t locks;
  locks.ptr=pthread_getspecific(rw->cntkey);
  return locks;
}

static void psync_rwlock_set_count(psync_rwlock_t *rw, psync_rwlock_lockcnt_t cnt){
  pthread_setspecific(rw->cntkey, cnt.ptr);
}

static int psync_rwlock_check_rdrecursive_in(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  if (cnt.cnt[0]){
    cnt.cnt[0]++;
    psync_rwlock_set_count(rw, cnt);
    return 1;
  }
  else if (cnt.cnt[1]){
    assert(cnt.cnt[1]!=PSYNC_WR_RESERVED);
    cnt.cnt[1]++;
    psync_rwlock_set_count(rw, cnt);
    return 1;
  }
  else
    return 0;
}

static int psync_rwlock_check_wrrecursive_in(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  assert(!cnt.cnt[0]);
  if (cnt.cnt[1]){
    assert(cnt.cnt[1]!=PSYNC_WR_RESERVED);
    cnt.cnt[1]++;
    psync_rwlock_set_count(rw, cnt);
    return 1;
  }
  else
    return 0;
}

static int psync_rwlock_check_recursive_out(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  if (cnt.cnt[0]){
    cnt.cnt[0]--;
    psync_rwlock_set_count(rw, cnt);
    return cnt.cnt[0]>0;
  }
  else{
    assert(cnt.cnt[1]);
    cnt.cnt[1]--;
    psync_rwlock_set_count(rw, cnt);
    return cnt.cnt[1]>0;
  }
}

static int psync_rwlock_is_reserved_by_this_thread_clr(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  if (cnt.cnt[1]==PSYNC_WR_RESERVED){
    cnt.cnt[1]=0;
    psync_rwlock_set_count(rw, cnt);
    return 1;
  }
  else
    return 0;
}

static psync_rwlock_lockcnt_t psync_rwlock_create_cnt(uint_halfptr_t rd, uint_halfptr_t wr){
  psync_rwlock_lockcnt_t cnt;
  cnt.cnt[0]=rd;
  cnt.cnt[1]=wr;
  return cnt;
}

void psync_rwlock_rdlock(psync_rwlock_t *rw){
  if (psync_rwlock_check_rdrecursive_in(rw))
    return;
  pthread_mutex_lock(&rw->mutex);
  while (rw->wcount || (rw->wwait && !(rw->opts&PSYNC_RW_OPT_RESERVED))){
    rw->rwait++;
    pthread_cond_wait(&rw->rcond, &rw->mutex);
    rw->rwait--;
  }
  rw->rcount++;
  pthread_mutex_unlock(&rw->mutex);
  psync_rwlock_set_count(rw, psync_rwlock_create_cnt(1, 0));
}

int psync_rwlock_tryrdlock(psync_rwlock_t *rw){
  if (psync_rwlock_check_rdrecursive_in(rw))
    return 0;
  pthread_mutex_lock(&rw->mutex);
  if (rw->wcount || (rw->wwait && !(rw->opts&PSYNC_RW_OPT_RESERVED))){
    pthread_mutex_unlock(&rw->mutex);
    return -1;
  }
  rw->rcount++;
  pthread_mutex_unlock(&rw->mutex);
  psync_rwlock_set_count(rw, psync_rwlock_create_cnt(1, 0));
  return 0;
}

int psync_rwlock_timedrdlock(psync_rwlock_t *rw, const struct timespec *abstime){
  if (psync_rwlock_check_rdrecursive_in(rw))
    return 0;
  pthread_mutex_lock(&rw->mutex);
  while (rw->wcount || (rw->wwait && !(rw->opts&PSYNC_RW_OPT_RESERVED))){
    rw->rwait++;
    if (unlikely(pthread_cond_timedwait(&rw->rcond, &rw->mutex, abstime))){
      rw->rwait--;
      pthread_mutex_unlock(&rw->mutex);
      return -1;
    }
    rw->rwait--;
  }
  rw->rcount++;
  pthread_mutex_unlock(&rw->mutex);
  psync_rwlock_set_count(rw, psync_rwlock_create_cnt(1, 0));
  return 0;
}

void psync_rwlock_rdlock_starvewr(psync_rwlock_t *rw){
  if (psync_rwlock_check_rdrecursive_in(rw))
    return;
  pthread_mutex_lock(&rw->mutex);
  while (rw->wcount){
    rw->rwait++;
    rw->opts|=PSYNC_RW_OPT_PREFER_READ;
    pthread_cond_wait(&rw->rcond, &rw->mutex);
    rw->rwait--;
    rw->opts&=~PSYNC_RW_OPT_PREFER_READ;
  }
  rw->rcount++;
  pthread_mutex_unlock(&rw->mutex);
  psync_rwlock_set_count(rw, psync_rwlock_create_cnt(1, 0));
}

void psync_rwlock_wrlock(psync_rwlock_t *rw){
  if (psync_rwlock_check_wrrecursive_in(rw))
    return;
  pthread_mutex_lock(&rw->mutex);
  while (rw->rcount || rw->wcount || (rw->opts&PSYNC_RW_OPT_RESERVED)){
    rw->wwait++;
    pthread_cond_wait(&rw->wcond, &rw->mutex);
    rw->wwait--;
  }
  rw->wcount++;
  pthread_mutex_unlock(&rw->mutex);
  psync_rwlock_set_count(rw, psync_rwlock_create_cnt(0, 1));
}

int psync_rwlock_trywrlock(psync_rwlock_t *rw){
  if (psync_rwlock_check_wrrecursive_in(rw))
    return 0;
  pthread_mutex_lock(&rw->mutex);
  if (rw->rcount || rw->wcount || (rw->opts&PSYNC_RW_OPT_RESERVED)){
    pthread_mutex_unlock(&rw->mutex);
    return -1;
  }
  rw->wcount++;
  pthread_mutex_unlock(&rw->mutex);
  psync_rwlock_set_count(rw, psync_rwlock_create_cnt(0, 1));
  return 0;
}

int psync_rwlock_timedwrlock(psync_rwlock_t *rw, const struct timespec *abstime){
  if (psync_rwlock_check_wrrecursive_in(rw))
    return 0;
  pthread_mutex_lock(&rw->mutex);
  while (rw->rcount || rw->wcount || (rw->opts&PSYNC_RW_OPT_RESERVED)){
    rw->wwait++;
    if (unlikely(pthread_cond_timedwait(&rw->wcond, &rw->mutex, abstime))){
      if (--rw->wwait==0 && !rw->wcount && rw->rwait)
        pthread_cond_broadcast(&rw->rcond);
      pthread_mutex_unlock(&rw->mutex);
      return -1;
    }
    rw->wwait--;
  }
  rw->wcount++;
  pthread_mutex_unlock(&rw->mutex);
  psync_rwlock_set_count(rw, psync_rwlock_create_cnt(0, 1));
  return 0;
}

void psync_rwlock_rslock(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  assert(cnt.cnt[0]==0);
  if (cnt.cnt[1]){
    if (cnt.cnt[1]==PSYNC_WR_RESERVED)
      cnt.cnt[0]++;
    else
      cnt.cnt[1]++;
    psync_rwlock_set_count(rw, cnt);
    return;
  }
  pthread_mutex_lock(&rw->mutex);
  while (rw->wcount || (rw->opts&PSYNC_RW_OPT_RESERVED)){
    rw->wwait++;
    pthread_cond_wait(&rw->wcond, &rw->mutex);
    rw->wwait--;
  }
  if (rw->rwait)
    pthread_cond_broadcast(&rw->rcond);
  rw->rcount++;
  rw->opts|=PSYNC_RW_OPT_RESERVED;
  pthread_mutex_unlock(&rw->mutex);
  cnt.cnt[0]=1;
  cnt.cnt[1]=PSYNC_WR_RESERVED;
  psync_rwlock_set_count(rw, cnt);
}

int psync_rwlock_towrlock(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  if (cnt.cnt[1] && cnt.cnt[1]!=PSYNC_WR_RESERVED)
    return 0;
  assert(cnt.cnt[0]);
  pthread_mutex_lock(&rw->mutex);
  assert(rw->rcount);
  assert(!rw->wcount);
  if (rw->opts&PSYNC_RW_OPT_RESERVED){
    if (cnt.cnt[1]!=PSYNC_WR_RESERVED){
      pthread_mutex_unlock(&rw->mutex);
//      debug(D_NOTICE, "could not upgrade to write lock, consider using reserved locks instead");
      return -1;
    }
  }
  else
    rw->opts|=PSYNC_RW_OPT_RESERVED;
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
  cnt.cnt[1]=cnt.cnt[0];
  cnt.cnt[0]=0;
  psync_rwlock_set_count(rw, cnt);
  return 0;
}

void psync_rwlock_unlock(psync_rwlock_t *rw){
  if (psync_rwlock_check_recursive_out(rw))
    return;
  pthread_mutex_lock(&rw->mutex);
  assert(!(rw->rcount && rw->wcount));
  if (rw->rcount){
    if ((rw->opts&PSYNC_RW_OPT_RESERVED) && psync_rwlock_is_reserved_by_this_thread_clr(rw))
      rw->opts&=~PSYNC_RW_OPT_RESERVED;
    if (--rw->rcount==0){
      if (rw->wwait){
        if (rw->opts&PSYNC_RW_OPT_RESERVED)
          pthread_cond_broadcast(&rw->wcond);
        else
          pthread_cond_signal(&rw->wcond);
      }
    }
  }
  else{
//    debug(D_NOTICE, "Releasing write lock.");
    assert(rw->wcount);
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

int psync_rwlock_holding_rdlock(psync_rwlock_t *rw){
  return psync_rwlock_get_count(rw).cnt[0]!=0;
}

int psync_rwlock_holding_wrlock(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  return cnt.cnt[1]!=0 && cnt.cnt[1]!=PSYNC_WR_RESERVED;
}

int psync_rwlock_holding_lock(psync_rwlock_t *rw){
  psync_rwlock_lockcnt_t cnt;
  cnt=psync_rwlock_get_count(rw);
  return cnt.cnt[0]!=0 || cnt.cnt[1]!=0;
}

