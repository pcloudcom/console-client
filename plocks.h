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

#ifndef _PSYNC_LOCKS_H
#define _PSYNC_LOCKS_H

#include <pthread.h>

typedef struct {
  unsigned rcount;
  unsigned rwait;
  unsigned wcount;
  unsigned wwait;
  unsigned opts;
  pthread_key_t cntkey;
  pthread_mutex_t mutex;
  pthread_cond_t rcond;
  pthread_cond_t wcond;
} psync_rwlock_t;

void psync_rwlock_init(psync_rwlock_t *rw);
void psync_rwlock_destroy(psync_rwlock_t *rw);
void psync_rwlock_rdlock(psync_rwlock_t *rw);
int psync_rwlock_tryrdlock(psync_rwlock_t *rw);
int psync_rwlock_timedrdlock(psync_rwlock_t *rw, const struct timespec *abstime);
void psync_rwlock_rdlock_starvewr(psync_rwlock_t *rw);
void psync_rwlock_wrlock(psync_rwlock_t *rw);
int psync_rwlock_trywrlock(psync_rwlock_t *rw);
int psync_rwlock_timedwrlock(psync_rwlock_t *rw, const struct timespec *abstime);
void psync_rwlock_rslock(psync_rwlock_t *rw);
int psync_rwlock_towrlock(psync_rwlock_t *rw);
void psync_rwlock_unlock(psync_rwlock_t *rw);
unsigned psync_rwlock_num_waiters(psync_rwlock_t *rw);
int psync_rwlock_holding_rdlock(psync_rwlock_t *rw);
int psync_rwlock_holding_wrlock(psync_rwlock_t *rw);
int psync_rwlock_holding_lock(psync_rwlock_t *rw);


#endif
