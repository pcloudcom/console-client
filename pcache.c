/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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
#include "psynclib.h"
#include "pcache.h"
#include "ptimer.h"
#include "plist.h"
#include "plibs.h"
#include <string.h>

#define CACHE_HASH_SIZE 2048
#define CACHE_LOCKS 8

#define CACHE_WAIT_FOR_TIMER 1
#define CACHE_TIMER_CALLED   2

typedef struct {
  psync_list list;
  void *value;
  psync_cache_free_callback free;
  psync_timer_t timer;
  uint32_t hash;
  uint32_t opts;
  char key[];
} hash_element;

static psync_list cache_hash[CACHE_HASH_SIZE];
static pthread_mutex_t cache_mutexes[CACHE_LOCKS];
static pthread_cond_t cache_cond=PTHREAD_COND_INITIALIZER;

void psync_cache_init(){
  psync_uint_t i;
  for (i=0; i<CACHE_HASH_SIZE; i++)
    psync_list_init(&cache_hash[i]);
  for (i=0; i<CACHE_LOCKS; i++)
    pthread_mutex_init(&cache_mutexes[i], NULL);
}

static psync_uint_t hash_func(const char *key){
  psync_uint_t c, hash;
  hash=0;  
  while ((c=(psync_uint_t)*key++))
    hash=c+(hash<<5)+hash;
  hash+=hash<<3;
  hash-=hash>>7;
  return hash%CACHE_HASH_SIZE;
}

static psync_uint_t hash_funcl(const char *key, size_t *len){
  psync_uint_t c, hash;
  size_t l;
  hash=0;
  l=0;
  while ((c=(psync_uint_t)*key++)){
    hash=c+(hash<<5)+hash;
    l++;
  }
  hash+=hash<<3;
  hash-=hash>>7;
  *len=l;
  return hash%CACHE_HASH_SIZE;
}

void *psync_cache_get(const char *key){
  psync_uint_t h;
  hash_element *he;
  void *val;
  if (IS_DEBUG && !strcmp(psync_thread_name, "timer"))
    debug(D_ERROR, "trying get key %s from the timer thread, this may (and eventually will) lead to a deadlock, "
                   "please start a worker thread to do the job or don't use cache (if you are looking up sql "
                   "query/statement, you can use _nocache version)", key);

  h=hash_func(key);
//  debug(D_NOTICE, "get %s %lu", key, h);
  pthread_mutex_lock(&cache_mutexes[h%CACHE_LOCKS]);
  psync_list_for_each_element (he, &cache_hash[h], hash_element, list)
    if (!strcmp(key, he->key)){
      psync_list_del(&he->list);
      if (psync_timer_stop(he->timer)){
        he->opts|=CACHE_WAIT_FOR_TIMER;
        do {
          pthread_cond_wait(&cache_cond, &cache_mutexes[h%CACHE_LOCKS]);
        } while (!(he->opts&CACHE_TIMER_CALLED));
      }
      pthread_mutex_unlock(&cache_mutexes[h%CACHE_LOCKS]);
      val=he->value;
      psync_free(he);
      return val;
    }
  pthread_mutex_unlock(&cache_mutexes[h%CACHE_LOCKS]);
  return NULL;
}

static void cache_timer(psync_timer_t timer, void *ptr){
  hash_element *he=(hash_element *)ptr;
  pthread_mutex_lock(&cache_mutexes[he->hash%CACHE_LOCKS]);
  if (unlikely(he->opts&CACHE_WAIT_FOR_TIMER)){
    he->opts|=CACHE_TIMER_CALLED;
    pthread_cond_broadcast(&cache_cond);
    pthread_mutex_unlock(&cache_mutexes[he->hash%CACHE_LOCKS]);
  }
  else{
    psync_list_del(&he->list);
    pthread_mutex_unlock(&cache_mutexes[he->hash%CACHE_LOCKS]);
    he->free(he->value);
    psync_free(he);
    psync_timer_stop(timer);
  }
}

void psync_cache_add(const char *key, void *ptr, time_t freeafter, psync_cache_free_callback freefunc, uint32_t maxkeys){
  psync_uint_t h;
  size_t l;
  hash_element *he, *he2;
  h=hash_funcl(key, &l);
  l++;
  he=(hash_element *)psync_malloc(offsetof(hash_element, key)+l);
  he->value=ptr;
  he->free=freefunc;
  he->hash=h;
  he->opts=0;
  memcpy(he->key, key, l);
  pthread_mutex_lock(&cache_mutexes[h%CACHE_LOCKS]);
  if (maxkeys){
    l=0;
    psync_list_for_each_element (he2, &cache_hash[h], hash_element, list)
      if (!strcmp(key, he2->key) && ++l==maxkeys){
        pthread_mutex_unlock(&cache_mutexes[h%CACHE_LOCKS]);
        psync_free(he);
        freefunc(ptr);
        debug(D_NOTICE, "not adding key %s to cache as there already %u elements present", key, (unsigned int)maxkeys);
        return;
      }
  }
  /* adding to head should be better than to the tail: more recent objects are likely to be in processor cache, more recent
   * connections are likely to be "faster" (e.g. further from idle slowstart reset)
   */
  psync_list_add_head(&cache_hash[h], &he->list);
  he->timer=psync_timer_register(cache_timer, freeafter, he);
  pthread_mutex_unlock(&cache_mutexes[h%CACHE_LOCKS]);
}

void psync_cache_add_free(char *key, void *ptr, time_t freeafter, psync_cache_free_callback freefunc, uint32_t maxkeys){
  psync_cache_add(key, ptr, freeafter, freefunc, maxkeys);
  psync_free(key);
}

void psync_cache_clean_all(){
  psync_list *l1, *l2;
  hash_element *he;
  psync_uint_t h;
  for (h=0; h<CACHE_HASH_SIZE; h++){
    pthread_mutex_lock(&cache_mutexes[h%CACHE_LOCKS]);
    psync_list_for_each_safe(l1, l2, &cache_hash[h]){
      he=psync_list_element(l1, hash_element, list);
      if (!psync_timer_stop(he->timer)){
        psync_list_del(l1);
        he->free(he->value);
        psync_free(he);
      }
    }
    pthread_mutex_unlock(&cache_mutexes[h%CACHE_LOCKS]);
  }
}