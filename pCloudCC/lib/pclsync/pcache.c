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
#include "pssl.h"
#include <string.h>

#define CACHE_HASH_SIZE 2048
#define CACHE_LOCKS 8

#define hash_to_bucket(h) ((h)%CACHE_HASH_SIZE)
#define hash_to_lock(h)   ((((h)*CACHE_LOCKS)/CACHE_HASH_SIZE)%CACHE_LOCKS)

#define CACHE_WAIT_FOR_TIMER 1
#define CACHE_TIMER_CALLED   2

typedef struct {
  psync_list list;
  void *value;
  psync_cache_free_callback free;
  psync_timer_t timer;
  uint32_t hash;
  char key[];
} hash_element;

static psync_list cache_hash[CACHE_HASH_SIZE];
static pthread_mutex_t cache_mutexes[CACHE_LOCKS];
static uint32_t hash_seed;

void psync_cache_init(){
  pthread_mutexattr_t mattr;
  psync_uint_t i;
  for (i=0; i<CACHE_HASH_SIZE; i++)
    psync_list_init(&cache_hash[i]);
  for (i=0; i<CACHE_LOCKS; i++){
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&cache_mutexes[i], &mattr);
    pthread_mutexattr_destroy(&mattr);
  }
  // do not use psync_ssl_rand_* here as it is not yet initialized
  hash_seed=psync_time()*0xc2b2ae35U;
}

static uint32_t hash_func(const char *key){
  uint32_t c, hash;
  hash=hash_seed;
  while ((c=(uint32_t)*key++))
    hash=c+(hash<<5)+hash;
  hash+=hash<<3;
  hash^=hash>>11;
  return hash;
}

static uint32_t hash_funcl(const char *key, size_t *len){
  const char *k;
  uint32_t c, hash;
  k=key;
  hash=hash_seed;
  while ((c=(uint32_t)*k++))
    hash=c+(hash<<5)+hash;
  hash+=hash<<3;
  hash^=hash>>11;
  *len=k-key-1;
  return hash;
}

void *psync_cache_get(const char *key){
  hash_element *he;
  void *val;
  psync_list *lst;
  uint32_t h;
  if (IS_DEBUG && !strcmp(psync_thread_name, "timer"))
    debug(D_ERROR, "trying get key %s from the timer thread, this may (and eventually will) lead to a deadlock, "
                   "please start a worker thread to do the job or don't use cache (if you are looking up sql "
                   "query/statement, you can use _nocache version)", key);

  h=hash_func(key);
//  debug(D_NOTICE, "get %s %lu", key, h);
  lst=&cache_hash[hash_to_bucket(h)];
  pthread_mutex_lock(&cache_mutexes[hash_to_lock(h)]);
  psync_list_for_each_element(he, lst, hash_element, list)
    if (he->hash==h && !strcmp(key, he->key)){
      if (psync_timer_stop(he->timer))
        continue;
      psync_list_del(&he->list);
      pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
      val=he->value;
      psync_free(he);
      return val;
    }
  pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
  return NULL;
}

int psync_cache_has(const char *key){
  hash_element *he;
  psync_list *lst;
  uint32_t h;
  int ret;
  h=hash_func(key);
  ret=0;
  lst=&cache_hash[hash_to_bucket(h)];
  pthread_mutex_lock(&cache_mutexes[hash_to_lock(h)]);
  psync_list_for_each_element(he, lst, hash_element, list)
    if (he->hash==h && !strcmp(key, he->key)){
      ret=1;
      break;
    }
  pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
  return ret;
}

static void cache_timer(psync_timer_t timer, void *ptr){
  hash_element *he=(hash_element *)ptr;
  pthread_mutex_lock(&cache_mutexes[hash_to_lock(he->hash)]);
  psync_list_del(&he->list);
  pthread_mutex_unlock(&cache_mutexes[hash_to_lock(he->hash)]);
  he->free(he->value);
  psync_free(he);
  psync_timer_stop(timer);
}

void psync_cache_add(const char *key, void *ptr, time_t freeafter, psync_cache_free_callback freefunc, uint32_t maxkeys){
  hash_element *he, *he2;
  psync_list *lst;
  size_t l;
  uint32_t h;
  h=hash_funcl(key, &l);
  l++;
  he=(hash_element *)psync_malloc(offsetof(hash_element, key)+l);
  he->value=ptr;
  he->free=freefunc;
  he->hash=h;
  memcpy(he->key, key, l);
  lst=&cache_hash[hash_to_bucket(h)];
  pthread_mutex_lock(&cache_mutexes[hash_to_lock(h)]);
  if (maxkeys){
    l=0;
    psync_list_for_each_element (he2, lst, hash_element, list)
      if (unlikely(he2->hash==h && !strcmp(key, he2->key) && ++l==maxkeys)){
        pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
        psync_free(he);
        freefunc(ptr);
//        debug(D_NOTICE, "not adding key %s to cache as there already %u elements present", key, (unsigned int)maxkeys);
        return;
      }
  }
  /* adding to head should be better than to the tail: more recent objects are likely to be in processor cache, more recent
   * connections are likely to be "faster" (e.g. further from idle slowstart reset)
   */
  psync_list_add_head(lst, &he->list);
  he->timer=psync_timer_register(cache_timer, freeafter, he);
  pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
}

void psync_cache_add_free(char *key, void *ptr, time_t freeafter, psync_cache_free_callback freefunc, uint32_t maxkeys){
  psync_cache_add(key, ptr, freeafter, freefunc, maxkeys);
  psync_free(key);
}

void psync_cache_del(const char *key){
  hash_element *he;
  psync_list *lst;
  uint32_t h;
  if (IS_DEBUG && !strcmp(psync_thread_name, "timer"))
    debug(D_ERROR, "trying get key %s from the timer thread, this may (and eventually will) lead to a deadlock, "
                   "please start a worker thread to do the job or don't use cache (if you are looking up sql "
                   "query/statement, you can use _nocache version)", key);

  h=hash_func(key);
  lst=&cache_hash[hash_to_bucket(h)];
restart:
  pthread_mutex_lock(&cache_mutexes[hash_to_lock(h)]);
  psync_list_for_each_element (he, lst, hash_element, list)
    if (he->hash==h && !strcmp(key, he->key)){
      if (psync_timer_stop(he->timer))
        continue;
      psync_list_del(&he->list);
      pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
      he->free(he->value);
      psync_free(he);
      goto restart;
    }
  pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
}

void psync_cache_clean_all(){
  psync_list *l1, *l2;
  hash_element *he;
  psync_uint_t h;
  for (h=0; h<CACHE_HASH_SIZE; h++){
    pthread_mutex_lock(&cache_mutexes[hash_to_lock(h)]);
    psync_list_for_each_safe(l1, l2, &cache_hash[h]){
      he=psync_list_element(l1, hash_element, list);
      if (!psync_timer_stop(he->timer)){
        psync_list_del(l1);
        he->free(he->value);
        psync_free(he);
      }
    }
    pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
  }
}

void psync_cache_clean_starting_with(const char *prefix){
  psync_cache_clean_starting_with_one_of(&prefix, 1);
}

void psync_cache_clean_starting_with_one_of(const char **prefixes, size_t cnt){
  psync_list *l1, *l2;
  hash_element *he;
  psync_uint_t h;
  size_t i;
  psync_def_var_arr(lens, size_t, cnt);
  for (i=0; i<cnt; i++)
    lens[i]=strlen(prefixes[i]);
  for (h=0; h<CACHE_HASH_SIZE; h++){
    pthread_mutex_lock(&cache_mutexes[hash_to_lock(h)]);
    psync_list_for_each_safe(l1, l2, &cache_hash[h]){
      he=psync_list_element(l1, hash_element, list);
      for (i=0; i<cnt; i++)
        if (!strncmp(he->key, prefixes[i], lens[i]))
          break;
      if (i==cnt)
        continue;
      if (!psync_timer_stop(he->timer)){
        psync_list_del(l1);
        he->free(he->value);
        psync_free(he);
      }
    }
    pthread_mutex_unlock(&cache_mutexes[hash_to_lock(h)]);
  }
}
