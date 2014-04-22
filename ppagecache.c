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

#include "ppagecache.h"
#include "psettings.h"
#include "plibs.h"
#include "ptimer.h"
#include "pnetlibs.h"
#include "pstatus.h"
#include "pcache.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>

#define CACHE_PAGES (PSYNC_FS_MEMORY_CACHE/PSYNC_FS_PAGE_SIZE)
#define CACHE_HASH (CACHE_PAGES/2)

#define PAGE_WAITER_HASH 1024
#define PAGE_WAITER_MUTEXES 16

#define DB_CACHE_UPDATE_HASH (32*1024)

#define PAGE_TYPE_FREE 0
#define PAGE_TYPE_READ 1

#define pagehash_by_hash_and_pageid(hash, pageid) (((hash)+(pageid))%CACHE_HASH)
#define waiterhash_by_hash_and_pageid(hash, pageid) (((hash)+(pageid))%PAGE_WAITER_HASH)
#define waiter_mutex_by_hash(hash) (hash%PAGE_WAITER_MUTEXES)
#define lock_wait(hash) pthread_mutex_lock(&wait_page_mutexes[waiter_mutex_by_hash(hash)])
#define unlock_wait(hash) pthread_mutex_unlock(&wait_page_mutexes[waiter_mutex_by_hash(hash)])

typedef struct {
  psync_list list;
  psync_list flushlist;
  char *page;
  uint64_t hash;
  psync_fileid_t fileid;
  uint64_t pageid;
  time_t lastuse;
  uint32_t size;
  uint32_t usecnt;
  uint32_t flushpageid;
  uint8_t type;
} psync_cache_page_t;

typedef struct {
  uint64_t pagecacheid;
  time_t lastuse;
  uint32_t usecnt;
} psync_cachepage_to_update;

typedef struct {
  /* list is an element of hash table for pages */
  psync_list list;
  /* list is root of a listpage elements of psync_page_waiter_t, if empty, nobody waits for this page */
  psync_list waiters;
  uint64_t hash;
  uint64_t pageid;
  psync_fileid_t fileid;
} psync_page_wait_t;

typedef struct {
  /* listpage is node element of psync_page_wait_t waiters list */
  psync_list listpage;
  /* listwaiter is node element of pages that are needed for current request */
  psync_list listwaiter;
  pthread_cond_t cond;
  psync_page_wait_t *waiting_for;
  char *buff;
  uint32_t pageidx;
  uint32_t rsize;
  uint32_t size;
  uint32_t off;
  int error;
  uint8_t ready;
} psync_page_waiter_t;

typedef struct {
  psync_list list;
  uint64_t offset;
  uint64_t length;
} psync_request_range_t;

typedef struct {
  psync_list ranges;
  psync_openfile_t *of;
} psync_request_t;

static psync_list cache_hash[CACHE_HASH];
static uint32_t cache_pages_in_hash=0;
static uint32_t cache_pages_free;
static psync_list free_pages;
static psync_list wait_page_hash[PAGE_WAITER_HASH];
static char *pages_base;

static psync_cachepage_to_update cachepages_to_update[DB_CACHE_UPDATE_HASH];
static uint32_t cachepages_to_update_cnt=0;
static uint32_t free_db_pages;

static pthread_mutex_t cache_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t clean_cache_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t flush_cache_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t wait_page_mutexes[PAGE_WAITER_MUTEXES];

static int flushedbetweentimers=0;
static int flushchacherun=0;

static uint64_t db_cache_in_pages;
static uint64_t db_cache_max_page;

static psync_file_t readcache;

static uint64_t offset_round_down_to_page(uint64_t offset){
  return offset&~(((uint64_t)PSYNC_FS_PAGE_SIZE)-1);
}

static uint64_t size_round_up_to_page(uint64_t size){
  return ((size-1)|(((uint64_t)PSYNC_FS_PAGE_SIZE)-1))+1;
}

static int has_page_in_cache_by_hash(uint64_t hash, uint64_t pageid){
  psync_cache_page_t *page;
  psync_uint_t h;
  h=pagehash_by_hash_and_pageid(hash, pageid);
  pthread_mutex_lock(&cache_mutex);
  psync_list_for_each_element(page, &cache_hash[h], psync_cache_page_t, list)
    if (page->type==PAGE_TYPE_READ && page->hash==hash && page->pageid==pageid){
      pthread_mutex_unlock(&cache_mutex);
      return 1;
    }
  pthread_mutex_unlock(&cache_mutex);
  return 0;
}

static unsigned char *has_pages_in_db(uint64_t hash, uint64_t pageid, uint32_t pagecnt){
  psync_sql_res *res;
  psync_uint_row row;
  unsigned char *ret;
  ret=psync_new_cnt(unsigned char, pagecnt);
  memset(ret, 0, pagecnt);
  res=psync_sql_query("SELECT pageid FROM pagecache WHERE type=+"NTO_STR(PAGE_TYPE_READ)" AND hash=? AND pageid>=? AND pageid<?");
  psync_sql_bind_uint(res, 1, hash);
  psync_sql_bind_uint(res, 2, pageid);
  psync_sql_bind_uint(res, 3, pageid+pagecnt);
  while ((row=psync_sql_fetch_rowint(res)))
    ret[row[0]-pageid]=1;
  psync_sql_free_result(res);
  return ret;
}

static psync_int_t check_page_in_memory_by_hash(uint64_t hash, uint64_t pageid, char *buff, psync_uint_t size, psync_uint_t off){
  psync_cache_page_t *page;
  psync_uint_t h;
  psync_int_t ret;
  time_t tm;
  ret=-1;
  h=pagehash_by_hash_and_pageid(hash, pageid);
  pthread_mutex_lock(&cache_mutex);
  psync_list_for_each_element(page, &cache_hash[h], psync_cache_page_t, list)
    if (page->type==PAGE_TYPE_READ && page->hash==hash && page->pageid==pageid){
      tm=psync_timer_time();
      if (tm>page->lastuse+5){
        page->usecnt++;
        page->lastuse=tm;
      }
      if (size+off>page->size){
        if (off>page->size)
          size=0;
        else
          size=page->size-off;
      }
      memcpy(buff, page->page+off, size);
      ret=size;
    }
  pthread_mutex_unlock(&cache_mutex);
  return ret;
}

typedef struct {
  time_t lastuse;
  uint32_t id;
  uint32_t usecnt;
} pagecache_entry;

static int pagecache_entry_cmp_lastuse(const void *p1, const void *p2){
  const pagecache_entry *e1, *e2;
  e1=(const pagecache_entry *)p1;
  e2=(const pagecache_entry *)p2;
  return (int)((int64_t)e1->lastuse-(int64_t)e2->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse2(const void *p1, const void *p2){
  const pagecache_entry *e1, *e2;
  e1=(const pagecache_entry *)p1;
  e2=(const pagecache_entry *)p2;
  if (e1->usecnt>=2 && e2->usecnt<2)
    return 1;
  else if (e2->usecnt>=2 && e1->usecnt<2)
    return -1;
  else
    return (int)((int64_t)e1->lastuse-(int64_t)e2->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse4(const void *p1, const void *p2){
  const pagecache_entry *e1, *e2;
  e1=(const pagecache_entry *)p1;
  e2=(const pagecache_entry *)p2;
  if (e1->usecnt>=4 && e2->usecnt<4)
    return 1;
  else if (e2->usecnt>=4 && e1->usecnt<4)
    return -1;
  else
    return (int)((int64_t)e1->lastuse-(int64_t)e2->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse8(const void *p1, const void *p2){
  const pagecache_entry *e1, *e2;
  e1=(const pagecache_entry *)p1;
  e2=(const pagecache_entry *)p2;
  if (e1->usecnt>=8 && e2->usecnt<8)
    return 1;
  else if (e2->usecnt>=8 && e1->usecnt<8)
    return -1;
  else
    return (int)((int64_t)e1->lastuse-(int64_t)e2->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse16(const void *p1, const void *p2){
  const pagecache_entry *e1, *e2;
  e1=(const pagecache_entry *)p1;
  e2=(const pagecache_entry *)p2;
  if (e1->usecnt>=16 && e2->usecnt<16)
    return 1;
  else if (e2->usecnt>=16 && e1->usecnt<16)
    return -1;
  else
    return (int)((int64_t)e1->lastuse-(int64_t)e2->lastuse);
}

/* sum should be around 90-95 percent, so after a run cache get smaller */
#define PSYNC_FS_CACHE_LRU_PERCENT 40
#define PSYNC_FS_CACHE_LRU2_PERCENT 25
#define PSYNC_FS_CACHE_LRU4_PERCENT 15
#define PSYNC_FS_CACHE_LRU8_PERCENT 10
#define PSYNC_FS_CACHE_LRU16_PERCENT 5

static void clean_cache(){
  psync_sql_res *res;
  uint64_t ocnt, cnt, i, j, e;
  psync_uint_row row;
  pagecache_entry *entries;
  debug(D_NOTICE, "cleaning cache, free cache pages %u", (unsigned)free_db_pages);
  if (pthread_mutex_trylock(&clean_cache_mutex)){
    debug(D_NOTICE, "cache clean already in progress, skipping");
    return;
  }
  cnt=psync_sql_cellint("SELECT COUNT(*) FROM pagecache", 0);
  entries=(pagecache_entry *)psync_malloc(cnt*sizeof(pagecache_entry));
  i=0;
  res=psync_sql_query("SELECT id, lastuse, usecnt, type FROM pagecache");
  while ((row=psync_sql_fetch_rowint(res))){
    if (i>=cnt)
      break;
    if (row[3]!=PAGE_TYPE_READ)
      continue;
    entries[i].lastuse=row[1];
    entries[i].id=row[0];
    entries[i].usecnt=row[2];
    i++;
  }
  psync_sql_free_result(res);
  ocnt=cnt=i;
  debug(D_NOTICE, "read %lu entries", (unsigned long)cnt);
  qsort(entries, cnt, sizeof(pagecache_entry), pagecache_entry_cmp_lastuse);
  cnt-=PSYNC_FS_CACHE_LRU_PERCENT*ocnt/100;
  debug(D_NOTICE, "sorted entries by lastuse, continuing with %lu oldest entries", (unsigned long)cnt);
  qsort(entries, cnt, sizeof(pagecache_entry), pagecache_entry_cmp_usecnt_lastuse2);
  cnt-=PSYNC_FS_CACHE_LRU2_PERCENT*ocnt/100;
  debug(D_NOTICE, "sorted entries by more than 2 uses and lastuse, continuing with %lu entries", (unsigned long)cnt);
  qsort(entries, cnt, sizeof(pagecache_entry), pagecache_entry_cmp_usecnt_lastuse4);
  cnt-=PSYNC_FS_CACHE_LRU4_PERCENT*ocnt/100;
  debug(D_NOTICE, "sorted entries by more than 4 uses and lastuse, continuing with %lu entries", (unsigned long)cnt);
  qsort(entries, cnt, sizeof(pagecache_entry), pagecache_entry_cmp_usecnt_lastuse8);
  cnt-=PSYNC_FS_CACHE_LRU8_PERCENT*ocnt/100;
  debug(D_NOTICE, "sorted entries by more than 8 uses and lastuse, continuing with %lu entries", (unsigned long)cnt);
  qsort(entries, cnt, sizeof(pagecache_entry), pagecache_entry_cmp_usecnt_lastuse16);
  cnt-=PSYNC_FS_CACHE_LRU16_PERCENT*ocnt/100;
  debug(D_NOTICE, "sorted entries by more than 16 uses and lastuse, deleting %lu entries", (unsigned long)cnt);
  ocnt=(cnt+999)/1000;
  for (j=0; j<ocnt; j++){
    i=j*1000;
    e=i+1000;
    if (e>cnt)
      e=cnt;
    psync_sql_start_transaction();
    res=psync_sql_prep_statement("UPDATE pagecache SET type="NTO_STR(PAGE_TYPE_FREE)" WHERE id=?");
    for (; i<e; i++){
      psync_sql_bind_uint(res, 1, entries[i].id);
      psync_sql_run(res);
      free_db_pages++;
    }
    psync_sql_free_result(res);
    psync_sql_commit_transaction();
    psync_milisleep(20);
  }
  pthread_mutex_unlock(&clean_cache_mutex);
  psync_free(entries);
  debug(D_NOTICE, "finished cleaning cache, free cache pages %u", (unsigned)free_db_pages);
}

static int flush_pages(){
  static time_t lastflush=0;
  psync_sql_res *res;
  psync_uint_row row;
  psync_cache_page_t *page;
  psync_list pages_to_flush;
  psync_uint_t i, updates, pagecnt;
  time_t ctime;
  int ret;
  flushedbetweentimers=1;
  pthread_mutex_lock(&flush_cache_mutex);
  if (db_cache_max_page<db_cache_in_pages && cache_pages_in_hash){
    i=0;
    psync_sql_start_transaction();
    res=psync_sql_prep_statement("INSERT INTO pagecache (type) VALUES ("NTO_STR(PAGE_TYPE_FREE)")");
    while (db_cache_max_page+i<db_cache_in_pages && i<CACHE_PAGES && i<cache_pages_in_hash){
      psync_sql_run(res);
      i++;
    }
    psync_sql_free_result(res);
    if (!psync_sql_commit_transaction()){
      free_db_pages+=i;
      db_cache_max_page+=i;
      debug(D_NOTICE, "inserted %lu new free pages to database, db_cache_in_pages=%lu, db_cache_max_page=%lu", 
                      (unsigned long)i, (unsigned long)db_cache_in_pages, (unsigned long)db_cache_max_page);
    }
  }
  updates=0;
  pagecnt=0;
  ctime=psync_timer_time();
  psync_list_init(&pages_to_flush);
  pthread_mutex_lock(&cache_mutex);
  if (cache_pages_in_hash){
    res=psync_sql_query("SELECT id FROM pagecache WHERE type="NTO_STR(PAGE_TYPE_FREE)" ORDER BY id");
    for (i=0; i<CACHE_HASH; i++)
      psync_list_for_each_element(page, &cache_hash[i], psync_cache_page_t, list)
        if (page->type==PAGE_TYPE_READ){
          if (!(row=psync_sql_fetch_rowint(res)))
            goto break2;
          page->flushpageid=row[0];
          psync_list_add_tail(&pages_to_flush, &page->flushlist);
        }
break2:
    psync_sql_free_result(res);
    pthread_mutex_unlock(&cache_mutex);
    psync_list_for_each_element(page, &pages_to_flush, psync_cache_page_t, flushlist){
      if (psync_file_pwrite(readcache, page->page, PSYNC_FS_PAGE_SIZE, (uint64_t)page->flushpageid*PSYNC_FS_PAGE_SIZE)!=PSYNC_FS_PAGE_SIZE){
        debug(D_ERROR, "write to cache file failed");
        pthread_mutex_unlock(&flush_cache_mutex);
        return -1;
      }
    }
    if (psync_file_sync(readcache)){
      debug(D_ERROR, "flush of cache file failed");
      pthread_mutex_unlock(&flush_cache_mutex);
      return -1;
    }
    pthread_mutex_lock(&cache_mutex);
  }  
  psync_sql_start_transaction();
  if (cachepages_to_update_cnt && (cache_pages_in_hash || cachepages_to_update_cnt>=2048 || lastflush+300<ctime)){
    res=psync_sql_prep_statement("UPDATE pagecache SET lastuse=?, usecnt=usecnt+? WHERE id=?");
    for (i=0; i<DB_CACHE_UPDATE_HASH; i++)
      if (cachepages_to_update[i].pagecacheid){
        psync_sql_bind_uint(res, 1, cachepages_to_update[i].lastuse);
        psync_sql_bind_uint(res, 2, cachepages_to_update[i].usecnt);
        psync_sql_bind_uint(res, 3, cachepages_to_update[i].pagecacheid);
        psync_sql_run(res);
        updates++;
      }
    psync_sql_free_result(res);
    debug(D_NOTICE, "flushed %u access records to database", (unsigned)cachepages_to_update_cnt);
    cachepages_to_update_cnt=0;
    memset(cachepages_to_update, 0, sizeof(cachepages_to_update));
    lastflush=ctime;
  }
  if (!psync_list_isempty(&pages_to_flush)){
    res=psync_sql_prep_statement("UPDATE pagecache SET hash=?, pageid=?, type="NTO_STR(PAGE_TYPE_READ)", lastuse=?, usecnt=?, size=? WHERE id=?");
    psync_list_for_each_element(page, &pages_to_flush, psync_cache_page_t, flushlist){
      psync_list_del(&page->list);
      psync_sql_bind_uint(res, 1, page->hash);
      psync_sql_bind_uint(res, 2, page->pageid);
      psync_sql_bind_uint(res, 3, page->lastuse);
      psync_sql_bind_uint(res, 4, page->usecnt);
      psync_sql_bind_uint(res, 5, page->size);
      psync_sql_bind_uint(res, 6, page->flushpageid);
      psync_sql_run(res);
      updates++;
      pagecnt++;
      cache_pages_free++;
      free_db_pages--;
      psync_list_add_head(&free_pages, &page->list);
    }
    psync_sql_free_result(res);
    debug(D_NOTICE, "flushed %u pages to cache file, free db pages %u", (unsigned)pagecnt, (unsigned)free_db_pages);
    cache_pages_in_hash-=pagecnt;
  }
  flushchacherun=0;
  if (updates){
    ret=psync_sql_commit_transaction();
    pthread_mutex_unlock(&cache_mutex);
    pthread_mutex_unlock(&flush_cache_mutex);
    if (free_db_pages<=CACHE_PAGES*2)
      psync_run_thread("clean cache", clean_cache);
    return ret;
  }
  else{
    psync_sql_rollback_transaction();
    pthread_mutex_unlock(&cache_mutex);
    pthread_mutex_unlock(&flush_cache_mutex);
    return 0;
  }
}

int psync_pagecache_flush(){
  if (flush_pages())
    return -EIO;
  else
    return 0;
}

static void flush_pages_noret(){
  flush_pages();
}

static void psync_pagecache_flush_timer(psync_timer_t timer, void *ptr){
  if (!flushedbetweentimers)
    psync_run_thread("flush pages timer", flush_pages_noret);
  flushedbetweentimers=0;
}

static void mark_pagecache_used(uint64_t pagecacheid){
  uint64_t h;
  time_t tm;
  h=pagecacheid%DB_CACHE_UPDATE_HASH;
  tm=psync_timer_time();
  if (cachepages_to_update_cnt>DB_CACHE_UPDATE_HASH/2)
    flush_pages();
  pthread_mutex_lock(&cache_mutex);
  while (1){
    if (cachepages_to_update[h].pagecacheid==0){
      cachepages_to_update[h].pagecacheid=pagecacheid;
      cachepages_to_update[h].lastuse=tm;
      cachepages_to_update[h].usecnt=1;
      cachepages_to_update_cnt++;
      break;
    }
    else if (cachepages_to_update[h].pagecacheid==pagecacheid){
      if (tm>cachepages_to_update[h].lastuse+5){
        cachepages_to_update[h].lastuse=tm;
        cachepages_to_update[h].usecnt++;
      }
      break;
    }
    if (++h>=DB_CACHE_UPDATE_HASH)
      h=0;
  }
  pthread_mutex_unlock(&cache_mutex);
}

static psync_int_t check_page_in_database_by_hash(uint64_t hash, uint64_t pageid, char *buff, psync_uint_t size, psync_uint_t off){
  psync_sql_res *res;
  psync_variant_row row;
  size_t dsize;
  psync_int_t ret;
  uint64_t pagecacheid;
  ret=-1;
  res=psync_sql_query("SELECT id, size FROM pagecache WHERE type="NTO_STR(PAGE_TYPE_READ)" AND hash=? AND pageid=?");
  psync_sql_bind_uint(res, 1, hash);
  psync_sql_bind_uint(res, 2, pageid);
  if ((row=psync_sql_fetch_row(res))){
    pagecacheid=psync_get_number(row[0]);
    dsize=psync_get_number(row[1]);
    if (size+off>dsize){
      if (off>dsize)
        size=0;
      else
        size=dsize-off;
    }
    ret=size;
  }
  psync_sql_free_result(res);
  if (ret!=-1){
    if (psync_file_pread(readcache, buff, size, pagecacheid*PSYNC_FS_PAGE_SIZE+off)!=size){
      debug(D_ERROR, "failed to read %lu bytes from cache file at offset %lu", (unsigned long)size, (unsigned long)(pagecacheid*PSYNC_FS_PAGE_SIZE+off));
      res=psync_sql_prep_statement("UPDATE pagecache SET type="NTO_STR(PAGE_TYPE_READ)" WHERE id=?");
      psync_sql_bind_uint(res, 1, pagecacheid);
      psync_sql_run_free(res);
      ret=-1;
    }
    else
      mark_pagecache_used(pagecacheid);
  }
  return ret;
}

int psync_pagecache_read_modified_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset){
  pthread_mutex_unlock(&of->mutex);
  return -ENOSYS;
}

#define run_command_get_res(cmd, params) do_run_command_get_res(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam))

static binresult *do_run_command_get_res(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt){
  psync_socket *api;
  binresult *res;
  uint64_t result;
  api=psync_apipool_get();
  if (unlikely(!api))
    goto neterr;
  res=do_send_command(api, cmd, cmdlen, params, paramscnt, -1, 1);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_apipool_release_bad(api);
    psync_timer_notify_exception();
    goto neterr;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    debug(D_WARNING, "command %s returned code %u", cmd, (unsigned)result);
    psync_free(res);
    return NULL;
  }
  else
    return res;
neterr:
  return NULL;
}


static binresult *psync_pagecache_of_get_urls(psync_openfile_t *of){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", of->fileid), P_NUM("hash", of->hash), 
                     P_STR("timeformat", "timestamp"), P_BOOL("skipfilename", 1)};
  char buff[64];
  binresult *ret;
  sprintf(buff, "urls-%"PRIu64, of->hash);
  ret=(binresult *)psync_cache_get(buff);
  if (ret){
    debug(D_NOTICE, "got file URLS of fileid %lu, hash %lu from cache", (unsigned long)of->fileid, (unsigned long)of->hash);
    return ret;
  }
  debug(D_NOTICE, "getting file URLS of fileid %lu, hash %lu", (unsigned long)of->fileid, (unsigned long)of->hash);
  return run_command_get_res("getfilelink", params);
}

static int psync_pagecache_of_has_urls(psync_openfile_t *of){
  binresult *res;
  unsigned char st;
  pthread_mutex_lock(&of->mutex);
  if (of->urlsstatus==1){
    do {
      of->condwaiters++;
      pthread_cond_wait(&of->cond, &of->mutex);
      of->condwaiters--;
    } while (of->urlsstatus==1);
  }
  if (of->urlsstatus==2)
    st=2;
  else
    st=of->urlsstatus=1;
  pthread_mutex_unlock(&of->mutex);
  if (st==2)
    return 0;
  res=psync_pagecache_of_get_urls(of);
  pthread_mutex_lock(&of->mutex);
  if (res){
    of->urls=res;
    of->urlsstatus=2;
  }
  else
    of->urlsstatus=3;
  if (of->condwaiters)
    pthread_cond_broadcast(&of->cond);
  pthread_mutex_unlock(&of->mutex);
  if (res){
    debug(D_NOTICE, "got urls");
    return 0;
  }
  else
    return -EIO;
}

static void psync_pagecache_free_request(psync_request_t *request){
  psync_list_for_each_element_call(&request->ranges, psync_request_range_t, list, psync_free);
  psync_free(request);
}

static void psync_pagecache_send_error_page_wait(psync_page_wait_t *pw, int err){
  psync_page_waiter_t *pwt;
  psync_list_del(&pw->list);
  psync_list_for_each_element(pwt, &pw->waiters, psync_page_waiter_t, listpage){
    pwt->error=err;
    pwt->ready=1;
    pthread_cond_broadcast(&pwt->cond);
  }
  psync_free(pw);
}

static void psync_pagecache_send_range_error(psync_request_range_t *range, psync_request_t *request, int err){
  uint64_t first_page_id;
  psync_page_wait_t *pw;
  psync_uint_t len, i, h;
  first_page_id=range->offset/PSYNC_FS_PAGE_SIZE;
  len=range->length/PSYNC_FS_PAGE_SIZE;
  debug(D_NOTICE, "sending error %d to request for offset %lu, length %lu of fileid %lu hash %lu",
                  err, (unsigned long)range->offset, (unsigned long)range->length, (unsigned long)request->of->fileid, (unsigned long)request->of->hash);
  for (i=0; i<len; i++){
    h=waiterhash_by_hash_and_pageid(request->of->hash, first_page_id+i);
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t, list)
      if (pw->hash==request->of->hash && pw->pageid==first_page_id+i){
        psync_pagecache_send_error_page_wait(pw, err);
        break;
      }
  }
}

static void psync_pagecache_send_error(psync_request_t *request, int err){
  psync_request_range_t *range;
  lock_wait(request->of->hash);
  psync_list_for_each_element(range, &request->ranges, psync_request_range_t, list)
    psync_pagecache_send_range_error(range, request, err);
  unlock_wait(request->of->hash);
  psync_fs_dec_of_refcnt_and_readers(request->of);
  psync_pagecache_free_request(request);
}

static psync_cache_page_t *psync_pagecache_get_free_page(){
  psync_cache_page_t *page;
  pthread_mutex_lock(&cache_mutex);
  if (cache_pages_free<=CACHE_PAGES*10/100 && !flushchacherun){
    psync_run_thread("flush pages get free page", flush_pages_noret);
    flushchacherun=1;
  }
  if (likely(!psync_list_isempty(&free_pages)))
    page=psync_list_remove_head_element(&free_pages, psync_cache_page_t, list);
  else{
    debug(D_NOTICE, "no free pages, flushing cache");
    pthread_mutex_unlock(&cache_mutex);
    flush_pages();
    pthread_mutex_lock(&cache_mutex);
    while (unlikely(psync_list_isempty(&free_pages))){
      pthread_mutex_unlock(&cache_mutex);
      debug(D_NOTICE, "no free pages after flush, sleeping");
      psync_milisleep(200);
      pthread_mutex_lock(&cache_mutex);
      flush_pages();
    }
    page=psync_list_remove_head_element(&free_pages, psync_cache_page_t, list);
  }
  cache_pages_free--;
  pthread_mutex_unlock(&cache_mutex);
  return page;
}

static void psync_pagecache_return_free_page(psync_cache_page_t *page){
  pthread_mutex_lock(&cache_mutex);
  psync_list_add_head(&free_pages, &page->list);
  cache_pages_free++;
  pthread_mutex_unlock(&cache_mutex);
}

static void psync_pagecache_send_page_wait_page(psync_page_wait_t *pw, psync_cache_page_t *page){
  psync_page_waiter_t *pwt;
  psync_list_del(&pw->list);
  psync_list_for_each_element(pwt, &pw->waiters, psync_page_waiter_t, listpage){
    page->usecnt++;
    if (pwt->off+pwt->size>page->size){
      if (pwt->off>=page->size)
        pwt->rsize=0;
      else
        pwt->rsize=page->size-pwt->off;
    }
    else
      pwt->rsize=pwt->size;
    memcpy(pwt->buff, page->page+pwt->off, pwt->rsize);
    pwt->error=0;
    pwt->ready=1;
    pthread_cond_broadcast(&pwt->cond);
  }
  psync_free(pw);
}

static int psync_pagecache_read_range_from_sock(psync_request_t *request, psync_request_range_t *range, psync_http_socket *sock){
  uint64_t first_page_id;
  psync_page_wait_t *pw;
  psync_cache_page_t *page;
  psync_uint_t len, i, h;
  int rb;
  first_page_id=range->offset/PSYNC_FS_PAGE_SIZE;
  len=range->length/PSYNC_FS_PAGE_SIZE;
  if (unlikely_log(psync_http_next_request(sock)))
    return -1;
  for (i=0; i<len; i++){
    page=psync_pagecache_get_free_page();
    rb=psync_http_request_readall(sock, page->page, PSYNC_FS_PAGE_SIZE);
    if (unlikely_log(rb<=0)){
      psync_pagecache_return_free_page(page);
      psync_timer_notify_exception();
      return -1;
    }
    page->hash=request->of->hash;
    page->fileid=request->of->fileid;
    page->pageid=first_page_id+i;
    page->lastuse=psync_timer_time();
    page->size=rb;
    page->usecnt=0;
    page->type=PAGE_TYPE_READ;
    h=waiterhash_by_hash_and_pageid(page->hash, page->pageid);
    lock_wait(page->hash);
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t, list)
      if (pw->hash==page->hash && pw->pageid==page->pageid){
        psync_pagecache_send_page_wait_page(pw, page);
        break;
      }
    unlock_wait(page->hash);
    pthread_mutex_lock(&cache_mutex);
    psync_list_add_tail(&cache_hash[pagehash_by_hash_and_pageid(page->hash, page->pageid)], &page->list);
    cache_pages_in_hash++;
    pthread_mutex_unlock(&cache_mutex);
  }
  return 0;
}

static void psync_pagecache_read_unmodified_thread(void *ptr){
  psync_request_t *request;
  psync_http_socket *sock;
  const char *host;
  const char *path;
  psync_request_range_t *range;
  int err;
  request=(psync_request_t *)ptr;
  if (psync_status_get(PSTATUS_TYPE_ONLINE)==PSTATUS_ONLINE_OFFLINE){
    psync_pagecache_send_error(request, -ENOTCONN);
    return;
  }
  range=psync_list_element(request->ranges.next, psync_request_range_t, list);
  debug(D_NOTICE, "thread run, first offset %lu, size %lu", (unsigned long)range->offset, (unsigned long)range->length);
  if ((err=psync_pagecache_of_has_urls(request->of))){
    psync_pagecache_send_error(request, err);
    return;
  }
  sock=psync_http_connect_multihost(psync_find_result(request->of->urls, "hosts", PARAM_ARRAY), &host);
  if (unlikely_log(!sock))
    goto err0;
//  debug(D_NOTICE, "connected to %s", host);
  path=psync_find_result(request->of->urls, "path", PARAM_STR)->str;
  psync_list_for_each_element(range, &request->ranges, psync_request_range_t, list){
    debug(D_NOTICE, "sending request for offset %lu, size %lu", (unsigned long)range->offset, (unsigned long)range->length);
    if (psync_http_request(sock, host, path, range->offset, range->offset+range->length-1))
      goto err1;
  }
  psync_list_for_each_element(range, &request->ranges, psync_request_range_t, list)
    if (psync_pagecache_read_range_from_sock(request, range, sock))
      goto err1;
  psync_http_close(sock);
  psync_fs_dec_of_refcnt_and_readers(request->of);
  psync_pagecache_free_request(request);
  return;
err1:
  psync_http_close(sock);
err0:
  psync_pagecache_send_error(request, -EIO);
  return;
}

static void psync_pagecache_read_unmodified_readahead(psync_openfile_t *of, uint64_t offset, uint64_t size, psync_list *ranges, psync_request_range_t *range){
  uint64_t readahead, frompageoff, topageoff, first_page_id, rto;
  psync_int_t i, pagecnt, h, streamid;
  psync_page_wait_t *pw;
  unsigned char *pages_in_db;
  int found;
  if (offset+size>=of->initialsize)
    return;
  readahead=0;
  frompageoff=offset/PSYNC_FS_PAGE_SIZE;
  topageoff=((offset+size+PSYNC_FS_PAGE_SIZE-1)/PSYNC_FS_PAGE_SIZE)-1;
  for (streamid=0; streamid<PSYNC_FS_FILESTREAMS_CNT; streamid++)
    if (of->streams[streamid].frompage<=frompageoff && of->streams[streamid].topage+2>=frompageoff){
      of->streams[streamid].id=++of->laststreamid;
      readahead=of->streams[streamid].length;
      of->streams[streamid].frompage=frompageoff;
      of->streams[streamid].topage=topageoff;
      of->streams[streamid].length+=size;
      break;
    }
  if (streamid==PSYNC_FS_FILESTREAMS_CNT){
    uint64_t min;
    debug(D_NOTICE, "ran out of readahead streams");
    min=~(uint64_t)0;
    streamid=0;
    for (i=0; i<PSYNC_FS_FILESTREAMS_CNT; i++)
      if (of->streams[i].id<min){
        min=of->streams[i].id;
        streamid=i;
      }
    of->streams[streamid].id=++of->laststreamid;
    of->streams[streamid].frompage=frompageoff;
    of->streams[streamid].topage=topageoff;
    of->streams[streamid].length=size;
    of->streams[streamid].requestedto=0;
  }
  if (of->runningreads>=6 && !range)
    return;
  if (offset==0 && (size<PSYNC_FS_MIN_READAHEAD_START) && readahead<PSYNC_FS_MIN_READAHEAD_START-size)
    readahead=PSYNC_FS_MIN_READAHEAD_START-size;
  else if (offset==PSYNC_FS_MIN_READAHEAD_START/2 && readahead==PSYNC_FS_MIN_READAHEAD_START/2){
    of->streams[streamid].length+=offset;
    readahead=(PSYNC_FS_MIN_READAHEAD_START/2)*3;
  }
  else if (offset!=0 && (size<PSYNC_FS_MIN_READAHEAD_RAND) && readahead<PSYNC_FS_MIN_READAHEAD_RAND-size)
    readahead=PSYNC_FS_MIN_READAHEAD_RAND-size;
  if (readahead>PSYNC_FS_MAX_READAHEAD)
    readahead=PSYNC_FS_MAX_READAHEAD;
  if (readahead>=8192*1024)
    readahead=(readahead+offset+size)/(4*1024*1024)*(4*1024*1024)-offset-size;
  else if (readahead>=2048*1024)
    readahead=(readahead+offset+size)/(1024*1024)*(1024*1024)-offset-size;
  else if (readahead>=512*1024)
    readahead=(readahead+offset+size)/(256*1024)*(256*1024)-offset-size;
  else if (readahead>=128*1024)
    readahead=(readahead+offset+size)/(64*1024)*(64*1024)-offset-size;
  if (offset+size+readahead>of->initialsize)
    readahead=size_round_up_to_page(of->initialsize-offset-size);
  rto=of->streams[streamid].requestedto;
  if (rto<offset+size+readahead)
    of->streams[streamid].requestedto=offset+size+readahead;
//  debug(D_NOTICE, "readahead=%lu, rto=%lu, offset=%lu, size=%lu", (long unsigned)readahead, (unsigned long)rto, (unsigned long)offset, (unsigned long)size);
//  debug(D_NOTICE, "rto=%lu", rto);
  if (rto>offset+size){
    if (rto>offset+size+readahead)
      return;
    first_page_id=rto/PSYNC_FS_PAGE_SIZE;
    pagecnt=(offset+size+readahead-rto)/PSYNC_FS_PAGE_SIZE;
  }
  else{
    first_page_id=(offset+size)/PSYNC_FS_PAGE_SIZE;
    pagecnt=readahead/PSYNC_FS_PAGE_SIZE;
  }
  pages_in_db=has_pages_in_db(of->hash, first_page_id, pagecnt);
  for (i=0; i<pagecnt; i++){
    if (pages_in_db[i])
      continue;
    if (has_page_in_cache_by_hash(of->hash, first_page_id+i))
      continue;
    h=waiterhash_by_hash_and_pageid(of->hash, first_page_id+i);
    found=0;
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t, list)
      if (pw->hash==of->hash && pw->pageid==first_page_id+i)        
        found=1;
    if (found)
      continue; 
//    debug(D_NOTICE, "read-aheading page %lu", first_page_id+i);
    pw=psync_new(psync_page_wait_t);
    psync_list_add_tail(&wait_page_hash[h], &pw->list);
    psync_list_init(&pw->waiters);
    pw->hash=of->hash;
    pw->pageid=first_page_id+i;
    pw->fileid=of->fileid;
    if (range && range->offset+range->length==(first_page_id+i)*PSYNC_FS_PAGE_SIZE)
      range->length+=PSYNC_FS_PAGE_SIZE;
    else{
      range=psync_new(psync_request_range_t);
      psync_list_add_tail(ranges, &range->list);
      range->offset=(first_page_id+i)*PSYNC_FS_PAGE_SIZE;
      range->length=PSYNC_FS_PAGE_SIZE;
    }
  }
  psync_free(pages_in_db);
}

static void psync_free_page_waiter(psync_page_waiter_t *pwt){
  pthread_cond_destroy(&pwt->cond);
  psync_free(pwt);
}

int psync_pagecache_read_unmodified(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset){
  uint64_t poffset, psize, first_page_id;
  psync_uint_t pageoff, pagecnt, i, copysize, copyoff;
  psync_int_t rb, h;
  char *pbuff;
  psync_page_waiter_t *pwt;
  psync_page_wait_t *pw;
  psync_request_t *rq;
  psync_request_range_t *range;
  psync_list waiting;
  int ret;
  if (offset>=of->initialsize)
    return 0;
  if (offset+size>of->initialsize)
    size=of->initialsize-offset;
  poffset=offset_round_down_to_page(offset);
  pageoff=offset-poffset;
  psize=size_round_up_to_page(size+pageoff);
  pagecnt=psize/PSYNC_FS_PAGE_SIZE;
  first_page_id=poffset/PSYNC_FS_PAGE_SIZE;
  psync_list_init(&waiting);
  rq=psync_new(psync_request_t);
  psync_list_init(&rq->ranges);
  range=NULL;
  lock_wait(of->hash);
  for (i=0; i<pagecnt; i++){
    if (i==0){
      copyoff=pageoff;
      if (size>PSYNC_FS_PAGE_SIZE-copyoff)
        copysize=PSYNC_FS_PAGE_SIZE-copyoff;
      else
        copysize=size;
      pbuff=buf;
    }
    else if (i==pagecnt-1){
      copyoff=0;
      copysize=(size+pageoff)&(PSYNC_FS_PAGE_SIZE-1);
      if (!copysize)
        copysize=PSYNC_FS_PAGE_SIZE;
      pbuff=buf+i*PSYNC_FS_PAGE_SIZE-pageoff;
    }
    else{
      copyoff=0;
      copysize=PSYNC_FS_PAGE_SIZE;
      pbuff=buf+i*PSYNC_FS_PAGE_SIZE-pageoff;
    }
    rb=check_page_in_memory_by_hash(of->hash, first_page_id+i, pbuff, copysize, copyoff);
    if (rb==-1)
      rb=check_page_in_database_by_hash(of->hash, first_page_id+i, pbuff, copysize, copyoff);
    if (rb!=-1){
      if (rb==copysize)
        continue;
      else{
        if (i)
          size=i*PSYNC_FS_PAGE_SIZE+rb-pageoff;
        else
          size=rb;
        break;
      }
    }
    pwt=psync_new(psync_page_waiter_t);
    pthread_cond_init(&pwt->cond, NULL);
    pwt->buff=pbuff;
    pwt->pageidx=i;
    pwt->off=copyoff;
    pwt->size=copysize;
    pwt->error=0;
    pwt->ready=0;
    psync_list_add_tail(&waiting, &pwt->listwaiter);
    h=waiterhash_by_hash_and_pageid(of->hash, first_page_id+i);
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t, list)
      if (pw->hash==of->hash && pw->pageid==first_page_id+i)        
        goto found;
    debug(D_NOTICE, "page %lu not found", first_page_id+i);
    pw=psync_new(psync_page_wait_t);
    psync_list_add_tail(&wait_page_hash[h], &pw->list);
    psync_list_init(&pw->waiters);
    pw->hash=of->hash;
    pw->pageid=first_page_id+i;
    pw->fileid=of->fileid;
    if (range && range->offset+range->length==(first_page_id+i)*PSYNC_FS_PAGE_SIZE)
      range->length+=PSYNC_FS_PAGE_SIZE;
    else{
      range=psync_new(psync_request_range_t);
      psync_list_add_tail(&rq->ranges, &range->list);
      range->offset=(first_page_id+i)*PSYNC_FS_PAGE_SIZE;
      range->length=PSYNC_FS_PAGE_SIZE;
    }
found:
    psync_list_add_tail(&pw->waiters, &pwt->listpage);
    pwt->waiting_for=pw;
  }
  psync_pagecache_read_unmodified_readahead(of, poffset, psize, &rq->ranges, range);
  if (!psync_list_isempty(&rq->ranges)){
    unlock_wait(of->hash);
    rq->of=of;
    psync_fs_inc_of_refcnt_and_readers(of);
    psync_run_thread1("read unmodified", psync_pagecache_read_unmodified_thread, rq);
    if (psync_list_isempty(&waiting))
      return size;
    lock_wait(of->hash);
  }
  else
    psync_free(rq);
  ret=size;
  if (!psync_list_isempty(&waiting)){
    psync_list_for_each_element(pwt, &waiting, psync_page_waiter_t, listwaiter){
      while (!pwt->ready)
        pthread_cond_wait(&pwt->cond, &wait_page_mutexes[waiter_mutex_by_hash(of->hash)]);
      if (pwt->error)
        ret=pwt->error;
      else if (pwt->rsize<pwt->size && ret>=0){
        if (pwt->rsize){
          if (pwt->pageidx)
            ret=pwt->pageidx*PSYNC_FS_PAGE_SIZE+pwt->rsize-pageoff;
          else
            ret=pwt->rsize;
        }
        else{
          if (pwt->pageidx){
            if (pwt->pageidx*PSYNC_FS_PAGE_SIZE+pwt->rsize-pageoff<ret)
              ret=pwt->pageidx*PSYNC_FS_PAGE_SIZE+pwt->rsize-pageoff;
          }
          else
            ret=pwt->rsize;
        }
      }
    }
    psync_list_for_each_element_call(&waiting, psync_page_waiter_t, listwaiter, psync_free_page_waiter);
  }
  unlock_wait(of->hash);
  return ret;
}

static void delete_extra_pages(){
  pthread_mutex_lock(&flush_cache_mutex);
  if (db_cache_max_page>db_cache_in_pages){
    psync_sql_res *res;
    psync_stat_t st;
    res=psync_sql_prep_statement("DELETE FROM pagecache ORDER BY id DESC LIMIT ?");
    psync_sql_bind_uint(res, 1, db_cache_in_pages-db_cache_max_page);
    psync_sql_run_free(res);
    db_cache_max_page=db_cache_in_pages;
    if (!psync_fstat(readcache, &st) && psync_stat_size(&st)>db_cache_in_pages*PSYNC_FS_PAGE_SIZE){
      if (likely_log(psync_file_seek(readcache, db_cache_in_pages*PSYNC_FS_PAGE_SIZE, P_SEEK_SET)!=-1))
        assertw(psync_file_truncate(readcache)==0);
    }
  }
  pthread_mutex_unlock(&flush_cache_mutex);
}

void psync_pagecache_init(){
  uint64_t i;
  char *page_data, *cache_file;
  const char *cache_dir;
  psync_sql_res *res;
  psync_cache_page_t *page;
  psync_stat_t st;
  for (i=0; i<CACHE_HASH; i++)
    psync_list_init(&cache_hash[i]);
  for (i=0; i<PAGE_WAITER_HASH; i++)
    psync_list_init(&wait_page_hash[i]);
  for (i=0; i<PAGE_WAITER_MUTEXES; i++)
    pthread_mutex_init(&wait_page_mutexes[i], NULL);
  psync_list_init(&free_pages);
  memset(cachepages_to_update, 0, sizeof(cachepages_to_update));
  pages_base=(char *)psync_malloc(CACHE_PAGES*(PSYNC_FS_PAGE_SIZE+sizeof(psync_cache_page_t)));
  page_data=pages_base;
  page=(psync_cache_page_t *)(page_data+CACHE_PAGES*PSYNC_FS_PAGE_SIZE);
  cache_pages_free=CACHE_PAGES;
  for (i=0; i<CACHE_PAGES; i++){
    page->page=page_data;
    psync_list_add_tail(&free_pages, &page->list);
    page_data+=PSYNC_FS_PAGE_SIZE;
    page++;
  }
  cache_dir=psync_setting_get_string(_PS(fscachepath));
  if (psync_stat(cache_dir, &st))
    psync_mkdir(cache_dir);
  cache_file=psync_strcat(cache_dir, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_READ_CACHE_FILE, NULL);
  if (psync_stat(cache_file, &st))
    psync_sql_statement("DELETE FROM pagecache");
  else{
    res=psync_sql_prep_statement("DELETE FROM pagecache WHERE id>? AND type!="NTO_STR(PAGE_TYPE_FREE));
    psync_sql_bind_uint(res, 1, psync_stat_size(&st)/PSYNC_FS_PAGE_SIZE);
    psync_sql_run_free(res);
  }
  db_cache_in_pages=psync_setting_get_uint(_PS(fscachesize))/PSYNC_FS_PAGE_SIZE;
  db_cache_max_page=psync_sql_cellint("SELECT MAX(id) FROM pagecache", 0);
  readcache=psync_file_open(cache_file, P_O_RDWR, P_O_CREAT);
  if (db_cache_max_page>db_cache_in_pages)
    delete_extra_pages();
  free_db_pages=psync_sql_cellint("SELECT COUNT(*) FROM pagecache WHERE type="NTO_STR(PAGE_TYPE_FREE), 0);
  psync_timer_register(psync_pagecache_flush_timer, PSYNC_FS_DISK_FLUSH_SEC, NULL);
}

