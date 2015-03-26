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

#include "pmemlock.h"
#include "pcompat.h"
#include "ptree.h"
#include "pintervaltree.h"
#include "plibs.h"
#include "pcloudcrypto.h"
#include <stdint.h>

typedef uintptr_t pageid_t;
typedef struct {
  psync_tree tree;
  pageid_t pageid;
  unsigned long refcnt;
} locked_page_t;

typedef struct {
  psync_tree tree;
  psync_interval_tree_t *freeintervals;
  char *mem;
  size_t size;
  int locked;
} allocator_range;

static pthread_mutex_t page_mutex=PTHREAD_MUTEX_INITIALIZER;
static psync_tree *locked_pages=PSYNC_TREE_EMPTY;

static pthread_mutex_t allocator_mutex;
static psync_tree *allocator_ranges=PSYNC_TREE_EMPTY;

void psync_locked_init(){
  pthread_mutexattr_t mattr;
  pthread_mutexattr_init(&mattr);
  pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&allocator_mutex, &mattr);
  pthread_mutexattr_destroy(&mattr);
}

static int lock_page(pageid_t pageid, int page_size){
  psync_tree *tr, **addto;
  locked_page_t *node;
  int found, ret, tryn;
  found=0;
  ret=0;
  tryn=0;
retry:
  pthread_mutex_lock(&page_mutex);
  tr=locked_pages;
  if (tr){
    while (1){
      node=psync_tree_element(tr, locked_page_t, tree);
      if (pageid<node->pageid){
        if (tr->left)
          tr=tr->left;
        else{
          addto=&tr->left;
          break;
        }
      }
      else if (pageid>node->pageid){
        if (tr->right)
          tr=tr->right;
        else{
          addto=&tr->right;
          break;
        }
      }
      else{
        found=1;
        break;
      }
    }
  }
  else
    addto=&locked_pages;
  if (found){
    node->refcnt++;
    debug(D_NOTICE, "page %lx is already locked, increasing refcnt to %u", (unsigned long)pageid*page_size, (unsigned)node->refcnt);
  }
  else{
    // Well, we can move the locking out of mutex protected area, but to do properly, an status "in progress" should be introduced for new elements in the tree
    // that mlock is yet not returned. This will complicate things a lot.
    if (unlikely(psync_mlock((void *)(pageid*page_size), page_size))){
      if (!tryn){
        tryn++;
        pthread_mutex_unlock(&page_mutex);
        debug(D_NOTICE, "mlock failed, trying to clean cache");
        psync_cloud_crypto_clean_cache();
        goto retry;
      }
      else{
        debug(D_WARNING, "mlock for page %lx failed even after cache clean", (unsigned long)pageid*page_size);
        ret=-1;
      }
    }
    else{
      debug(D_NOTICE, "locked page %lx", (unsigned long)pageid*page_size);
      node=psync_new(locked_page_t);
      node->pageid=pageid;
      node->refcnt=1;
      *addto=&node->tree;
      psync_tree_added_at(&locked_pages, tr, &node->tree);
    }
  }
  pthread_mutex_unlock(&page_mutex);
  return ret;
}

static int unlock_page(pageid_t pageid, int page_size){
  psync_tree *tr;
  locked_page_t *node;
  int ret;
  pthread_mutex_lock(&page_mutex);
  tr=locked_pages;
  while (tr){
    node=psync_tree_element(tr, locked_page_t, tree);
    if (pageid<node->pageid)
      tr=tr->left;
    else if (pageid>node->pageid)
      tr=tr->right;
    else
      break;
  }
  if (likely(tr)){
    if (--node->refcnt){
      debug(D_NOTICE, "decreased refcnt of page %lx to %u", (unsigned long)pageid*page_size, (unsigned)node->refcnt);
      ret=0;
    }
    else{
      psync_tree_del(&locked_pages, tr);
      psync_free(node);
      // do not move out of the mutex, will create race conditions
      if (unlikely(psync_munlock((void *)(pageid*page_size), page_size)))
        ret=PRINT_RETURN(-1);
      else{
        debug(D_NOTICE, "unlocked page %lx", (unsigned long)pageid*page_size);
        ret=0;
      }
    }
  }
  else{
    ret=-1;
    debug(D_WARNING, "unlocking page %lx that is not locked", (unsigned long)pageid*page_size);
  }
  pthread_mutex_unlock(&page_mutex);
  return ret;
}

int psync_mem_lock(void *ptr, size_t size){
  pageid_t frompage, topage, i;
  int page_size;
  page_size=psync_get_page_size();
  if (page_size==-1)
    return PRINT_RETURN(-1);
  frompage=(uintptr_t)ptr/page_size;
  topage=((uintptr_t)ptr+size-1)/page_size;
  for (i=frompage; i<=topage; i++)
    if (unlikely(lock_page(i, page_size))){
      while (i>frompage)
        unlock_page(--i, page_size);
      return PRINT_RETURN(-1);
    }
  return 0;
}

int psync_mem_unlock(void *ptr, size_t size){
  pageid_t frompage, topage, i;
  int page_size, ret;
  page_size=psync_get_page_size();
  if (page_size==-1)
    return PRINT_RETURN(-1);
  frompage=(uintptr_t)ptr/page_size;
  topage=((uintptr_t)ptr+size-1)/page_size;
  ret=0;
  for (i=frompage; i<=topage; i++)
    if (unlikely(unlock_page(i, page_size)))
      ret=PRINT_RETURN(-1);
  return ret;
}

#define LM_ALIGN_TO (sizeof(size_t)*2)
#define LM_OVERHEAD (sizeof(size_t)*2)
#define LM_RANGE_OVERHEAD (LM_ALIGN_TO-sizeof(size_t))
#define LM_END_MARKER (~((size_t)0))

#if IS_DEBUG
static void mark_aligment_bytes(char *ptr, size_t from, size_t to){
  size_t i;
  for (i=from; i<to; i++)
    ((unsigned char *)ptr)[i]=((size_t)0xff+from-i)&0xff;
}
#endif

void *psync_locked_malloc(size_t size){
  allocator_range *range, *brange;
  psync_tree *tr, **addto;
  psync_interval_tree_t *interval;
  char *ret;
  uint64_t boffset;
  size_t intsize, bestsize;
#if IS_DEBUG
  size_t origsize=size;
#endif
  int page_size;
  size=((size+LM_ALIGN_TO-1))/LM_ALIGN_TO*LM_ALIGN_TO+LM_OVERHEAD;
#if IS_DEBUG
  debug(D_NOTICE, "size=%lu, size with overhead=%lu", (unsigned long)origsize, (unsigned long)size);
#endif
  bestsize=~((size_t)0);
  brange=NULL;
  boffset=0; // just to make compilers happy
  // psync_mem_lock may call psync_cloud_crypto_clean_cache(), which in turn can call psync_locked_free() on few pointers, therefore
  // allocator_mutex is recursive
  pthread_mutex_lock(&allocator_mutex);
  psync_tree_for_each_element(range, allocator_ranges, allocator_range, tree)
    psync_interval_tree_for_each(interval, range->freeintervals){
      intsize=interval->to-interval->from;
      if (intsize>=size && intsize<bestsize){
        bestsize=intsize;
        brange=range;
        boffset=interval->from;
        if (intsize==size)
          goto foundneededsize;
      }
    }
  if (brange){
foundneededsize:
    if (unlikely(!brange->locked))
      if (!psync_mem_lock(brange->mem, brange->size))
        brange->locked=1;
    psync_interval_tree_remove(&brange->freeintervals, boffset, boffset+size);
    ret=brange->mem+boffset;
#if IS_DEBUG
    *((size_t *)ret)=origsize;
#else
    *((size_t *)ret)=size;
#endif
    *((size_t *)(ret+size-sizeof(size_t)))=LM_END_MARKER;
    ret+=sizeof(size_t);
#if IS_DEBUG
    mark_aligment_bytes(ret, origsize, size-LM_OVERHEAD);
#endif
  }
  else
    ret=NULL;
  pthread_mutex_unlock(&allocator_mutex);
  if (ret)
    return ret;
  page_size=psync_get_page_size();
  if (unlikely(page_size==-1))
    page_size=4096;
  intsize=(size+LM_RANGE_OVERHEAD+page_size-1)/page_size*page_size;
  brange=psync_new(allocator_range);
  brange->freeintervals=NULL;
  brange->mem=psync_mmap_anon_safe(intsize);
  brange->size=intsize;
  debug(D_NOTICE, "allocating new locked block of size %lu at %p", (unsigned long)intsize, brange->mem);
  if (unlikely(psync_mem_lock(brange->mem, intsize))){
    brange->locked=0;
    debug(D_WARNING, "could not lock %lu bytes in memory", (unsigned long)intsize);
  }
  else
    brange->locked=1;
  if (intsize>size+LM_RANGE_OVERHEAD)
    psync_interval_tree_add(&brange->freeintervals, LM_RANGE_OVERHEAD+size, intsize);
  ret=brange->mem+LM_RANGE_OVERHEAD;
#if IS_DEBUG
  *((size_t *)ret)=origsize;
#else
  *((size_t *)ret)=size;
#endif
  *((size_t *)(ret+size-sizeof(size_t)))=LM_END_MARKER;
  ret+=sizeof(size_t);
#if IS_DEBUG
  mark_aligment_bytes(ret, origsize, size-LM_OVERHEAD);
#endif
  pthread_mutex_lock(&allocator_mutex);
  tr=allocator_ranges;
  if (tr){
    while (1){
      range=psync_tree_element(tr, allocator_range, tree);
      if (brange->mem<range->mem){
        assert(brange->mem+brange->size<=range->mem);
        if (tr->left)
          tr=tr->left;
        else{
          addto=&tr->left;
          break;
        }
      }
      else{
        assert(range->mem+range->size<=brange->mem);
        if (tr->right)
          tr=tr->right;
        else{
          addto=&tr->right;
          break;
        }
      }
    }
  }
  else
    addto=&allocator_ranges;
  *addto=&brange->tree;
  psync_tree_added_at(&allocator_ranges, tr, &brange->tree);
  pthread_mutex_unlock(&allocator_mutex);
  return ret;
}

void psync_locked_free(void *ptr){
  allocator_range *range;
  psync_tree *tr;
  char *cptr;
  size_t size;
#if IS_DEBUG
  size_t origsize, i;
#endif
  cptr=((char *)ptr)-sizeof(size_t);
  size=*((size_t *)cptr);
#if IS_DEBUG
  origsize=size;
  size=((size+LM_ALIGN_TO-1))/LM_ALIGN_TO*LM_ALIGN_TO;
  debug(D_NOTICE, "size=%lu", (unsigned long)origsize);
  for (i=origsize; i<size; i++)
    assert(((unsigned char *)ptr)[i]==(((size_t)0xff+origsize-i)&0xff));
  size+=LM_OVERHEAD;
#endif
  assert(*((size_t *)(cptr+size-sizeof(size_t)))==LM_END_MARKER);
  pthread_mutex_lock(&allocator_mutex);
  tr=allocator_ranges;
  while (tr){
    range=psync_tree_element(tr, allocator_range, tree);
    if (cptr<range->mem)
      tr=tr->left;
    else if (cptr>=range->mem+range->size)
      tr=tr->right;
    else
      goto found;
  }
  debug(D_CRITICAL, "freeing memory at %p not found in any range", ptr);
  abort();
found:
  psync_interval_tree_add(&range->freeintervals, cptr-range->mem, cptr-range->mem+size);
  if (range->freeintervals->from==LM_RANGE_OVERHEAD && range->freeintervals->to==range->size)
    psync_tree_del(&allocator_ranges, &range->tree);
  else
    range=NULL;
  pthread_mutex_unlock(&allocator_mutex);
  if (range){
    debug(D_NOTICE, "freeing block of size %lu at %p", (unsigned long)range->size, range->mem);
    if (range->locked)
      psync_mem_unlock(range->mem, range->size);
    psync_munmap_anon(range->mem, range->size);
    psync_free(range);
  }
}
