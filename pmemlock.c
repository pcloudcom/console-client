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
#include "plibs.h"
#include "pcloudcrypto.h"
#include <stdint.h>

typedef uintptr_t pageid_t;
typedef struct {
  psync_tree tree;
  pageid_t pageid;
  unsigned long refcnt;
} locked_page_t;

static pthread_mutex_t page_mutex=PTHREAD_MUTEX_INITIALIZER;
static psync_tree *locked_pages=PSYNC_TREE_EMPTY;

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
  topage=((uintptr_t)ptr+size)/page_size;
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
  topage=((uintptr_t)ptr+size)/page_size;
  ret=0;
  for (i=frompage; i<=topage; i++)
    if (unlikely(unlock_page(i, page_size)))
      ret=PRINT_RETURN(-1);
  return ret;
}
