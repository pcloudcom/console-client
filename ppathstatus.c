/* Copyright (c) 2016 Anton Titov.
 * Copyright (c) 2016 pCloud Ltd.
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

#include "ppathstatus.h"
#include "plist.h"
#include "plibs.h"
#include "pfs.h"
#include "pfolder.h"
#include "pcloudcrypto.h"
#include <string.h>
#include <ctype.h>

#define PATH_CACHE_SIZE 512
#define PATH_HASH_SIZE 512

#define PARENT_CACHE_SIZE 128
#define PARENT_HASH_SIZE 128

#define FOLDER_TASKS_HASH_SIZE 1024

#define ENTRY_FLAG_FOLDER    1
#define ENTRY_FLAG_ENCRYPTED 2

typedef struct {
  uint32_t hash[4];
  psync_list list_hash;
  psync_list list_lru;
  int64_t itemid;
  uint64_t flags;
} path_cache_entry_t;

typedef struct {
  psync_folderid_t folderid;
  psync_folderid_t parentfolderid;
  psync_list list_hash;
  psync_list list_lru;
} parent_cache_entry_t;

typedef struct _folder_tasks_t {
  psync_folderid_t folderid;
  struct _folder_tasks_t *hash_next;
  uint32_t child_task_cnt;
  uint32_t own_tasks; // this is not a count (just 0 or 1), so can be changed to a "flags" with multiple flags if needed
} folder_tasks_t;

typedef struct {
  char *path;
  size_t path_len;
  psync_folderid_t folderid;
  psync_syncid_t syncid;
  uint32_t flags;
} path_sync_list_entry_t;

typedef struct {
  size_t sync_cnt;
  path_sync_list_entry_t syncs[];
} path_sync_list_t;

static char *drive_path=NULL;
static size_t drive_path_len;
static path_sync_list_t *syncs=NULL;

static uint64_t drv_hash_seed;
static uint64_t sync_hash_seed;
static psync_list cache_free;
static psync_list path_cache_lru;
static psync_list path_cache_hash[PATH_HASH_SIZE];
static path_cache_entry_t path_cache_entries[PATH_CACHE_SIZE];
static psync_list parent_cache_lru;
static psync_list parent_cache_hash[PARENT_HASH_SIZE];
static parent_cache_entry_t parent_cache_entries[PARENT_CACHE_SIZE];
static folder_tasks_t *folder_tasks_hash[FOLDER_TASKS_HASH_SIZE];

void psync_path_status_init() {
  size_t i;
  psync_sql_lock();
  psync_list_init(&cache_free);
  psync_list_init(&path_cache_lru);
  psync_list_init(&parent_cache_lru);
  for (i=0; i<PATH_HASH_SIZE; i++)
    psync_list_init(&path_cache_hash[i]);
  for (i=0; i<PATH_CACHE_SIZE; i++) {
    psync_list_add_tail(&path_cache_lru, &path_cache_entries[i].list_lru);
    psync_list_add_tail(&cache_free, &path_cache_entries[i].list_hash);
  }
  for (i=0; i<PARENT_HASH_SIZE; i++)
     psync_list_init(&parent_cache_hash[i]);
  for (i=0; i<PARENT_CACHE_SIZE; i++) {
    psync_list_add_tail(&parent_cache_lru, &parent_cache_entries[i].list_lru);
    psync_list_add_tail(&cache_free, &parent_cache_entries[i].list_hash);
  }
  for (i=0; i<FOLDER_TASKS_HASH_SIZE; i++) {
    while (folder_tasks_hash[i]) {
      folder_tasks_t *t=folder_tasks_hash[i]->hash_next;
      psync_free(folder_tasks_hash[i]);
      folder_tasks_hash[i]=t;
    }
  }
  psync_path_status_reload_syncs();
  psync_path_status_clear_path_cache();
  psync_sql_unlock();
}

static int create_sync_list_entry(psync_list_builder_t *builder, void *element, psync_variant_row row){
  path_sync_list_entry_t *entry;
  const char *str;
  size_t len;
  entry=(path_sync_list_entry_t *)element;
  str=psync_get_lstring(row[0], &len);
  entry->path=(char *)str;
  entry->path_len=len;
  psync_list_add_lstring_offset(builder, offsetof(path_sync_list_entry_t, path), len);
  entry->syncid=psync_get_number(row[1]);
  entry->folderid=psync_get_number(row[2]);
  entry->flags=0;
  return 0;
}

void psync_path_status_reload_syncs() {
  psync_list_builder_t *builder;
  psync_sql_res *res;
  path_sync_list_t *old;
  psync_sql_lock();
  builder=psync_list_builder_create(sizeof(path_sync_list_entry_t), offsetof(path_sync_list_t, syncs));
  res=psync_sql_query_nolock("SELECT sf.localpath, sf.id, sf.folderid, f.flags FROM syncfolder sf, folder f WHERE sf.folderid=f.id");
  psync_list_bulder_add_sql(builder, res, create_sync_list_entry);
  old=syncs;
  syncs=(path_sync_list_t *)psync_list_builder_finalize(builder);
  psync_path_status_clear_sync_path_cache();
  psync_sql_unlock();
  if (old)
    psync_free_after_sec(old, 30);
}

void psync_path_status_clear_path_cache() {
  uint64_t ndrv_hash_seed, nsync_hash_seed;
  do {
    psync_ssl_rand_strong((unsigned char *)&ndrv_hash_seed, sizeof(ndrv_hash_seed));
  } while (unlikely(!ndrv_hash_seed));
  nsync_hash_seed=0x49916a8e891d1dafULL*ndrv_hash_seed;
  psync_sql_lock();
  drv_hash_seed=ndrv_hash_seed;
  sync_hash_seed=nsync_hash_seed;
  psync_sql_unlock();
}

void psync_path_status_clear_sync_path_cache() {
  uint64_t nsync_hash_seed;
  do {
    psync_ssl_rand_strong((unsigned char *)&nsync_hash_seed, sizeof(nsync_hash_seed));
  } while (unlikely(nsync_hash_seed==drv_hash_seed));
  psync_sql_lock();
  sync_hash_seed=nsync_hash_seed;
  psync_sql_unlock();
}

static uint32_t hash_folderid(psync_folderid_t folderid) {
  uint32_t h;
  h=(uint32_t)folderid;
  h*=0x4c8cbb55;
  h^=h>>19;
  return h;
}

void psync_path_status_del_from_parent_cache(psync_folderid_t folderid) {
  parent_cache_entry_t *p;
  uint32_t h;
  h=hash_folderid(folderid)%PARENT_HASH_SIZE;
  psync_list_for_each_element (p, &parent_cache_hash[h], parent_cache_entry_t, list_hash)
    if (p->folderid==folderid) {
      psync_list_del(&p->list_lru);
      psync_list_add_head(&parent_cache_lru, &p->list_lru);
      psync_list_del(&p->list_hash);
      psync_list_add_tail(&cache_free, &p->list_hash);
      break;
    }
}

static folder_tasks_t *get_folder_tasks(psync_folderid_t folderid, int create) {
  folder_tasks_t *ft;
  uint32_t h;
  h=hash_folderid(folderid)%FOLDER_TASKS_HASH_SIZE;
  ft=folder_tasks_hash[h];
  while (ft) {
    if (ft->folderid==folderid)
      return ft;
    ft=ft->hash_next;
  }
  if (create) {
    ft=psync_new(folder_tasks_t);
    ft->folderid=folderid;
    ft->hash_next=folder_tasks_hash[h];
    ft->child_task_cnt=0;
    ft->own_tasks=0;
    folder_tasks_hash[h]=ft;
    debug(D_NOTICE, "marking folderid %lu as having (sub)tasks", (unsigned long)folderid);
    return ft;
  } else {
    return NULL;
  }
}

static void free_folder_tasks(folder_tasks_t *ft) {
  folder_tasks_t *f, **pf;
  uint32_t h;
  debug(D_NOTICE, "marking folderid %lu as clean", (unsigned long)ft->folderid);
  h=hash_folderid(ft->folderid)%FOLDER_TASKS_HASH_SIZE;
  f=folder_tasks_hash[h];
  pf=&folder_tasks_hash[h];
  while (ft!=f) { // if we crash here, the problem is elsewhere, do not change to check for if f is NULL
    pf=&f->hash_next;
    f=f->hash_next;
  }
  *pf=f->hash_next;
  psync_free(f);
}

static psync_folderid_t get_parent_folder(psync_folderid_t folderid) {
  psync_sql_res *res;
  psync_uint_row row;
  parent_cache_entry_t *p;
  uint32_t h;
  h=hash_folderid(folderid)%PARENT_HASH_SIZE;
  psync_list_for_each_element (p, &parent_cache_hash[h], parent_cache_entry_t, list_hash)
    if (p->folderid==folderid) {
      psync_list_del(&p->list_lru);
      psync_list_add_tail(&parent_cache_lru, &p->list_lru);
      return p->parentfolderid;
    }
  res=psync_sql_query_nolock("SELECT parentfolderid FROM folder WHERE id=?");
  psync_sql_bind_uint(res, 1, folderid);
  row=psync_sql_fetch_rowint(res);
  if (unlikely(!row)) {
    debug(D_ERROR, "can not find parent folder for folderid %lu", (unsigned long)folderid);
    psync_sql_free_result(res);
    return 0;
  }
  p=psync_list_remove_head_element(&parent_cache_lru, parent_cache_entry_t, list_lru);
  psync_list_del(&p->list_hash);
  p->folderid=folderid;
  p->parentfolderid=row[0];
  psync_list_add_head(&parent_cache_hash[h], &p->list_hash);
  psync_list_add_tail(&parent_cache_lru, &p->list_lru);
  psync_sql_free_result(res);
  return p->parentfolderid;
}

void psync_path_status_drive_folder_changed(psync_folderid_t folderid) {
  psync_fstask_folder_t *folder;
  folder_tasks_t *ft;
  int changed;
  psync_sql_lock();
  folder=psync_fstask_get_folder_tasks_rdlocked(folderid);
  changed=folder && (folder->creats || folder->mkdirs);
  ft=get_folder_tasks(folderid, changed);
  if ((!changed && (!ft || ft->child_task_cnt)) || (changed && (ft->own_tasks || ft->child_task_cnt))) {
    if (changed && !ft->own_tasks)
      ft->own_tasks=1;
    else if (!changed && ft && ft->own_tasks)
      ft->own_tasks=0;
    psync_sql_unlock();
    return;
  }
  if (changed) {
    assert(!ft->own_tasks);
    assert(!ft->child_task_cnt);
    ft->own_tasks=1;
    while (folderid!=0) {
      folderid=get_parent_folder(folderid);
      ft=get_folder_tasks(folderid, 1);
      ft->child_task_cnt++;
      if (ft->child_task_cnt>1 || ft->own_tasks)
        break;
    }
  } else {
    assert(ft);
    assert(!ft->child_task_cnt);
    assert(ft->own_tasks);
    free_folder_tasks(ft);
    while (folderid!=0) {
      folderid=get_parent_folder(folderid);
      ft=get_folder_tasks(folderid, 0);
      assert(ft); // if assert fails, the problem is not the assert, don't change it to "if (!ft) break;"
      ft->child_task_cnt--;
      if (ft->child_task_cnt || ft->own_tasks)
        break;
      free_folder_tasks(ft);
    }
  }
  psync_sql_unlock();
}

void psync_path_status_folder_moved(psync_folderid_t folderid, psync_folderid_t old_parent_folderid, psync_folderid_t new_parent_folderid) {
  parent_cache_entry_t *p;
  folder_tasks_t *ft, *pft;
  uint32_t h;
  if (old_parent_folderid==new_parent_folderid)
    return;
  h=hash_folderid(folderid)%PARENT_HASH_SIZE;
  psync_sql_lock();
  psync_list_for_each_element (p, &parent_cache_hash[h], parent_cache_entry_t, list_hash)
    if (p->folderid==folderid) {
      assert(p->parentfolderid==old_parent_folderid);
      p->parentfolderid=new_parent_folderid;
    }
  ft=get_folder_tasks(folderid, 0);
  if (!ft) {
    psync_sql_unlock();
    return;
  }
  pft=get_folder_tasks(old_parent_folderid, 0);
  assert(pft);
  pft->child_task_cnt--;
  while (!pft->child_task_cnt && !pft->own_tasks) {
    free_folder_tasks(pft);
    if (old_parent_folderid==0)
      break;
    old_parent_folderid=get_parent_folder(old_parent_folderid);
    pft=get_folder_tasks(old_parent_folderid, 0);
    assert(pft);
    pft->child_task_cnt--;
  }
  pft=get_folder_tasks(new_parent_folderid, 1);
  pft->child_task_cnt++;
  while (pft->child_task_cnt==1 && !pft->own_tasks && new_parent_folderid!=0) {
    new_parent_folderid=get_parent_folder(new_parent_folderid);
    pft=get_folder_tasks(new_parent_folderid, 1);
    pft->child_task_cnt++;
  }
  psync_sql_unlock();
}

static inline int is_slash(char ch) {
#if defined(P_OS_WINDOWS)
  return ch=='/' || ch=='\\';
#else
  return ch=='/';
#endif
}

static inline int valid_last_char(char ch) {
  return is_slash(ch) || ch==0;
}

static psync_path_status_t rdunlock_return(psync_path_status_t st) {
  psync_sql_rdunlock();
  return st;
}

static psync_path_status_t rdunlock_return_in_prog() {
  psync_sql_rdunlock();
  return PSYNC_PATH_STATUS_IN_PROG;
}

static psync_path_status_t psync_path_status_drive_folder_locked(psync_folderid_t folderid) {
  if (get_folder_tasks(folderid, 0))
    return rdunlock_return_in_prog();
  psync_sql_rdunlock();
  return PSYNC_PATH_STATUS_IN_SYNC;
}

#define HASH_ROUND() \
    a+=n;\
    a*=0x5724c9d1;\
    b^=n;\
    b*=0x6a511717;\
    c+=n;\
    c*=0x76459457;\
    d^=n;\
    d*=0x51a97a23;


static void comp_hash(const char *s, size_t len, uint32_t *out, uint64_t seed1, uint64_t seed2) {
  uint32_t a, b, c, d, n;
  a=seed1&0xffffffffU;
  b=seed1>>32;
  c=seed2&0xffffffffU;
  d=seed2>>32;
  b^=len;
  b*=0x6a511717;
  c+=len;
  c*=0x76459457;
  while (len>=sizeof(uint32_t)) {
    n=*(const uint32_t *)s;
    s+=sizeof(uint32_t);
    len-=sizeof(uint32_t);
    HASH_ROUND();
  }
  n=len<<24;
  switch (len) {
    case 3:
      n+=0xffffU*s[2];
    case 2:
      n+=0xffU*s[1];
    case 1:
      n+=s[0];
      HASH_ROUND();
  }
  out[0]=a^(a>>17);
  out[1]=b;
  out[2]=c^(c>>15);
  out[3]=d;
}

static int move_encname_to_buff(psync_folderid_t folderid, char *buff, size_t buff_size, const char *name, size_t namelen) {
  psync_crypto_aes256_text_encoder_t enc;
  char *encname;
  size_t len;
  if (unlikely(namelen>=buff_size))
    return -1;
  memcpy(buff, name, namelen);
  buff[namelen]=0;
  enc=psync_cloud_crypto_get_folder_encoder(folderid);
  if (unlikely(psync_crypto_is_error(enc)))
    return -1;
  encname=psync_cloud_crypto_encode_filename(enc, buff);
  psync_cloud_crypto_release_folder_encoder(folderid, enc);
  len=strlen(encname);
  if (unlikely(len>=sizeof(buff)))
    return -1;
  memcpy(buff, encname, len+1);
  psync_free(encname);
  return 0;
}

static psync_path_status_t psync_path_status_drive(const char *path, size_t path_len) {
  char buff[2048];
  uint32_t hash[4], h;
  psync_fstask_folder_t *folder;
  path_cache_entry_t *ce;
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t folderid;
  uint64_t flags;
  size_t off, poff;
  const char *name;
  size_t namelen;
  int wrlocked, found;
  while (is_slash(*path)) {
    path++;
    path_len--;
  }
  wrlocked=0;
  psync_sql_rdlock();
  if (!path_len)
    return psync_path_status_drive_folder_locked(0);
restart:
  poff=0;
  folderid=0;
  flags=ENTRY_FLAG_FOLDER;
  for (off=0; off<path_len; off++)
    if (is_slash(path[off])) {
      if (off && is_slash(path[off-1])) {
        poff=off+1;
      } else {
        folder=psync_fstask_get_folder_tasks_rdlocked(folderid);
        if (folder) {
          if (unlikely(off-poff>=sizeof(buff)))
            return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
          if (likely((flags&ENTRY_FLAG_ENCRYPTED)==0)) {
            memcpy(buff, path+poff, off-poff);
            buff[off-poff]=0;
          } else {
            if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff), path+poff, off-poff)))
              return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
          }
          if (psync_fstask_find_mkdir(folder, buff, 0))
            return rdunlock_return_in_prog();
          if (psync_fstask_find_rmdir(folder, buff, 0))
            return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
        }
        comp_hash(path+poff, off-poff, hash, folderid, drv_hash_seed);
        h=(hash[0]+hash[2])%PATH_HASH_SIZE;
        found=0;
        psync_list_for_each_element (ce, &path_cache_hash[h], path_cache_entry_t, list_hash)
          if (!memcmp(hash, ce->hash, sizeof(hash)) && (ce->flags&ENTRY_FLAG_FOLDER)) {
            if (wrlocked) {
              psync_list_del(&ce->list_lru);
              psync_list_add_tail(&path_cache_lru, &ce->list_lru);
            }
            folderid=ce->itemid;
            flags=ce->flags;
            found=1;
            poff=off+1;
            break;
          }
        if (found)
          continue;
        res=psync_sql_query_nolock("SELECT id, permissions, flags, userid FROM folder WHERE parentfolderid=? AND name=?");
        psync_sql_bind_uint(res, 1, folderid);
        if (likely((flags&ENTRY_FLAG_ENCRYPTED)==0)) {
          psync_sql_bind_lstring(res, 2, path+poff, off-poff);
        } else {
          psync_sql_free_result(res);
          if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff), path+poff, off-poff)))
            return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
          psync_sql_bind_string(res, 2, buff);

        }
        row=psync_sql_fetch_rowint(res);
        if (!row) {
          psync_sql_free_result(res);
          return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
        }
        if (!wrlocked) {
          psync_sql_free_result(res);
          wrlocked=1;
          if (psync_sql_tryupgradelock()) {
            psync_sql_rdunlock();
            psync_sql_lock();
          }
          goto restart;
        }
        folderid=row[0];
        flags=ENTRY_FLAG_FOLDER;
        if (row[2]&PSYNC_FOLDER_FLAG_ENCRYPTED)
          flags|=ENTRY_FLAG_ENCRYPTED;
        psync_sql_free_result(res);
        ce=psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t, list_lru);
        psync_list_add_tail(&path_cache_lru, &ce->list_lru);
        psync_list_del(&ce->list_hash);
        psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
        memcpy(ce->hash, hash, sizeof(hash));
        ce->itemid=folderid;
        ce->flags=flags;
        poff=off+1;
      }
    }
  if (poff==path_len)
    return psync_path_status_drive_folder_locked(folderid);
  folder=psync_fstask_get_folder_tasks_rdlocked(folderid);
  name=path+poff;
  namelen=path_len-poff;
  if (folder) {
    if (unlikely(flags&ENTRY_FLAG_ENCRYPTED)) {
      if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff), path+poff, path_len-poff)))
        return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
      name=buff;
      namelen=strlen(buff);
    }
    if (psync_fstask_find_mkdir(folder, name, 0))
      return rdunlock_return_in_prog();
    if (psync_fstask_find_creat(folder, name, 0))
      return rdunlock_return_in_prog();
  }
  // we do the hash with the unencrypted name
  comp_hash(path+poff, path_len-poff, hash, folderid, drv_hash_seed);
  h=(hash[0]+hash[2])%PATH_HASH_SIZE;
  found=0;
  psync_list_for_each_element (ce, &path_cache_hash[h], path_cache_entry_t, list_hash)
    if (!memcmp(hash, ce->hash, sizeof(hash))) {
      if (wrlocked) {
        psync_list_del(&ce->list_lru);
        psync_list_add_tail(&path_cache_lru, &ce->list_lru);
      }
      folderid=ce->itemid;
      flags=ce->flags;
      found=1;
      break;
    }
  if (found) {
    if (flags&ENTRY_FLAG_FOLDER) {
      if (folder && psync_fstask_find_rmdir(folder, name, 0))
        return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
      else
        return psync_path_status_drive_folder_locked(folderid);
    } else {
      if (folder && psync_fstask_find_unlink(folder, name, 0))
        return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
      else
        return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
    }
  }
  if (unlikely (!folder && (flags&ENTRY_FLAG_ENCRYPTED))) {
    if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff), path+poff, path_len-poff)))
      return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
    name=buff;
    namelen=strlen(buff);
  }
  res=psync_sql_query_nolock("SELECT id, permissions, flags, userid FROM folder WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_lstring(res, 2, name, namelen);
  row=psync_sql_fetch_rowint(res);
  if (!row || (folder && psync_fstask_find_rmdir(folder, path+poff, 0))) {
    psync_sql_free_result(res);
    if (folder && psync_fstask_find_unlink(folder, path+poff, 0))
      return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
    res=psync_sql_query_nolock("SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, namelen);
    row=psync_sql_fetch_rowint(res);
    if (!row) {
      psync_sql_free_result(res);
      return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
    }
    if (!wrlocked) {
      psync_sql_free_result(res);
      wrlocked=1;
      if (psync_sql_tryupgradelock()) {
        psync_sql_rdunlock();
        psync_sql_lock();
      }
      goto restart;
    }
    folderid=row[0];
    flags&=~ENTRY_FLAG_FOLDER;
    psync_sql_free_result(res);
    ce=psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t, list_lru);
    psync_list_add_tail(&path_cache_lru, &ce->list_lru);
    psync_list_del(&ce->list_hash);
    psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
    memcpy(ce->hash, hash, sizeof(hash));
    ce->itemid=folderid;
    ce->flags=flags;
    return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
  }
  if (!wrlocked) {
    psync_sql_free_result(res);
    wrlocked=1;
    if (psync_sql_tryupgradelock()) {
      psync_sql_rdunlock();
      psync_sql_lock();
    }
    goto restart;
  }
  folderid=row[0];
  flags=ENTRY_FLAG_FOLDER;
  psync_sql_free_result(res);
  ce=psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t, list_lru);
  psync_list_add_tail(&path_cache_lru, &ce->list_lru);
  psync_list_del(&ce->list_hash);
  psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
  memcpy(ce->hash, hash, sizeof(hash));
  ce->itemid=folderid;
  ce->flags=flags;
  return psync_path_status_drive_folder_locked(folderid);
}

static psync_path_status_t psync_path_status_sync(const char *path, size_t path_len, psync_folderid_t folderid, psync_syncid_t syncid, uint32_t flags) {
  return PSYNC_PATH_STATUS_IN_SYNC;
}

static int psync_path_is_prefix_of(const char *prefix, size_t prefix_len, const char **ppath, size_t *ppath_len) {
  const char *path=*ppath;
  size_t path_len=*ppath_len;
  while (1) {
    while (prefix_len && path_len && !is_slash(*prefix) && *prefix==*path) {
      prefix++;
      path++;
      prefix_len--;
      path_len--;
    }
    if (!path_len || !prefix_len)
      break;
    if (is_slash(*prefix)!=is_slash(*path))
      return 0;
    if (is_slash(*prefix)) {
      do {
        prefix_len--;
        prefix++;
      } while (prefix_len && is_slash(*prefix));
      do {
        path_len--;
        path++;
      } while (path_len && is_slash(*path));
      if (!prefix_len) {
        *ppath=path;
        *ppath_len=path_len;
        return 1;
      } else if (!path_len)
        return 0;
      continue;
    }
#if defined(P_OS_WINDOWS)
    if (tolower(*prefix)!=tolower(*path))
      return 0;
    prefix++;
    path++;
    prefix_len--;
    path_len--;
#else
    return 0;
#endif
  }
  if (!prefix_len && valid_last_char(*path)) {
    *ppath=path;
    *ppath_len=path_len;
    return 1;
  } else {
    return 0;
  }
}

psync_path_status_t psync_path_status_get(const char *path) {
  char *dp;
  path_sync_list_t *sn;
  size_t i, len;
  len=strlen(path);
  if (drive_path) {
    if (len>=drive_path_len && !memcmp(drive_path, path, drive_path_len) && valid_last_char(path[drive_path_len]))
      return psync_path_status_drive(path+drive_path_len, len-drive_path_len);
  } else {
    dp=psync_fs_getmountpoint();
    if (dp) {
      // assign the len before the mutex, so we use it as a barrier
      drive_path_len=strlen(dp);
      psync_sql_lock();
      if (!drive_path) {
        drive_path=dp;
        dp=NULL;
      }
      psync_sql_unlock();
      psync_free(dp);
      if (len>=drive_path_len && !memcmp(drive_path, path, drive_path_len) && valid_last_char(path[drive_path_len]))
        return psync_path_status_drive(path+drive_path_len, len-drive_path_len);
    }
  }
  sn=syncs;
  if (!sn) {
    psync_sql_rdlock();
    sn=syncs;
    psync_sql_unlock();
    if (!sn)
      goto slower_check;
  }
  for (i=0; i<sn->sync_cnt; i++)
    if (sn->syncs[i].path_len<=len && !memcmp(sn->syncs[i].path, path, sn->syncs[i].path_len) && valid_last_char(path[sn->syncs[i].path_len]))
      return psync_path_status_sync(path+sn->syncs[i].path_len, len-sn->syncs[i].path_len, sn->syncs[i].folderid, sn->syncs[i].syncid, sn->syncs[i].flags);
slower_check:
  if (drive_path && psync_path_is_prefix_of(drive_path, drive_path_len, &path, &len))
    return psync_path_status_drive(path, len);
  sn=syncs;
  if (sn)
    for (i=0; i<sn->sync_cnt; i++)
      if (sn->syncs[i].path_len<=len && psync_path_is_prefix_of(sn->syncs[i].path, sn->syncs[i].path_len, &path, &len))
        return psync_path_status_sync(path, len, sn->syncs[i].folderid, sn->syncs[i].syncid, sn->syncs[i].flags);
  return PSYNC_PATH_STATUS_NOT_OURS;
}
