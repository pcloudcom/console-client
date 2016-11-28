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

#include "plibs.h"
#include "pfscrypto.h"
#include "pcloudcrypto.h"
#include "ppagecache.h"
#include <ctype.h>

// this is only for debug, adds needless checks of tree for local files
#if IS_DEBUG
#define PSYNC_DO_LOCAL_FULL_TREE_CHECK 1
#endif

#define PSYNC_CRYPTO_LOG_DATA   1
#define PSYNC_CRYPTO_LOG_INT    2

#define PSYNC_CRYPTO_HASH_TREE_SHIFT 8

#define PSYNC_LOG_STATUS_INCOMPLETE 0
#define PSYNC_LOG_STATUS_FINALIZED  1

#define PSYNC_LOG_HASHID_FH256      0

typedef struct {
  uint8_t type;
  union {
    uint8_t u8;
    uint8_t finalized;
  };
  union {
    uint16_t u16;
    uint16_t length;
    uint16_t longlengthhi;
  };
  union {
    uint32_t u32;
    uint32_t longlengthlo;
  };
  union {
    uint64_t u64;
    uint64_t offset;
    uint64_t filesize;
  };
} psync_crypto_log_header;

typedef struct {
  uint32_t status;
  uint32_t hashid;
  uint64_t logsize;
  uint64_t filesize;
  unsigned char hash[PSYNC_FAST_HASH256_LEN];
  uint32_t crc;
} psync_crypto_master_record;

typedef struct {
  psync_crypto_log_header header;
  unsigned char data[PSYNC_CRYPTO_SECTOR_SIZE];
} psync_crypto_log_data_record;

static const uint64_t max_level_size[PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL+1]={
  0x1000,
  0x81000,
  0x4081000,
  0x204081000,
  0x10204081000,
  0x810204081000,
  0x40810204081000
};

psync_crypto_sectorid_t psync_fs_crypto_data_sectorid_by_sectorid(psync_crypto_sectorid_t sectorid){
  psync_crypto_sectorid_t sect;
  sect=sectorid;
  while (sectorid>=PSYNC_CRYPTO_HASH_TREE_SECTORS){
    sectorid/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    sect+=sectorid;
  }
  return sect;
}

static uint64_t psync_fs_crypto_data_offset_by_sectorid(psync_crypto_sectorid_t sectorid){
  uint64_t off;
  off=(uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE;
  while (sectorid>=PSYNC_CRYPTO_HASH_TREE_SECTORS){
    sectorid/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    off+=(uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE;
  }
  return off;
}

/* works for all sectors of auth data except the last one of each level */
static uint64_t psync_fs_crypto_auth_offset(uint32_t level, uint32_t id){
  uint64_t ret;
  ret=max_level_size[level+1]*(id+1)-PSYNC_CRYPTO_SECTOR_SIZE;
  while (id>=PSYNC_CRYPTO_HASH_TREE_SECTORS){
    id/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    ret+=id*PSYNC_CRYPTO_SECTOR_SIZE;
  }
  return ret;
}

void psync_fs_crypto_offsets_by_plainsize(uint64_t size, psync_crypto_offsets_t *offsets){
  uint64_t off;
  psync_crypto_sectorid_t lastsectorid;
  uint32_t lastsectorsize, sz, level;
  memset(offsets, 0, sizeof(psync_crypto_offsets_t));
  offsets->plainsize=size;
  offsets->needmasterauth=size>PSYNC_CRYPTO_SECTOR_SIZE;
  if (!size)
    return;
  lastsectorid=size/PSYNC_CRYPTO_SECTOR_SIZE;
  lastsectorsize=size%PSYNC_CRYPTO_SECTOR_SIZE;
  if (lastsectorsize==0){
    lastsectorid--;
    lastsectorsize=PSYNC_CRYPTO_SECTOR_SIZE;
  }
  off=psync_fs_crypto_data_offset_by_sectorid(lastsectorid)+lastsectorsize;
  level=0;
  size=(size+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE;
  do {
    sz=size%PSYNC_CRYPTO_HASH_TREE_SECTORS;
    size=(size+PSYNC_CRYPTO_HASH_TREE_SECTORS-1)/PSYNC_CRYPTO_HASH_TREE_SECTORS;
    if (!sz)
      sz=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    sz*=PSYNC_CRYPTO_AUTH_SIZE;
    offsets->lastauthsectoroff[level]=off;
    offsets->lastauthsectorlen[level]=sz;
    off+=sz;
    level++;
  } while (size>1);
  offsets->lastauthsectoroff[level]=off;
  offsets->lastauthsectorlen[level]=PSYNC_CRYPTO_AUTH_SIZE;
  offsets->masterauthoff=off;
  offsets->treelevels=level;
}

static void psync_fs_crypto_offsets_by_cryptosize(uint64_t size, psync_crypto_offsets_t *offsets){
  uint64_t off, cnt;
  uint32_t level;
  memset(offsets, 0, sizeof(psync_crypto_offsets_t));
  if (size<=PSYNC_CRYPTO_AUTH_SIZE)
    return;
  offsets->needmasterauth=size>PSYNC_CRYPTO_SECTOR_SIZE+PSYNC_CRYPTO_AUTH_SIZE;
  if (offsets->needmasterauth)
    size-=PSYNC_CRYPTO_AUTH_SIZE;
  offsets->masterauthoff=size;
  for (level=1; level<=PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL; level++)
    if (size<=max_level_size[level])
      break;
  assert(level<=PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL);
  offsets->treelevels=level;
  off=size;
  offsets->lastauthsectoroff[level]=off;
  offsets->lastauthsectorlen[level]=PSYNC_CRYPTO_AUTH_SIZE;
  do {
    level--;
    cnt=((size+max_level_size[level]+PSYNC_CRYPTO_AUTH_SIZE-1)/(max_level_size[level]+PSYNC_CRYPTO_AUTH_SIZE));
    size-=cnt*PSYNC_CRYPTO_AUTH_SIZE;
    cnt%=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    if (!cnt)
      cnt=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    off-=cnt*PSYNC_CRYPTO_AUTH_SIZE;
    offsets->lastauthsectorlen[level]=cnt*PSYNC_CRYPTO_AUTH_SIZE;
    offsets->lastauthsectoroff[level]=off;
  } while (level);
  offsets->plainsize=size;
}

int psync_fs_crypto_init_log(psync_openfile_t *of){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  ssize_t wrt;
  assert(sizeof(psync_crypto_master_record)<=PSYNC_CRYPTO_SECTOR_SIZE);
  memset(buff, 0xff, sizeof(buff));
  wrt=psync_file_pwrite(of->logfile, buff, PSYNC_CRYPTO_SECTOR_SIZE, 0);
  if (unlikely(wrt!=PSYNC_CRYPTO_SECTOR_SIZE)){
    debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)PSYNC_CRYPTO_SECTOR_SIZE, (int)wrt);
    return -EIO;
  }
  of->logoffset=PSYNC_CRYPTO_SECTOR_SIZE;
  psync_fast_hash256_init(&of->loghashctx);
  return 0;
}

static int psync_fs_crypto_read_newfile_full_sector_from_log(psync_openfile_t *of, char *buf, psync_sector_inlog_t *se){
  unsigned char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  psync_crypto_log_header hdr;
  ssize_t rd;
  rd=psync_file_pread(of->logfile, &hdr, sizeof(hdr), se->logoffset);
  if (unlikely(rd!=sizeof(hdr))){
    debug(D_ERROR, "read from log of %u bytes returned %d", (unsigned)sizeof(hdr), (int)rd);
    return -EIO;
  }
  if (hdr.type!=PSYNC_CRYPTO_LOG_DATA){
    debug(D_ERROR, "bad log record type %u", (unsigned)hdr.type);
    return -EIO;
  }
  assert(hdr.offset==(uint64_t)psync_fs_crypto_data_sectorid_by_sectorid(se->sectorid)*PSYNC_CRYPTO_SECTOR_SIZE);
  assert(hdr.length<=PSYNC_CRYPTO_SECTOR_SIZE);
  rd=psync_file_pread(of->logfile, buff, hdr.length, se->logoffset+sizeof(hdr));
  if (unlikely(rd!=hdr.length)){
    debug(D_ERROR, "read from log of %u bytes returned %d", (unsigned)hdr.length, (int)rd);
    return -EIO;
  }
  if (unlikely_log(psync_crypto_aes256_decode_sector(of->encoder, buff, rd, (unsigned char *)buf, se->auth, se->sectorid)))
    return -EIO;
  else
    return rd;
}

/*static psync_crypto_sectorid_t size_div_hash_tree_sectors(psync_crypto_sectorid_t sectorid){
  psync_crypto_sectorid_t ret;
  ret=sectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
  if (sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS==0 && ret)
    ret--;
  return ret;
}*/

static psync_crypto_sectorid_t get_last_sectorid_by_size(uint64_t size){
  if (unlikely(size==0)){
    debug(D_NOTICE, "called for 0 size");
    return 0;
  }
  else
    return (size-1)/PSYNC_CRYPTO_SECTOR_SIZE;
}

#if defined(PSYNC_DO_LOCAL_FULL_TREE_CHECK)
static int psync_fs_crypto_do_local_tree_check(psync_openfile_t *of, psync_crypto_sectorid_t sectorid, psync_crypto_offsets_t *offsets){
  unsigned char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  psync_crypto_sector_auth_t auth;
  uint64_t off;
  ssize_t rd;
  psync_crypto_sectorid_t sizesect;
  uint32_t ssize, authoff, level;
  if (!offsets->needmasterauth)
    return 0;
  sectorid/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
  sizesect=get_last_sectorid_by_size(offsets->plainsize)/PSYNC_CRYPTO_HASH_TREE_SECTORS;
  if (sectorid==sizesect){
    off=offsets->lastauthsectoroff[0];
    ssize=offsets->lastauthsectorlen[0];
  }
  else{
    off=psync_fs_crypto_auth_offset(0, sectorid);
    ssize=PSYNC_CRYPTO_SECTOR_SIZE;
  }
//  debug(D_NOTICE, "reading first sector from offset %lu, size %u", (unsigned long)off, (unsigned)ssize);
  rd=psync_file_pread(of->datafile, buff, ssize, off);
  if (unlikely_log(rd!=ssize))
    return -1;
  psync_crypto_sign_auth_sector(of->encoder, buff, ssize, auth);
  level=0;
  while (level<offsets->treelevels){
    level++;
    authoff=(sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS)*PSYNC_CRYPTO_AUTH_SIZE;
    sectorid/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    sizesect/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    if (sectorid==sizesect){
      off=offsets->lastauthsectoroff[level];
      ssize=offsets->lastauthsectorlen[level];
    }
    else{
      off=psync_fs_crypto_auth_offset(level, sectorid);
      ssize=PSYNC_CRYPTO_SECTOR_SIZE;
    }
    rd=psync_file_pread(of->datafile, buff, ssize, off);
    if (unlikely_log(rd!=ssize))
      return -1;
    if (unlikely(memcmp(buff+authoff, auth, sizeof(auth)))){
      debug(D_WARNING, "verify failed on level %u, sectorid %u, off %lu, ssize %u, authoff %u",
            (unsigned)level, (unsigned)sectorid, (unsigned long)off, (unsigned)ssize, (unsigned)authoff);
      return -1;
    }
    psync_crypto_sign_auth_sector(of->encoder, buff, ssize, auth);
  }
  return 0;
}
#endif

static int psync_fs_crypto_wait_no_extender_locked(psync_openfile_t *of){
  int ret;
  while (of->extender && !of->extender->ready){
    debug(D_NOTICE, "waiting for extender to finish");
    of->extender->waiters++;
    pthread_cond_wait(&of->extender->cond, &of->mutex);
    of->extender->waiters--;
  }
  if (of->extender){
    ret=of->extender->error;
    do {
      pthread_mutex_unlock(&of->mutex);
      psync_milisleep(1);
      psync_fs_lock_file(of);
    } while (of->extender);
    debug(D_NOTICE, "waited for extender to finish");
    return ret;
  }
  else
    return 0;
}

static int psync_fs_crypto_wait_extender_after_locked(psync_openfile_t *of, uint64_t offset){
  while (of->extender && !of->extender->ready && of->extender->extendedto<offset){
    debug(D_NOTICE, "waiting for extending process to reach %lu, currently at %lu", (unsigned long)offset, (unsigned long)of->extender->extendedto);
    of->extender->waiters++;
    pthread_cond_wait(&of->extender->cond, &of->mutex);
    of->extender->waiters--;
    debug(D_NOTICE, "waited extending process to reach %lu", (unsigned long)of->extender->extendedto);
  }
  if (of->extender)
    return of->extender->error;
  else
    return 0;
}

static int psync_fs_crypto_kill_extender_locked(psync_openfile_t *of){
  if (of->extender){
    debug(D_NOTICE, "killing extender of file %s", of->currentname);
    of->extender->kill=1;
    if (of->extender->error)
      return of->extender->error;
  }
  return 0;
}

static int psync_fs_crypto_read_newfile_full_sector_from_datafile(psync_openfile_t *of, char *buf, psync_crypto_sectorid_t sectorid){
  unsigned char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  psync_crypto_sector_auth_t auth;
  psync_crypto_offsets_t offsets;
  uint64_t off;
  int64_t fs;
  ssize_t rd;
  uint32_t ssize;
//  debug(D_NOTICE, "reading sector %u", sectorid);
  fs=psync_file_size(of->datafile);
  if (unlikely_log(fs==-1))
    return -EIO;
  psync_fs_crypto_offsets_by_cryptosize(fs, &offsets);
  if ((uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE>=offsets.plainsize)
    return 0;
  if ((uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE+PSYNC_CRYPTO_SECTOR_SIZE>offsets.plainsize)
    ssize=offsets.plainsize-(uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE;
  else
    ssize=PSYNC_CRYPTO_SECTOR_SIZE;
  off=psync_fs_crypto_data_offset_by_sectorid(sectorid);
//  debug(D_NOTICE, "data offset=%lu", off);
  rd=psync_file_pread(of->datafile, buff, ssize, off);
  if (unlikely_log(rd!=ssize))
    return -EIO;
  if (sectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS==get_last_sectorid_by_size(offsets.plainsize)/PSYNC_CRYPTO_HASH_TREE_SECTORS)
    off=offsets.lastauthsectoroff[0];
  else
    off=psync_fs_crypto_auth_offset(0, sectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS);
  off+=(sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS)*PSYNC_CRYPTO_AUTH_SIZE;
//  debug(D_NOTICE, "auth offset=%lu", off);
  rd=psync_file_pread(of->datafile, auth, sizeof(auth), off);
  if (unlikely_log(rd!=sizeof(auth)))
    return -EIO;
  if (unlikely_log(psync_crypto_aes256_decode_sector(of->encoder, buff, ssize, (unsigned char *)buf, auth, sectorid)))
    return -EIO;
#if defined(PSYNC_DO_LOCAL_FULL_TREE_CHECK)
  else if (psync_fs_crypto_do_local_tree_check(of, sectorid, &offsets))
    return -EIO;
#endif
  else
    return ssize;
}

static int psync_fs_crypto_read_newfile_full_sector(psync_openfile_t *of, char *buf, psync_crypto_sectorid_t sectorid){
  psync_crypto_sectorid_diff_t d;
  psync_sector_inlog_t *tr;
  tr=psync_tree_element(of->sectorsinlog, psync_sector_inlog_t, tree);
  while (tr){
    d=sectorid-tr->sectorid;
    if (d<0)
      tr=psync_tree_element(tr->tree.left, psync_sector_inlog_t, tree);
    else if (d>0)
      tr=psync_tree_element(tr->tree.right, psync_sector_inlog_t, tree);
    else
      return psync_fs_crypto_read_newfile_full_sector_from_log(of, buf, tr);
  }
  return psync_fs_crypto_read_newfile_full_sector_from_datafile(of, buf, sectorid);
}

static int psync_fs_crypto_read_newfile_partial_sector(psync_openfile_t *of, char *buf, psync_crypto_sectorid_t sectorid, size_t size, off_t offset){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  int rd;
  assert(offset+size<=PSYNC_CRYPTO_SECTOR_SIZE);
  rd=psync_fs_crypto_read_newfile_full_sector(of, buff, sectorid);
  if (rd<=0)
    return rd;
  if (rd<=offset)
    return 0;
  rd-=offset;
  if (rd>size)
    rd=size;
  memcpy(buf, buff+offset, rd);
  return rd;
}

static int psync_fs_unlock_ret(psync_openfile_t *of, int ret){
  pthread_mutex_unlock(&of->mutex);
  return ret;
}

int psync_fs_crypto_read_newfile_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset){
  uint64_t off2, offdiff;
  psync_crypto_sectorid_t sectorid;
  int ret, rd;
  assert(of->encrypted);
  assert(of->encoder);
  if (unlikely((size+offset+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE>PSYNC_CRYPTO_MAX_SECTORID))
    return psync_fs_unlock_ret(of, -EINVAL);
  ret=psync_fs_crypto_wait_extender_after_locked(of, offset+size);
  if (unlikely_log(ret))
    return psync_fs_unlock_ret(of, ret);
  if (unlikely(!size || of->currentsize<=offset))
    return psync_fs_unlock_ret(of, 0);
  if (offset+size>of->currentsize)
    size=of->currentsize-offset;
  sectorid=offset/PSYNC_CRYPTO_SECTOR_SIZE;
  off2=offset%PSYNC_CRYPTO_SECTOR_SIZE;
  rd=0;
  if (off2){
    if (PSYNC_CRYPTO_SECTOR_SIZE-off2<size)
      offdiff=PSYNC_CRYPTO_SECTOR_SIZE-off2;
    else
      offdiff=size;
    ret=psync_fs_crypto_read_newfile_partial_sector(of, buf, sectorid, offdiff, off2);
    offset+=offdiff;
    buf+=offdiff;
    rd+=offdiff;
    size-=offdiff;
    sectorid++;
    if (ret!=offdiff)
      return psync_fs_unlock_ret(of, ret);
  }
  while (size>=PSYNC_CRYPTO_SECTOR_SIZE){
    ret=psync_fs_crypto_read_newfile_full_sector(of, buf, sectorid);
    if (ret!=PSYNC_CRYPTO_SECTOR_SIZE){
      if (ret<0)
        return psync_fs_unlock_ret(of, ret);
      else
        return psync_fs_unlock_ret(of, ret+rd);
    }
    buf+=PSYNC_CRYPTO_SECTOR_SIZE;
    offset+=PSYNC_CRYPTO_SECTOR_SIZE;
    rd+=PSYNC_CRYPTO_SECTOR_SIZE;
    size-=PSYNC_CRYPTO_SECTOR_SIZE;
    sectorid++;
  }
  if (size){
    ret=psync_fs_crypto_read_newfile_partial_sector(of, buf, sectorid, size, 0);
    if (ret!=size){
      if (ret<0)
        return psync_fs_unlock_ret(of, ret);
      else
        return psync_fs_unlock_ret(of, ret+rd);
    }
    rd+=size;
  }
  pthread_mutex_unlock(&of->mutex);
  return rd;
}

static void psync_fs_crypto_set_sector_log_offset(psync_openfile_t *of, psync_crypto_sectorid_t sectorid, uint32_t offset, unsigned char *auth){
  psync_crypto_sectorid_diff_t d;
  psync_sector_inlog_t *tr, *ntr;
  psync_tree **pe;
  tr=psync_tree_element(of->sectorsinlog, psync_sector_inlog_t, tree);
  pe=&of->sectorsinlog;
  while (tr){
    d=sectorid-tr->sectorid;
    if (d<0){
      if (tr->tree.left)
        tr=psync_tree_element(tr->tree.left, psync_sector_inlog_t, tree);
      else{
        pe=&tr->tree.left;
        break;
      }
    }
    else if (d>0){
      if (tr->tree.right)
        tr=psync_tree_element(tr->tree.right, psync_sector_inlog_t, tree);
      else{
        pe=&tr->tree.right;
        break;
      }
    }
    else{
      tr->logoffset=offset;
      memcpy(tr->auth, auth, PSYNC_CRYPTO_AUTH_SIZE);
      return;
    }
  }
  ntr=psync_new(psync_sector_inlog_t);
  *pe=&ntr->tree;
  ntr->sectorid=sectorid;
  ntr->logoffset=offset;
  memcpy(ntr->auth, auth, PSYNC_CRYPTO_AUTH_SIZE);
  psync_tree_added_at(&of->sectorsinlog, &tr->tree, &ntr->tree);
}

static int psync_fs_crypto_switch_sectors(psync_openfile_t *of, psync_crypto_sectorid_t oldsectorid, psync_crypto_sectorid_t newsectorid,
                                          psync_crypto_auth_sector_t *autharr, psync_crypto_offsets_t *offsets){
  psync_crypto_log_header hdr;
  psync_crypto_offsets_t ooffsets;
  int64_t filesize, off;
  psync_crypto_sectorid_t oldsecd, newsecd, sizesecd;
  uint32_t level, oldsecn, sz;
  ssize_t wrt;
  if (oldsectorid!=PSYNC_CRYPTO_INVALID_SECTORID){
    level=0;
    oldsecd=oldsectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
    newsecd=newsectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
    sizesecd=get_last_sectorid_by_size(offsets->plainsize)/PSYNC_CRYPTO_HASH_TREE_SECTORS;
    do{
      oldsecn=oldsecd%PSYNC_CRYPTO_HASH_TREE_SECTORS;
      memset(&hdr, 0, sizeof(hdr));
      hdr.type=PSYNC_CRYPTO_LOG_DATA;
      if (oldsecd==sizesecd){
        hdr.offset=offsets->lastauthsectoroff[level];
        sz=offsets->lastauthsectorlen[level];
      }
      else{
        assert(oldsecd<sizesecd);
        hdr.offset=psync_fs_crypto_auth_offset(level, oldsecd);
        sz=PSYNC_CRYPTO_SECTOR_SIZE;
      }
      assert(hdr.offset+sz<=offsets->masterauthoff+PSYNC_CRYPTO_AUTH_SIZE);
//      debug(D_NOTICE, "writing level %u signatures to offset %lu size %u", level, hdr.offset, sz);
      hdr.length=sz;
      psync_crypto_sign_auth_sector(of->encoder, (unsigned char *)&autharr[level], sz, autharr[level+1][oldsecn]);
      wrt=psync_file_pwrite(of->logfile, &hdr, sizeof(hdr), of->logoffset);
      if (unlikely(wrt!=sizeof(hdr))){
        debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)sizeof(hdr), (int)wrt);
        return -EIO;
      }
      psync_fast_hash256_update(&of->loghashctx, &hdr, sizeof(hdr));
      wrt=psync_file_pwrite(of->logfile, &autharr[level], sz, of->logoffset+sizeof(hdr));
      if (unlikely(wrt!=sz)){
        debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)sz, (int)wrt);
        return -EIO;
      }
      psync_fast_hash256_update(&of->loghashctx, &autharr[level], sz);
      if (!of->newfile)
        psync_interval_tree_add(&of->writeintervals, hdr.offset, hdr.offset+sz);
      of->logoffset+=sz+sizeof(hdr);
      oldsecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
      newsecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
      sizesecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
      level++;
    } while (oldsecd!=newsecd && level<offsets->treelevels);
  }
  if (newsectorid!=PSYNC_CRYPTO_INVALID_SECTORID){
    filesize=psync_file_size(of->datafile);
    if (unlikely_log(filesize==-1))
      return -EIO;
    if (filesize>PSYNC_CRYPTO_AUTH_SIZE){
      psync_fs_crypto_offsets_by_cryptosize(filesize, &ooffsets);
      level=0;
      oldsecd=oldsectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
      newsecd=newsectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
      sizesecd=get_last_sectorid_by_size(ooffsets.plainsize)/PSYNC_CRYPTO_HASH_TREE_SECTORS;
      do{
        if (newsecd<=sizesecd){
          if (newsecd==sizesecd){
            off=ooffsets.lastauthsectoroff[level];
            sz=ooffsets.lastauthsectorlen[level];
          }
          else{
            assert(newsecd<sizesecd);
            off=psync_fs_crypto_auth_offset(level, newsecd);
            sz=PSYNC_CRYPTO_SECTOR_SIZE;
          }
          wrt=psync_file_pread(of->datafile, &autharr[level], sz, off);
          if (unlikely(wrt!=sz)){
            debug(D_ERROR, "read from datafile of %u bytes returned %d at offset %u", (unsigned)sz, (int)wrt, (unsigned)off);
            return -EIO;
          }
        }
        oldsecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
        newsecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
        sizesecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
        level++;
      } while (oldsecd!=newsecd && level<offsets->treelevels && (level<ooffsets.treelevels || (ooffsets.needmasterauth && level==ooffsets.treelevels)));
    }
  }
  return 0;
}

static int psync_fs_crypto_write_master_auth(psync_openfile_t *of, psync_crypto_auth_sector_t *autharr, psync_crypto_offsets_t *offsets){
  ssize_t wrt;
  struct {
    psync_crypto_log_header hdr;
    psync_crypto_sector_auth_t auth;
  } data;
  assert(sizeof(data)==sizeof(psync_crypto_log_header)+PSYNC_CRYPTO_AUTH_SIZE);
  assert(offsets->treelevels>0);
  assert(offsets->lastauthsectorlen[offsets->treelevels-1]>0);
  assert(offsets->lastauthsectorlen[offsets->treelevels-1]<=PSYNC_CRYPTO_SECTOR_SIZE);
  psync_crypto_sign_auth_sector(of->encoder, (unsigned char *)&autharr[offsets->treelevels-1], offsets->lastauthsectorlen[offsets->treelevels-1], data.auth);
  memset(&data.hdr, 0, sizeof(psync_crypto_log_header));
  data.hdr.type=PSYNC_CRYPTO_LOG_DATA;
  data.hdr.length=PSYNC_CRYPTO_AUTH_SIZE;
  data.hdr.offset=offsets->masterauthoff;
  wrt=psync_file_pwrite(of->logfile, &data, sizeof(data), of->logoffset);
  if (unlikely(wrt!=sizeof(data))){
    debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)sizeof(data), (int)wrt);
    return -EIO;
  }
  psync_fast_hash256_update(&of->loghashctx, &data, sizeof(data));
  if (!of->newfile)
    psync_interval_tree_add(&of->writeintervals, offsets->masterauthoff, offsets->masterauthoff+PSYNC_CRYPTO_AUTH_SIZE);
  of->logoffset+=sizeof(data);
  debug(D_NOTICE, "wrote master auth to offset %lu", (unsigned long)offsets->masterauthoff);
  return 0;
}

static int psync_fs_write_auth_tree_to_log(psync_openfile_t *of, psync_crypto_offsets_t *offsets){
  psync_sector_inlog_t *sect;
  psync_crypto_sectorid_t lastsect;
  int ret;
  psync_def_var_arr(authsect, psync_crypto_auth_sector_t, offsets->treelevels+1);
  lastsect=PSYNC_CRYPTO_INVALID_SECTORID;
  sect=psync_tree_element(psync_tree_get_first(of->sectorsinlog), psync_sector_inlog_t, tree);
  while (sect){
    if (lastsect/PSYNC_CRYPTO_HASH_TREE_SECTORS!=sect->sectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS){
      ret=psync_fs_crypto_switch_sectors(of, lastsect, sect->sectorid, authsect, offsets);
      if (ret)
        return PRINT_RETURN(ret);
    }
    memcpy(authsect[0][sect->sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS], sect->auth, PSYNC_CRYPTO_AUTH_SIZE);
    lastsect=sect->sectorid;
    sect=psync_tree_element(psync_tree_get_next(&sect->tree), psync_sector_inlog_t, tree);
  }
  ret=psync_fs_crypto_switch_sectors(of, lastsect, PSYNC_CRYPTO_INVALID_SECTORID, authsect, offsets);
  if (ret)
    return PRINT_RETURN(ret);
  if (offsets->needmasterauth && (ret=psync_fs_crypto_write_master_auth(of, authsect, offsets)))
    return PRINT_RETURN(ret);
  debug(D_NOTICE, "wrote tree to log, lastsectorid=%u, currentsize=%lu", (unsigned)lastsect, (unsigned long)of->currentsize);
  return 0;
}

PSYNC_NOINLINE static int psync_fs_crypto_check_log_hash(psync_file_t lfd, psync_crypto_master_record *mr){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  psync_fast_hash256_ctx ctx;
  uint64_t off;
  ssize_t rd;
  unsigned char chash[PSYNC_FAST_HASH256_LEN];
  if (unlikely(mr->hashid!=PSYNC_LOG_HASHID_FH256)){
    debug(D_WARNING, "invalid hashid in log file %u", (unsigned)mr->hashid);
    return -1;
  }
  psync_fast_hash256_init(&ctx);
  off=PSYNC_CRYPTO_SECTOR_SIZE;
  while ((rd=psync_file_pread(lfd, buff, PSYNC_CRYPTO_SECTOR_SIZE, off))!=0){
    if (unlikely(rd==-1)){
      debug(D_WARNING, "got error %d while reading from log", (int)psync_fs_err());
      return -1;
    }
    psync_fast_hash256_update(&ctx, buff, rd);
    off+=rd;
  }
  psync_fast_hash256_final(chash, &ctx);
  if (memcmp(chash, mr->hash, PSYNC_FAST_HASH256_LEN)){
    debug(D_WARNING, "calculated hash does not match");
#if IS_DEBUG
    psync_binhex(buff, chash, PSYNC_FAST_HASH256_LEN);
    buff[PSYNC_FAST_HASH256_LEN*2]=0;
    debug(D_NOTICE, "calculated: %s", buff);
    psync_binhex(buff, mr->hash, PSYNC_FAST_HASH256_LEN);
    buff[PSYNC_FAST_HASH256_LEN*2]=0;
    debug(D_NOTICE, "expected:   %s", buff);
#endif
    return -1;
  }
  else{
    debug(D_NOTICE, "successfully checked log hash");
    return 0;
  }
}

static int psync_fs_crypto_process_log(psync_file_t lfd, psync_file_t dfd, psync_file_t ifd, int checkhash){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  psync_fs_index_record *records;
  psync_crypto_master_record *mr;
  psync_crypto_log_header hdr;
  uint64_t off, size, ioff;
  ssize_t rd;
  uint32_t recid;
  mr=(psync_crypto_master_record *)buff;
  rd=psync_file_pread(lfd, mr, sizeof(psync_crypto_master_record), 0);
  if (unlikely(rd!=sizeof(psync_crypto_master_record))){
    debug(D_WARNING, "error reading from log file, expected to read %u got %d", (unsigned)sizeof(psync_crypto_master_record), (int)rd);
    return -1;
  }
  if (unlikely(mr->status!=PSYNC_LOG_STATUS_FINALIZED)){
    debug(D_WARNING, "got log file that is not finalized, skipping");
    return -1;
  }
  if (unlikely(mr->logsize!=psync_file_size(lfd))){
    debug(D_WARNING, "got log file that does not match in size, expected %u, got %d", (unsigned)mr->logsize, (int)psync_file_size(lfd));
    return -1;
  }
  if (unlikely(mr->crc!=psync_crc32c(PSYNC_CRC_INITIAL, mr, offsetof(psync_crypto_master_record, crc)))){
    debug(D_WARNING, "got log file with bad master record CRC, expected %u got %u", (unsigned)mr->crc,
          (unsigned)psync_crc32c(PSYNC_CRC_INITIAL, mr, offsetof(psync_crypto_master_record, crc)));
    return -1;
  }
  if (unlikely(checkhash && psync_fs_crypto_check_log_hash(lfd, mr))){
    debug(D_WARNING, "log checksum failed, skipping replay");
    return -1;
  }
  size=mr->filesize;
  off=PSYNC_CRYPTO_SECTOR_SIZE;
  if (unlikely_log(psync_file_seek(dfd, size, P_SEEK_SET)!=size || psync_file_truncate(dfd)))
    return -1;
  if (ifd!=INVALID_HANDLE_VALUE && unlikely_log(psync_file_seek(ifd, sizeof(psync_fs_index_header), P_SEEK_SET)!=sizeof(psync_fs_index_header) || psync_file_truncate(ifd)))
    return -1;
  records=(psync_fs_index_record *)buff;
  recid=0;
  ioff=0;
  while ((rd=psync_file_pread(lfd, &hdr, sizeof(hdr), off))!=0){
    if (unlikely_log(rd!=sizeof(hdr)))
      return -1;
    off+=sizeof(hdr);
    if (hdr.type==PSYNC_CRYPTO_LOG_DATA){
      assert(hdr.length<=sizeof(buff));
      assert(recid==0);
      if (unlikely(hdr.offset+hdr.length>size)){
        debug(D_NOTICE, "got record past the current end of file, this should only happen if file was truncated down, skipping record");
        off+=hdr.length;
        continue;
      }
      rd=psync_file_pread(lfd, buff, hdr.length, off);
      if (unlikely(rd!=hdr.length)){
        debug(D_ERROR, "error reading from log file, expected to read %u got %d", (unsigned)hdr.length, (int)rd);
        return -1;
      }
      off+=hdr.length;
      rd=psync_file_pwrite(dfd, buff, hdr.length, hdr.offset);
      if (unlikely(rd!=hdr.length)){
        debug(D_ERROR, "error writing to data file, expected to write %u got %d", (unsigned)hdr.length, (int)rd);
        return -1;
      }
    }
    else if (hdr.type==PSYNC_CRYPTO_LOG_INT){
      assert(ifd!=INVALID_HANDLE_VALUE);
      records[recid].offset=hdr.offset;
      records[recid].length=hdr.longlengthlo+((uint64_t)hdr.longlengthhi<<32);
      if (++recid>=PSYNC_CRYPTO_SECTOR_SIZE/sizeof(psync_fs_index_record)){
        rd=psync_file_pwrite(ifd, records, sizeof(psync_fs_index_record)*recid, sizeof(psync_fs_index_record)*ioff+sizeof(psync_fs_index_header));
        if (rd!=sizeof(psync_fs_index_record)*recid){
          debug(D_ERROR, "error writing to index file, expected to write %u got %d", (unsigned)(sizeof(psync_fs_index_record)*recid), (int)rd);
          return -1;
        }
        ioff+=recid;
        recid=0;
      }
    }
    else{
      debug(D_ERROR, "bad record type %u", (unsigned)hdr.type);
      return -1;
    }
  }
  if (recid){
    rd=psync_file_pwrite(ifd, records, sizeof(psync_fs_index_record)*recid, sizeof(psync_fs_index_record)*ioff+sizeof(psync_fs_index_header));
    if (rd!=sizeof(psync_fs_index_record)*recid){
      debug(D_ERROR, "error writing to index file, expected to write %u got %d", (unsigned)(sizeof(psync_fs_index_record)*recid), (int)rd);
      return -1;
    }
  }
  if (unlikely_log(psync_file_seek(dfd, size, P_SEEK_SET)!=size || psync_file_truncate(dfd)))
    return -1;
  return 0;
}

static void wait_before_flush(psync_openfile_t *of, uint32_t millisec){
  debug(D_NOTICE, "waiting up to %u milliseconds before flush of %s", (unsigned)millisec, of->currentname);
  psync_milisleep(millisec);
}

/*static int psync_fs_flush_cache_dir(){
  const char *path;
  int ret;
  path=psync_setting_get_string(_PS(fscachepath));
  debug(D_NOTICE, "flushing directory %s", path);
  ret=psync_folder_sync(path);
  if (!ret)
    debug(D_NOTICE, "flushed directory %s", path);
  return ret;
}*/

static int psync_fs_crypto_mark_log_finalized(psync_openfile_t *of, uint64_t filesize){
  psync_crypto_master_record mr;
  int64_t lsize;
  ssize_t wrt;
  lsize=psync_file_size(of->logfile);
  if (unlikely_log(lsize==-1))
    return -EIO;
  assert(lsize==of->loghashctx.length+PSYNC_CRYPTO_SECTOR_SIZE);
  mr.status=PSYNC_LOG_STATUS_FINALIZED;
  mr.hashid=PSYNC_LOG_HASHID_FH256;
  mr.logsize=lsize;
  mr.filesize=filesize;
  psync_fast_hash256_final(&mr.hash, &of->loghashctx);
  mr.crc=psync_crc32c(PSYNC_CRC_INITIAL, &mr, offsetof(psync_crypto_master_record, crc));
  wrt=psync_file_pwrite(of->logfile, &mr, sizeof(mr), 0);
  if (unlikely_log(wrt!=sizeof(mr)))
    return -EIO;
  else
    return 0;
}

static int psync_fs_crypto_log_flush_and_process(psync_openfile_t *of, const char *filename, int dowaits, int locked){
  psync_file_t fd;
  fd=psync_file_open(filename, P_O_RDWR, 0);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE))
    return -EIO;
  if (dowaits && !locked)
    wait_before_flush(of, 2000);
  debug(D_NOTICE, "flushing log data %s", filename);
  if (unlikely_log(psync_file_sync(fd)))
    goto err_eio;
  debug(D_NOTICE, "flushed log data %s", filename);
/* flushing directory does not seem to work on either Windows on Mac, disable for now, maybe look at SQLite code to see if they flush
  if (unlikely_log(psync_fs_flush_cache_dir()))
    goto err_eio;
*/

//  assert(NULL=="break here to test log replay");
  if (unlikely_log(psync_fs_crypto_process_log(fd, of->datafile, of->indexfile, 0)))
    goto err_eio;
  psync_file_close(fd);
  if (dowaits && !locked)
    wait_before_flush(of, 2000);
  debug(D_NOTICE, "flushing data of %s", of->currentname);
  if (unlikely_log(psync_file_sync(of->datafile)))
    return -EIO;
  debug(D_NOTICE, "flushed data of %s", of->currentname);
  if (!of->newfile){
    debug(D_NOTICE, "flushing index of %s", of->currentname);
    if (unlikely_log(psync_file_sync(of->indexfile)))
      return -EIO;
    debug(D_NOTICE, "flushed index of %s", of->currentname);
  }
  return 0;
err_eio:
  psync_file_close(fd);
  return -EIO;
}

static int psync_fs_write_interval_tree_to_log(psync_openfile_t *of){
  psync_crypto_log_header logs[4096/sizeof(psync_crypto_log_header)];
  psync_interval_tree_t *itr;
  uint64_t len;
  ssize_t wrt;
  uint32_t last;
  last=0;
  itr=psync_interval_tree_get_first(of->writeintervals);
  while (itr){
    if (last==ARRAY_SIZE(logs)){
      wrt=psync_file_pwrite(of->logfile, logs, sizeof(logs), of->logoffset);
      if (wrt!=sizeof(logs)){
        debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)sizeof(logs), (int)wrt);
        return -EIO;
      }
      psync_fast_hash256_update(&of->loghashctx, logs, sizeof(logs));
      of->logoffset+=sizeof(logs);
      last=0;
    }
    len=itr->to-itr->from;
    assert((len>>48)==0);
    logs[last].type=PSYNC_CRYPTO_LOG_INT;
    logs[last].longlengthhi=len>>32;
    logs[last].longlengthlo=len&0xffffffffU;
    logs[last].offset=itr->from;
    last++;
    itr=psync_interval_tree_get_next(itr);
  }
  if (last){
    last*=sizeof(psync_crypto_log_header);
    wrt=psync_file_pwrite(of->logfile, logs, last, of->logoffset);
    if (wrt!=last){
      debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)(sizeof(psync_crypto_log_header)*last), (int)wrt);
      return -EIO;
    }
    psync_fast_hash256_update(&of->loghashctx, logs, last);
    of->logoffset+=last;
  }
  return 0;
}

static int psync_fs_crypto_do_finalize_log(psync_openfile_t *of, int fullsync){
  psync_crypto_offsets_t offsets;
  psync_fsfileid_t fileid;
  const char *cachepath;
  char *olog, *flog;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  int ret;
  psync_fs_crypto_offsets_by_plainsize(of->currentsize, &offsets);
  if (of->logoffset==PSYNC_CRYPTO_SECTOR_SIZE && offsets.masterauthoff+(offsets.needmasterauth?PSYNC_CRYPTO_AUTH_SIZE:0)==psync_file_size(of->datafile)){
    debug(D_NOTICE, "skipping finalize of %s", of->currentname);
    return 0;
  }
  debug(D_NOTICE, "finalizing log of %s size %lu", of->currentname, (unsigned long)of->currentsize);
  psync_fs_crypto_offsets_by_plainsize(of->currentsize, &offsets);
  ret=psync_fs_write_auth_tree_to_log(of, &offsets);
  if (unlikely_log(ret))
    return ret;
  debug(D_NOTICE, "wrote checksums to log of %s", of->currentname);
  if (!of->newfile){
    debug(D_NOTICE, "writing interval tree to log of %s", of->currentname);
    ret=psync_fs_write_interval_tree_to_log(of);
    if (unlikely_log(ret))
      return ret;
    debug(D_NOTICE, "wrote interval tree to log of %s", of->currentname);
  }
  ret=psync_fs_crypto_mark_log_finalized(of, offsets.masterauthoff+(offsets.needmasterauth?PSYNC_CRYPTO_AUTH_SIZE:0));
  if (unlikely_log(ret))
    return ret;
  psync_file_schedulesync(of->logfile);
  ret=psync_file_close(of->logfile);
  of->logfile=INVALID_HANDLE_VALUE;
  if (unlikely_log(ret))
    return -EIO;
  debug(D_NOTICE, "finalized log of %s", of->currentname);
  cachepath=psync_setting_get_string(_PS(fscachepath));
  fileid=-of->fileid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)]='l';
  fileidhex[sizeof(psync_fsfileid_t)+1]=0;
  olog=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
  fileidhex[sizeof(psync_fsfileid_t)]='f';
  flog=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
  if (unlikely_log(psync_file_rename_overwrite(olog, flog)) ||
      unlikely_log((of->logfile=psync_file_open(olog, P_O_RDWR, P_O_CREAT|P_O_TRUNC))==INVALID_HANDLE_VALUE) ||
      unlikely_log(psync_fs_crypto_init_log(of))){
    psync_free(olog);
    psync_free(flog);
    return -EIO;
  }
  psync_tree_for_each_element_call_safe(of->sectorsinlog, psync_sector_inlog_t, tree, psync_free);
  of->sectorsinlog=PSYNC_TREE_EMPTY;
  ret=psync_fs_crypto_log_flush_and_process(of, flog, 0, 1);
  psync_file_delete(flog);
  psync_free(olog);
  psync_free(flog);
  return PRINT_NEG_RETURN(ret);
}

static int psync_fs_crypto_finalize_log(psync_openfile_t *of, int fullsync){
  int ret;
  if (of->extender){
    assert(of->currentsize==of->extender->extendto);
    of->currentsize=of->extender->extendedto;
    ret=psync_fs_crypto_do_finalize_log(of, fullsync);
    of->currentsize=of->extender->extendto;
  }
  else
    ret=psync_fs_crypto_do_finalize_log(of, fullsync);
  return ret;
}

static void psync_fs_crypt_add_sector_to_interval_tree(psync_openfile_t *of, psync_crypto_sectorid_t sectorid, size_t size){
  uint64_t offset;
  offset=(uint64_t)psync_fs_crypto_data_sectorid_by_sectorid(sectorid)*PSYNC_CRYPTO_SECTOR_SIZE;
  psync_interval_tree_add(&of->writeintervals, offset, offset+size);
}

PSYNC_NOINLINE static void psync_fs_crypto_reset_log_to_off(psync_openfile_t *of, uint32_t off){
  int64_t sz;
  sz=psync_file_size(of->logfile);
  if (sz!=off)
    debug(D_NOTICE, "need to reset log from size %d to %u", (int)sz, (unsigned)off);
  if (sz==-1 || sz<off || (sz>off && (psync_file_seek(of->logfile, off, P_SEEK_SET)!=off || psync_file_truncate(of->logfile)))){
    const char *cachepath;
    char *log;
    psync_fsfileid_t fileid;
    char fileidhex[sizeof(psync_fsfileid_t)*2+2];
    sz=psync_file_size(of->datafile);
    if (sz==-1){
      debug(D_ERROR, "can not stat data file of %s, can't do anything", of->currentname);
      return;
    }
    of->currentsize=psync_fs_crypto_plain_size(sz);
    debug(D_WARNING, "emptying log");
    psync_file_close(of->logfile);
    cachepath=psync_setting_get_string(_PS(fscachepath));
    fileid=-of->fileid;
    psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
    fileidhex[sizeof(psync_fsfileid_t)]='l';
    fileidhex[sizeof(psync_fsfileid_t)+1]=0;
    log=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    if (psync_file_delete(log))
      debug(D_NOTICE, "could not delete old log file %s", log);
    of->logfile=psync_file_open(log, P_O_RDWR, P_O_CREAT|P_O_TRUNC);
    if (of->logfile==INVALID_HANDLE_VALUE)
      debug(D_WARNING, "could not create new file %s", log);
    else if (psync_fs_crypto_init_log(of))
      debug(D_WARNING, "could not init log file %s", log);

  }
  else
    debug(D_NOTICE, "no need to reset log");
}

static int psync_fs_crypto_write_newfile_full_sector(psync_openfile_t *of, const char *buf, psync_crypto_sectorid_t sectorid, size_t size){
  psync_crypto_log_data_record rec;
  ssize_t wrt;
  uint32_t len;
  psync_crypto_sector_auth_t auth;
  assert(size<=PSYNC_CRYPTO_SECTOR_SIZE);
  assert(sizeof(psync_crypto_log_data_record)==sizeof(psync_crypto_log_header)+PSYNC_CRYPTO_SECTOR_SIZE);
  psync_crypto_aes256_encode_sector(of->encoder, (const unsigned char *)buf, size, rec.data, auth, sectorid);
  memset(&rec.header, 0, sizeof(psync_crypto_log_header));
  rec.header.type=PSYNC_CRYPTO_LOG_DATA;
  rec.header.length=size;
  rec.header.offset=psync_fs_crypto_data_offset_by_sectorid(sectorid);
  len=offsetof(psync_crypto_log_data_record, data)+size;
  wrt=psync_file_pwrite(of->logfile, &rec, len, of->logoffset);
  if (unlikely(wrt!=len)){
    debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)len, (int)wrt);
    psync_fs_crypto_reset_log_to_off(of, of->logoffset);
    return -EIO;
  }
  psync_fast_hash256_update(&of->loghashctx, &rec, len);
  psync_fs_crypto_set_sector_log_offset(of, sectorid, of->logoffset, auth);
  of->logoffset+=len;
  if (!of->newfile)
    psync_fs_crypt_add_sector_to_interval_tree(of, sectorid, size);
  return 0;
}

static int psync_fs_crypto_write_newfile_partial_sector(psync_openfile_t *of, const char *buf, psync_crypto_sectorid_t sectorid, size_t size, off_t offset){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  int rd;
  assert(offset+size<=PSYNC_CRYPTO_SECTOR_SIZE);
  memset(buff, 0, sizeof(buff));
  rd=psync_fs_crypto_read_newfile_full_sector(of, buff, sectorid);
  if (rd<0)
    return rd;
  assertw(rd>=offset);
  memcpy(buff+offset, buf, size);
  if (rd<size+offset)
    rd=size+offset;
  return psync_fs_crypto_write_newfile_full_sector(of, buff, sectorid, rd);
}

static int psync_fs_newfile_fillzero(psync_openfile_t *of, uint64_t size, uint64_t offset){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  uint64_t wr;
  psync_crypto_sectorid_t sectorid;
  int ret;
  memset(buff, 0, sizeof(buff));
  sectorid=offset/PSYNC_CRYPTO_SECTOR_SIZE;
  if (offset%PSYNC_CRYPTO_SECTOR_SIZE){
    wr=PSYNC_CRYPTO_SECTOR_SIZE-(offset%PSYNC_CRYPTO_SECTOR_SIZE);
    if (wr>size)
      wr=size;
    ret=psync_fs_crypto_write_newfile_partial_sector(of, buff, sectorid, wr, offset%PSYNC_CRYPTO_SECTOR_SIZE);
    if (ret<0)
      goto fail;
    size-=wr;
    offset+=wr;
    if (likely(of->currentsize<offset))
      of->currentsize=offset;
    sectorid++;
  }
  while (size){
    if (size>PSYNC_CRYPTO_SECTOR_SIZE)
      wr=PSYNC_CRYPTO_SECTOR_SIZE;
    else
      wr=size;
    ret=psync_fs_crypto_write_newfile_full_sector(of, buff, sectorid, wr);
    if (ret<0)
      goto fail;
    size-=wr;
    offset+=wr;
    if (likely(of->currentsize<offset))
      of->currentsize=offset;
    sectorid++;
  }
  return 0;
fail:
  return PRINT_RETURN(ret);
}

static int psync_fs_crypto_write_newfile_locked_nu(psync_openfile_t *of, const char *buf, uint64_t size, uint64_t offset, int checkextender){
  uint64_t off2, offdiff;
  psync_crypto_sectorid_t sectorid;
  int ret, wrt;
  assert(of->encrypted);
  assert(of->encoder);
//  debug(D_NOTICE, "write to %s size %lu, offset %lu, currentsize %lu", of->currentname, (unsigned long)size, (unsigned long)offset, (unsigned long)of->currentsize);
  if (unlikely((size+offset+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE>PSYNC_CRYPTO_MAX_SECTORID))
    return -EINVAL;
  if (unlikely(!size))
    return 0;
  if (checkextender){
    ret=psync_fs_crypto_wait_extender_after_locked(of, offset+size);
    if (unlikely_log(ret))
      return ret;
  }
  if (unlikely(of->currentsize<offset)){
    ret=psync_fs_newfile_fillzero(of, offset-of->currentsize, of->currentsize);
    if (ret)
      return ret;
    assert(of->currentsize==offset);
  }
  sectorid=offset/PSYNC_CRYPTO_SECTOR_SIZE;
  off2=offset%PSYNC_CRYPTO_SECTOR_SIZE;
  wrt=0;
  if (off2){
    if (PSYNC_CRYPTO_SECTOR_SIZE-off2<size)
      offdiff=PSYNC_CRYPTO_SECTOR_SIZE-off2;
    else
      offdiff=size;
    ret=psync_fs_crypto_write_newfile_partial_sector(of, buf, sectorid, offdiff, off2);
    offset+=offdiff;
    buf+=offdiff;
    wrt+=offdiff;
    size-=offdiff;
    sectorid++;
    if (ret)
      return ret;
    if (of->currentsize<offset)
      of->currentsize=offset;
  }
  while (size>=PSYNC_CRYPTO_SECTOR_SIZE){
    ret=psync_fs_crypto_write_newfile_full_sector(of, buf, sectorid, PSYNC_CRYPTO_SECTOR_SIZE);
    buf+=PSYNC_CRYPTO_SECTOR_SIZE;
    offset+=PSYNC_CRYPTO_SECTOR_SIZE;
    wrt+=PSYNC_CRYPTO_SECTOR_SIZE;
    size-=PSYNC_CRYPTO_SECTOR_SIZE;
    sectorid++;
    if (ret)
      return ret;
    if (of->currentsize<offset)
      of->currentsize=offset;
  }
  if (size){
    if (offset==of->currentsize)
      ret=psync_fs_crypto_write_newfile_full_sector(of, buf, sectorid, size);
    else
      ret=psync_fs_crypto_write_newfile_partial_sector(of, buf, sectorid, size, 0);
    if (ret)
      return ret;
    wrt+=size;
    if (of->currentsize<offset+size)
      of->currentsize=offset+size;
  }
  if (of->logoffset>=PSYNC_CRYPTO_MAX_LOG_SIZE){
    ret=psync_fs_crypto_finalize_log(of, 0);
    if (ret)
      return ret;
  }
  return wrt;

}

int psync_fs_crypto_write_newfile_locked(psync_openfile_t *of, const char *buf, uint64_t size, uint64_t offset){
  int ret=psync_fs_crypto_write_newfile_locked_nu(of, buf, size, offset, 1);
  pthread_mutex_unlock(&of->mutex);
  return ret;
}

int psync_fs_crypto_read_modified_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset){
  psync_interval_tree_t *itr;
  char *bufoff;
  uint64_t eoffset;
  size_t rd;
  psync_crypto_sectorid_t firstsectorid, lastsectorid, sectorid, esectorid;
  uint32_t offmod;
  int rfr;
  assert(of->encrypted);
  assert(of->encoder);
  if (unlikely((size+offset+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE>PSYNC_CRYPTO_MAX_SECTORID))
    return psync_fs_unlock_ret(of, -EINVAL);
  if (unlikely(!size || offset>=of->currentsize))
    return psync_fs_unlock_ret(of, 0);
  if (offset+size>of->currentsize)
    size=of->currentsize-offset;
  firstsectorid=offset/PSYNC_CRYPTO_SECTOR_SIZE;
  lastsectorid=(offset+size-1)/PSYNC_CRYPTO_SECTOR_SIZE;
  rfr=0;
  itr=NULL;
  for (sectorid=firstsectorid; sectorid<=lastsectorid; sectorid++){
    esectorid=psync_fs_crypto_data_sectorid_by_sectorid(sectorid);
    eoffset=(uint64_t)esectorid*PSYNC_CRYPTO_SECTOR_SIZE;
    if (itr && itr->from<=eoffset && itr->to>eoffset)
      rfr|=1;
    else{
      itr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, eoffset);
      if (itr && itr->from<=eoffset)
        rfr|=1;
      else
        rfr|=2;
    }
  }
  if (rfr==1){
    debug(D_NOTICE, "doing read at offset %lu size %lu from local changes", (unsigned long)offset, (unsigned long)size);
    return psync_fs_crypto_read_newfile_locked(of, buf, size, offset);
  }
  else if (rfr==2){
    debug(D_NOTICE, "doing read at offset %lu size %lu from remote only", (unsigned long)offset, (unsigned long)size);
    return psync_pagecache_read_unmodified_encrypted_locked(of, buf, size, offset);
  }
  else{
    assert(rfr==3);
    debug(D_NOTICE, "doing read at offset %lu size %lu from remote and local merge", (unsigned long)offset, (unsigned long)size);
  }
  rfr=psync_pagecache_read_unmodified_encrypted_locked(of, buf, size, offset);
  if (unlikely(rfr<0)){
    debug(D_WARNING, "reading from remote failed with error %d", rfr);
    return rfr;
  }
  psync_fs_lock_file(of);
  if (unlikely(offset+size>of->currentsize)){
    debug(D_NOTICE, "file size changed during read");
    if (offset>=of->currentsize)
      return psync_fs_unlock_ret(of, 0);
    size=of->currentsize-offset;
    lastsectorid=(offset+size-1)/PSYNC_CRYPTO_SECTOR_SIZE;
  }
  offmod=offset%PSYNC_CRYPTO_SECTOR_SIZE;
  for (sectorid=firstsectorid; sectorid<=lastsectorid; sectorid++){
    esectorid=psync_fs_crypto_data_sectorid_by_sectorid(sectorid);
    eoffset=(uint64_t)esectorid*PSYNC_CRYPTO_SECTOR_SIZE;
    if (!(itr && itr->from<=eoffset && itr->to>eoffset)){
      itr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, eoffset);
      if (!(itr && itr->from<=eoffset))
        continue;
    }
    if (sectorid==firstsectorid && offmod){
      rd=PSYNC_CRYPTO_SECTOR_SIZE-offmod;
      if (rd>size)
        rd=size;
      rfr=psync_fs_crypto_read_newfile_partial_sector(of, buf, sectorid, rd, offmod);
      if (unlikely_log(rfr!=rd))
        psync_fs_unlock_ret(of, rfr);
    }
    else{
      bufoff=buf+(sectorid-firstsectorid)*PSYNC_CRYPTO_SECTOR_SIZE-offmod;
      if (sectorid==lastsectorid && (offset+size)%PSYNC_CRYPTO_SECTOR_SIZE)
        rd=(offset+size)%PSYNC_CRYPTO_SECTOR_SIZE;
      else
        rd=PSYNC_CRYPTO_SECTOR_SIZE;
      if (rd==PSYNC_CRYPTO_SECTOR_SIZE)
        rfr=psync_fs_crypto_read_newfile_full_sector(of, bufoff, sectorid);
      else
        rfr=psync_fs_crypto_read_newfile_partial_sector(of, bufoff, sectorid, rd, 0);
      if (unlikely_log(rfr!=rd))
        psync_fs_unlock_ret(of, rfr);
    }
  }
  return psync_fs_unlock_ret(of, size);
}

int psync_fs_crypto_write_modified_locked_nu(psync_openfile_t *of, const char *buf, uint64_t size, uint64_t offset, int checkextender);

static int psync_fs_modfile_fillzero(psync_openfile_t *of, uint64_t size, uint64_t offset, int checkextender){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  uint64_t wr;
  int ret;
  memset(buff, 0, sizeof(buff));
  while (size){
    if (offset%PSYNC_CRYPTO_SECTOR_SIZE){
      wr=PSYNC_CRYPTO_SECTOR_SIZE-(offset%PSYNC_CRYPTO_SECTOR_SIZE);
      if (wr>size)
        wr=size;
    }
    else{
      if (size>PSYNC_CRYPTO_SECTOR_SIZE)
        wr=PSYNC_CRYPTO_SECTOR_SIZE;
      else
        wr=size;
    }
    ret=psync_fs_crypto_write_modified_locked_nu(of, buff, wr, offset, checkextender);
    if (ret<=0)
      return ret;
    offset+=ret;
    size-=ret;
  }
  return 0;
}

int psync_fs_crypto_write_modified_locked_nu(psync_openfile_t *of, const char *buf, uint64_t size, uint64_t offset, int checkextender){
  psync_interval_tree_t *itr, *needtodwl;
  psync_pagecache_read_range *ranges;
  char *tmpbuf;
  psync_crypto_offsets_t offsets;
  uint64_t eoffset, end;
  size_t isize;
  ssize_t bw;
  psync_crypto_sectorid_t firstsectorid, lastsectorid, sectorid, esectorid;
  uint32_t l, asize, aid, icnt;
  int ret;
//  debug(D_NOTICE, "off=%lu size=%lu cs=%lu ce=%d", (unsigned long)offset, (unsigned long)size, (unsigned long)of->currentsize, checkextender);
  if (unlikely((size+offset+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE>PSYNC_CRYPTO_MAX_SECTORID))
    return -EINVAL;
  if (checkextender){
    ret=psync_fs_crypto_wait_extender_after_locked(of, offset+size);
    if (unlikely_log(ret))
      return ret;
  }
  if (unlikely(!size))
    return 0;
retry:
  if (unlikely(of->currentsize<offset)){
    ret=psync_fs_modfile_fillzero(of, offset-of->currentsize, of->currentsize, 0);
    if (ret)
      return ret;
  }
  firstsectorid=offset/PSYNC_CRYPTO_SECTOR_SIZE;
  lastsectorid=(offset+size-1)/PSYNC_CRYPTO_SECTOR_SIZE;
  itr=NULL;
  needtodwl=NULL;
  if (offset==of->initialsize && firstsectorid && offset%PSYNC_CRYPTO_SECTOR_SIZE==0)
    lastsectorid=--firstsectorid;
  for (sectorid=firstsectorid; sectorid<=lastsectorid; sectorid++){
    if ((uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE>=of->initialsize || (uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE>=of->currentsize)
      break;
    esectorid=psync_fs_crypto_data_sectorid_by_sectorid(sectorid);
    eoffset=(uint64_t)esectorid*PSYNC_CRYPTO_SECTOR_SIZE;
    if (itr && itr->from<=eoffset && itr->to>eoffset)
      continue;
    itr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, eoffset);
    if (itr && itr->from<=eoffset)
      continue;
    if ((sectorid==firstsectorid && offset%PSYNC_CRYPTO_SECTOR_SIZE!=0) || (sectorid==lastsectorid && (offset+size)%PSYNC_CRYPTO_SECTOR_SIZE!=0)){
      end=eoffset+PSYNC_CRYPTO_SECTOR_SIZE;
      if (itr && itr->from<end)
        end=itr->from;
      psync_interval_tree_add(&needtodwl, eoffset, end);
    }
    if (sectorid!=firstsectorid && sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS!=0)
      continue;
    // Here we create offsets by current size as if the file grew, we would have already moved all trailing checksums to a new location and
    // they would be in of->writeintervals anyway.
    if (of->extender)
      psync_fs_crypto_offsets_by_plainsize(of->extender->extendedto, &offsets);
    else
      psync_fs_crypto_offsets_by_plainsize(of->currentsize, &offsets);
    for (l=0; l<=offsets.treelevels; l++){
      psync_fs_crypto_get_auth_sector_off(sectorid, l, &offsets, &eoffset, &asize, &aid);
      itr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, eoffset);
      if (itr && itr->from<=eoffset)
        continue;
      end=eoffset+asize;
      if (itr && itr->from<end)
        end=itr->from;
      psync_interval_tree_add(&needtodwl, eoffset, end);
    }
  }
  if (needtodwl){
    icnt=0;
    isize=0;
    if (of->currentsize<of->initialsize)
      eoffset=psync_fs_crypto_crypto_size(of->currentsize);
    else
      eoffset=psync_fs_crypto_crypto_size(of->initialsize);
    itr=psync_interval_tree_get_first(needtodwl);
    do {
      // if we are past initialsize, we are probably trying to download uncommited auth sector
      if (itr->from>=eoffset)
        break;
      debug(D_NOTICE, "need to download from offset %lu size %lu to do a write at offset %lu size %lu",
            (unsigned long)itr->from, (unsigned long)(itr->to-itr->from), (unsigned long)offset, (unsigned long)size);
      if (itr->to>eoffset)
        itr->to=eoffset;
      icnt++;
      isize+=itr->to-itr->from;
      itr=psync_interval_tree_get_next(itr);
    } while (itr);
    if (!icnt)
      psync_interval_tree_free(needtodwl);
    else{
      ranges=psync_new_cnt(psync_pagecache_read_range, icnt);
      tmpbuf=psync_new_cnt(char, isize);
      icnt=0;
      isize=0;
      itr=psync_interval_tree_get_first(needtodwl);
      do {
        if (itr->from>=eoffset)
          break;
        ranges[icnt].offset=itr->from;
        ranges[icnt].size=itr->to-itr->from;
        ranges[icnt].buf=tmpbuf+isize;
        isize+=ranges[icnt].size;
        icnt++;
        itr=psync_interval_tree_get_next(itr);
      } while (itr);
      psync_interval_tree_free(needtodwl);
      ret=psync_pagecache_readv_locked(of, ranges, icnt);
      // we are unlocked now
      psync_fs_lock_file(of);
      if (unlikely(ret)){
        psync_free(ranges);
        psync_free(tmpbuf);
        debug(D_NOTICE, "downloading of ranges failed");
        return ret;
      }
      ret=0;
      debug(D_NOTICE, "ranges downloaded");
      for (l=0; l<icnt; l++){
        itr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, ranges[l].offset);
        if (unlikely(itr && itr->from<ranges[l].offset+ranges[l].size && ranges[l].offset<itr->to)){
          // we were not supposed to have intersection, some write happened while we were unlocked in psync_pagecache_readv_locked
          debug(D_NOTICE, "restarting write as range %lu to %lu downloaded and %lu to %lu local intersect", (unsigned long)ranges[l].offset,
                (unsigned long)(ranges[l].offset+ranges[l].size), (unsigned long)itr->from, (unsigned long)itr->to);
          psync_free(ranges);
          psync_free(tmpbuf);
          goto retry;
        }
        debug(D_NOTICE, "wrote %u bytes to offset %lu", (unsigned)ranges[l].size, (unsigned long)ranges[l].offset);
        bw=psync_file_pwrite(of->datafile, ranges[l].buf, ranges[l].size, ranges[l].offset);
        if (bw!=ranges[l].size){
          debug(D_ERROR, "write to datafile of %u bytes returned %d", (unsigned)ranges[l].size, (int)bw);
          ret=-EIO;
          break;
        }
        psync_interval_tree_add(&of->writeintervals, ranges[l].offset, ranges[l].offset+ranges[l].size);
      }
      // we do NOT need to fsync of->datafile, as we wrote to positions that were empty
      psync_free(ranges);
      psync_free(tmpbuf);
      if (unlikely(ret))
        return ret;
    }
  }
  // now that we have all auth or partial data sectors, we proceed the same way as if it is a new file write
  return psync_fs_crypto_write_newfile_locked_nu(of, buf, size, offset, checkextender);
}

int psync_fs_crypto_write_modified_locked(psync_openfile_t *of, const char *buf, uint64_t size, uint64_t offset){
  int ret=psync_fs_crypto_write_modified_locked_nu(of, buf, size, offset, 1);
  pthread_mutex_unlock(&of->mutex);
  return ret;
}

static int psync_fs_crypto_ftruncate_to_zero(psync_openfile_t *of){
  int ret;
  debug(D_NOTICE, "truncating file %s from %lu to zero", of->currentname, (unsigned long)of->currentsize);
  if (psync_file_seek(of->logfile, 0, P_SEEK_SET)!=0 || psync_file_truncate(of->logfile)){
    debug(D_WARNING, "failed to truncate log file of %s", of->currentname);
    return -EIO;
  }
  ret=psync_fs_crypto_init_log(of);
  if (unlikely(ret))
    return ret;
  if (!of->newfile){
    psync_interval_tree_free(of->writeintervals);
    of->writeintervals=NULL;
    psync_interval_tree_add(&of->writeintervals, 0, psync_fs_crypto_crypto_size(of->initialsize));
  }
  psync_tree_for_each_element_call_safe(of->sectorsinlog, psync_sector_inlog_t, tree, psync_free);
  of->sectorsinlog=PSYNC_TREE_EMPTY;
  of->currentsize=0;
  psync_fs_crypto_kill_extender_locked(of);
  return 0;
}

static int psync_fs_crypto_ftruncate_down(psync_openfile_t *of, uint64_t size){
  char buf[PSYNC_CRYPTO_SECTOR_SIZE];
  uint64_t writeid, lastsectoff, elastsectoroff;
  psync_interval_tree_t *intr;
  psync_tree *tr, *ntr;
  psync_crypto_sectorid_t lastsectorid, elastsectorid;
  uint32_t lastsectornewsize, lastsectoroldsize;
  int ret;
  assert(size>0 && size<of->currentsize);
  debug(D_NOTICE, "truncating file %s from %lu down to %lu", of->currentname, (unsigned long)of->currentsize, (unsigned long)size);
  if (of->extender){
    if (of->extender->error)
      return of->extender->error;
    if (!of->extender->ready){
      if (of->extender->extendedto>size)
        psync_fs_crypto_kill_extender_locked(of);
      else{
        debug(D_NOTICE, "extender is so far extended up to %lu, switching target from %lu to %lu and we are done",
              (unsigned long)of->extender->extendedto, (unsigned long)of->extender->extendto, (unsigned long)size);
        of->extender->extendto=size;
        of->currentsize=size;
        return 0;
      }
    }
  }
  lastsectorid=(size-1)/PSYNC_CRYPTO_SECTOR_SIZE;
  lastsectoff=(uint64_t)lastsectorid*PSYNC_CRYPTO_SECTOR_SIZE;
  lastsectornewsize=size-lastsectoff;
  if (of->currentsize>=lastsectoff+PSYNC_CRYPTO_SECTOR_SIZE)
    lastsectoroldsize=PSYNC_CRYPTO_SECTOR_SIZE;
  else
    lastsectoroldsize=of->currentsize-lastsectoff;
  elastsectorid=psync_fs_crypto_data_sectorid_by_sectorid(lastsectorid);
  elastsectoroff=(uint64_t)elastsectorid*PSYNC_CRYPTO_SECTOR_SIZE;
retry:
  if (of->newfile || ((intr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, elastsectoroff)) && intr->from<=elastsectoroff)){
    ret=psync_fs_crypto_read_newfile_full_sector(of, buf, lastsectorid);
    if (ret<0)
      return ret;
    assert(ret==lastsectoroldsize);
  }
  else{
    writeid=of->writeid;
    ret=psync_fs_crypto_read_modified_locked(of, buf, lastsectoroldsize, lastsectoff);
    // unlocked now
    if (ret<0)
      return ret;
    psync_fs_lock_file(of);
    if (unlikely(of->writeid!=writeid)){
      debug(D_NOTICE, "writeid changed, restarting");
      goto retry;
    }
    // the write will push all the auth data we need to the datafile (it is probably in cache from the read)
    ret=psync_fs_crypto_write_modified_locked(of, buf, lastsectoroldsize, lastsectoff);
    // unlocked now
    if (ret<0)
      return ret;
    psync_fs_lock_file(of);
    if (unlikely(of->writeid!=writeid)){
      debug(D_NOTICE, "writeid changed, restarting");
      goto retry;
    }
  }
  of->currentsize=lastsectoff;
  tr=psync_tree_get_last(of->sectorsinlog);
  while (tr && psync_tree_element(tr, psync_sector_inlog_t, tree)->sectorid>=lastsectorid){
    ntr=psync_tree_get_prev(tr);
    assert(!ntr || psync_tree_element(tr, psync_sector_inlog_t, tree)->sectorid>psync_tree_element(ntr, psync_sector_inlog_t, tree)->sectorid);
    psync_tree_del(&of->sectorsinlog, tr);
    psync_free(tr);
    tr=ntr;
  }
  ret=psync_fs_crypto_write_newfile_full_sector(of, buf, lastsectorid, lastsectornewsize);
  if (ret<0)
    return ret;
  of->currentsize=size;
  if (!of->newfile)
    psync_interval_tree_cut_end(&of->writeintervals, psync_fs_crypto_crypto_size(size));
  debug(D_NOTICE, "file %s truncated to %lu", of->currentname, (unsigned long)size);
  return 0;
}

static void psync_fs_extender_thread(void *ptr){
  psync_openfile_t *of;
  psync_enc_file_extender_t *ext;
  uint64_t cs;
  int ret;
  of=(psync_openfile_t *)ptr;
  psync_fs_lock_file(of);
  assert(of->extender);
  ext=of->extender;
  while (!ext->kill && ext->extendedto<ext->extendto){
    if (ext->extendto-ext->extendedto>PSYNC_CRYPTO_EXTENDER_STEP){
      cs=PSYNC_CRYPTO_EXTENDER_STEP;
      if (ext->extendedto%PSYNC_CRYPTO_SECTOR_SIZE)
        cs-=ext->extendedto%PSYNC_CRYPTO_SECTOR_SIZE;
    }
    else
      cs=ext->extendto-ext->extendedto;
    if (of->newfile)
      ret=psync_fs_newfile_fillzero(of, cs, ext->extendedto);
    else
      ret=psync_fs_modfile_fillzero(of, cs, ext->extendedto, 0);
    if (ret){
      ext->error=ret;
      of->currentsize=ext->extendedto;
      break;
    }
    ext->extendedto+=cs;
    pthread_mutex_unlock(&of->mutex);
    debug(D_NOTICE, "extender at %lu of %lu", (unsigned long)ext->extendedto, (unsigned long)ext->extendto);
    psync_yield_cpu();
    psync_fs_lock_file(of);
    if (ext->waiters){
      pthread_cond_broadcast(&ext->cond);
      pthread_mutex_unlock(&of->mutex);
      psync_yield_cpu();
      psync_fs_lock_file(of);
    }
    if (of->logoffset>=PSYNC_CRYPTO_MAX_LOG_SIZE){
      ret=psync_fs_crypto_finalize_log(of, 0);
      if (ret){
        ext->error=ret;
        of->currentsize=ext->extendedto;
        break;
      }
    }
  }
  ext->ready=1;
  if (ext->kill)
    debug(D_NOTICE, "killed");
  else if (ext->error)
    debug(D_NOTICE, "error %d", ext->error);
  else
    debug(D_NOTICE, "finished");
  while (ext->waiters){
    debug(D_NOTICE, "waiting for waiters to finish");
    pthread_cond_broadcast(&ext->cond);
    pthread_mutex_unlock(&of->mutex);
    psync_milisleep(1);
    psync_fs_lock_file(of);
  }
  of->extender=NULL;
  pthread_mutex_unlock(&of->mutex);
  pthread_cond_destroy(&ext->cond);
  psync_free(ext);
  psync_fs_dec_of_refcnt(of);
}

static int psync_fs_crypto_run_extender(psync_openfile_t *of, uint64_t size){
  psync_enc_file_extender_t *ext;
  assert(of->currentsize<size);
  assert(!of->extender);
  debug(D_NOTICE, "will run extender thread to extend from %lu to %lu", (unsigned long)of->currentsize, (unsigned long)size);
  ext=psync_new(psync_enc_file_extender_t);
  pthread_cond_init(&ext->cond, NULL);
  ext->extendto=size;
  ext->extendedto=of->currentsize;
  of->currentsize=size;
  ext->waiters=0;
  ext->error=0;
  ext->ready=0;
  ext->kill=0;
  of->extender=ext;
  psync_fs_inc_of_refcnt_locked(of);
  psync_run_thread1("extender", psync_fs_extender_thread, of);
  return 0;
}

int psync_fs_crypto_ftruncate(psync_openfile_t *of, uint64_t size){
  int ret;
  assert(of->modified);
retry:
  if (of->currentsize<size){
    debug(D_NOTICE, "truncating file %s from %lu up to %lu", of->currentname, (unsigned long)of->currentsize, (unsigned long)size);
    if (of->extender){
      if (of->extender->ready){
        ret=psync_fs_crypto_wait_no_extender_locked(of);
        if (ret)
          return ret;
        else
          goto retry; // we've unlocked mutex while waiting, of->currentsize might be changed
      }
      assert(of->extender->extendto<size);
      debug(D_NOTICE, "found active extender that extended the file up to %lu of target %lu, changing target to %lu",
            (unsigned long)of->extender->extendedto, (unsigned long)of->extender->extendto, (unsigned long)size);
      of->extender->extendto=size;
      of->currentsize=size;
      return 0;
    }
    if (size-of->currentsize>=PSYNC_CRYPTO_RUN_EXTEND_IN_THREAD_OVER){
      if (!of->newfile){
        // for files that are not new, there is a chance for a network error, better catch it now
        // there is no any significance in the size of the write, even 1 byte write should download everything that we need
        ret=psync_fs_modfile_fillzero(of, of->currentsize%PSYNC_CRYPTO_SECTOR_SIZE+PSYNC_CRYPTO_SECTOR_SIZE, of->currentsize, 0);
        if (ret)
          return ret;
      }
      return psync_fs_crypto_run_extender(of, size);
    }
    if (of->newfile)
      ret=psync_fs_newfile_fillzero(of, size-of->currentsize, of->currentsize);
    else
      ret=psync_fs_modfile_fillzero(of, size-of->currentsize, of->currentsize, 0);
  }
  else if (of->currentsize>size){
    if (size==0)
      ret=psync_fs_crypto_ftruncate_to_zero(of);
    else
      return psync_fs_crypto_ftruncate_down(of, size);
  }
  else
    ret=0;
  return ret;
}

int psync_fs_crypto_flush_file(psync_openfile_t *of){
  int ret=psync_fs_crypto_wait_no_extender_locked(of);
  if (ret)
    return ret;
  return psync_fs_crypto_finalize_log(of, 1);
}

uint64_t psync_fs_crypto_plain_size(uint64_t cryptosize){
  psync_crypto_offsets_t offsets;
  psync_fs_crypto_offsets_by_cryptosize(cryptosize, &offsets);
  return offsets.plainsize;
}

uint64_t psync_fs_crypto_crypto_size(uint64_t plainsize){
  psync_crypto_offsets_t offsets;
  psync_fs_crypto_offsets_by_plainsize(plainsize, &offsets);
  return offsets.masterauthoff+(offsets.needmasterauth?PSYNC_CRYPTO_AUTH_SIZE:0);
}

void psync_fs_crypto_get_auth_sector_off(psync_crypto_sectorid_t sectorid, uint32_t level, psync_crypto_offsets_t *offsets,
                                         uint64_t *offset, uint32_t *size, uint32_t *authid){
  psync_crypto_sectorid_t sizesecd, secd;
  uint32_t i, aid;
  sizesecd=get_last_sectorid_by_size(offsets->plainsize)/PSYNC_CRYPTO_HASH_TREE_SECTORS;
  secd=sectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
  aid=sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS;
  for (i=0; i<level; i++){
    sizesecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    aid=secd%PSYNC_CRYPTO_HASH_TREE_SECTORS;
    secd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
  }
  if (secd==sizesecd){
    *offset=offsets->lastauthsectoroff[level];
    *size=offsets->lastauthsectorlen[level];
  }
  else{
    assert(secd<sizesecd);
    *offset=psync_fs_crypto_auth_offset(level, secd);
    *size=PSYNC_CRYPTO_SECTOR_SIZE;
  }
  *authid=aid;
}

static void psync_fs_crypto_del_log(const char *path){
  debug(D_NOTICE, "deleting not finalized log file %s", path);
  if (psync_file_delete(path))
    debug(D_WARNING, "failed to delete %s", path);
}

static unsigned conv_xdigit(char dig){
  if (dig>='0' && dig<='9')
    return dig-'0';
  else if (dig>='a' && dig<='f')
    return dig-'a'+10;
  else
    return dig-'A'+10;
}

static void psync_fs_pause_task_by_name(const char *fn){
  uint64_t taskid, mul;
  psync_sql_res *res;
  taskid=0;
  mul=1;
  while (isxdigit(fn[0]) && isxdigit(fn[1])){
    fn+=2;
    taskid+=mul*(conv_xdigit(fn[0])*16+conv_xdigit(fn[1]));
    mul*=256;
  }
  debug(D_NOTICE, "pausing taskid %lu", (unsigned long)taskid);
  res=psync_sql_prep_statement("UPDATE fstask SET status=1 WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_run_free(res);
}

static void psync_fs_crypto_check_log(char *path, const char *fn){
  psync_file_t lfd, dfd, ifd;
  size_t plen;
  int ret;
  char och;
  lfd=psync_file_open(path, P_O_RDONLY, 0);
  if (unlikely(lfd==INVALID_HANDLE_VALUE)){
    debug(D_WARNING, "could not open %s for reading, errno=%d", path, (int)psync_fs_err());
    psync_fs_pause_task_by_name(fn);
    return;
  }
  debug(D_NOTICE, "processing log file %s", path);
  plen=strlen(path)-1;
  och=path[plen];
  path[plen]='d';
  dfd=psync_file_open(path, P_O_RDWR, 0);
  if (unlikely(dfd==INVALID_HANDLE_VALUE)){
    debug(D_WARNING, "could not open data file %s, errno=%d", path, (int)psync_fs_err());
    psync_file_close(lfd);
    path[plen]=och;
    psync_fs_crypto_del_log(path);
    return;
  }
  path[plen]='i';
  ifd=psync_file_open(path, P_O_RDWR, 0);
  ret=psync_fs_crypto_process_log(lfd, dfd, ifd, 1) || psync_file_sync(dfd);
  psync_file_close(lfd);
  psync_file_close(dfd);
  if (ifd!=INVALID_HANDLE_VALUE){
    if (psync_file_sync(ifd))
      ret=-1;
    psync_file_close(ifd);
  }
  path[plen]=och;
  if (unlikely(ret)){
    debug(D_WARNING, "failed to process log file %s", path);
    psync_fs_crypto_del_log(path);
  }
  else{
    psync_file_delete(path);
    debug(D_NOTICE, "processed log file %s", path);
  }
}

static void psync_fs_crypto_check_file(void *ptr, psync_pstat_fast *st){
  size_t len;
  char *path;
  char ch;
  if (st->isfolder)
    return;
  len=strlen(st->name);
  if (!len)
    return;
  ch=st->name[len-1];
  if (ch=='l' || ch=='f'){
    path=psync_strcat((const char *)ptr, PSYNC_DIRECTORY_SEPARATOR, st->name, NULL);
    psync_fs_crypto_check_log(path, st->name);
    psync_free(path);
  }
}

void psync_fs_crypto_check_logs(){
  const char *cachepath;
  cachepath=psync_setting_get_string(_PS(fscachepath));
  debug(D_NOTICE, "checking for unprocessed log files in %s", cachepath);
  if (psync_list_dir_fast(cachepath, psync_fs_crypto_check_file, (char *)cachepath))
    debug(D_WARNING, "list of %s failed", cachepath);
  debug(D_NOTICE, "log check finished");
}
