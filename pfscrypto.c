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

// this is only for debug, adds needless checks of tree for local files
#define PSYNC_DO_LOCAL_FULL_TREE_CHECK 1

#define PSYNC_CRYPTO_LOG_HEADER 0
#define PSYNC_CRYPTO_LOG_DATA   1
#define PSYNC_CRYPTO_LOG_INT    2

#define PSYNC_CRYPTO_HASH_TREE_SHIFT 8

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
  psync_crypto_log_header hdr;
  ssize_t wrt;
  memset(&hdr, 0, sizeof(hdr));
  hdr.type=PSYNC_CRYPTO_LOG_HEADER;
  wrt=psync_file_pwrite(of->logfile, &hdr, sizeof(hdr), 0);
  if (unlikely(wrt!=sizeof(hdr))){
    debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)sizeof(hdr), (int)wrt);
    return -EIO;
  }
  of->logoffset=sizeof(hdr);
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
  if (rd!=hdr.length)
    return -EIO;
  if (psync_crypto_aes256_decode_sector(of->encoder, buff, rd, (unsigned char *)buf, se->auth, se->sectorid))
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
      debug(D_WARNING, "verify failed on level %u, sectorid %u, off %lu, ssize %u", level, sectorid, off, ssize);
      return -1;
    }
    psync_crypto_sign_auth_sector(of->encoder, buff, ssize, auth);
  }
  return 0;
}
#endif

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
    else{
      return psync_fs_crypto_read_newfile_full_sector_from_log(of, buf, tr);
    }
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
      wrt=psync_file_pwrite(of->logfile, &autharr[level], sz, of->logoffset+sizeof(hdr));
      if (unlikely(wrt!=sz)){
        debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)sz, (int)wrt);
        return -EIO;
      }
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
      } while (oldsecd!=newsecd && (level<ooffsets.treelevels || (ooffsets.needmasterauth && level==ooffsets.treelevels)));
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
        return ret;
    }
    memcpy(authsect[0][sect->sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS], sect->auth, PSYNC_CRYPTO_AUTH_SIZE);
    lastsect=sect->sectorid;
    sect=psync_tree_element(psync_tree_get_next(&sect->tree), psync_sector_inlog_t, tree);
  }
  ret=psync_fs_crypto_switch_sectors(of, lastsect, PSYNC_CRYPTO_INVALID_SECTORID, authsect, offsets);
  if (ret)
    return ret;
  if (offsets->needmasterauth && (ret=psync_fs_crypto_write_master_auth(of, authsect, offsets)))
    return ret;
  debug(D_NOTICE, "wrote three to log, lastsectorid=%u, currentsize=%lu", (unsigned)lastsect, (unsigned long)of->currentsize);
  return 0;
}

static int psync_fs_crypto_process_log(psync_openfile_t *of, psync_fsfileid_t fd){
  char buff[PSYNC_CRYPTO_SECTOR_SIZE];
  psync_fs_index_record *records;
  psync_crypto_log_header hdr;
  uint64_t off, size;
  ssize_t rd;
  uint32_t recid;
  if (unlikely_log(psync_file_pread(fd, &hdr, sizeof(hdr), 0)!=sizeof(hdr)))
    return -1;
  if (unlikely_log(hdr.type!=PSYNC_CRYPTO_LOG_HEADER))
    return -1;
  size=hdr.filesize;
  off=sizeof(hdr);
  if (unlikely_log(psync_file_seek(of->datafile, size, P_SEEK_SET)!=size || psync_file_truncate(of->datafile)))
    return -1;
  if (!of->newfile && (psync_file_seek(of->indexfile, sizeof(psync_fs_index_header), P_SEEK_SET)!=0 || psync_file_truncate(of->indexfile)))
    return -1;
  records=(psync_fs_index_record *)buff;
  recid=0;
  of->indexoff=0;
  while ((rd=psync_file_pread(fd, &hdr, sizeof(hdr), off))!=0){
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
      rd=psync_file_pread(fd, buff, hdr.length, off);
      if (unlikely(rd!=hdr.length)){
        debug(D_ERROR, "error reading from log file of %s, expected to read %u got %d", of->currentname, (unsigned)hdr.length, (int)rd);
        return -1;
      }
      off+=hdr.length;
      rd=psync_file_pwrite(of->datafile, buff, hdr.length, hdr.offset);
      if (unlikely(rd!=hdr.length)){
        debug(D_ERROR, "error writing to data file of %s, expected to write %u got %d", of->currentname, (unsigned)hdr.length, (int)rd);
        return -1;
      }
    }
    else if (hdr.type==PSYNC_CRYPTO_LOG_INT){
      assert(!of->newfile);
      records[recid].offset=hdr.offset;
      records[recid].length=hdr.longlengthlo+((uint64_t)hdr.longlengthhi<<32);
      if (++recid>=PSYNC_CRYPTO_SECTOR_SIZE/sizeof(psync_fs_index_record)){
        rd=psync_file_pwrite(of->indexfile, records, sizeof(psync_fs_index_record)*recid, sizeof(psync_fs_index_record)*of->indexoff+sizeof(psync_fs_index_header));
        if (rd!=sizeof(psync_fs_index_record)*recid){
          debug(D_ERROR, "error writing to index file of %s, expected to write %u got %d", of->currentname, (unsigned)(sizeof(psync_fs_index_record)*recid), (int)rd);
          return -1;
        }
        of->indexoff+=recid;
        recid=0;
      }
    }
    else{
      debug(D_ERROR, "bad record type %u", (unsigned)hdr.type);
      return -1;
    }
  }
  if (recid){
    rd=psync_file_pwrite(of->indexfile, records, sizeof(psync_fs_index_record)*recid, sizeof(psync_fs_index_record)*of->indexoff+sizeof(psync_fs_index_header));
    if (rd!=sizeof(psync_fs_index_record)*recid){
      debug(D_ERROR, "error writing to index file of %s, expected to write %u got %d", of->currentname, (unsigned)(sizeof(psync_fs_index_record)*recid), (int)rd);
      return -1;
    }
    of->indexoff+=recid;
  }
  if (unlikely_log(psync_file_seek(of->datafile, size, P_SEEK_SET)!=size || psync_file_truncate(of->datafile)))
    return -1;
  return 0;
}

static void wait_before_flush(psync_openfile_t *of, uint32_t millisec){
  debug(D_NOTICE, "waiting up to %u milliseconds before flush of %s", (unsigned)millisec, of->currentname);
  psync_milisleep(millisec);
}

static int psync_fs_crypto_mark_log_finalized_and_process(psync_openfile_t *of, const char *filename, uint64_t filesize, int dowaits, int locked){
  psync_crypto_log_header hdr;
  ssize_t wrt;
  psync_file_t fd;
  fd=open(filename, P_O_RDWR, 0);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE))
    return -EIO;
  if (dowaits && !locked)
    wait_before_flush(of, 2000);
  debug(D_NOTICE, "flushing log data %s", filename);
  if (unlikely_log(psync_file_sync(fd)))
    goto err_eio;
  debug(D_NOTICE, "flushed log data %s", filename);
  memset(&hdr, 0, sizeof(hdr));
  hdr.type=PSYNC_CRYPTO_LOG_HEADER;
  hdr.finalized=1;
  hdr.filesize=filesize;
  wrt=psync_file_pwrite(fd, &hdr, sizeof(hdr), 0);
  if (unlikely_log(wrt!=sizeof(hdr)))
    goto err_eio;
  debug(D_NOTICE, "flushing finalized log header %s", filename);
  if (unlikely_log(psync_file_sync(fd)))
    goto err_eio;
  debug(D_NOTICE, "flushed finalized log header %s", filename);
  if (unlikely_log(psync_fs_crypto_process_log(of, fd)))
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
      of->logoffset+=sizeof(logs);
      last=0;
    }
    len=itr->to-itr->from;
    assert(len>>48==0);
    logs[last].type=PSYNC_CRYPTO_LOG_INT;
    logs[last].longlengthhi=len>>32;
    logs[last].longlengthlo=len&0xffffffffU;
    logs[last].offset=itr->from;
    last++;
    itr=psync_interval_tree_get_next(itr);
  }
  if (last){
    wrt=psync_file_pwrite(of->logfile, logs, sizeof(psync_crypto_log_header)*last, of->logoffset);
    if (wrt!=sizeof(psync_crypto_log_header)*last){
      debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)(sizeof(psync_crypto_log_header)*last), (int)wrt);
      return -EIO;
    }
    of->logoffset+=sizeof(psync_crypto_log_header)*last;
  }
  return 0;
}

static int psync_fs_crypto_finalize_log(psync_openfile_t *of, int fullsync){
  psync_crypto_offsets_t offsets;
  psync_fsfileid_t fileid;
  const char *cachepath;
  char *olog, *flog;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  int ret;
  psync_fs_crypto_offsets_by_plainsize(of->currentsize, &offsets);
  if (of->logoffset==sizeof(psync_crypto_log_header) && offsets.masterauthoff+(offsets.needmasterauth?PSYNC_CRYPTO_AUTH_SIZE:0)==psync_file_size(of->datafile)){
    debug(D_NOTICE, "skipping finalize of %s", of->currentname);
    return 0;
  }
  debug(D_NOTICE, "finalizing log of %s", of->currentname);
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
  ret=psync_file_close(of->logfile);
  of->logfile=INVALID_HANDLE_VALUE;
  if (unlikely_log(ret))
    return -EIO;
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
  ret=psync_fs_crypto_mark_log_finalized_and_process(of, flog, offsets.masterauthoff+(offsets.needmasterauth?PSYNC_CRYPTO_AUTH_SIZE:0), 0, 1);
  psync_file_delete(flog);
  psync_free(olog);
  psync_free(flog);
  if (unlikely_log(ret))
    return ret;
  return 0;
}

static void psync_fs_crypt_add_sector_to_interval_tree(psync_openfile_t *of, psync_crypto_sectorid_t sectorid, size_t size){
  uint64_t offset;
  offset=(uint64_t)psync_fs_crypto_data_sectorid_by_sectorid(sectorid)*PSYNC_CRYPTO_SECTOR_SIZE;
  psync_interval_tree_add(&of->writeintervals, offset, offset+size);
}

static int psync_fs_crypto_write_newfile_full_sector(psync_openfile_t *of, const char *buf, psync_crypto_sectorid_t sectorid, size_t size){
  psync_crypto_log_data_record rec;
  ssize_t wrt;
  uint32_t len;
  psync_crypto_sector_auth_t auth;
  assert(size<=PSYNC_CRYPTO_SECTOR_SIZE);
  psync_crypto_aes256_encode_sector(of->encoder, (const unsigned char *)buf, size, rec.data, auth, sectorid);
  memset(&rec.header, 0, sizeof(psync_crypto_log_header));
  rec.header.type=PSYNC_CRYPTO_LOG_DATA;
  rec.header.length=size;
  rec.header.offset=psync_fs_crypto_data_offset_by_sectorid(sectorid);
  len=offsetof(psync_crypto_log_data_record, data)+size;
  wrt=psync_file_pwrite(of->logfile, &rec, len, of->logoffset);
  if (unlikely(wrt!=len)){
    debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)len, (int)wrt);
    return -EIO;
  }
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
    ret=psync_fs_crypto_write_newfile_locked(of, buff, wr, offset);
    if (ret<=0)
      return ret;
    offset+=ret;
    size-=ret;
  }
  return 0;
}

int psync_fs_crypto_write_newfile_locked(psync_openfile_t *of, const char *buf, uint64_t size, uint64_t offset){
  uint64_t off2, offdiff;
  psync_crypto_sectorid_t sectorid;
  int ret, wrt;
  assert(of->encrypted);
  assert(of->encoder);
  if (unlikely((size+offset+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE>PSYNC_CRYPTO_MAX_SECTORID))
    return psync_fs_unlock_ret(of, -EINVAL);
  if (unlikely(!size))
    return psync_fs_unlock_ret(of, 0);
  if (unlikely(of->currentsize<offset)){
    ret=psync_fs_newfile_fillzero(of, offset-of->currentsize, of->currentsize);
    if (ret)
      return psync_fs_unlock_ret(of, ret);
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
      return psync_fs_unlock_ret(of, ret);
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
      return psync_fs_unlock_ret(of, ret);
    if (of->currentsize<offset)
      of->currentsize=offset;
  }
  if (size){
    if (offset==of->currentsize)
      ret=psync_fs_crypto_write_newfile_full_sector(of, buf, sectorid, size);
    else
      ret=psync_fs_crypto_write_newfile_partial_sector(of, buf, sectorid, size, 0);
    if (ret)
      return psync_fs_unlock_ret(of, ret);
    wrt+=size;
    if (of->currentsize<offset+size)
      of->currentsize=offset+size;
  }
  if (of->logoffset>=PSYNC_CRYPTO_MAX_LOG_SIZE){
    ret=psync_fs_crypto_finalize_log(of, 0);
    if (ret)
      return psync_fs_unlock_ret(of, ret);
  }
  pthread_mutex_unlock(&of->mutex);
  return wrt;
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
  pthread_mutex_lock(&of->mutex);
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
  return size;
}

static int psync_fs_modfile_fillzero(psync_openfile_t *of, uint64_t size, uint64_t offset){
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
    ret=psync_fs_crypto_write_modified_locked(of, buff, wr, offset);
    if (ret<=0)
      return ret;
    offset+=ret;
    size-=ret;
  }
  return 0;
}

int psync_fs_crypto_write_modified_locked(psync_openfile_t *of, const char *buf, uint64_t size, uint64_t offset){
  psync_interval_tree_t *itr, *needtodwl;
  psync_pagecache_read_range *ranges;
  char *tmpbuf;
  psync_crypto_offsets_t offsets;
  uint64_t eoffset;
  size_t isize;
  ssize_t bw;
  psync_crypto_sectorid_t firstsectorid, lastsectorid, sectorid, esectorid;
  uint32_t l, asize, aid, icnt;
  int ret;
  debug(D_NOTICE, "off=%lu size=%lu cs=%lu", (unsigned long)offset, (unsigned long)size, (unsigned long)of->currentsize);
  if (unlikely((size+offset+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE>PSYNC_CRYPTO_MAX_SECTORID))
    return psync_fs_unlock_ret(of, -EINVAL);
  if (unlikely(!size))
    return psync_fs_unlock_ret(of, 0);
  if (unlikely(of->currentsize<offset)){
    ret=psync_fs_modfile_fillzero(of, offset-of->currentsize, of->currentsize);
    if (ret)
      return psync_fs_unlock_ret(of, ret);
  }
retry:
  firstsectorid=offset/PSYNC_CRYPTO_SECTOR_SIZE;
  lastsectorid=(offset+size-1)/PSYNC_CRYPTO_SECTOR_SIZE;
  itr=NULL;
  needtodwl=NULL;
  if (offset==of->initialsize && offset && offset%PSYNC_CRYPTO_SECTOR_SIZE==0)
    lastsectorid=--firstsectorid;
  for (sectorid=firstsectorid; sectorid<=lastsectorid; sectorid++){
    if ((uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE>of->initialsize)
      break;
    esectorid=psync_fs_crypto_data_sectorid_by_sectorid(sectorid);
    eoffset=(uint64_t)esectorid*PSYNC_CRYPTO_SECTOR_SIZE;
    if (itr && itr->from<=eoffset && itr->to>eoffset)
      continue;
    itr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, eoffset);
    if (itr && itr->from<=eoffset)
      continue;
    if ((sectorid==firstsectorid && offset%PSYNC_CRYPTO_SECTOR_SIZE!=0) || (sectorid==lastsectorid && (offset+size)%PSYNC_CRYPTO_SECTOR_SIZE!=0))
      psync_interval_tree_add(&needtodwl, eoffset, eoffset+PSYNC_CRYPTO_SECTOR_SIZE);
    if (sectorid!=firstsectorid && sectorid%PSYNC_CRYPTO_HASH_TREE_SECTORS!=0)
      continue;
    psync_fs_crypto_offsets_by_plainsize(of->currentsize, &offsets);
    // Here we create offsets by current size as if the file grew, we would have already moved all trailing checksums to new location.
    for (l=0; l<offsets.treelevels; l++){
      psync_fs_crypto_get_auth_sector_off(sectorid, l, &offsets, &eoffset, &asize, &aid);
      itr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, eoffset);
      if (itr && itr->from<=eoffset)
        continue;
      psync_interval_tree_add(&needtodwl, eoffset, eoffset+asize);
    }
  }
  if (needtodwl){
    icnt=0;
    isize=0;
    eoffset=psync_fs_crypto_crypto_size(of->initialsize);
    itr=psync_interval_tree_get_first(needtodwl);
    do {
      debug(D_NOTICE, "need to download from offset %lu size %lu to do a write at offset %lu size %lu", 
            (unsigned long)itr->from, (unsigned long)(itr->to-itr->from), (unsigned long)offset, (unsigned long)size);
      assert(itr->from<eoffset);
      if (itr->to>eoffset)
        itr->to=eoffset;
      icnt++;
      isize+=itr->to-itr->from;
      itr=psync_interval_tree_get_next(itr);
    } while (itr);
    ranges=psync_new_cnt(psync_pagecache_read_range, icnt);
    tmpbuf=psync_new_cnt(char, isize);
    icnt=0;
    isize=0;
    itr=psync_interval_tree_get_first(needtodwl);
    do {
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
    if (unlikely(ret)){
      psync_free(ranges);
      psync_free(tmpbuf);
      debug(D_NOTICE, "downloading of ranges failed");
      return ret;
    }
    ret=0;
    debug(D_NOTICE, "ranges downloaded");
    pthread_mutex_lock(&of->mutex);
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
      bw=psync_file_pwrite(of->datafile, ranges[l].buf, ranges[l].size, ranges[l].offset);
      if (bw!=ranges[l].size){
        debug(D_ERROR, "write to datafile of %u bytes returned %d", (unsigned)ranges[l].size, (int)bw);
        ret=-EIO;
        break;
      }
      psync_interval_tree_add(&of->writeintervals, ranges[l].offset, ranges[l].offset+ranges[l].size);
    }
    // we do NOT need to fsync of->datafile, as we wrote to positions that were empty, next log flush will fsync
    psync_free(ranges);
    psync_free(tmpbuf);
    if (unlikely(ret))
      return psync_fs_unlock_ret(of, ret);
  }
  // now that we have all auth or partial data sectors, we proceed the same way as it is a new file write
  return psync_fs_crypto_write_newfile_locked(of, buf, size, offset);
}

static int psync_fs_crypto_ftruncate_to_zero(psync_openfile_t *of){
  int ret;
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
  }
  psync_tree_for_each_element_call_safe(of->sectorsinlog, psync_sector_inlog_t, tree, psync_free);
  of->sectorsinlog=PSYNC_TREE_EMPTY;
  of->currentsize=0;
  return 0;
}

static int psync_fs_crypto_ftruncate_down(psync_openfile_t *of, uint64_t size){
  char buf[PSYNC_CRYPTO_SECTOR_SIZE];
  uint64_t writeid, lastsectoff, elastsectoroff;
  psync_interval_tree_t *intr;
  psync_crypto_sectorid_t lastsectorid, elastsectorid;
  uint32_t lastsectornewsize, lastsectoroldsize;
  int ret;
  assert(size>0 && size<of->currentsize);
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
      return psync_fs_unlock_ret(of, ret);
    assert(ret==lastsectoroldsize);
  }
  else{
    writeid=of->writeid;
    ret=psync_fs_crypto_read_modified_locked(of, buf, lastsectoroldsize, lastsectoff);
    // unlocked now
    if (ret<0)
      return ret;
    pthread_mutex_lock(&of->mutex);
    if (unlikely(of->writeid!=writeid)){
      debug(D_NOTICE, "writeid changed, restarting");
      goto retry;
    }
    ret=psync_fs_crypto_write_modified_locked(of, buf, lastsectoroldsize, lastsectoff);
    // unlocked now
    if (ret<0)
      return ret;
    pthread_mutex_lock(&of->mutex);
    if (unlikely(of->writeid!=writeid)){
      debug(D_NOTICE, "writeid changed, restarting");
      goto retry;
    }
  }
  of->currentsize=lastsectoff;
  ret=psync_fs_crypto_write_newfile_full_sector(of, buf, lastsectorid, lastsectornewsize);
  if (ret<0)
    return psync_fs_unlock_ret(of, ret);
  of->currentsize=size;
  if (!of->newfile)
    psync_interval_tree_cut_end(&of->writeintervals, psync_fs_crypto_crypto_size(size));
  debug(D_NOTICE, "file truncated");
  return psync_fs_unlock_ret(of, 0);
}

int psync_fs_crypto_ftruncate(psync_openfile_t *of, uint64_t size){
  int ret;
  assert(of->modified);
  if (of->currentsize<size){
    if (of->newfile)
      ret=psync_fs_newfile_fillzero(of, size-of->currentsize, of->currentsize);
    else
      ret=psync_fs_modfile_fillzero(of, size-of->currentsize, of->currentsize);
  }
  else if (of->currentsize>size){
    if (size==0)
      ret=psync_fs_crypto_ftruncate_to_zero(of);
    else
      return psync_fs_crypto_ftruncate_down(of, size);
  }
  else
    ret=0;  
  return psync_fs_unlock_ret(of, ret);
}

int psync_fs_crypto_flush_file(psync_openfile_t *of){
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
