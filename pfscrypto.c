#include "plibs.h"
#include "pfscrypto.h"
#include "pcloudcrypto.h"

#define PSYNC_CRYPTO_LOG_HEADER 0
#define PSYNC_CRYPTO_LOG_DATA   1

#define PSYNC_CRYPTO_HASH_TREE_SECTORS (PSYNC_CRYPTO_SECTOR_SIZE/PSYNC_CRYPTO_AUTH_SIZE)
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
  };
  union {
    uint32_t u32;
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

typedef psync_crypto_sector_auth_t psync_crypto_auth_sector_t[PSYNC_CRYPTO_HASH_TREE_SECTORS];

static const uint64_t max_level_size[PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL+1]={
  0x1000,
  0x101000,
  0x10101000,
  0x1010101000,
  0x101010101000,
  0x10101010101000,
  0x1010101010101000
};

static uint64_t psync_fs_crypto_data_offset_by_sectorid(psync_crypto_sectorid_t sectorid){
  uint64_t off;
  uint32_t i;
  off=(uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE;
  while (sectorid>=PSYNC_CRYPTO_HASH_TREE_SECTORS){
    sectorid/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    off+=(uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE;
  }
  return off;
}

/* works for all sectors of auth data except the last one of each level */
static uint64_t psync_fs_crypto_auth_offset(uint32_t level, uint32_t id){
  uint64_t off, add;
  uint32_t i;
  assert((1<<PSYNC_CRYPTO_HASH_TREE_SHIFT)==PSYNC_CRYPTO_HASH_TREE_SECTORS);
  off=0;
  i=id;
  while (i>=PSYNC_CRYPTO_HASH_TREE_SECTORS){
    i/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
    off+=i*PSYNC_CRYPTO_SECTOR_SIZE;
  }
  add=PSYNC_CRYPTO_SECTOR_SIZE;
  for (i=0; i<level; i++){
    off=off*PSYNC_CRYPTO_HASH_TREE_SECTORS+PSYNC_CRYPTO_SECTOR_SIZE;
    add=add*PSYNC_CRYPTO_HASH_TREE_SECTORS+PSYNC_CRYPTO_SECTOR_SIZE;
  }
  off+=(uint64_t)PSYNC_CRYPTO_SECTOR_SIZE*((uint64_t)1<<((1+level)*PSYNC_CRYPTO_HASH_TREE_SHIFT))*(id+1);
  off+=add*(id%PSYNC_CRYPTO_HASH_TREE_SECTORS);
  return off;
}

static void psync_fs_crypto_offsets_by_plainsize(uint64_t size, psync_crypto_offsets_t *offsets){
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

static uint32_t psync_fs_crypto_get_next_sector_revision(psync_openfile_t *of, psync_crypto_sectorid_t sectorid){
  return 0;
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

static int psync_fs_crypto_switch_sectors(psync_openfile_t *of, uint32_t oldsectorid, uint32_t newsectorid, 
                                          psync_crypto_auth_sector_t *autharr, psync_crypto_offsets_t *offsets){
  psync_crypto_log_header hdr;
  uint32_t level, oldsecd, oldsecn, newsecd, sizesecd, sz;
  int64_t filesize;
  ssize_t wrt;
  if (oldsectorid!=PSYNC_CRYPTO_INVALID_SECTORID){
    level=0;
    oldsecd=oldsectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
    newsecd=newsectorid/PSYNC_CRYPTO_HASH_TREE_SECTORS;
    sizesecd=offsets->plainsize/PSYNC_CRYPTO_SECTOR_SIZE/PSYNC_CRYPTO_HASH_TREE_SECTORS;
    do{
      oldsecn=oldsecd%PSYNC_CRYPTO_HASH_TREE_SECTORS;
      if (oldsecd==sizesecd)
        sz=offsets->lastauthsectorlen[level];
      else
        sz=PSYNC_CRYPTO_SECTOR_SIZE;
      psync_crypto_sign_auth_sector(of->encoder, &autharr[level], sz, autharr[level+1][oldsecn]);
      memset(&hdr, 0, sizeof(hdr));
      hdr.type=PSYNC_CRYPTO_LOG_DATA;
      hdr.length=sz;
      if (oldsecd==sizesecd)
        hdr.offset=offsets->lastauthsectoroff[level];
      else
        hdr.offset=psync_fs_crypto_auth_offset(level, oldsecd);
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
      of->logoffset+=sz+sizeof(hdr);
      oldsecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
      newsecd/=PSYNC_CRYPTO_HASH_TREE_SECTORS;
      level++;
    } while (oldsecd!=newsecd && level<offsets->treelevels);
  }
  if (newsectorid!=PSYNC_CRYPTO_INVALID_SECTORID){
    filesize=psync_file_size(of->datafile);
    if (unlikely_log(filesize==-1))
      return -EIO;
    if (filesize>0){
    }
  }
  return 0;
}

static int psync_fs_write_auth_tree_to_log(psync_openfile_t *of, psync_crypto_offsets_t *offsets){
  psync_sector_inlog_t *sect;
  uint32_t lastsect;
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
  else
    return 0;
}

static int psync_fs_crypto_finalize_log(psync_openfile_t *of, int fullsync){
  psync_crypto_offsets_t offsets;
  uint32_t treelevelsize;
  int ret;
  if (of->logoffset==sizeof(psync_crypto_log_header))
    return 0;
  psync_fs_crypto_offsets_by_plainsize(of->currentsize, &offsets);
  ret=psync_fs_write_auth_tree_to_log(of, &offsets);
  if (unlikely_log(ret))
    return ret;
  return 0;
}

static int psync_fs_crypto_write_newfile_full_sector(psync_openfile_t *of, const char *buf, psync_crypto_sectorid_t sectorid, size_t size){
  psync_crypto_log_data_record rec;
  ssize_t wrt;
  uint32_t revisionid, len;
  pcloud_crypto_sector_auth_t auth;
  assert(size<=PSYNC_CRYPTO_SECTOR_SIZE);
  if ((uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE>=of->currentsize)
    revisionid=0;
  else{
    revisionid=psync_fs_crypto_get_next_sector_revision(of, sectorid);
    if (unlikely_log(revisionid==PSYNC_CRYPTO_INVALID_REVISIONID))
      return -EIO;
  }
  psync_crypto_aes256_encode_sector(of->encoder, (const unsigned char *)buf, size, rec.data, auth, sectorid, revisionid);
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
  if (of->logoffset>=PSYNC_CRYPTO_MAX_LOG_SIZE)
    return psync_fs_crypto_finalize_log(of, 0);
  else
    return 0;
}

static int psync_fs_crypto_write_newfile_partial_sector(psync_openfile_t *of, const char *buf, psync_crypto_sectorid_t sectorid, size_t size, off_t offset){
  assert(offset+size<=PSYNC_CRYPTO_SECTOR_SIZE);
  return -ENOSYS;
}

static int psync_fs_unlock_ret(psync_openfile_t *of, int ret){
  pthread_mutex_unlock(&of->mutex);
  return ret;
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
    offset+=wr;
    size-=wr;
    if (ret)
      return ret;
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
      ret=psync_fs_crypto_write_newfile_partial_sector(of, buf, sectorid, size, offset);
    if (ret)
      return psync_fs_unlock_ret(of, ret);
    wrt+=size;
    if (of->currentsize<offset+size)
      of->currentsize=offset+size;
  }
  pthread_mutex_unlock(&of->mutex);
  return wrt;
}
