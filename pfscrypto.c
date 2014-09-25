#include "plibs.h"
#include "pfscrypto.h"
#include "pcloudcrypto.h"

#define PSYNC_CRYPTO_LOG_RECORD_DATASECTOR 0

typedef struct {
  uint8_t type;
  union {
    uint8_t u8;
  };
  union {
    uint16_t u16;
    uint16_t length;
  };
  union {
    uint32_t u32;
    uint32_t sectorid;
  };
  union {
    uint64_t u64;
  };
} psync_crypto_log_header;

typedef struct {
  psync_crypto_log_header header;
  unsigned char authdata[PSYNC_CRYPTO_AUTH_SIZE];
} psync_crypto_log_header_auth;

typedef struct {
  psync_crypto_log_header_auth ha;
  unsigned char data[PSYNC_CRYPTO_SECTOR_SIZE];
} psync_crypto_log_data_record;

static uint32_t psync_fs_crypto_get_next_sector_revision(psync_openfile_t *of, psync_crypto_sectorid_t sectorid){
  return 0;
}

static void psync_fs_crypto_set_sector_log_offset(psync_openfile_t *of, psync_crypto_sectorid_t sectorid, uint32_t offset){
  psync_crypto_sectorid_diff_t d;
  psync_sector_inlog_t *tr, *ntr;
  psync_tree **pe;
  tr=psync_tree_element(of->sectorsinlog, psync_sector_inlog_t, tree);
  while (tr){
    d=sectorid-tr->sectorid;
    if (d<0){
      if (tr->tree.left)
        tr=psync_tree_element(tr->tree.left, psync_sector_inlog_t, tree);
      else{
        *pe=&tr->tree.left;
        break;
      }
    }
    else if (d>0){
      if (tr->tree.right)
        tr=psync_tree_element(tr->tree.right, psync_sector_inlog_t, tree);
      else{
        *pe=&tr->tree.right;
        break;
      }
    }
    else{
      tr->logoffset=offset;
      return;
    }
  }
  ntr=psync_new(psync_sector_inlog_t);
  *pe=&ntr->tree;
  ntr->sectorid=sectorid;
  ntr->logoffset=offset;
  psync_tree_added_at(&of->sectorsinlog, &tr->tree, &ntr->tree);
}

static int psync_fs_crypto_write_newfile_full_sector(psync_openfile_t *of, const char *buf, psync_crypto_sectorid_t sectorid, size_t size){
  psync_crypto_log_data_record rec;
  ssize_t wrt;
  uint32_t revisionid, len;
  assert(size<=PSYNC_CRYPTO_SECTOR_SIZE);
  if ((uint64_t)sectorid*PSYNC_CRYPTO_SECTOR_SIZE>=of->currentsize)
    revisionid=0;
  else{
    revisionid=psync_fs_crypto_get_next_sector_revision(of, sectorid);
    if (revisionid==PSYNC_CRYPTO_INVALID_REVISIONID)
      return -EIO;
  }
  psync_crypto_aes256_encode_sector(of->encoder, (const unsigned char *)buf, size, rec.data, rec.ha.authdata, sectorid, revisionid);
  memset(&rec.ha.header, 0, sizeof(psync_crypto_log_header));
  rec.ha.header.type=PSYNC_CRYPTO_LOG_RECORD_DATASECTOR;
  rec.ha.header.length=size;
  rec.ha.header.sectorid=sectorid;
  len=offsetof(psync_crypto_log_data_record, data)+size;
  wrt=psync_file_pwrite(of->logfile, &rec, len, of->logoffset);
  if (unlikely(wrt!=len)){
    debug(D_ERROR, "write to log of %u bytes returned %d", (unsigned)len, (int)wrt);
    return -EIO;
  }
  psync_fs_crypto_set_sector_log_offset(of, sectorid, of->logoffset);
  of->logoffset+=len;
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
  if (unlikely((size+offset+PSYNC_CRYPTO_SECTOR_SIZE-1)/PSYNC_CRYPTO_SECTOR_SIZE>=PSYNC_CRYPTO_MAX_SECTORID))
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
