/* Copyright (c) 2013-2014 Anton Titov.
 * Copyright (c) 2013-2014 pCloud Ltd.
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

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64

#include <pthread.h>
#include <fuse.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "pfs.h"
#include "pfsxattr.h"
#include "pfsfolder.h"
#include "pcompat.h"
#include "plibs.h"
#include "psettings.h"
#include "pfsfolder.h"
#include "pcache.h"
#include "ppagecache.h"
#include "ptimer.h"
#include "pfstasks.h"
#include "pfsupload.h"
#include "pstatus.h"
#include "pssl.h"
#include "pfolder.h"
#include "pnetlibs.h"
#include "pcloudcrypto.h"
#include "pfscrypto.h"

#ifndef FUSE_STAT
#define FUSE_STAT stat
#endif

#ifndef HAS_FUSE_OFF_T
typedef off_t fuse_off_t;
#endif

#if defined(P_OS_POSIX)
#include <signal.h>
#endif

#if defined(P_OS_MACOSX)
#include <sys/mount.h>
#include <sys/mount.h>
#endif

#if IS_DEBUG
#define psync_fs_set_thread_name() do {psync_thread_name=__FUNCTION__;} while (0)
#else
#define psync_fs_set_thread_name() do {} while (0)
#endif

#define fh_to_openfile(x) ((psync_openfile_t *)((uintptr_t)x))
#define openfile_to_fh(x) ((uintptr_t)x)

#define FS_BLOCK_SIZE 4096
#define FS_MAX_WRITE  16*1024*1024

#if defined(P_OS_MACOSX)
#define FS_MAX_ACCEPTABLE_FILENAME_LEN 255
#endif

typedef struct {
  uint64_t offset;
  uint64_t length;
} index_record;

typedef struct {
  uint64_t copyfromoriginal;
} index_header;

static struct fuse_chan *psync_fuse_channel=NULL;
static struct fuse *psync_fuse=NULL;
static char *psync_current_mountpoint=NULL;
char *psync_fake_prefix=NULL;
size_t psync_fake_prefix_len=0;
static int64_t psync_fake_fileid=INT64_MIN;

static pthread_mutex_t start_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond=PTHREAD_COND_INITIALIZER;
static int started=0;
static int initonce=0;
static int waitingforlogin=0;

static uid_t myuid=0;
static gid_t mygid=0;

static psync_tree *openfiles=PSYNC_TREE_EMPTY;

static void delete_log_files(psync_openfile_t *of){
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  const char *cachepath;
  char *filename;
  psync_fsfileid_t fileid;
  cachepath=psync_setting_get_string(_PS(fscachepath));
  fileid=-of->fileid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)]='l';
  fileidhex[sizeof(psync_fsfileid_t)+1]=0;
  filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
  psync_file_delete(filename);
  psync_free(filename);
  fileidhex[sizeof(psync_fsfileid_t)]='f';
  filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
  psync_file_delete(filename);
  psync_free(filename);
}

int psync_fs_update_openfile(uint64_t taskid, uint64_t writeid, psync_fileid_t newfileid, uint64_t hash, uint64_t size){
  psync_sql_res *res;
  psync_uint_row row;
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_fsfileid_t fileid;
  int64_t d;
  int ret;
  fileid=-taskid;
  psync_sql_lock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      pthread_mutex_lock(&fl->mutex);
      if (fl->writeid==writeid){
        debug(D_NOTICE, "updating fileid %ld to %lu, hash %lu", (long)fileid, (unsigned long)newfileid, (unsigned long)hash);
        fl->fileid=newfileid;
        fl->remotefileid=newfileid;
        fl->hash=hash;
        fl->modified=0;
        fl->newfile=0;
        fl->currentsize=size;
        fl->initialsize=size;
        fl->releasedforupload=0;
        if (fl->datafile!=INVALID_HANDLE_VALUE){
          psync_file_close(fl->datafile);
          fl->datafile=INVALID_HANDLE_VALUE;
        }
        if (fl->indexfile!=INVALID_HANDLE_VALUE){
          psync_file_close(fl->indexfile);
          fl->indexfile=INVALID_HANDLE_VALUE;
        }
        psync_tree_del(&openfiles, &fl->tree);
        if (fl->encrypted){
          if (fl->logfile){
            psync_file_close(fl->logfile);
            fl->indexfile=INVALID_HANDLE_VALUE;
          }
          delete_log_files(fl);
          if (fl->authenticatedints){
            psync_interval_tree_free(fl->authenticatedints);
            fl->authenticatedints=NULL;
          }
        }
        tr=openfiles;
        d=-1;
        while (tr){
          d=newfileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
          if (d<0){
            if (tr->left)
              tr=tr->left;
            else
              break;
          }
          else if (d>0){
            if (tr->right)
              tr=tr->right;
            else
              break;
          }
          else{
            debug(D_BUG, "found already open file %lu, should not happen", (unsigned long)newfileid);
            break;
          }
        }
        if (d<0)
          psync_tree_add_before(&openfiles, tr, &fl->tree);
        else
          psync_tree_add_after(&openfiles, tr, &fl->tree);
        ret=0;
      }
      else{
        debug(D_NOTICE, "writeid of fileid %ld (%s) differs %lu!=%lu", (long)fileid, fl->currentname, (unsigned long)fl->writeid, (unsigned long)writeid);
        if (fl->newfile){
          res=psync_sql_prep_statement("REPLACE INTO fstaskfileid (fstaskid, fileid) VALUES (?, ?)");
          psync_sql_bind_uint(res, 1, taskid);
          psync_sql_bind_uint(res, 2, newfileid);
          psync_sql_run_free(res);
        }
        ret=-1;
      }
      pthread_mutex_unlock(&fl->mutex);
      psync_sql_unlock();
      return ret;
    }
  }
  res=psync_sql_query("SELECT int1 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  if ((row=psync_sql_fetch_rowint(res)) && row[0]==writeid)
    ret=0;
  else
    ret=-1;
  psync_sql_free_result(res);
  psync_sql_unlock();
  return ret;
}

/*void psync_fs_uploading_openfile(uint64_t taskid){
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_fsfileid_t fileid;
  int64_t d;
  fileid=-taskid;
  psync_sql_lock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      pthread_mutex_lock(&fl->mutex);
      fl->uploading=1;
      pthread_mutex_unlock(&fl->mutex);
      break;
    }
  }
  psync_sql_unlock();
}*/

int psync_fs_rename_openfile_locked(psync_fsfileid_t fileid, psync_fsfolderid_t folderid, const char *name){
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      pthread_mutex_lock(&fl->mutex);
      if (fl->currentfolder->folderid!=folderid){
        psync_fstask_release_folder_tasks_locked(fl->currentfolder);
        fl->currentfolder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
      }
      psync_free(fl->currentname);
      fl->currentname=psync_strdup(name);
      pthread_mutex_unlock(&fl->mutex);
      return 1;
    }
  }
  return 0;
}

static int psync_fs_relock_fileid(psync_fsfileid_t fileid){
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  psync_sql_lock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      pthread_mutex_lock(&fl->mutex);
      pthread_mutex_unlock(&fl->mutex);
      psync_sql_unlock();
      return 1;
    }
  }
  psync_sql_unlock();
  return 0;
}

void psync_fs_mark_openfile_deleted(uint64_t taskid){
  psync_sql_res *res;
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  psync_fsfileid_t fileid;
  fileid=-taskid;
  psync_sql_lock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      debug(D_NOTICE, "file being deleted %s is still open, marking as deleted", fl->currentname);
      pthread_mutex_lock(&fl->mutex);
      fl->deleted=1;
      pthread_mutex_unlock(&fl->mutex);
      res=psync_sql_prep_statement("UPDATE fstask SET status=12 WHERE id=?");
      psync_sql_bind_uint(res, 1, taskid);
      psync_sql_run_free(res);
      break;
    }
  }
  psync_sql_unlock();
}

int64_t psync_fs_get_file_writeid(uint64_t taskid){
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_sql_res *res;
  psync_uint_row row;
  psync_fsfileid_t fileid;
  int64_t d;
  fileid=-taskid;
  psync_sql_lock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      pthread_mutex_lock(&fl->mutex);
      d=fl->writeid;
      pthread_mutex_unlock(&fl->mutex);
      psync_sql_unlock();
      return d;
    }
  }
  res=psync_sql_query("SELECT int1 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  if ((row=psync_sql_fetch_rowint(res)))
    d=row[0];
  else
    d=-1;
  psync_sql_free_result(res);
  psync_sql_unlock();
  return d;
}

void psync_fs_update_openfile_fileid_locked(psync_openfile_t *of, psync_fsfileid_t fileid){
  psync_tree *tr;
  int64_t d;
  assertw(of->fileid!=fileid);
  psync_tree_del(&openfiles, &of->tree);
  of->fileid=fileid;
  tr=openfiles;
  if (tr)
    while (1){
      d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
      if (d<0){
        if (tr->left)
          tr=tr->left;
        else{
          tr->left=&of->tree;
          break;
        }
      }
      else{
        assertw(d>0);
        if (tr->right)
          tr=tr->right;
        else{
          tr->right=&of->tree;
          break;
        }
      }
    }
  else
    openfiles=&of->tree;
  psync_tree_added_at(&openfiles, tr, &of->tree);
}

#define folderid_to_inode(folderid) ((folderid)*3)
#define fileid_to_inode(fileid) ((fileid)*3+1)
#define taskid_to_inode(taskid) ((taskid)*3+2)

static void psync_row_to_folder_stat(psync_variant_row row, struct FUSE_STAT *stbuf){
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  stbuf->st_ino=folderid_to_inode(psync_get_number(row[0]));
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=psync_get_number(row[2]);
  stbuf->st_ctime=psync_get_number(row[3]);
  stbuf->st_mtime=stbuf->st_ctime;
#else
  stbuf->st_ctime=psync_get_number(row[2]);
  stbuf->st_mtime=psync_get_number(row[3]);
#endif
  stbuf->st_atime=stbuf->st_mtime;
  stbuf->st_mode=S_IFDIR | 0755;
  stbuf->st_nlink=psync_get_number(row[4])+2;
  stbuf->st_size=FS_BLOCK_SIZE;
#if defined(P_OS_POSIX)
  stbuf->st_blocks=1;
  stbuf->st_blksize=FS_BLOCK_SIZE;
#endif
  stbuf->st_uid=myuid;
  stbuf->st_gid=mygid;
}

static void psync_row_to_file_stat(psync_variant_row row, struct FUSE_STAT *stbuf, uint32_t flags){
  uint64_t size;
  stbuf->st_ino=fileid_to_inode(psync_get_number(row[4]));
  size=psync_get_number(row[1]);
  if (flags&PSYNC_FOLDER_FLAG_ENCRYPTED)
    size=psync_fs_crypto_plain_size(size);
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=psync_get_number(row[2]);
  stbuf->st_ctime=psync_get_number(row[3]);
  stbuf->st_mtime=stbuf->st_ctime;
#else
  stbuf->st_ctime=psync_get_number(row[2]);
  stbuf->st_mtime=psync_get_number(row[3]);
#endif
  stbuf->st_atime=stbuf->st_mtime;
  stbuf->st_mode=S_IFREG | 0644;
  stbuf->st_nlink=1;
  stbuf->st_size=size;
#if defined(P_OS_POSIX)
  stbuf->st_blocks=(size+511)/512;
  stbuf->st_blksize=FS_BLOCK_SIZE;
#endif
  stbuf->st_uid=myuid;
  stbuf->st_gid=mygid;
}

static void psync_mkdir_to_folder_stat(psync_fstask_mkdir_t *mk, struct FUSE_STAT *stbuf){
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  if (mk->folderid>=0)
    stbuf->st_ino=folderid_to_inode(mk->folderid);
  else
    stbuf->st_ino=taskid_to_inode(-mk->folderid);    
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=mk->ctime;
  stbuf->st_ctime=mk->mtime;
  stbuf->st_mtime=mk->mtime;
#else
  stbuf->st_ctime=mk->ctime;
  stbuf->st_mtime=mk->mtime;
#endif
  stbuf->st_atime=stbuf->st_mtime;
  stbuf->st_mode=S_IFDIR | 0755;
  stbuf->st_nlink=mk->subdircnt+2;
  stbuf->st_size=FS_BLOCK_SIZE;
#if defined(P_OS_POSIX)
  stbuf->st_blocks=1;
  stbuf->st_blksize=FS_BLOCK_SIZE;
#endif
  stbuf->st_uid=myuid;
  stbuf->st_gid=mygid;
}

static int psync_creat_db_to_file_stat(psync_fileid_t fileid, struct FUSE_STAT *stbuf, uint32_t flags){
  psync_sql_res *res;
  psync_variant_row row;
  res=psync_sql_query("SELECT name, size, ctime, mtime, id, folderid FROM file WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  if ((row=psync_sql_fetch_row(res)))
    psync_row_to_file_stat(row, stbuf, flags);
  else
    debug(D_NOTICE, "fileid %lu not found in database", (unsigned long)fileid);
  psync_sql_free_result(res);
  return row?0:-1;
}

static int psync_creat_stat_fake_file(struct FUSE_STAT *stbuf){
  time_t ctime;
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  ctime=psync_timer_time();
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=ctime;
#endif
  stbuf->st_ctime=ctime;
  stbuf->st_mtime=ctime;
  stbuf->st_atime=ctime;
  stbuf->st_mode=S_IFREG | 0644;
  stbuf->st_nlink=1;
  stbuf->st_size=0;
#if defined(P_OS_POSIX)
  stbuf->st_blocks=0;
  stbuf->st_blksize=FS_BLOCK_SIZE;
#endif
  stbuf->st_uid=myuid;
  stbuf->st_gid=mygid;
  return 0;
}

static int fill_stat_from_open_file(psync_fsfileid_t fileid, struct FUSE_STAT *stbuf){
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_stat_t st;
  int64_t d;
  psync_sql_lock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      pthread_mutex_lock(&fl->mutex);
      stbuf->st_size=fl->currentsize;
      if (!psync_fstat(fl->logfile, &st))
        stbuf->st_mtime=psync_stat_mtime(&st);
      pthread_mutex_unlock(&fl->mutex);
      psync_sql_unlock();
      return 1;
    }
  }
  psync_sql_unlock();
  return 0;
}

static int psync_creat_local_to_file_stat(psync_fstask_creat_t *cr, struct FUSE_STAT *stbuf, uint32_t folderflags){
  psync_stat_t st;
  psync_fsfileid_t fileid;
  uint64_t size;
  const char *cachepath;
  char *filename;
//  psync_file_t fd;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  int stret;
  if (unlikely(psync_fs_need_per_folder_refresh_const() && cr->fileid<psync_fake_fileid))
    return psync_creat_stat_fake_file(stbuf);
  fileid=-cr->fileid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)]='d';
  fileidhex[sizeof(psync_fsfileid_t)+1]=0;
  cachepath=psync_setting_get_string(_PS(fscachepath));
  filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
  stret=psync_stat(filename, &st);
  if (unlikely_log(stret)){
    // since files are created out of sql_lock, it is possible that file is not created
    // we can lookup cr->fileid in openfiles and take of->mutex, once we did it, the file
    // should exist as we are holding sql_lock
    debug(D_NOTICE, "could not stat file %s", filename);
    psync_fs_relock_fileid(cr->fileid);
    stret=psync_stat(filename, &st);
  }
  psync_free(filename);
  if (stret)
    return -1;
/*  if (cr->newfile)
    osize=0;
  else{
    fileidhex[sizeof(psync_fsfileid_t)]='i';
    filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    fd=psync_file_open(filename, P_O_RDONLY, 0);
    psync_free(filename);
    if (fd==INVALID_HANDLE_VALUE)
      return -EIO;
    stret=psync_file_pread(fd, &osize, sizeof(osize), offsetof(index_header, copyfromoriginal));
    psync_file_close(fd);
    if (stret!=sizeof(osize))
      return -EIO;
  }*/
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  stbuf->st_ino=taskid_to_inode(fileid);
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=st.st_birthtime;
  stbuf->st_ctime=st.st_ctime;
  stbuf->st_mtime=st.st_mtime;
#else
  stbuf->st_ctime=psync_stat_ctime(&st);
  stbuf->st_mtime=psync_stat_mtime(&st);
#endif
  stbuf->st_atime=stbuf->st_mtime;
  stbuf->st_mode=S_IFREG | 0644;
  stbuf->st_nlink=1;
  if (folderflags&PSYNC_FOLDER_FLAG_ENCRYPTED){
    if (fill_stat_from_open_file(cr->fileid, stbuf))
      size=stbuf->st_size;
    else{
      size=psync_fs_crypto_plain_size(psync_stat_size(&st));
      stbuf->st_size=size;
    }
  }
  else{
    size=psync_stat_size(&st);
    stbuf->st_size=size;
  }
#if defined(P_OS_POSIX)
  stbuf->st_blocks=(size+511)/512;
  stbuf->st_blksize=FS_BLOCK_SIZE;
#endif
  stbuf->st_uid=myuid;
  stbuf->st_gid=mygid;
  return 0;
}

static int psync_creat_to_file_stat(psync_fstask_creat_t *cr, struct FUSE_STAT *stbuf, uint32_t folderflags){
  debug(D_NOTICE, "getting stat from creat for file %s fileid %ld taskid %lu", cr->name, (long)cr->fileid, (unsigned long)cr->taskid);
  if (cr->fileid>=0)
    return psync_creat_db_to_file_stat(cr->fileid, stbuf, folderflags);
  else
    return psync_creat_local_to_file_stat(cr, stbuf, folderflags);
}

int psync_fs_crypto_err_to_errno(int cryptoerr){
  switch (cryptoerr){
    case PSYNC_CRYPTO_NOT_STARTED:          return EACCES;
    case PSYNC_CRYPTO_RSA_ERROR:            return EIO;
    case PSYNC_CRYPTO_FOLDER_NOT_FOUND:     return ENOENT;
    case PSYNC_CRYPTO_FILE_NOT_FOUND:       return ENOENT;
    case PSYNC_CRYPTO_INVALID_KEY:          return EIO;
    case PSYNC_CRYPTO_CANT_CONNECT:         return ENOTCONN;
    case PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED: return EINVAL;
    case PSYNC_CRYPTO_INTERNAL_ERROR:       return EINVAL;
    default:                                return EINVAL;
  }
}

static int psync_fs_getrootattr(struct FUSE_STAT *stbuf){
  psync_sql_res *res;
  psync_variant_row row;
  res=psync_sql_query("SELECT 0, 0, IFNULL(s.value, 1414766136)*1, f.mtime, f.subdircnt FROM folder f LEFT JOIN setting s ON s.id='registered' WHERE f.id=0");
  if ((row=psync_sql_fetch_row(res)))
    psync_row_to_folder_stat(row, stbuf);
  psync_sql_free_result(res);
  return 0;
}

#define CHECK_LOGIN_LOCKED() do {\
  if (unlikely(waitingforlogin)){\
    psync_sql_unlock();\
    debug(D_NOTICE, "returning EACCES for not logged in");\
    return -EACCES;\
  }\
} while (0)

static int psync_fs_getattr(const char *path, struct FUSE_STAT *stbuf){
  psync_sql_res *res;
  psync_variant_row row;
  psync_fspath_t *fpath;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  int crr;
  psync_fs_set_thread_name();
//  debug(D_NOTICE, "getattr %s", path);
  if (path[0]=='/' && path[1]==0)
    return psync_fs_getrootattr(stbuf);
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    psync_sql_unlock();
    debug(D_NOTICE, "could not find path component of %s, returning ENOENT", path);
    return -ENOENT;
  }
  folder=psync_fstask_get_folder_tasks_locked(fpath->folderid);
  if (!folder || !psync_fstask_find_rmdir(folder, fpath->name, 0)){
    res=psync_sql_query("SELECT id, permissions, ctime, mtime, subdircnt FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fpath->folderid);
    psync_sql_bind_string(res, 2, fpath->name);
    if ((row=psync_sql_fetch_row(res)))
      psync_row_to_folder_stat(row, stbuf);
    psync_sql_free_result(res);
    if (row){
      if (folder)
        psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      return 0;
    }
  }
  if (folder){
    psync_fstask_mkdir_t *mk;
    mk=psync_fstask_find_mkdir(folder, fpath->name, 0);
    if (mk){
      psync_mkdir_to_folder_stat(mk, stbuf);
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      return 0;
    }
  }
  res=psync_sql_query("SELECT name, size, ctime, mtime, id FROM file WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, fpath->folderid);
  psync_sql_bind_string(res, 2, fpath->name);
  if ((row=psync_sql_fetch_row(res)))
    psync_row_to_file_stat(row, stbuf, fpath->flags);
  psync_sql_free_result(res);
  if (folder){
    if (psync_fstask_find_unlink(folder, fpath->name, 0))
      row=NULL;
    if (!row && (cr=psync_fstask_find_creat(folder, fpath->name, 0)))
      crr=psync_creat_to_file_stat(cr, stbuf, fpath->flags);
    else
      crr=-1;
    psync_fstask_release_folder_tasks_locked(folder);
  }
  else
    crr=-1;
  psync_sql_unlock();
  psync_free(fpath);
  if (row || !crr)
    return 0;
  debug(D_NOTICE, "returning ENOENT for %s", path);
  return -ENOENT;
}

static int filler_decoded(psync_crypto_aes256_text_decoder_t dec, fuse_fill_dir_t filler, void *buf, const char *name, struct stat *st, off_t off){
  if (dec){
    char *namedec;
    int ret;
    namedec=psync_cloud_crypto_decode_filename(dec, name);
    if (!namedec)
      return 0;
    ret=filler(buf, namedec, st, off);
    psync_free(namedec);
    return ret;
  }
  else
    return filler(buf, name, st, off);
}

static int psync_fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, fuse_off_t offset, struct fuse_file_info *fi){
  psync_sql_res *res;
  psync_variant_row row;
  psync_fsfolderid_t folderid;
  psync_fstask_folder_t *folder;
  psync_tree *trel;
  const char *name;
  psync_crypto_aes256_text_decoder_t dec;
  uint32_t flags;
  size_t namelen;
  struct FUSE_STAT st;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "readdir %s", path);
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  folderid=psync_fsfolderid_by_path(path, &flags);
  if (unlikely_log(folderid==PSYNC_INVALID_FSFOLDERID)){
    psync_sql_unlock();
    return -ENOENT;
  }
  if (flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
    dec=psync_cloud_crypto_get_folder_decoder(folderid);
    if (psync_crypto_is_error(dec)){
      psync_sql_unlock();
      return -psync_fs_crypto_err_to_errno(psync_crypto_to_error(dec));
    }
  }
  else
    dec=NULL;
  filler(buf, ".", NULL, 0);
  if (folderid!=0)
    filler(buf, "..", NULL, 0);
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folderid>=0){
    res=psync_sql_query("SELECT id, permissions, ctime, mtime, subdircnt, name FROM folder WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, folderid);
    while ((row=psync_sql_fetch_row(res))){
      name=psync_get_lstring(row[5], &namelen);
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (unlikely_log(namelen>FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      if (!name || !name[0])
        continue;
      if (folder && (psync_fstask_find_rmdir(folder, name, 0) || psync_fstask_find_mkdir(folder, name, 0)))
        continue;
      psync_row_to_folder_stat(row, &st);
      filler_decoded(dec, filler, buf, name, &st, 0);
    }
    psync_sql_free_result(res);
    res=psync_sql_query("SELECT name, size, ctime, mtime, id FROM file WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, folderid);
    while ((row=psync_sql_fetch_row(res))){
      name=psync_get_lstring(row[0], &namelen);
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (unlikely_log(namelen>FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      if (!name || !name[0])
        continue;
      if (folder && psync_fstask_find_unlink(folder, name, 0))
        continue;
      psync_row_to_file_stat(row, &st, flags);
      filler_decoded(dec, filler, buf, name, &st, 0);
    }
    psync_sql_free_result(res);
  }
  if (folder){
    psync_tree_for_each(trel, folder->mkdirs){
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (unlikely_log(strlen(psync_tree_element(trel, psync_fstask_mkdir_t, tree)->name)>FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      psync_mkdir_to_folder_stat(psync_tree_element(trel, psync_fstask_mkdir_t, tree), &st);
      filler_decoded(dec, filler, buf, psync_tree_element(trel, psync_fstask_mkdir_t, tree)->name, &st, 0);
    }
    psync_tree_for_each(trel, folder->creats){
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (unlikely_log(strlen(psync_tree_element(trel, psync_fstask_creat_t, tree)->name)>FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      if (!psync_creat_to_file_stat(psync_tree_element(trel, psync_fstask_creat_t, tree), &st, flags))
        filler_decoded(dec, filler, buf, psync_tree_element(trel, psync_fstask_creat_t, tree)->name, &st, 0);
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
  psync_sql_unlock();
  if (dec)
    psync_cloud_crypto_release_folder_decoder(folderid, dec);
  return 0;
}

static psync_openfile_t *psync_fs_create_file(psync_fsfileid_t fileid, psync_fsfileid_t remotefileid, uint64_t size, uint64_t hash, int lock, 
                                              uint32_t writeid, psync_fstask_folder_t *folder, const char *name, 
                                              psync_crypto_aes256_sector_encoder_decoder_t encoder){
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  psync_sql_lock();
  tr=openfiles;
  d=-1;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0){
      if (tr->left)
        tr=tr->left;
      else
        break;
    }
    else if (d>0){
      if (tr->right)
        tr=tr->right;
      else
        break;
    }
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      if (lock){
        pthread_mutex_lock(&fl->mutex);
        psync_fs_inc_of_refcnt_locked(fl);
      }
      else
        psync_fs_inc_of_refcnt(fl);
      assertw(fl->currentfolder==folder);
      assertw(!strcmp(fl->currentname, name));
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      debug(D_NOTICE, "found open file %ld, refcnt %u", (long int)fileid, (unsigned)fl->refcnt);
      return fl;
    }
  }
  if (encoder==PSYNC_CRYPTO_INVALID_ENCODER){
    fl=(psync_openfile_t *)psync_malloc(offsetof(psync_openfile_t, encoder));
    memset(fl, 0, offsetof(psync_openfile_t, encoder));
  }
  else{
    fl=psync_new(psync_openfile_t);
    memset(fl, 0, sizeof(psync_openfile_t));
    size=psync_fs_crypto_plain_size(size);
  }
  if (d<0)
    psync_tree_add_before(&openfiles, tr, &fl->tree);
  else
    psync_tree_add_after(&openfiles, tr, &fl->tree);
  pthread_mutex_init(&fl->mutex, NULL);
  fl->currentfolder=folder;
  fl->currentname=psync_strdup(name);
  fl->fileid=fileid;
  fl->remotefileid=remotefileid;
  fl->hash=hash;
  fl->initialsize=size;
  fl->currentsize=size;
  fl->writeid=writeid;
  fl->datafile=INVALID_HANDLE_VALUE;
  fl->indexfile=INVALID_HANDLE_VALUE;
  fl->refcnt=1;
  fl->modified=fileid<0?1:0;
  if (encoder!=PSYNC_CRYPTO_INVALID_ENCODER){
    fl->encrypted=1;
    fl->encoder=encoder;
    fl->logfile=INVALID_HANDLE_VALUE;
  }
  if (lock)
    pthread_mutex_lock(&fl->mutex);
  psync_sql_unlock();
  return fl;
}

int64_t psync_fs_load_interval_tree(psync_file_t fd, uint64_t size, psync_interval_tree_t **tree){
  index_record records[512];
  uint64_t cnt;
  uint64_t i;
  ssize_t rrd, rd, j;
  if (size<sizeof(index_header))
    return 0;
  size-=sizeof(index_header);
  assertw(size%sizeof(index_record)==0);
  cnt=size/sizeof(index_record);
  debug(D_NOTICE, "loading %lu intervals", (unsigned long)cnt);
  for (i=0; i<cnt; i+=ARRAY_SIZE(records)){
    rd=ARRAY_SIZE(records)>cnt-i?cnt-i:ARRAY_SIZE(records);
    rrd=psync_file_pread(fd, records, rd*sizeof(index_record), i*sizeof(index_record)+sizeof(index_header));
    if (unlikely_log(rrd!=rd*sizeof(index_record)))
      return -1;
    for (j=0; j<rd; j++)
      psync_interval_tree_add(tree, records[j].offset, records[j].offset+records[j].length);
  }
  if (IS_DEBUG && *tree){
    psync_interval_tree_t *tr;
    tr=*tree;
    debug(D_NOTICE, "loaded approx %lu intervals", (unsigned long)1<<(tr->tree.height-1));
    tr=psync_interval_tree_get_first(*tree);
    debug(D_NOTICE, "first interval from %lu to %lu", (unsigned long)tr->from, (unsigned long)tr->to);
//    while ((tr=psync_interval_tree_get_next(tr)))
//      debug(D_NOTICE, "next interval from %lu to %lu", (unsigned long)tr->from, (unsigned long)tr->to);
    tr=psync_interval_tree_get_last(*tree);
    debug(D_NOTICE, "last interval from %lu to %lu", (unsigned long)tr->from, (unsigned long)tr->to);
  }
  return cnt;
}

static int load_interval_tree(psync_openfile_t *of){
  index_header hdr;
  int64_t ifs;
  ifs=psync_file_size(of->indexfile);
  if (unlikely_log(ifs==-1))
    return -1;
  if (ifs<sizeof(index_header)){
    assertw(ifs==0);
    hdr.copyfromoriginal=of->initialsize;
    if (psync_file_pwrite(of->indexfile, &hdr, sizeof(index_header), 0)!=sizeof(index_header))
      return -1;
    else
      return 0;
  }
  ifs=psync_fs_load_interval_tree(of->indexfile, ifs, &of->writeintervals);
  if (ifs==-1)
    return -1;
  else{
    of->indexoff=ifs;
    return 0;
  }
}

static int open_write_files(psync_openfile_t *of, int trunc){
  psync_fsfileid_t fileid;
  const char *cachepath;
  char *filename;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  int64_t fs;
  int ret;
  fileid=-of->fileid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)]='d';
  fileidhex[sizeof(psync_fsfileid_t)+1]=0;
  cachepath=psync_setting_get_string(_PS(fscachepath));
  if (of->datafile==INVALID_HANDLE_VALUE){
    filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    of->datafile=psync_file_open(filename, P_O_RDWR, P_O_CREAT|(trunc?P_O_TRUNC:0));
    psync_free(filename);
    if (of->datafile==INVALID_HANDLE_VALUE){
      debug(D_ERROR, "could not open cache file for fileid %ld", (long)of->fileid);
      return -EIO;
    }
  }
  fs=psync_file_size(of->datafile);
  if (unlikely_log(fs==-1))
    return -EIO;
  if (of->encrypted)
    of->currentsize=psync_fs_crypto_plain_size(fs);
  else
    of->currentsize=fs;
  if (!of->newfile && of->indexfile==INVALID_HANDLE_VALUE){
    fileidhex[sizeof(psync_fsfileid_t)]='i';
    filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    of->indexfile=psync_file_open(filename, P_O_RDWR, P_O_CREAT|(trunc?P_O_TRUNC:0));
    psync_free(filename);
    if (of->indexfile==INVALID_HANDLE_VALUE){
      debug(D_ERROR, "could not open cache index file for fileid %ld", (long)of->fileid);
      return -EIO;
    }
    if (load_interval_tree(of)){
      debug(D_ERROR, "could not load cache file for fileid %ld to interval tree", (long)of->fileid);
      return -EIO;
    }
  }
  if (of->encrypted){
    if (of->logfile==INVALID_HANDLE_VALUE){
      fileidhex[sizeof(psync_fsfileid_t)]='l';
      filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
      of->logfile=psync_file_open(filename, P_O_RDWR, P_O_CREAT|P_O_TRUNC);
      psync_free(filename);
      if (of->logfile==INVALID_HANDLE_VALUE){
        debug(D_ERROR, "could not open log file for fileid %ld", (long)of->fileid);
        return -EIO;
      }
      ret=psync_fs_crypto_init_log(of);
      if (ret){
        debug(D_ERROR, "could not init log file for fileid %ld", (long)of->fileid);
        return ret;
      }
    }
  }
  return 0;
}

static void psync_fs_del_creat(psync_fspath_t *fpath, psync_openfile_t *of){
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  psync_sql_lock();
  folder=psync_fstask_get_or_create_folder_tasks_locked(fpath->folderid);
  if (likely(folder)){
    if (likely((cr=psync_fstask_find_creat(folder, fpath->name, 0)))){
      psync_tree_del(&folder->creats, &cr->tree);
      folder->taskscnt--;
      psync_free(cr);
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
  psync_fs_dec_of_refcnt(of);
  psync_sql_unlock();
  psync_free(fpath);
}

static int psync_fs_open(const char *path, struct fuse_file_info *fi){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fsfileid_t fileid;
  uint64_t size, hash, writeid;
  psync_fspath_t *fpath;
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  psync_openfile_t *of;
  psync_crypto_aes256_sector_encoder_decoder_t encoder;
  char *encsymkey;
  size_t encsymkeylen;
  int ret, status, type;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "open %s", path);
  fileid=writeid=hash=size=0;
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
    psync_sql_unlock();
    return -ENOENT;
  }
  if ((fi->flags&3)!=O_RDONLY && !(fpath->permissions&PSYNC_PERM_MODIFY)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  folder=psync_fstask_get_or_create_folder_tasks_locked(fpath->folderid);
  row=NULL;
  if ((cr=psync_fstask_find_creat(folder, fpath->name, 0))){
    if (cr->fileid>=0){
      res=psync_sql_query("SELECT id, size, hash FROM file WHERE id=?");
      psync_sql_bind_uint(res, 1, cr->fileid);
      row=psync_sql_fetch_rowint(res);
      if (row){
        fileid=row[0];
        size=row[1];
        hash=row[2];
        debug(D_NOTICE, "opening moved regular file %lu %s size %lu hash %lu", (unsigned long)fileid, fpath->name, (unsigned long)size, (unsigned long)hash);
      }
      psync_sql_free_result(res);
      if (unlikely_log(!row)){
        ret=-ENOENT;
        goto ex0;
      }
    }
    else{
      status=type=0; // prevent (stupid) warnings
      res=psync_sql_query("SELECT type, status, fileid, int1, int2 FROM fstask WHERE id=?");
      psync_sql_bind_uint(res, 1, -cr->fileid);
      row=psync_sql_fetch_rowint(res);
      if (row){
        type=row[0];
        status=row[1];
        fileid=row[2];
        writeid=row[3];
        hash=row[4];
      }
      psync_sql_free_result(res);
      if (unlikely_log(!row)){
        ret=-ENOENT;
        goto ex0;
      }
      if (type==PSYNC_FS_TASK_CREAT){
        fileid=cr->fileid;
        if (fpath->flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
          encoder=psync_cloud_crypto_get_file_encoder(fileid, 1);
          if (unlikely_log(psync_crypto_is_error(encoder))){
            ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encoder));
            goto ex0;
          }
        }
        else
          encoder=PSYNC_CRYPTO_INVALID_ENCODER;
        of=psync_fs_create_file(fileid, 0, 0, 0, 1, writeid, psync_fstask_get_ref_locked(folder), fpath->name, encoder);
        psync_fstask_release_folder_tasks_locked(folder);
        psync_sql_unlock();
        debug(D_NOTICE, "opening new file %ld %s", (long)fileid, fpath->name);
        psync_free(fpath);
        of->newfile=1;
        of->releasedforupload=status!=1;
        ret=open_write_files(of, fi->flags&O_TRUNC);
        pthread_mutex_unlock(&of->mutex);
        fi->fh=openfile_to_fh(of);
        if (unlikely_log(ret)){
          psync_fs_dec_of_refcnt(of);
          return ret;
        }
        else
          return ret;
      }
      else if (type==PSYNC_FS_TASK_MODIFY){
        debug(D_NOTICE, "opening sparse file %ld %s", (long)cr->fileid, fpath->name);
        if (fi->flags&O_TRUNC)
          size=0;
        else{
          res=psync_sql_query("SELECT size FROM filerevision WHERE fileid=? AND hash=?");
          psync_sql_bind_uint(res, 1, fileid);
          psync_sql_bind_uint(res, 2, hash);
          row=psync_sql_fetch_rowint(res);
          if (row)
            size=row[0];
          psync_sql_free_result(res);
          if (unlikely(!row)){
            debug(D_WARNING, "could not find fileid %lu with hash %lu (%ld) in filerevision", (unsigned long)fileid, (unsigned long)hash, (long)hash);
            ret=-ENOENT;
            goto ex0;
          }
        }
      }
      else{
        debug(D_BUG, "trying to open file %s with id %ld but task type is %d", fpath->name, (long)cr->fileid, type);
        ret=-EIO;
        goto ex0;
      }
      if (fpath->flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
        encoder=psync_cloud_crypto_get_file_encoder(fileid, 1);
        if (unlikely_log(psync_crypto_is_error(encoder))){
          ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encoder));
          goto ex0;
        }
      }
      else
        encoder=PSYNC_CRYPTO_INVALID_ENCODER;
      of=psync_fs_create_file(cr->fileid, fileid, size, hash, 1, writeid, psync_fstask_get_ref_locked(folder), fpath->name, encoder);
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      of->newfile=0;
      of->releasedforupload=status!=1;
      ret=open_write_files(of, fi->flags&O_TRUNC);
      pthread_mutex_unlock(&of->mutex);
      fi->fh=openfile_to_fh(of);
      if (unlikely_log(ret)){
        psync_fs_dec_of_refcnt(of);
        return ret;
      }
      else
        return ret;

    }
  }
  if (!row && fpath->folderid>=0 && !psync_fstask_find_unlink(folder, fpath->name, 0)){
    res=psync_sql_query("SELECT id, size, hash FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fpath->folderid);
    psync_sql_bind_string(res, 2, fpath->name);
    row=psync_sql_fetch_rowint(res);
    if (row){
      fileid=row[0];
      size=row[1];
      hash=row[2];
      debug(D_NOTICE, "opening regular file %lu %s size %lu hash %lu", (unsigned long)fileid, fpath->name, (unsigned long)size, (unsigned long)hash);
    }
    psync_sql_free_result(res);
  }
  if (fi->flags&O_TRUNC || (fi->flags&O_CREAT && !row)){
    if (fi->flags&O_TRUNC)
      debug(D_NOTICE, "truncating file %s", path);
    else
      debug(D_NOTICE, "creating file %s", path);
    if (fpath->flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
      if (row){
        encoder=psync_cloud_crypto_get_file_encoder(fileid, 1);
        if (unlikely_log(psync_crypto_is_error(encoder))){
          ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encoder));
          goto ex0;
        }
        
      }
      else{
        psync_symmetric_key_t symkey;
        encsymkey=psync_cloud_crypto_get_new_encoded_and_plain_key(0, &encsymkeylen, &symkey);
        if (unlikely_log(psync_crypto_is_error(encsymkey))){
          ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
          goto ex0;
        }
        encoder=psync_crypto_aes256_sector_encoder_decoder_create(symkey);
        psync_ssl_free_symmetric_key(symkey);
        if (unlikely_log(encoder==PSYNC_CRYPTO_INVALID_ENCODER)){
          psync_free(encsymkey);
          ret=-ENOMEM;
          goto ex0;
        }
      }
    }
    else{
      encoder=PSYNC_CRYPTO_INVALID_ENCODER;
      encsymkey=NULL;
      encsymkeylen=0;
    }
    cr=psync_fstask_add_creat(folder, fpath->name, encsymkey, encsymkeylen);
    psync_free(encsymkey);
    if (unlikely_log(!cr)){
      ret=-EIO;
      goto ex0;
    }
    of=psync_fs_create_file(cr->fileid, 0, 0, 0, 1, 0, psync_fstask_get_ref_locked(folder), fpath->name, encoder);
    psync_fstask_release_folder_tasks_locked(folder);
    psync_sql_unlock();
    of->newfile=1;
    of->modified=1;
    ret=open_write_files(of, 1);
    pthread_mutex_unlock(&of->mutex);
    if (unlikely_log(ret)){
      psync_fs_del_creat(fpath, of);
      return ret;
    }
    psync_free(fpath);
    fi->fh=openfile_to_fh(of);
    return 0;
  }
  else if (row){
    if (fpath->flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
      encoder=psync_cloud_crypto_get_file_encoder(fileid, 1);
      if (unlikely_log(psync_crypto_is_error(encoder))){
        ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encoder));
        goto ex0;
      }
    }
    else
      encoder=PSYNC_CRYPTO_INVALID_ENCODER;
    of=psync_fs_create_file(fileid, fileid, size, hash, 0, 0, psync_fstask_get_ref_locked(folder), fpath->name, encoder);
    fi->fh=openfile_to_fh(of);
    ret=0;
  }
  else
    ret=-ENOENT;
ex0:
  psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
  psync_free(fpath);
  return ret;
}

static int psync_fs_file_exists_in_folder(psync_fstask_folder_t *folder, const char *name){
  psync_fstask_creat_t *cr;
  psync_sql_res *res;
  psync_uint_row row;
  cr=psync_fstask_find_creat(folder, name, 0);
  if (cr)
    return 1;
  if (folder->folderid<0)
    return 0;
  if (psync_fstask_find_unlink(folder, name, 0))
    return 0;
  res=psync_sql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, folder->folderid);
  psync_sql_bind_string(res, 2, name);
  row=psync_sql_fetch_rowint(res);
  psync_sql_free_result(res);
  return row?1:0;
}

static int psync_fs_creat_fake_locked(psync_fspath_t *fpath, struct fuse_file_info *fi){
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  psync_openfile_t *of;
  psync_fsfileid_t fileid;
  size_t len;
  fileid=psync_fake_fileid++;
  len=strlen(fpath->name)+1;
  cr=(psync_fstask_creat_t *)psync_malloc(offsetof(psync_fstask_creat_t, name)+len);
  cr->fileid=fileid;
  cr->taskid=fileid;
  memcpy(cr->name, fpath->name, len);
  folder=psync_fstask_get_or_create_folder_tasks_locked(fpath->folderid);
  psync_fstask_inject_creat(folder, cr);
  of=psync_fs_create_file(fileid, 0, 0, 0, 0, 0, psync_fstask_get_ref_locked(folder), fpath->name, PSYNC_CRYPTO_INVALID_ENCODER);
  psync_fstask_release_folder_tasks_locked(folder);
  of->newfile=0;
  of->modified=0;
  psync_sql_unlock();
  psync_free(fpath);
  fi->fh=openfile_to_fh(of);
  return 0;
}

static int psync_fs_creat(const char *path, mode_t mode, struct fuse_file_info *fi){
  psync_fspath_t *fpath;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_symmetric_key_t symkey;
  psync_crypto_aes256_sector_encoder_decoder_t encoder;
  char *encsymkey;
  size_t encsymkeylen;
  psync_openfile_t *of;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "creat %s", path);
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
    psync_sql_unlock();
    return -ENOENT;
  }
  if (unlikely(psync_fs_need_per_folder_refresh_const() && !memcmp(psync_fake_prefix, fpath->name, psync_fake_prefix_len)))
    return psync_fs_creat_fake_locked(fpath, fi);
  if (!(fpath->permissions&PSYNC_PERM_CREATE)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  folder=psync_fstask_get_or_create_folder_tasks_locked(fpath->folderid);
  if (psync_fs_file_exists_in_folder(folder, fpath->name)){
    psync_fstask_release_folder_tasks_locked(folder);
    debug(D_NOTICE, "file %s already exists, processing as open", path);
    ret=psync_fs_open(path, fi);
    psync_sql_unlock();
    psync_free(fpath);
    return ret;
  }
  if (fpath->flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
    encsymkey=psync_cloud_crypto_get_new_encoded_and_plain_key(0, &encsymkeylen, &symkey);
    if (unlikely_log(psync_crypto_is_error(encsymkey))){
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      return -psync_fs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
    }
    encoder=psync_crypto_aes256_sector_encoder_decoder_create(symkey);
    psync_ssl_free_symmetric_key(symkey);
    if (unlikely_log(encoder==PSYNC_CRYPTO_INVALID_ENCODER)){
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      psync_free(encsymkey);
      return -ENOMEM;
    }
  }
  else{
    encoder=PSYNC_CRYPTO_INVALID_ENCODER;
    encsymkey=NULL;
    encsymkeylen=0;
  }
  cr=psync_fstask_add_creat(folder, fpath->name, encsymkey, encsymkeylen);
  if (encsymkey)
    psync_free(encsymkey);
  if (unlikely_log(!cr)){
    psync_fstask_release_folder_tasks_locked(folder);
    psync_sql_unlock();
    psync_free(fpath);
    return -EIO;
  }
  of=psync_fs_create_file(cr->fileid, 0, 0, 0, 1, 0, psync_fstask_get_ref_locked(folder), fpath->name, encoder);
  psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
  of->newfile=1;
  of->modified=1;
  ret=open_write_files(of, 1);
  pthread_mutex_unlock(&of->mutex);
  if (unlikely_log(ret)){
    psync_fs_del_creat(fpath, of);
    return ret;
  }
  psync_free(fpath);
  fi->fh=openfile_to_fh(of);
  return 0;
}

void psync_fs_inc_of_refcnt_locked(psync_openfile_t *of){
  of->refcnt++;
}

void psync_fs_inc_of_refcnt(psync_openfile_t *of){
  pthread_mutex_lock(&of->mutex);
  psync_fs_inc_of_refcnt_locked(of);
  pthread_mutex_unlock(&of->mutex);
}

static void close_if_valid(psync_file_t fd){
  if (fd!=INVALID_HANDLE_VALUE)
    psync_file_close(fd);
}

static void psync_fs_free_openfile(psync_openfile_t *of){
  debug(D_NOTICE, "releasing file %s", of->currentname);
  if (of->deleted && of->fileid<0){
    psync_sql_res *res;
    debug(D_NOTICE, "file %s marked for deletion, releasing cancel tasks", of->currentname);
    res=psync_sql_prep_statement("UPDATE fstask SET status=11 WHERE id=? AND status=12");
    psync_sql_bind_uint(res, 1, -of->fileid);
    psync_sql_run_free(res);
    psync_fsupload_wake();
  }
  if (of->encrypted){
    psync_crypto_aes256_sector_encoder_decoder_free(of->encoder);
    close_if_valid(of->logfile);
    psync_tree_for_each_element_call(of->sectorsinlog, psync_sector_inlog_t, tree, psync_free);
    delete_log_files(of);
    if (of->authenticatedints)
      psync_interval_tree_free(of->authenticatedints);
  }
  pthread_mutex_destroy(&of->mutex);
  close_if_valid(of->datafile);
  close_if_valid(of->indexfile);
  if (of->writeintervals)
    psync_interval_tree_free(of->writeintervals);
  if (unlikely(psync_fs_need_per_folder_refresh_const() && of->fileid<psync_fake_fileid)){
    psync_fstask_creat_t *cr;
    psync_sql_lock();
    cr=psync_fstask_find_creat(of->currentfolder, of->currentname, 0);
    if (cr){
      psync_tree_del(&of->currentfolder->creats, &cr->tree);
      of->currentfolder->taskscnt--;
      psync_free(cr);
    }
    psync_sql_unlock();
  }
  psync_fstask_release_folder_tasks(of->currentfolder);
  psync_free(of->currentname);
  psync_free(of);
}

void psync_fs_dec_of_refcnt(psync_openfile_t *of){
  uint32_t refcnt;
  psync_sql_lock();
  pthread_mutex_lock(&of->mutex);
  refcnt=--of->refcnt;
  if (refcnt==0)
    psync_tree_del(&openfiles, &of->tree);
  psync_sql_unlock();
  pthread_mutex_unlock(&of->mutex);
  if (!refcnt)
    psync_fs_free_openfile(of);
}

void psync_fs_inc_of_refcnt_and_readers(psync_openfile_t *of){
  pthread_mutex_lock(&of->mutex);
  of->refcnt++;
  of->runningreads++;
  pthread_mutex_unlock(&of->mutex);
}

void psync_fs_dec_of_refcnt_and_readers(psync_openfile_t *of){
  uint32_t refcnt;
  psync_sql_lock();
  pthread_mutex_lock(&of->mutex);
  of->runningreads--;
  refcnt=--of->refcnt;
  if (refcnt==0)
    psync_tree_del(&openfiles, &of->tree);
  psync_sql_unlock();
  pthread_mutex_unlock(&of->mutex);
  if (!refcnt)
    psync_fs_free_openfile(of);
}

static int psync_fs_release(const char *path, struct fuse_file_info *fi){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "release %s", path);
  psync_fs_dec_of_refcnt(fh_to_openfile(fi->fh));
  return 0;
}

static int psync_fs_flush(const char *path, struct fuse_file_info *fi){
  psync_openfile_t *of;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "flush %s", path);
  of=fh_to_openfile(fi->fh);
  pthread_mutex_lock(&of->mutex);
  if (of->modified){
    psync_sql_res *res;
    uint64_t writeid;
    uint32_t aff;
    int ret;
    writeid=of->writeid;
    of->releasedforupload=1;
    if (of->encrypted){
      ret=psync_fs_crypto_flush_file(of);
      if (unlikely_log(ret)){
        pthread_mutex_unlock(&of->mutex);
        return ret;
      }
    }
    pthread_mutex_unlock(&of->mutex);
    debug(D_NOTICE, "releasing file %s for upload, size=%lu, writeid=%u", path, (unsigned long)of->currentsize, (unsigned)of->writeid);
    res=psync_sql_prep_statement("UPDATE fstask SET status=0, int1=? WHERE id=? AND status=1");
    psync_sql_bind_uint(res, 1, writeid);
    psync_sql_bind_uint(res, 2, -of->fileid);
    psync_sql_run(res);
    aff=psync_sql_affected_rows();
    psync_sql_free_result(res);
    if (aff)
      psync_fsupload_wake();
    else{
      res=psync_sql_prep_statement("UPDATE fstask SET int1=? WHERE id=? AND int1<?");
      psync_sql_bind_uint(res, 1, writeid);
      psync_sql_bind_uint(res, 2, -of->fileid);
      psync_sql_bind_uint(res, 3, writeid);
      psync_sql_run_free(res);
    }
    psync_status_recalc_to_upload_async();
    return 0;
  }
  pthread_mutex_unlock(&of->mutex);
  return 0;
}

static int psync_fs_fsync(const char *path, int datasync, struct fuse_file_info *fi){
  psync_openfile_t *of;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "fsync %s", path);
  of=fh_to_openfile(fi->fh);
  pthread_mutex_lock(&of->mutex);
  if (!of->modified){
    pthread_mutex_unlock(&of->mutex);
    return 0;
  }
  if (of->encrypted){
    ret=psync_fs_crypto_flush_file(of);
    if (unlikely_log(ret)){
      pthread_mutex_unlock(&of->mutex);
      return ret;
    }
  }
  if (unlikely_log(psync_file_sync(of->datafile)) || unlikely_log(!of->newfile && psync_file_sync(of->indexfile))){
    pthread_mutex_unlock(&of->mutex);
    return -EIO;
  }
  pthread_mutex_unlock(&of->mutex);
  if (unlikely_log(psync_sql_sync()))
    return -EIO;
  return 0;
}

static int psync_fs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "fsyncdir %s", path);
  if (unlikely_log(psync_sql_sync()))
    return -EIO;
  else
    return 0;
}

static int psync_read_newfile(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset){
  ssize_t br=psync_file_pread(of->datafile, buf, size, offset);
  if (br==-1){
    debug(D_NOTICE, "error reading from new file offset %lu, size %lu, error %d", (unsigned long)offset, (unsigned long)size, (int)psync_fs_err());
    return -EIO;
  }
  else
    return br;
}

static int psync_fs_read(const char *path, char *buf, size_t size, fuse_off_t offset, struct fuse_file_info *fi){
  psync_openfile_t *of;
  time_t currenttime;
  psync_fs_set_thread_name();
  of=fh_to_openfile(fi->fh);
  currenttime=psync_timer_time();
  pthread_mutex_lock(&of->mutex);
  if (of->currentsec==currenttime){
    of->bytesthissec+=size;
    if (of->currentspeed<of->bytesthissec)
      of->currentspeed=of->bytesthissec;
  }
  else{
    if (of->currentsec<currenttime-10)
      of->currentspeed=size;
    else if (of->currentspeed==0)
      of->currentspeed=of->bytesthissec;
    else
      of->currentspeed=(of->bytesthissec/(currenttime-of->currentsec)+of->currentspeed*3)/4;
    of->currentsec=currenttime;
    of->bytesthissec=size;
  }
  if (of->newfile){
    if (of->encrypted)
      return psync_fs_crypto_read_newfile_locked(of, buf, size, offset);
    else{
      int ret=psync_read_newfile(of, buf, size, offset);
      pthread_mutex_unlock(&of->mutex);
      return ret;
    }
  }
  if (of->modified)
    return psync_pagecache_read_modified_locked(of, buf, size, offset);
  else{
    if (of->encrypted)
      return psync_pagecache_read_unmodified_encrypted_locked(of, buf, size, offset);
    else
      return psync_pagecache_read_unmodified_locked(of, buf, size, offset);
  }
}

static void psync_fs_inc_writeid_locked(psync_openfile_t *of){
  if (unlikely(of->releasedforupload)){
    if (unlikely(psync_sql_trylock())){
      pthread_mutex_unlock(&of->mutex);
      psync_sql_lock();
      pthread_mutex_lock(&of->mutex);
    }
    if (of->releasedforupload){
      of->releasedforupload=0;
      debug(D_NOTICE, "stopping upload of file %s as new write arrived", of->currentname);
      assertw(of->fileid<0);
      psync_fsupload_stop_upload_locked(-of->fileid);
    }
    psync_sql_unlock();
  }
  of->writeid++;
}

static int psync_fs_modfile_check_size_ok(psync_openfile_t *of, uint64_t size){
  if (unlikely(of->currentsize<size)){
    debug(D_NOTICE, "extending file %s from %lu to %lu bytes", of->currentname, (unsigned long)of->currentsize, (unsigned long)size);
    if (psync_file_seek(of->datafile, size, P_SEEK_SET)==-1 || psync_file_truncate(of->datafile))
      return -1;
    if (of->newfile)
      return 0;
    else{
      index_record rec;
      uint64_t ioff;
      assertw(of->modified);
      ioff=of->indexoff++;
      rec.offset=of->currentsize;
      rec.length=size-of->currentsize;
      if (unlikely_log(psync_file_pwrite(of->indexfile, &rec, sizeof(rec), sizeof(rec)*ioff+sizeof(index_header))!=sizeof(rec)))
        return -1;
      psync_interval_tree_add(&of->writeintervals, of->currentsize, size);
      of->currentsize=size;
    }
  }
  return 0;
}

static int psync_fs_reopen_file_for_writing(psync_openfile_t *of){
  psync_fstask_creat_t *cr;
  uint64_t size;
  int ret;
  debug(D_NOTICE, "reopening file %s for writing size %lu", of->currentname, (unsigned long)of->currentsize);
  if (psync_sql_trylock()){
    // we have to take sql_lock and retake of->mutex AFTER, then check if the case is still !of->newfile && !of->modified
    pthread_mutex_unlock(&of->mutex);
    psync_sql_lock();
    pthread_mutex_lock(&of->mutex);
    if (of->newfile || of->modified){
      psync_sql_unlock();
      return 1;
    }
  }
  if (of->encrypted)
    size=psync_fs_crypto_crypto_size(of->initialsize);
  else
    size=of->initialsize;
  if (size==0 || (size<=PSYNC_FS_MAX_SIZE_CONVERT_NEWFILE && 
        psync_pagecache_have_all_pages_in_cache(of->hash, size) && !psync_pagecache_lock_pages_in_cache())){
    debug(D_NOTICE, "we have all pages of file %s, convert it to new file as they are cheaper to work with", of->currentname);
    cr=psync_fstask_add_creat(of->currentfolder, of->currentname, NULL, 0);
    if (unlikely_log(!cr)){
      psync_sql_unlock();
      pthread_mutex_unlock(&of->mutex);
      psync_pagecache_unlock_pages_from_cache();
      return -EIO;
    }
    psync_fs_update_openfile_fileid_locked(of, cr->fileid);
    psync_sql_unlock();
    of->newfile=1;
    of->modified=1;
    ret=open_write_files(of, 0);
    if (unlikely_log(ret)){
      pthread_mutex_unlock(&of->mutex);
      psync_pagecache_unlock_pages_from_cache();
      return ret;
    }
    if (size){
      ret=psync_pagecache_copy_all_pages_from_cache_to_file_locked(of, of->hash, size);
      psync_pagecache_unlock_pages_from_cache();
      if (unlikely_log(ret)){
        pthread_mutex_unlock(&of->mutex);
        return -EIO;
      }
    }
    return 1;
  }
  cr=psync_fstask_add_modified_file(of->currentfolder, of->currentname, of->fileid, of->hash);
  if (unlikely_log(!cr)){
    psync_sql_unlock();
    pthread_mutex_unlock(&of->mutex);
    return -EIO;
  }
  psync_fs_update_openfile_fileid_locked(of, cr->fileid);
  psync_sql_unlock();
  ret=open_write_files(of, 0);
  if (unlikely_log(ret) || psync_file_seek(of->datafile, of->initialsize, P_SEEK_SET)==-1 || psync_file_truncate(of->datafile)){
    pthread_mutex_unlock(&of->mutex);
    if (!ret)
      ret=-EIO;
    return ret;
  }
  of->modified=1;
  of->indexoff=0;
  return 0;
}

static int psync_fs_write(const char *path, const char *buf, size_t size, fuse_off_t offset, struct fuse_file_info *fi){
  psync_openfile_t *of;
  ssize_t bw;
  uint64_t ioff;
  index_record rec;
  int ret;
  psync_fs_set_thread_name();
  of=fh_to_openfile(fi->fh);
  pthread_mutex_lock(&of->mutex);
  if (of->writeid%256==0 && of->currentsize<=offset){
    int64_t freespc=psync_get_free_space_by_path(psync_setting_get_string(_PS(fscachepath)));
    if (likely_log(freespc!=-1)){
      if (freespc>=psync_setting_get_uint(_PS(minlocalfreespace)))
        psync_set_local_full(0);
      else{
        psync_set_local_full(1);
        pthread_mutex_unlock(&of->mutex);
        return -ENOSPC;
      }
    }
  }
  psync_fs_inc_writeid_locked(of);
retry:
  if (of->newfile){
    if (of->encrypted)
      return psync_fs_crypto_write_newfile_locked(of, buf, size, offset);
    bw=psync_file_pwrite(of->datafile, buf, size, offset);
    if (of->currentsize<offset+size && bw!=-1)
      of->currentsize=offset+size;
    pthread_mutex_unlock(&of->mutex);
    if (unlikely_log(bw==-1))
      return -EIO;
    else
      return bw;
  }
  else{
    if (of->encrypted){
      debug(D_ERROR, "not implemented");
      return -ENOSYS;
    }
    if (unlikely(!of->modified)){
      ret=psync_fs_reopen_file_for_writing(of);
      if (ret==1)
        goto retry;
      else if (ret<0)
        return ret;
    }
    if (unlikely_log(psync_fs_modfile_check_size_ok(of, offset)))
      return -1;
    ioff=of->indexoff++;
    bw=psync_file_pwrite(of->datafile, buf, size, offset);
    if (unlikely_log(bw==-1)){
      pthread_mutex_unlock(&of->mutex);
      return -EIO;
    }
    rec.offset=offset;
    rec.length=bw;
    if (unlikely_log(psync_file_pwrite(of->indexfile, &rec, sizeof(rec), sizeof(rec)*ioff+sizeof(index_header))!=sizeof(rec))){
      pthread_mutex_unlock(&of->mutex);
      return -EIO;
    }
    psync_interval_tree_add(&of->writeintervals, offset, offset+bw);
    if (of->currentsize<offset+size)
      of->currentsize=offset+size;
    pthread_mutex_unlock(&of->mutex);
    return bw;
  }
}

static int psync_fs_mkdir(const char *path, mode_t mode){
  psync_fspath_t *fpath;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "mkdir %s", path);
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath)
    ret=-ENOENT;
  else if (!(fpath->permissions&PSYNC_PERM_CREATE))
    ret=-EACCES;
  else{
    ret=psync_fstask_mkdir(fpath->folderid, fpath->name, fpath->flags);
  }
  psync_sql_unlock();
  psync_free(fpath);
  debug(D_NOTICE, "mkdir %s=%d", path, ret);
  return ret;
}

#if defined(FUSE_HAS_CAN_UNLINK)
static int psync_fs_can_rmdir(const char *path){
  psync_fspath_t *fpath;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "can_rmdir %s", path);
  psync_sql_lock();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath)
    ret=-ENOENT;
  else if (!(fpath->permissions&PSYNC_PERM_DELETE))
    ret=-EACCES;
  else
    ret=psync_fstask_can_rmdir(fpath->folderid, fpath->name);
  psync_sql_unlock();
  psync_free(fpath);
  debug(D_NOTICE, "can_rmdir %s=%d", path, ret);
  return ret;
}
#endif

static int psync_fs_rmdir(const char *path){
  psync_fspath_t *fpath;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "rmdir %s", path);
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath)
    ret=-ENOENT;
  else if (!(fpath->permissions&PSYNC_PERM_DELETE))
    ret=-EACCES;
  else
    ret=psync_fstask_rmdir(fpath->folderid, fpath->name);
  psync_sql_unlock();
  psync_free(fpath);
  debug(D_NOTICE, "rmdir %s=%d", path, ret);
  return ret;
}

#if defined(FUSE_HAS_CAN_UNLINK)
static int psync_fs_can_unlink(const char *path){
  psync_fspath_t *fpath;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "can_unlink %s", path);
  psync_sql_lock();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath)
    ret=-ENOENT;
  else if (!(fpath->permissions&PSYNC_PERM_DELETE))
    ret=-EACCES;
  else
    ret=psync_fstask_can_unlink(fpath->folderid, fpath->name);
  psync_sql_unlock();
  psync_free(fpath);
  debug(D_NOTICE, "can_unlink %s=%d", path, ret);
  return ret;
}
#endif

static int psync_fs_unlink(const char *path){
  psync_fspath_t *fpath;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "unlink %s", path);
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath)
    ret=-ENOENT;
  else if (!(fpath->permissions&PSYNC_PERM_DELETE))
    ret=-EACCES;
  else
    ret=psync_fstask_unlink(fpath->folderid, fpath->name);
  psync_sql_unlock();
  psync_free(fpath);
  debug(D_NOTICE, "unlink %s=%d", path, ret);
  return ret;
}

static int psync_fs_rename_folder(psync_fsfolderid_t folderid, psync_fsfolderid_t parentfolderid, const char *name, uint32_t srcpermissions,
                                  psync_fsfolderid_t to_folderid, const char *new_name, uint32_t targetperms){
  if (parentfolderid==to_folderid){
    assertw(targetperms==srcpermissions);
    if (!(srcpermissions&PSYNC_PERM_MODIFY))
      return -EACCES;
  }
  else{
    if (!(srcpermissions&PSYNC_PERM_DELETE) || !(targetperms&PSYNC_PERM_CREATE))
      return -EACCES;
  }
  return psync_fstask_rename_folder(folderid, parentfolderid, name, to_folderid, new_name);
}

static int psync_fs_rename_file(psync_fsfileid_t fileid, psync_fsfolderid_t parentfolderid, const char *name, uint32_t srcpermissions,
                                  psync_fsfolderid_t to_folderid, const char *new_name, uint32_t targetperms){
  if (parentfolderid==to_folderid){
    assertw(targetperms==srcpermissions);
    if (!(srcpermissions&PSYNC_PERM_MODIFY))
      return -EACCES;
  }
  else{
    if (!(srcpermissions&PSYNC_PERM_DELETE) || !(targetperms&PSYNC_PERM_CREATE))
      return -EACCES;
  }
  return psync_fstask_rename_file(fileid, parentfolderid, name, to_folderid, new_name);
}

static int psync_fs_is_file(psync_fsfolderid_t folderid, const char *name){
  psync_fstask_folder_t *folder;
  psync_sql_res *res;
  int ret;
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder){
    if (psync_fstask_find_creat(folder, name, 0))
      ret=2;
    else if (psync_fstask_find_unlink(folder, name, 0))
      ret=1;
    else
      ret=0;
    psync_fstask_release_folder_tasks_locked(folder);
    if (ret)
      return ret-1;
  }
  res=psync_sql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_string(res, 2, name);
  if (psync_sql_fetch_rowint(res))
    ret=1;
  else
    ret=0;
  psync_sql_free_result(res);
  return ret;
}

static int psync_fs_is_folder(psync_fsfolderid_t folderid, const char *name){
  psync_fstask_folder_t *folder;
  psync_sql_res *res;
  int ret;
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder){
    if (psync_fstask_find_mkdir(folder, name, 0))
      ret=2;
    else if (psync_fstask_find_rmdir(folder, name, 0))
      ret=1;
    else
      ret=0;
    psync_fstask_release_folder_tasks_locked(folder);
    if (ret)
      return ret-1;
  }
  res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_string(res, 2, name);
  if (psync_sql_fetch_rowint(res))
    ret=1;
  else
    ret=0;
  psync_sql_free_result(res);
  return ret;
}

static int psync_fs_is_folder_nonempty(psync_fsfolderid_t folderid){
  psync_fstask_folder_t *folder;
  psync_sql_res *res;
  psync_str_row row;
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder && (folder->creats || folder->mkdirs)){
    psync_fstask_release_folder_tasks_locked(folder);
    return 1;
  }
  if (folderid>=0){
    res=psync_sql_query("SELECT name FROM file WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, folderid);
    while ((row=psync_sql_fetch_rowstr(res)))
      if (!folder || !psync_fstask_find_unlink(folder, row[0], 0)){
        psync_sql_free_result(res);
        if (folder)
          psync_fstask_release_folder_tasks_locked(folder);
        return 1;
      }
    psync_sql_free_result(res);
    res=psync_sql_query("SELECT name FROM folder WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, folderid);
    while ((row=psync_sql_fetch_rowstr(res)))
      if (!folder || !psync_fstask_find_rmdir(folder, row[0], 0)){
        psync_sql_free_result(res);
        if (folder)
          psync_fstask_release_folder_tasks_locked(folder);
        return 1;
      }
    psync_sql_free_result(res);
  }
  if (folder)
    psync_fstask_release_folder_tasks_locked(folder);
  return 0;
}

static int psync_fs_is_nonempty_folder(psync_fsfolderid_t folderid, const char *name){
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  int ret;
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder){
    if ((mk=psync_fstask_find_mkdir(folder, name, 0)))
      ret=psync_fs_is_folder_nonempty(mk->folderid)+1;
    else if (psync_fstask_find_rmdir(folder, name, 0))
      ret=1;
    else
      ret=0;
    psync_fstask_release_folder_tasks_locked(folder);
    if (ret)
      return ret-1;
  }
  res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_string(res, 2, name);
  if ((row=psync_sql_fetch_rowint(res)))
    ret=psync_fs_is_folder_nonempty(row[0]);
  else
    ret=0;
  psync_sql_free_result(res);
  return ret;
}

static int psync_fs_rename(const char *old_path, const char *new_path){
  psync_fspath_t *fold_path, *fnew_path;
  psync_sql_res *res;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mkdir;
  psync_fstask_creat_t *creat;
  psync_uint_row row;
  psync_fileorfolderid_t fid;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "rename %s to %s", old_path, new_path);
  folder=NULL;
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fold_path=psync_fsfolder_resolve_path(old_path);
  fnew_path=psync_fsfolder_resolve_path(new_path);
  if (!fold_path || !fnew_path)
    goto err_enoent;
  if ((fold_path->flags&PSYNC_FOLDER_FLAG_ENCRYPTED)!=(fnew_path->flags&PSYNC_FOLDER_FLAG_ENCRYPTED)){
    ret=-EXDEV;
    goto finish;
  }
  folder=psync_fstask_get_folder_tasks_locked(fold_path->folderid);
  if (folder){
    if ((mkdir=psync_fstask_find_mkdir(folder, fold_path->name, 0))){
      if (psync_fs_is_file(fnew_path->folderid, fnew_path->name))
        ret=-ENOTDIR;
      else if (psync_fs_is_nonempty_folder(fnew_path->folderid, fnew_path->name))
        ret=-ENOTEMPTY;
      else
        ret=psync_fs_rename_folder(mkdir->folderid, fold_path->folderid, fold_path->name, fold_path->permissions, fnew_path->folderid, fnew_path->name, fnew_path->permissions);
      goto finish;
    }
    else if ((creat=psync_fstask_find_creat(folder, fold_path->name, 0))){
      if (psync_fs_is_file(fnew_path->folderid, fnew_path->name))
        ret=-EISDIR;
      else
        ret=psync_fs_rename_file(creat->fileid, fold_path->folderid, fold_path->name, fold_path->permissions, fnew_path->folderid, fnew_path->name, fnew_path->permissions);
      goto finish;
    }
  }
  if (!folder || !psync_fstask_find_rmdir(folder, fold_path->name, 0)){
    res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fold_path->folderid);
    psync_sql_bind_string(res, 2, fold_path->name);
    if ((row=psync_sql_fetch_rowint(res))){
      fid=row[0];
      psync_sql_free_result(res);
      if (psync_fs_is_file(fnew_path->folderid, fnew_path->name))
        ret=-ENOTDIR;
      else if (psync_fs_is_nonempty_folder(fnew_path->folderid, fnew_path->name))
        ret=-ENOTEMPTY;
      else
        ret=psync_fs_rename_folder(fid, fold_path->folderid, fold_path->name, fold_path->permissions, fnew_path->folderid, fnew_path->name, fnew_path->permissions);
      goto finish;
    }
    psync_sql_free_result(res);
  }
  if (!folder || !psync_fstask_find_unlink(folder, fold_path->name, 0)){
    res=psync_sql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fold_path->folderid);
    psync_sql_bind_string(res, 2, fold_path->name);
    if ((row=psync_sql_fetch_rowint(res))){
      fid=row[0];
      psync_sql_free_result(res);
      if (psync_fs_is_folder(fnew_path->folderid, fnew_path->name))
        ret=-EISDIR;
      else
        ret=psync_fs_rename_file(fid, fold_path->folderid, fold_path->name, fold_path->permissions, fnew_path->folderid, fnew_path->name, fnew_path->permissions);
      goto finish;
    }
    psync_sql_free_result(res);
  }
  goto err_enoent;
finish:
  if (folder)
    psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
  psync_free(fold_path);
  psync_free(fnew_path);
  return ret;
err_enoent:
  if (folder)
    psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
  psync_free(fold_path);
  psync_free(fnew_path);
  debug(D_NOTICE, "returning ENOENT, folder not found");
  return -ENOENT;
}

static int psync_fs_statfs(const char *path, struct statvfs *stbuf){
  uint64_t q, uq;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "statfs %s", path);
  if (waitingforlogin)
    return -EACCES;
/* TODO:
   return -ENOENT if path is invalid if fuse does not call getattr first
   */
  memset(stbuf, 0, sizeof(struct statvfs));
  q=psync_get_uint_value("quota");
  uq=psync_get_uint_value("usedquota");
  if (uq>q)
    uq=q;
  stbuf->f_bsize=FS_BLOCK_SIZE;
  stbuf->f_frsize=FS_BLOCK_SIZE;
  stbuf->f_blocks=q/FS_BLOCK_SIZE;
  stbuf->f_bfree=stbuf->f_blocks-uq/FS_BLOCK_SIZE;
  stbuf->f_bavail=stbuf->f_bfree;
  stbuf->f_flag=ST_NOSUID;
  stbuf->f_namemax=1024;
  return 0;
}

static int psync_fs_chmod(const char *path, mode_t mode){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "chmod %s %u", path, (unsigned)mode);
  return 0;
}

int psync_fs_chown(const char *path, uid_t uid, gid_t gid){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "chown %s %u %u", path, (unsigned)uid, (unsigned)gid);
  return 0;
}

static int psync_fs_utimens(const char *path, const struct timespec tv[2]){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "utimens %s", path);
  return 0;
}

static int psync_fs_ftruncate(const char *path, fuse_off_t size, struct fuse_file_info *fi){
  psync_openfile_t *of;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "ftruncate %s %lu", path, (unsigned long)size);
  of=fh_to_openfile(fi->fh);
  pthread_mutex_lock(&of->mutex);
  psync_fs_inc_writeid_locked(of);
retry:
  if (unlikely(!of->newfile && !of->modified)){
    psync_fstask_creat_t *cr;
    debug(D_NOTICE, "reopening file %s for writing", of->currentname);
    if (psync_sql_trylock()){
      // we have to take sql_lock and retake of->mutex AFTER, then check if the case is still !of->newfile && !of->modified
      pthread_mutex_unlock(&of->mutex);
      psync_sql_lock();
      pthread_mutex_lock(&of->mutex);
      if (of->newfile || of->modified){
        psync_sql_unlock();
        goto retry;
      }
    }
    cr=psync_fstask_add_modified_file(of->currentfolder, of->currentname, of->fileid, of->hash);
    psync_sql_unlock();
    if (unlikely_log(!cr)){
      pthread_mutex_unlock(&of->mutex);
      return -EIO;
    }
    of->fileid=cr->fileid;
    ret=open_write_files(of, 0);
    if (unlikely_log(ret) || psync_fs_modfile_check_size_ok(of, size) ||
        (of->currentsize!=size && (psync_file_seek(of->datafile, size, P_SEEK_SET)==-1 || psync_file_truncate(of->datafile)))){
      if (!ret)
        ret=-EIO;
    }
    else{
      of->modified=1;
      of->indexoff=0;
      of->currentsize=size;
      ret=0;
    }
  }
  else{
    if (psync_fs_modfile_check_size_ok(of, size))
      ret=-EIO;
    else if (of->currentsize!=size && (psync_file_seek(of->datafile, size, P_SEEK_SET)==-1 || psync_file_truncate(of->datafile)))
      ret=-EIO;
    else{
      ret=0;
      of->currentsize=size;
    }
  }
  pthread_mutex_unlock(&of->mutex);
  debug(D_NOTICE, "ftruncate %s %lu=%d", path, (unsigned long)size, ret);
  return ret;
}

static int psync_fs_truncate(const char *path, fuse_off_t size){
  struct fuse_file_info fi;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "truncate %s %lu", path, (unsigned long)size);
  memset(&fi, 0, sizeof(fi));
  ret=psync_fs_open(path, &fi);
  if (ret)
    return ret;
  ret=psync_fs_ftruncate(path, size, &fi);
  psync_fs_flush(path, &fi);
  psync_fs_release(path, &fi);
  return ret;
}

static void *psync_fs_init(struct fuse_conn_info *conn){
#if defined(FUSE_CAP_ASYNC_READ)
  conn->want|=FUSE_CAP_ASYNC_READ;
#endif
#if defined(FUSE_CAP_ATOMIC_O_TRUNC)
  conn->want|=FUSE_CAP_ATOMIC_O_TRUNC;
#endif
#if defined(FUSE_CAP_BIG_WRITES)
  conn->want|=FUSE_CAP_BIG_WRITES;
#endif
  conn->max_readahead=0;
  conn->max_write=FS_MAX_WRITE;
  return 0;
}

static pthread_mutex_t fsrefreshmutex=PTHREAD_MUTEX_INITIALIZER;
static time_t lastfsrefresh=0;
static int fsrefreshtimerscheduled=0;
#define REFRESH_SEC 3

static void psync_invalidate_os_cache_noret(){
  char *path;
  pthread_mutex_lock(&start_mutex);
  if (started==1)
    path=psync_strdup(psync_current_mountpoint);
  else
    path=NULL;
  pthread_mutex_unlock(&start_mutex);
  if (path){
    psync_invalidate_os_cache(path);
    psync_free(path);
  }
}

static void psync_fs_refresh_timer(psync_timer_t timer, void *ptr){
  time_t ct;
  ct=psync_timer_time();
  psync_timer_stop(timer);
  pthread_mutex_lock(&fsrefreshmutex);
  fsrefreshtimerscheduled=0;
  lastfsrefresh=ct;
  pthread_mutex_unlock(&fsrefreshmutex);
  psync_run_thread("os cache invalidate timer", psync_invalidate_os_cache_noret);
}

void psync_fs_refresh(){
  time_t ct;
  int todo;
  if (!psync_invalidate_os_cache_needed())
    return;
  ct=psync_timer_time();
  todo=0;
  pthread_mutex_lock(&fsrefreshmutex);
  if (fsrefreshtimerscheduled)
    todo=2;
  else if (lastfsrefresh+REFRESH_SEC<ct)
    lastfsrefresh=ct;
  else{
    todo=1;
    fsrefreshtimerscheduled=1;
  }
  pthread_mutex_unlock(&fsrefreshmutex);
  if (todo==0){
    debug(D_NOTICE, "running cache invalidate direct");
    psync_run_thread("os cache invalidate", psync_invalidate_os_cache_noret);
  }
  else if (todo==1){
    debug(D_NOTICE, "setting timer to invalidate cache");
    psync_timer_register(psync_fs_refresh_timer, REFRESH_SEC, NULL);
  }
}

int psync_fs_need_per_folder_refresh_f(){
#if psync_fs_need_per_folder_refresh_const()
  return started==1;
#else
  return 0;
#endif
}

void psync_fs_refresh_folder(psync_folderid_t folderid){
  char *path, *fpath;
  unsigned char rndbuff[20];
  char rndhex[42];
  psync_file_t fd;
  path=psync_get_path_by_folderid_sep(folderid, PSYNC_DIRECTORY_SEPARATOR, NULL);
  if (path==PSYNC_INVALID_PATH)
    return;
  psync_ssl_rand_weak(rndbuff, sizeof(rndbuff));
  psync_binhex(rndhex, rndbuff, sizeof(rndbuff));
  rndhex[2*sizeof(rndbuff)]=0;
  pthread_mutex_lock(&start_mutex);
  if (started==1){
	  if (psync_invalidate_os_cache_needed())
      fpath=psync_strcat(psync_current_mountpoint, path, NULL);
    else
	    fpath=psync_strcat(psync_current_mountpoint, path, "/", psync_fake_prefix, rndhex, NULL);
  }
  else
    fpath=NULL;
  pthread_mutex_unlock(&start_mutex);
  psync_free(path);
  if (!fpath)
    return;
  if (psync_invalidate_os_cache_needed())
    psync_invalidate_os_cache(fpath);
  else{
    debug(D_NOTICE, "creating fake file %s", fpath);
    fd=psync_file_open(fpath, P_O_WRONLY, P_O_CREAT);
    if (fd!=INVALID_HANDLE_VALUE)
      psync_file_close(fd);
  }
  psync_free(fpath);
}

#if defined(P_OS_WINDOWS)

static int is_mountable(char where){
    DWORD drives = GetLogicalDrives();
    where = tolower(where) - 'a';
    return !(drives & (1<<where));
}

static int get_first_free_drive(){
    DWORD drives = GetLogicalDrives();
    int pos = 3;
    while (pos < 26 && (drives & (1<<pos)))
        pos++;
    return pos < 26 ? pos : 0;
}

static char mount_point = 'a';

static char *psync_fuse_get_mountpoint(){
  const char *stored;
  char *mp = (char*)psync_malloc(3);
  mp[0] = 'P';
  mp[1] = ':';
  mp[2] = '\0';
  stored = psync_setting_get_string(_PS(fsroot));
  if (stored[0] && stored[1] && is_mountable(stored[0])){
      mp[0] = stored[0];
      goto ready;
  }
  if (is_mountable('P')){
      goto ready;
  }
  mp[0] = 'A' + get_first_free_drive();
ready:
  mount_point = mp[0];
  return mp;
}

#else

static char *psync_fuse_get_mountpoint(){
  psync_stat_t st;
  char *mp;
  mp=psync_strdup(psync_setting_get_string(_PS(fsroot)));
  if (psync_stat(mp, &st) && psync_mkdir(mp)){
    psync_free(mp);
    return NULL;
  }
  return mp;
}

#endif

char *psync_fs_getmountpoint(){
  char *ret;
  pthread_mutex_lock(&start_mutex);
  if (started==1)
    ret=psync_strdup(psync_current_mountpoint);
  else
    ret=NULL;
  pthread_mutex_unlock(&start_mutex);
  return ret;
}

char *psync_fs_get_path_by_folderid(psync_folderid_t folderid){
  char *mp, *path, *ret;
  pthread_mutex_lock(&start_mutex);
  if (started==1)
    mp=psync_strdup(psync_current_mountpoint);
  else
    mp=NULL;
  pthread_mutex_unlock(&start_mutex);
  if (!mp || folderid==0)
    return mp;
  path=psync_get_path_by_folderid_sep(folderid, PSYNC_DIRECTORY_SEPARATOR, NULL);
  if (path==PSYNC_INVALID_PATH){
    psync_free(mp);
    return NULL;
  }
  ret=psync_strcat(mp, path, NULL);
  psync_free(mp);
  psync_free(path);
  return ret;
}

static void psync_fs_do_stop(void){
  struct timespec ts;
  debug(D_NOTICE, "stopping");
  pthread_mutex_lock(&start_mutex);
  if (started==1){
#if defined(P_OS_MACOSX)
    debug(D_NOTICE, "running unmount");
    unmount(psync_current_mountpoint, MNT_FORCE);
    debug(D_NOTICE, "unmount exited");
#endif
    debug(D_NOTICE, "running fuse_exit");
    fuse_exit(psync_fuse);
    started=2;
    debug(D_NOTICE, "fuse_exit exited, flushing cache");
    psync_pagecache_flush();
    debug(D_NOTICE, "cache flushed, waiting for fuse to exit");
    psync_nanotime(&ts);
    ts.tv_sec+=2;
    if (pthread_cond_timedwait(&start_cond, &start_mutex, &ts))
      debug(D_NOTICE, "timeouted waiting for fuse to exit");
    else
      debug(D_NOTICE, "waited for fuse to exit");
  }
  pthread_mutex_unlock(&start_mutex);
}

void psync_fs_stop(){
  psync_fs_do_stop();
}

#if defined(P_OS_POSIX)

static void psync_signal_handler(int sig){
  debug(D_NOTICE, "got signal %d\n", sig);
  psync_fs_do_stop();
  exit(1);
}

static void psync_set_signal(int sig, void (*handler)(int)){
  struct sigaction sa;
  
  if (unlikely_log(sigaction(sig, NULL, &sa)))
    return;

  if (sa.sa_handler==SIG_DFL){
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&(sa.sa_mask));
    sa.sa_handler=handler;
    sa.sa_flags=0;
    sigaction(sig, &sa, NULL);
  }
}

static void psync_setup_signals(){
  psync_set_signal(SIGTERM, psync_signal_handler);
  psync_set_signal(SIGINT, psync_signal_handler);
  psync_set_signal(SIGHUP, psync_signal_handler);
}

#endif

static void psync_fs_init_once(){
#if psync_fs_need_per_folder_refresh_const()
  unsigned char rndbuff[16];
  char rndhex[34];
  psync_ssl_rand_weak(rndbuff, sizeof(rndbuff));
  psync_binhex(rndhex, rndbuff, sizeof(rndbuff));
  rndhex[2*sizeof(rndbuff)]=0;
  psync_fake_prefix=psync_strcat(".refresh", rndhex, NULL);
  psync_fake_prefix_len=strlen(psync_fake_prefix);
#endif
  psync_fstask_init();
  psync_pagecache_init();
  atexit(psync_fs_do_stop);
#if defined(P_OS_POSIX)
  psync_setup_signals();
#endif
}

static void psync_fuse_thread(){
  pthread_mutex_lock(&start_mutex);
  if (!initonce){
    psync_fs_init_once();
    initonce=1;
  }
  pthread_mutex_unlock(&start_mutex);
  debug(D_NOTICE, "running fuse_loop_mt");
  fuse_loop_mt(psync_fuse);
  pthread_mutex_lock(&start_mutex);
  debug(D_NOTICE, "fuse_loop_mt exited, running fuse_destroy");
  fuse_destroy(psync_fuse);
  debug(D_NOTICE, "fuse_destroy exited");
/*#if defined(P_OS_MACOSX)
  debug(D_NOTICE, "calling unmount");
  unmount(psync_current_mountpoint, MNT_FORCE);
  debug(D_NOTICE, "unmount exited");
#endif*/
  psync_free(psync_current_mountpoint);
  started=0;
  pthread_cond_broadcast(&start_cond);
  pthread_mutex_unlock(&start_mutex);
}

static int psync_fs_do_start(){
  char *mp;
  struct fuse_operations psync_oper;
  struct fuse_args args=FUSE_ARGS_INIT(0, NULL);

// it seems that fuse option parser ignores the first argument
// it is ignored as it's like the exec(), argv[0] is the program
    
#if defined(P_OS_LINUX)
  fuse_opt_add_arg(&args, "argv");
  fuse_opt_add_arg(&args, "-oauto_unmount");
  fuse_opt_add_arg(&args, "-ofsname=pCloud.fs");
#endif
#if defined(P_OS_MACOSX)
  fuse_opt_add_arg(&args, "argv");
  fuse_opt_add_arg(&args, "-ovolname=pCloud Drive");
  fuse_opt_add_arg(&args, "-ofsname=pCloud.fs");
  fuse_opt_add_arg(&args, "-olocal");
  if (psync_user_is_admin())
    fuse_opt_add_arg(&args, "-oallow_root");
  fuse_opt_add_arg(&args, "-onolocalcaches");
#endif

  memset(&psync_oper, 0, sizeof(psync_oper));
  
  psync_oper.init     = psync_fs_init;
  psync_oper.getattr  = psync_fs_getattr;
  psync_oper.readdir  = psync_fs_readdir;
  psync_oper.open     = psync_fs_open;
  psync_oper.create   = psync_fs_creat;
  psync_oper.release  = psync_fs_release;
  psync_oper.flush    = psync_fs_flush;
  psync_oper.fsync    = psync_fs_fsync;
  psync_oper.fsyncdir = psync_fs_fsyncdir;
  psync_oper.read     = psync_fs_read;
  psync_oper.write    = psync_fs_write;
  psync_oper.mkdir    = psync_fs_mkdir;
  psync_oper.rmdir    = psync_fs_rmdir;
  psync_oper.unlink   = psync_fs_unlink;
  psync_oper.rename   = psync_fs_rename;
  psync_oper.statfs   = psync_fs_statfs;
  psync_oper.chmod    = psync_fs_chmod;
  psync_oper.chown    = psync_fs_chown;
  psync_oper.utimens  = psync_fs_utimens;
  psync_oper.ftruncate= psync_fs_ftruncate;
  psync_oper.truncate = psync_fs_truncate;
  
  psync_oper.setxattr = psync_fs_setxattr;
  psync_oper.getxattr = psync_fs_getxattr;
  psync_oper.listxattr= psync_fs_listxattr;
  psync_oper.removexattr=psync_fs_removexattr;
  
#if defined(FUSE_HAS_CAN_UNLINK)
  psync_oper.can_unlink=psync_fs_can_unlink;
  psync_oper.can_rmdir=psync_fs_can_rmdir;
#endif

#if defined(P_OS_POSIX)
  myuid=getuid();
  mygid=getgid();
#endif
  pthread_mutex_lock(&start_mutex);
  if (started)
    goto err00;
  mp=psync_fuse_get_mountpoint();
  
#if defined(P_OS_MACOSX)
  unmount(mp, MNT_FORCE);
#endif

  psync_fuse_channel=fuse_mount(mp, &args);
  if (unlikely_log(!psync_fuse_channel))
    goto err0;
  psync_fuse=fuse_new(psync_fuse_channel, &args, &psync_oper, sizeof(psync_oper), NULL);
  if (unlikely_log(!psync_fuse))
    goto err1;
  psync_current_mountpoint=mp;
  started=1;
  pthread_mutex_unlock(&start_mutex);
  fuse_opt_free_args(&args);
  psync_run_thread("fuse", psync_fuse_thread);
  return 0;
err1:
  fuse_unmount(mp, psync_fuse_channel);
err0:
  psync_free(mp);
err00:
  pthread_mutex_unlock(&start_mutex);
  fuse_opt_free_args(&args);
  return -1;
}

static void psync_fs_wait_start(){
  debug(D_NOTICE, "waiting for online status");
  psync_wait_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
  if (psync_do_run){
    debug(D_NOTICE, "starting fs");
    psync_fs_do_start();
  }
}

static void psync_fs_wait_login(){
  debug(D_NOTICE, "waiting for online status");
  psync_wait_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
  debug(D_NOTICE, "waited for online status");
  psync_sql_lock();
  waitingforlogin=0;
  psync_sql_unlock();
}

void psync_fs_pause_until_login(){
  psync_sql_lock();
  if (waitingforlogin==0){
    waitingforlogin=1;
    debug(D_NOTICE, "stopping fs until login");
    psync_run_thread("fs wait login", psync_fs_wait_login);
  }
  psync_sql_unlock();  
}

int psync_fs_start(){
  uint32_t status;
  int ret;
  pthread_mutex_lock(&start_mutex);
  if (started)
    ret=-1;
  else
    ret=0;
  pthread_mutex_unlock(&start_mutex);
  if (ret)
    return ret;
  status=psync_status_get(PSTATUS_TYPE_AUTH);
  debug(D_NOTICE, "auth status=%u", status);
  if (status==PSTATUS_AUTH_PROVIDED)
    return psync_fs_do_start();
  else{
    psync_run_thread("fs wait login", psync_fs_wait_start);
    return 0;
  }
}

int psync_fs_isstarted(){
  int s;
  pthread_mutex_lock(&start_mutex);
  s=started;
  pthread_mutex_unlock(&start_mutex);
  return s==1;
}

int psync_fs_remount(){
  int s;
  pthread_mutex_lock(&start_mutex);
  s=started;
  pthread_mutex_unlock(&start_mutex);
  if (s){
    psync_fs_stop();
    return psync_fs_start();
  }
  else
    return 0;
}
