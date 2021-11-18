/* Copyright (c) 2013-2016 Anton Titov.
 * Copyright (c) 2013-2016 pCloud Ltd.
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

#include <stdlib.h>
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
#include "pfsstatic.h"

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

#if defined(P_OS_LINUX)
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
#define FUSE_HAS_SETCRTIME 1

#if defined(_DARWIN_FEATURE_64_BIT_INODE)
#define FUSE_STAT_HAS_BIRTHTIME
#endif

#endif

#if defined(P_OS_LINUX)
#define PSYNC_FS_ERR_CRYPTO_EXPIRED EROFS
#define PSYNC_FS_ERR_MOVE_ACROSS_CRYPTO EXDEV
#elif defined(P_OS_WINDOWS)
#define PSYNC_FS_ERR_CRYPTO_EXPIRED EACCES
#define PSYNC_FS_ERR_MOVE_ACROSS_CRYPTO EACCES
#else
#define PSYNC_FS_ERR_CRYPTO_EXPIRED EIO
#define PSYNC_FS_ERR_MOVE_ACROSS_CRYPTO EXDEV
#endif

static struct fuse_chan *psync_fuse_channel=NULL;
static struct fuse *psync_fuse=NULL;
static char *psync_current_mountpoint=NULL;
static psync_generic_callback_t psync_start_callback=NULL;
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

extern int errno;

static psync_tree *openfiles=PSYNC_TREE_EMPTY;

static int psync_fs_ftruncate_of_locked(psync_openfile_t *of, fuse_off_t size);

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

int psync_fs_update_openfile(uint64_t taskid, uint64_t writeid, psync_fileid_t newfileid, uint64_t hash, uint64_t size, time_t ctime){
  psync_sql_res *res;
  psync_uint_row row;
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_fsfileid_t fileid;
  int64_t d;
  int ret;
  fileid=-(psync_fsfileid_t)taskid;
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
      psync_fs_lock_file(fl);
      if (fl->writeid==writeid){
        if (fl->encrypted){
          if (fl->logfile){
            psync_file_close(fl->logfile);
            fl->logfile=INVALID_HANDLE_VALUE;
          }
          delete_log_files(fl);
          if (fl->authenticatedints){
            psync_interval_tree_free(fl->authenticatedints);
            fl->authenticatedints=NULL;
          }
          size=psync_fs_crypto_plain_size(size);
        }
        debug(D_NOTICE, "updating fileid %ld to %lu, hash %lu size %lu", (long)fileid, (unsigned long)newfileid, (unsigned long)hash, (unsigned long)size);
        fl->fileid=newfileid;
        fl->remotefileid=newfileid;
        fl->hash=hash;
        fl->modified=0;
        fl->newfile=0;
        fl->currentsize=size;
        fl->initialsize=size;
        fl->releasedforupload=0;
        fl->origctime=ctime;
        if (fl->datafile!=INVALID_HANDLE_VALUE){
          psync_file_close(fl->datafile);
          fl->datafile=INVALID_HANDLE_VALUE;
        }
        if (fl->indexfile!=INVALID_HANDLE_VALUE){
          psync_file_close(fl->indexfile);
          fl->indexfile=INVALID_HANDLE_VALUE;
        }
        psync_tree_del(&openfiles, &fl->tree);
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
  else{
    if (row)
      debug(D_NOTICE, "writeid of fileid %ld differs %lu!=%lu", (long)fileid, (unsigned long)row[0], (unsigned long)writeid);
    ret=-1;
  }
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
      psync_fs_lock_file(fl);
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
      psync_fs_lock_file(fl);
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

void psync_fs_mark_openfile_deleted(uint64_t taskid){
  psync_sql_res *res;
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  psync_fsfileid_t fileid;
  fileid=-(psync_fsfileid_t)taskid;
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
      psync_fs_lock_file(fl);
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
  fileid=-(psync_fsfileid_t)taskid;
  psync_sql_rdlock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      psync_fs_lock_file(fl);
      d=fl->writeid;
      pthread_mutex_unlock(&fl->mutex);
      psync_sql_rdunlock();
      return d;
    }
  }
  res=psync_sql_query_nolock("SELECT int1 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  if ((row=psync_sql_fetch_rowint(res)))
    d=row[0];
  else
    d=-1;
  psync_sql_free_result(res);
  psync_sql_rdunlock();
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
  psync_folderid_t folderid;
  uint64_t mtime;
  psync_fstask_folder_t *folder;
  folderid=psync_get_number(row[0]);
  mtime=psync_get_number(row[3]);
  folder=psync_fstask_get_folder_tasks_rdlocked(folderid);
  if (folder && folder->mtime)
    mtime=folder->mtime;
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  stbuf->st_ino=folderid_to_inode(folderid);
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime=psync_get_number(row[2]);
#endif
  stbuf->st_ctime=mtime;
  stbuf->st_mtime=mtime;
  stbuf->st_atime=mtime;
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
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime=psync_get_number(row[2]);
#endif
  stbuf->st_ctime=psync_get_number(row[3]);
  stbuf->st_mtime=stbuf->st_ctime;
  stbuf->st_atime=stbuf->st_ctime;
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
  uint64_t mtime;
  psync_fstask_folder_t *folder;
  folder=psync_fstask_get_folder_tasks_rdlocked(mk->folderid);
  if (folder && folder->mtime)
    mtime=folder->mtime;
  else
    mtime=mk->mtime;
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  if (mk->folderid>=0)
    stbuf->st_ino=folderid_to_inode(mk->folderid);
  else
    stbuf->st_ino=taskid_to_inode(-mk->folderid);
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime=mk->ctime;
#endif
  stbuf->st_ctime=mtime;
  stbuf->st_mtime=mtime;
  stbuf->st_atime=mtime;
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
  res=psync_sql_query_rdlock("SELECT name, size, ctime, mtime, id, parentfolderid FROM file WHERE id=?");
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
#ifdef FUSE_STAT_HAS_BIRTHTIME
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
  psync_sql_rdlock();
  tr=openfiles;
  while (tr){
    d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      psync_fs_lock_file(fl);
      stbuf->st_size=fl->currentsize;
      debug(D_NOTICE, "found open file with size %lu", (unsigned long)fl->currentsize);
      if (!psync_fstat(fl->logfile, &st))
        stbuf->st_mtime=psync_stat_mtime(&st);
      pthread_mutex_unlock(&fl->mutex);
      psync_sql_rdunlock();
      return 1;
    }
  }
  psync_sql_rdunlock();
  return 0;
}

static int psync_creat_local_to_file_stat(psync_fstask_creat_t *cr, struct FUSE_STAT *stbuf, uint32_t folderflags){
  psync_stat_t st;
  psync_fsfileid_t fileid;
  uint64_t size;
  const char *cachepath;
  char *filename;
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
//  psync_file_t fd;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  int stret;
  if (unlikely(psync_fs_need_per_folder_refresh_const() && cr->fileid<psync_fake_fileid))
    return psync_creat_stat_fake_file(stbuf);
  fl=NULL;
  fileid=-cr->fileid;
  psync_sql_rdlock();
  tr=openfiles;
  while (tr){
    d=cr->fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=psync_tree_element(tr, psync_openfile_t, tree);
      psync_fs_lock_file(fl);
      break;
    }
  }
  psync_sql_rdunlock();
  if (fl && fl->datafile!=INVALID_HANDLE_VALUE){
    stret=psync_fstat(fl->datafile, &st);
    pthread_mutex_unlock(&fl->mutex);
    if (stret)
      debug(D_NOTICE, "could not stat open file %ld", (long)cr->fileid);
    else
      debug(D_NOTICE, "got stat from open file %ld", (long)cr->fileid);
  }
  else{
    if (fl)
      pthread_mutex_unlock(&fl->mutex);
    psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
    fileidhex[sizeof(psync_fsfileid_t)]='d';
    fileidhex[sizeof(psync_fsfileid_t)+1]=0;
    cachepath=psync_setting_get_string(_PS(fscachepath));
    filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    stret=psync_stat(filename, &st);
    if (stret)
      debug(D_NOTICE, "could not stat file %s", filename);
    psync_free(filename);
  }
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
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime=psync_stat_birthtime(&st);
#endif
  stbuf->st_mtime=psync_stat_mtime(&st);
  stbuf->st_ctime=stbuf->st_mtime;
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

static int psync_creat_static_to_file_stat(psync_fstask_creat_t *cr, struct FUSE_STAT *stbuf, uint32_t folderflags){
  psync_fstask_local_creat_t *lc;
  lc=psync_fstask_creat_get_local(cr);
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  stbuf->st_ino=cr->taskid;
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime=lc->ctime;
#endif
  stbuf->st_ctime=lc->ctime;
  stbuf->st_mtime=lc->ctime;
  stbuf->st_atime=lc->ctime;
  stbuf->st_mode=S_IFREG | 0644;
  stbuf->st_nlink=1;
  stbuf->st_size=lc->datalen;
#if defined(P_OS_POSIX)
  stbuf->st_blocks=(lc->datalen+511)/512;
  stbuf->st_blksize=FS_BLOCK_SIZE;
#endif
  stbuf->st_uid=myuid;
  stbuf->st_gid=mygid;
  return 0;
}

static int psync_creat_to_file_stat(psync_fstask_creat_t *cr, struct FUSE_STAT *stbuf, uint32_t folderflags){
  debug(D_NOTICE, "getting stat from creat for file %s fileid %ld taskid %lu", cr->name, (long)cr->fileid, (unsigned long)cr->taskid);
  if (cr->fileid>0)
    return psync_creat_db_to_file_stat(cr->fileid, stbuf, folderflags);
  else if (cr->fileid<0)
    return psync_creat_local_to_file_stat(cr, stbuf, folderflags);
  else
    return psync_creat_static_to_file_stat(cr, stbuf, folderflags);
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
  res=psync_sql_query_rdlock("SELECT 0, 0, IFNULL(s.value, 1414766136)*1, f.mtime, f.subdircnt FROM folder f LEFT JOIN setting s ON s.id='registered' WHERE f.id=0");
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

#define CHECK_LOGIN_RDLOCKED() do {\
  if (unlikely(waitingforlogin)){\
    psync_sql_rdunlock();\
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
  if (path[1]==0 && path[0]=='/')
    return psync_fs_getrootattr(stbuf);
  psync_sql_rdlock();
  CHECK_LOGIN_RDLOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    psync_sql_rdunlock();
    crr=psync_fsfolder_crypto_error();
    if (crr){
      crr=-psync_fs_crypto_err_to_errno(crr);
      debug(D_NOTICE, "got crypto error for %s, returning %d", path, crr);
      return crr;
    }
    else{
      debug(D_NOTICE, "could not find path component of %s, returning ENOENT", path);
      return -ENOENT;
    }
  }
  folder=psync_fstask_get_folder_tasks_rdlocked(fpath->folderid);
  if (folder){
    psync_fstask_mkdir_t *mk;
    mk=psync_fstask_find_mkdir(folder, fpath->name, 0);
    if (mk){
      if (mk->flags&PSYNC_FOLDER_FLAG_INVISIBLE){
        psync_sql_rdunlock();
        psync_free(fpath);
        return -ENOENT;
      }
      psync_mkdir_to_folder_stat(mk, stbuf);
      psync_sql_rdunlock();
      psync_free(fpath);
      return 0;
    }
  }
  if (!folder || !psync_fstask_find_rmdir(folder, fpath->name, 0)){
    res=psync_sql_query_nolock("SELECT id, permissions, ctime, mtime, subdircnt FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fpath->folderid);
    psync_sql_bind_string(res, 2, fpath->name);
    if ((row=psync_sql_fetch_row(res)))
      psync_row_to_folder_stat(row, stbuf);
    psync_sql_free_result(res);
    if (row){
      psync_sql_rdunlock();
      psync_free(fpath);
      return 0;
    }
  }
  res=psync_sql_query_nolock("SELECT name, size, ctime, mtime, id FROM file WHERE parentfolderid=? AND name=?");
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
  }
  else
    crr=-1;
  psync_sql_rdunlock();
  psync_free(fpath);
  if (row || !crr)
    return 0;
  debug(D_NOTICE, "returning ENOENT for %s", path);
  return -ENOENT;
}

static int filler_decoded(psync_crypto_aes256_text_decoder_t dec, fuse_fill_dir_t filler, void *buf, const char *name, struct FUSE_STAT *st, fuse_off_t off){
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
  psync_sql_rdlock();
  CHECK_LOGIN_RDLOCKED();
  folderid=psync_fsfolderid_by_path(path, &flags);
  if (unlikely_log(folderid==PSYNC_INVALID_FSFOLDERID)){
    psync_sql_rdunlock();
    if (psync_fsfolder_crypto_error())
      return PRINT_RETURN(-psync_fs_crypto_err_to_errno(psync_fsfolder_crypto_error()));
    else
      return -PRINT_RETURN_CONST(ENOENT);
  }
  if (flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
    dec=psync_cloud_crypto_get_folder_decoder(folderid);
    if (psync_crypto_is_error(dec)){
      psync_sql_rdunlock();
      return PRINT_RETURN(-psync_fs_crypto_err_to_errno(psync_crypto_to_error(dec)));
    }
  }
  else
    dec=NULL;
  filler(buf, ".", NULL, 0);
  if (folderid!=0)
    filler(buf, "..", NULL, 0);
  folder=psync_fstask_get_folder_tasks_rdlocked(folderid);
  if (folderid>=0){
    res=psync_sql_query_nolock("SELECT id, permissions, ctime, mtime, subdircnt, name FROM folder WHERE parentfolderid=?");
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
    res=psync_sql_query_nolock("SELECT name, size, ctime, mtime, id FROM file WHERE parentfolderid=?");
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
      if (psync_tree_element(trel, psync_fstask_mkdir_t, tree)->flags&PSYNC_FOLDER_FLAG_INVISIBLE)
        continue;
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
  }
  psync_sql_rdunlock();
  if (dec)
    psync_cloud_crypto_release_folder_decoder(folderid, dec);
  return PRINT_RETURN(0);
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
        psync_fs_lock_file(fl);
        psync_fs_inc_of_refcnt_locked(fl);
      }
      else
        psync_fs_inc_of_refcnt(fl);
      assertw(fl->currentfolder==folder);
      assertw(!strcmp(fl->currentname, name));
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      if (encoder!=PSYNC_CRYPTO_INVALID_ENCODER && encoder!=PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)
        psync_cloud_crypto_release_file_encoder(fileid, hash, encoder);
      debug(D_NOTICE, "found open file %ld, refcnt %u, currentsize=%lu", (long int)fileid, (unsigned)fl->refcnt, (unsigned long)fl->currentsize);
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
#if IS_DEBUG
  {
    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&fl->mutex, &mattr);
    pthread_mutexattr_destroy(&mattr);
  }
#else
  pthread_mutex_init(&fl->mutex, NULL);
#endif
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
  fl->writetimer=PSYNC_INVALID_TIMER;
  fl->refcnt=1;
  fl->modified=fileid<0?1:0;
  if (encoder!=PSYNC_CRYPTO_INVALID_ENCODER){
    fl->encrypted=1;
    fl->encoder=encoder;
    fl->logfile=INVALID_HANDLE_VALUE;
  }
  if (lock)
    psync_fs_lock_file(fl);
  psync_sql_unlock();
  return fl;
}

int64_t psync_fs_load_interval_tree(psync_file_t fd, uint64_t size, psync_interval_tree_t **tree){
  psync_fs_index_record records[512];
  uint64_t cnt;
  uint64_t i;
  ssize_t rrd, rd, j;
  if (unlikely(size<sizeof(psync_fs_index_header)))
    return 0;
  size-=sizeof(psync_fs_index_header);
  assertw(size%sizeof(psync_fs_index_record)==0);
  cnt=size/sizeof(psync_fs_index_record);
  debug(D_NOTICE, "loading %lu intervals", (unsigned long)cnt);
  for (i=0; i<cnt; i+=ARRAY_SIZE(records)){
    rd=ARRAY_SIZE(records)>cnt-i?cnt-i:ARRAY_SIZE(records);
    rrd=psync_file_pread(fd, records, rd*sizeof(psync_fs_index_record), i*sizeof(psync_fs_index_record)+sizeof(psync_fs_index_header));
    if (unlikely_log(rrd!=rd*sizeof(psync_fs_index_record)))
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
  psync_fs_index_header hdr;
  int64_t ifs;
  ifs=psync_file_size(of->indexfile);
  if (unlikely_log(ifs==-1))
    return -1;
  if (ifs<sizeof(psync_fs_index_header)){
    assertw(ifs==0);
    if (psync_file_pwrite(of->indexfile, &hdr, sizeof(psync_fs_index_header), 0)!=sizeof(psync_fs_index_header))
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
  debug(D_NOTICE, "opening write files of %s, trunc=%d", of->currentname, trunc!=0);
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
    fs=psync_file_size(of->datafile);
    if (unlikely_log(fs==-1))
      return -EIO;
    if (of->encrypted)
      of->currentsize=psync_fs_crypto_plain_size(fs);
    else
      of->currentsize=fs;
  }
  else{
    debug(D_NOTICE, "data file already open");
    if (trunc)
      return psync_fs_ftruncate_of_locked(of, 0);
    else
      return 0;
  }
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
  psync_sql_res *res;
  psync_sql_lock();
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("DELETE FROM fstaskdepend WHERE dependfstaskid=?");
  psync_sql_bind_uint(res, 1, -of->fileid);
  psync_sql_run_free(res);
  if (psync_sql_affected_rows())
    psync_fsupload_wake();
  res=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, -of->fileid);
  psync_sql_run_free(res);
  psync_sql_commit_transaction();
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
  time_t ctime;
  int ret, status, type;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "open %s", path);
  fileid=writeid=hash=size=ctime=0;
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    psync_sql_unlock();
    ret=psync_fsfolder_crypto_error();
    if (ret){
      ret=-psync_fs_crypto_err_to_errno(ret);
      return PRINT_RETURN(ret);
    }
    else{
      debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
      return -ENOENT;
    }
  }
  if ((fi->flags&3)!=O_RDONLY && !(fpath->permissions&PSYNC_PERM_MODIFY)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  // even if there are existing files there, just don't allow opening those
  if (fpath->flags&(PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST|PSYNC_FOLDER_FLAG_BACKUP_DEVICE)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  folder=psync_fstask_get_or_create_folder_tasks_locked(fpath->folderid);
  row=NULL;
  if ((cr=psync_fstask_find_creat(folder, fpath->name, 0))){
    if (cr->fileid>0){
      res=psync_sql_query("SELECT id, size, hash, ctime FROM file WHERE id=?");
      psync_sql_bind_uint(res, 1, cr->fileid);
      row=psync_sql_fetch_rowint(res);
      if (row){
        fileid=row[0];
        size=row[1];
        hash=row[2];
        ctime=row[3];
        debug(D_NOTICE, "opening moved regular file %lu %s size %lu hash %lu", (unsigned long)fileid, fpath->name, (unsigned long)size, (unsigned long)hash);
      }
      psync_sql_free_result(res);
      if (unlikely_log(!row)){
        ret=-ENOENT;
        goto ex0;
      }
    }
    else if (cr->fileid<0){
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
          encoder=psync_cloud_crypto_get_file_encoder(fileid, hash, 1);
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
        encoder=psync_cloud_crypto_get_file_encoder(fileid, hash, 1);
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
    else{ /* cr->fileid==0 */
      psync_fstask_local_creat_t *lc;
      lc=psync_fstask_creat_get_local(cr);
      of=psync_fs_create_file(INT64_MAX-(UINT64_MAX-cr->taskid), 0, lc->datalen, 0, 1, 0, psync_fstask_get_ref_locked(folder), fpath->name, PSYNC_CRYPTO_INVALID_ENCODER);
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      of->modified=1;
      of->staticfile=1;
      of->staticdata=(const char *)lc->data;
      of->staticctime=lc->ctime;
      pthread_mutex_unlock(&of->mutex);
      fi->fh=openfile_to_fh(of);
      return 0;
    }
  }
  if (!row && fpath->folderid>=0 && !psync_fstask_find_unlink(folder, fpath->name, 0)){
    res=psync_sql_query("SELECT id, size, hash, ctime FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fpath->folderid);
    psync_sql_bind_string(res, 2, fpath->name);
    row=psync_sql_fetch_rowint(res);
    if (row){
      fileid=row[0];
      size=row[1];
      hash=row[2];
      ctime=row[3];
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
        encoder=psync_cloud_crypto_get_file_encoder(fileid, hash, 0);
        if (unlikely_log(psync_crypto_is_error(encoder))){
          ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encoder));
          goto ex0;
        }
        encsymkey=psync_cloud_crypto_get_file_encoded_key(fileid, hash, &encsymkeylen);
        if (unlikely_log(psync_crypto_is_error(encsymkey))){
          psync_cloud_crypto_release_file_encoder(fileid, hash, encoder);
          ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
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
    cr=psync_fstask_add_creat(folder, fpath->name, 0, encsymkey, encsymkeylen);
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
      encoder=psync_cloud_crypto_get_file_encoder(fileid, hash, 1);
      if (unlikely_log(psync_crypto_is_error(encoder))){
        ret=-psync_fs_crypto_err_to_errno(psync_crypto_to_error(encoder));
        goto ex0;
      }
    }
    else
      encoder=PSYNC_CRYPTO_INVALID_ENCODER;
    of=psync_fs_create_file(fileid, fileid, size, hash, 0, 0, psync_fstask_get_ref_locked(folder), fpath->name, encoder);
    of->origctime=ctime;
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
  cr->rfileid=0;
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
    psync_sql_unlock();
    ret=psync_fsfolder_crypto_error();
    if (ret){
      ret=psync_fs_crypto_err_to_errno(ret);
      return PRINT_RETURN(-ret);
    }
    else{
      debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
      return -ENOENT;
    }
  }
  if (unlikely(psync_fs_need_per_folder_refresh_const() && !strncmp(psync_fake_prefix, fpath->name, psync_fake_prefix_len)))
    return psync_fs_creat_fake_locked(fpath, fi);
  if (!(fpath->permissions&PSYNC_PERM_CREATE) || (fpath->flags&(PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST|PSYNC_FOLDER_FLAG_BACKUP_DEVICE))){
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
    if (psync_crypto_isexpired()){
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      return -PRINT_RETURN_CONST(PSYNC_FS_ERR_CRYPTO_EXPIRED);
    }
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
  cr=psync_fstask_add_creat(folder, fpath->name, 0, encsymkey, encsymkeylen);
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
  psync_fs_lock_file(of);
  psync_fs_inc_of_refcnt_locked(of);
  pthread_mutex_unlock(&of->mutex);
}

static void close_if_valid(psync_file_t fd){
  if (fd!=INVALID_HANDLE_VALUE)
    psync_file_close(fd);
}

static void psync_fs_free_openfile(psync_openfile_t *of){
  debug(D_NOTICE, "releasing file %s", of->currentname);
  if (unlikely(of->writetimer!=PSYNC_INVALID_TIMER))
    debug(D_BUG, "file %s with active timer is set to free, this is not supposed to happen", of->currentname);
  if (of->deleted && of->fileid<0){
    psync_sql_res *res;
    debug(D_NOTICE, "file %s marked for deletion, releasing cancel tasks", of->currentname);
    res=psync_sql_prep_statement("UPDATE fstask SET status=11 WHERE id=? AND status=12");
    psync_sql_bind_uint(res, 1, -of->fileid);
    psync_sql_run_free(res);
    psync_fsupload_wake();
  }
  if (of->encrypted){
    if (of->encoder!=PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER && of->encoder!=PSYNC_CRYPTO_FAILED_SECTOR_ENCODER){
      assert(of->encoder!=PSYNC_CRYPTO_LOADING_SECTOR_ENCODER);
      psync_crypto_aes256_sector_encoder_decoder_free(of->encoder);
    }
    close_if_valid(of->logfile);
    psync_tree_for_each_element_call_safe(of->sectorsinlog, psync_sector_inlog_t, tree, psync_free);
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

static void psync_fs_get_both_locks(psync_openfile_t *of){
retry:
  psync_sql_lock();
  if (pthread_mutex_trylock(&of->mutex)){
    psync_sql_unlock();
    psync_fs_lock_file(of);
    if (psync_sql_trylock()){
      pthread_mutex_unlock(&of->mutex);
      psync_milisleep(1);
      goto retry;
    }
  }
}

void psync_fs_dec_of_refcnt(psync_openfile_t *of){
  uint32_t refcnt;
  psync_fs_get_both_locks(of);
  refcnt=--of->refcnt;
  if (!refcnt)
    psync_tree_del(&openfiles, &of->tree);
  psync_sql_unlock();
  pthread_mutex_unlock(&of->mutex);
  if (!refcnt)
    psync_fs_free_openfile(of);
}

void psync_fs_inc_of_refcnt_and_readers(psync_openfile_t *of){
  psync_fs_lock_file(of);
  of->refcnt++;
  of->runningreads++;
  pthread_mutex_unlock(&of->mutex);
}

void psync_fs_dec_of_refcnt_and_readers(psync_openfile_t *of){
  uint32_t refcnt;
  psync_fs_get_both_locks(of);
  of->runningreads--;
  refcnt=--of->refcnt;
  if (refcnt==0)
    psync_tree_del(&openfiles, &of->tree);
  psync_sql_unlock();
  pthread_mutex_unlock(&of->mutex);
  if (!refcnt)
    psync_fs_free_openfile(of);
}

typedef struct {
  psync_openfile_t *of;
  uint64_t writeid;
} psync_openfile_writeid_t;

static void psync_fs_upload_release_timer(void *ptr){
  psync_sql_res *res;
  psync_openfile_writeid_t *ofw;
  uint32_t aff;
  ofw=(psync_openfile_writeid_t *)ptr;
  debug(D_NOTICE, "releasing file %s for upload, size=%lu, writeid=%u", ofw->of->currentname, (unsigned long)ofw->of->currentsize, (unsigned)ofw->writeid);
  res=psync_sql_prep_statement("UPDATE fstask SET status=0, int1=? WHERE id=? AND status=1");
  psync_sql_bind_uint(res, 1, ofw->writeid);
  psync_sql_bind_uint(res, 2, -ofw->of->fileid);
  psync_sql_run(res);
  aff=psync_sql_affected_rows();
  psync_sql_free_result(res);
  if (aff)
    psync_fsupload_wake();
  else{
    res=psync_sql_prep_statement("UPDATE fstask SET int1=? WHERE id=? AND int1<?");
    psync_sql_bind_uint(res, 1, ofw->writeid);
    psync_sql_bind_uint(res, 2, -ofw->of->fileid);
    psync_sql_bind_uint(res, 3, ofw->writeid);
    psync_sql_run_free(res);
  }
  psync_fs_dec_of_refcnt(ofw->of);
  psync_free(ofw);
  psync_status_recalc_to_upload_async();
}

static void psync_fs_write_timer(psync_timer_t timer, void *ptr){
  psync_openfile_t *of;
  of=(psync_openfile_t *)ptr;
  psync_fs_lock_file(of);
  psync_timer_stop(timer);
  of->writetimer=PSYNC_INVALID_TIMER;
  debug(D_NOTICE, "got write timer for file %s", of->currentname);
  if (of->releasedforupload)
    debug(D_NOTICE, "file seems to be already released for upload");
  else if (of->modified){
    psync_openfile_writeid_t *ofw;
    if (unlikely(of->staticfile)){
      debug(D_ERROR, "file is static file, which should not generally happen");
      goto unlock_ex;
    }
    if (unlikely(of->encrypted && psync_fs_crypto_flush_file(of))){
      debug(D_WARNING, "we are in timer and we failed to flush crypto file, life sux");
      goto unlock_ex;
    }
    of->releasedforupload=1;
    ofw=psync_new(psync_openfile_writeid_t);
    ofw->of=of;
    ofw->writeid=of->writeid;
    pthread_mutex_unlock(&of->mutex);
    debug(D_NOTICE, "running separate thread to release file for upload");
    psync_run_thread1("upload release timer", psync_fs_upload_release_timer, ofw);
    return;
  }
  else
    debug(D_NOTICE, "file seems to be already uploaded");
unlock_ex:
  pthread_mutex_unlock(&of->mutex);
  psync_fs_dec_of_refcnt(of);
}

static int psync_fs_flush(const char *path, struct fuse_file_info *fi){
  psync_openfile_t *of;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "flush %s", path);
  of=fh_to_openfile(fi->fh);
  psync_fs_lock_file(of);
  if (of->modified){
    psync_sql_res *res;
    uint64_t writeid;
    uint32_t aff;
    int ret;
    if (of->staticfile){
      pthread_mutex_unlock(&of->mutex);
      return 0;
    }
    writeid=of->writeid;
    if (of->encrypted){
      ret=psync_fs_crypto_flush_file(of);
      if (unlikely_log(ret)){
        pthread_mutex_unlock(&of->mutex);
        return ret;
      }
    }
    of->releasedforupload=1;
    if (of->writetimer && !psync_timer_stop(of->writetimer)){
      if (--of->refcnt==0){
        debug(D_BUG, "zero refcnt in flush after canceling timer");
        assert(of->refcnt);
      }
      of->writetimer=PSYNC_INVALID_TIMER;
    }
    pthread_mutex_unlock(&of->mutex);
    debug(D_NOTICE, "releasing file %s for upload, size=%lu, writeid=%u", path, (unsigned long)of->currentsize, (unsigned)writeid);
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

static int psync_fs_release(const char *path, struct fuse_file_info *fi){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "release %s", path);
  psync_fs_flush(path, fi);
  psync_fs_dec_of_refcnt(fh_to_openfile(fi->fh));
  return 0;
}

static int psync_fs_fsync(const char *path, int datasync, struct fuse_file_info *fi){
  psync_openfile_t *of;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "fsync %s", path);
  of=fh_to_openfile(fi->fh);
  psync_fs_lock_file(of);
  if (!of->modified || of->staticfile){
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
  pthread_mutex_unlock(&of->mutex);
  if (br==-1){
    debug(D_NOTICE, "error reading from new file offset %lu, size %lu, error %d", (unsigned long)offset, (unsigned long)size, (int)psync_fs_err());
    br=-EIO;
  }
  return br;
}

static int psync_read_staticfile(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset){
  int ret;
  if (of->currentsize<offset)
    ret=0;
  else{
    if (offset+size>of->currentsize)
      ret=of->currentsize-offset;
    else
      ret=size;
    memcpy(buf, of->staticdata+offset, ret);
  }
  pthread_mutex_unlock(&of->mutex);
  return ret;
}

static int psync_fs_read(const char *path, char *buf, size_t size, fuse_off_t offset, struct fuse_file_info *fi){
  psync_openfile_t *of;
  time_t currenttime;
  psync_fs_set_thread_name();
  of=fh_to_openfile(fi->fh);
  currenttime=psync_timer_time();
  psync_fs_lock_file(of);
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
  if (of->encrypted){
    if (of->newfile)
      return psync_fs_crypto_read_newfile_locked(of, buf, size, offset);
    else if (of->modified)
      return psync_fs_crypto_read_modified_locked(of, buf, size, offset);
    else
      return psync_pagecache_read_unmodified_encrypted_locked(of, buf, size, offset);
  }
  else{
    if (of->newfile)
      return psync_read_newfile(of, buf, size, offset);
    else if (of->modified){
      if (unlikely(of->staticfile))
        return psync_read_staticfile(of, buf, size, offset);
      else
        return psync_pagecache_read_modified_locked(of, buf, size, offset);
    }
    else
      return psync_pagecache_read_unmodified_locked(of, buf, size, offset);
  }
}

static void psync_fs_inc_writeid_locked(psync_openfile_t *of){
  if (unlikely(of->releasedforupload)){
    if (unlikely(psync_sql_trylock())){
      pthread_mutex_unlock(&of->mutex);
      psync_sql_lock();
      psync_fs_lock_file(of);
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
  if (of->writetimer==PSYNC_INVALID_TIMER || !psync_timer_stop(of->writetimer)){
    if (of->writetimer==PSYNC_INVALID_TIMER)
      psync_fs_inc_of_refcnt_locked(of);
    of->writetimer=psync_timer_register(psync_fs_write_timer, PSYNC_UPLOAD_NOWRITE_TIMER, of);
  }
}

static int psync_fs_modfile_check_size_ok(psync_openfile_t *of, uint64_t size){
  if (unlikely(of->currentsize<size)){
    debug(D_NOTICE, "extending file %s from %lu to %lu bytes", of->currentname, (unsigned long)of->currentsize, (unsigned long)size);
    if (psync_file_seek(of->datafile, size, P_SEEK_SET)==-1 || psync_file_truncate(of->datafile))
      return -1;
    if (of->newfile)
      return 0;
    else{
      psync_fs_index_record rec;
      uint64_t ioff;
      assertw(of->modified);
      ioff=of->indexoff++;
      rec.offset=of->currentsize;
      rec.length=size-of->currentsize;
      if (unlikely_log(psync_file_pwrite(of->indexfile, &rec, sizeof(rec), sizeof(rec)*ioff+sizeof(psync_fs_index_header))!=sizeof(rec)))
        return -1;
      psync_interval_tree_add(&of->writeintervals, of->currentsize, size);
      of->currentsize=size;
    }
  }
  return 0;
}

PSYNC_NOINLINE static int psync_fs_reopen_file_for_writing(psync_openfile_t *of){
  psync_fstask_creat_t *cr;
  uint64_t size;
  char *encsymkey;
  size_t encsymkeylen;
  int ret;
  debug(D_NOTICE, "reopening file %s for writing size %lu", of->currentname, (unsigned long)of->currentsize);
  if (unlikely(of->encrypted && of->encoder==PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)){
    psync_crypto_aes256_sector_encoder_decoder_t enc;
    // we should unlock of->mutex as it can deadlock with sqllock and taking sqllock before network operation is not a good idea
    pthread_mutex_unlock(&of->mutex);
    enc=psync_cloud_crypto_get_file_encoder(of->remotefileid, of->hash, 0);
    if (unlikely(psync_crypto_is_error(enc)))
      return -psync_fs_crypto_err_to_errno(psync_crypto_to_error(enc));
    psync_fs_lock_file(of);
    if (of->encoder==PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)
      of->encoder=enc;
    else
      psync_cloud_crypto_release_file_encoder(of->remotefileid, of->hash, enc);
    if (of->newfile || of->modified)
      return 1;
  }
  if (unlikely(psync_sql_trylock())){
    // we have to take sql_lock and retake of->mutex AFTER, then check if the case is still !of->newfile && !of->modified
    pthread_mutex_unlock(&of->mutex);
    psync_sql_lock();
    psync_fs_lock_file(of);
    if (of->newfile || of->modified){
      psync_sql_unlock();
      return 1;
    }
  }
  if (of->encrypted){
    if (unlikely(psync_crypto_isexpired())){
      psync_sql_unlock();
      return -PRINT_RETURN_CONST(PSYNC_FS_ERR_CRYPTO_EXPIRED);
    }
    size=psync_fs_crypto_crypto_size(of->initialsize);
    encsymkey=psync_cloud_crypto_get_file_encoded_key(of->fileid, of->hash, &encsymkeylen);
    if (unlikely_log(psync_crypto_is_error(encsymkey))){
      psync_sql_unlock();
      return -psync_fs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
    }
  }
  else{
    encsymkey=NULL;
    encsymkeylen=0;
    size=of->initialsize;
  }
  if (size==0 || (size<=PSYNC_FS_MAX_SIZE_CONVERT_NEWFILE &&
        psync_pagecache_have_all_pages_in_cache(of->hash, size) && !psync_pagecache_lock_pages_in_cache())){
    debug(D_NOTICE, "we have all pages of file %s, convert it to new file as they are cheaper to work with", of->currentname);
    cr=psync_fstask_add_creat(of->currentfolder, of->currentname, of->fileid, encsymkey, encsymkeylen);
    if (unlikely_log(!cr)){
      psync_sql_unlock();
      psync_pagecache_unlock_pages_from_cache();
      psync_free(encsymkey);
      return -EIO;
    }
    psync_fs_update_openfile_fileid_locked(of, cr->fileid);
    psync_fs_file_to_task(of->remotefileid, cr->taskid);
    psync_sql_unlock();
    of->newfile=1;
    of->modified=1;
    ret=open_write_files(of, 0);
    if (unlikely_log(ret)){
      psync_pagecache_unlock_pages_from_cache();
      psync_free(encsymkey);
      return ret;
    }
    if (of->origctime)
      psync_file_set_creation(of->datafile, of->origctime);
    if (size){
      ret=psync_pagecache_copy_all_pages_from_cache_to_file_locked(of, of->hash, size);
      psync_pagecache_unlock_pages_from_cache();
      if (unlikely_log(ret)){
        psync_free(encsymkey);
        return -EIO;
      }
    }
    of->currentsize=of->initialsize;
    return 1;
  }
  cr=psync_fstask_add_modified_file(of->currentfolder, of->currentname, of->fileid, of->hash, encsymkey, encsymkeylen);
  psync_free(encsymkey);
  if (unlikely_log(!cr)){
    psync_sql_unlock();
    return -EIO;
  }
  psync_fs_update_openfile_fileid_locked(of, cr->fileid);
  psync_sql_unlock();
  ret=open_write_files(of, 0);
  if (unlikely_log(ret) || psync_file_seek(of->datafile, size, P_SEEK_SET)==-1 || psync_file_truncate(of->datafile)){
    if (!ret)
      ret=-EIO;
    return ret;
  }
  if (of->origctime)
    psync_file_set_creation(of->datafile, of->origctime);
  of->modified=1;
  of->indexoff=0;
  of->currentsize=of->initialsize;
  return 0;
}

PSYNC_NOINLINE static int psync_fs_reopen_static_file_for_writing(psync_openfile_t *of){
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  uint64_t taskid;
  int ret;
  assert(!of->encrypted);
  assert(of->staticfile);
  if (unlikely(psync_sql_trylock())){
    // we have to take sql_lock and retake of->mutex AFTER, then check if the case is still !of->newfile && !of->modified
    pthread_mutex_unlock(&of->mutex);
    psync_sql_lock();
    psync_fs_lock_file(of);
    if (!of->staticfile){
      psync_sql_unlock();
      return 1;
    }
  }
  taskid=UINT64_MAX-(INT64_MAX-of->fileid);
  debug(D_NOTICE, "reopening static file %s for writing size %lu, taskid %lu", of->currentname, (unsigned long)of->currentsize, (unsigned long)taskid);
  cr=psync_fstask_add_creat(of->currentfolder, of->currentname, 0, NULL, 0);
  if (unlikely_log(!cr)){
    psync_sql_unlock();
    return -EIO;
  }
  psync_fs_update_openfile_fileid_locked(of, cr->fileid);
  psync_fs_static_to_task(taskid, cr->taskid);
  cr=psync_fstask_find_creat(of->currentfolder, of->currentname, taskid);
  if (likely_log(cr)){
    psync_tree_del(&of->currentfolder->creats, &cr->tree);
    of->currentfolder->taskscnt--;
    psync_free(cr);
  }
  un=psync_fstask_find_unlink(of->currentfolder, of->currentname, taskid);
  if (likely_log(un)){
    psync_tree_del(&of->currentfolder->unlinks, &un->tree);
    of->currentfolder->taskscnt--;
    psync_free(un);
  }
  psync_sql_unlock();
  of->writeid=0;
  of->newfile=1;
  of->modified=1;
  of->staticfile=0;
  ret=open_write_files(of, 1);
  if (unlikely_log(ret))
    return ret;
  if (psync_file_pwrite(of->datafile, of->staticdata, of->currentsize, 0)!=of->currentsize)
    ret=-PRINT_RETURN_CONST(EIO);
  else
    ret=1;
  return ret;
}

PSYNC_NOINLINE static int psync_fs_check_modified_file_write_space(psync_openfile_t *of, size_t size, fuse_off_t offset){
  uint64_t from, to;
  psync_interval_tree_t *tr;
  if (of->encrypted){
    from=psync_fs_crypto_data_sectorid_by_sectorid(offset/PSYNC_CRYPTO_SECTOR_SIZE)*PSYNC_CRYPTO_SECTOR_SIZE;
    to=psync_fs_crypto_data_sectorid_by_sectorid((offset+size)/PSYNC_CRYPTO_SECTOR_SIZE)*PSYNC_CRYPTO_SECTOR_SIZE+(offset+size)%PSYNC_CRYPTO_SECTOR_SIZE;
  }
  else{
    from=offset;
    to=offset+size;
  }
  tr=psync_interval_tree_first_interval_containing_or_after(of->writeintervals, from);
  if (tr && tr->from<=from && tr->to>=to)
    return 1;
  else
    return 0;
}

static void psync_fs_throttle(size_t size, uint64_t speed){
  static pthread_mutex_t throttle_mutex=PTHREAD_MUTEX_INITIALIZER;
  static uint64_t writtenthissec=0;
  static time_t thissec=0;
  time_t currsec;
  int cnt;
  assert(speed>0);
  cnt=0;
  while (++cnt<=PSYNC_FS_MAX_SHAPER_SLEEP_SEC){
    currsec=psync_timer_time();
    pthread_mutex_lock(&throttle_mutex);
    if (currsec!=thissec){
      thissec=currsec;
      writtenthissec=0;
    }
    if (writtenthissec<speed){
      if (writtenthissec+size>speed){
        size-=speed-writtenthissec;
        writtenthissec=speed;
      }
      else{
        writtenthissec+=size;
        pthread_mutex_unlock(&throttle_mutex);
        assert(size<=speed);
        psync_milisleep(size*1000/speed);
        return;
      }
    }
    pthread_mutex_unlock(&throttle_mutex);
    psync_timer_wait_next_sec();
  }
}

PSYNC_NOINLINE static int psync_fs_do_check_write_space(psync_openfile_t *of, size_t size){
  const char *cachepath;
  uint64_t minlocal, mult, speed;
  int64_t freespc;
  int freed;
  cachepath=psync_setting_get_string(_PS(fscachepath));
  minlocal=psync_setting_get_uint(_PS(minlocalfreespace));
  freespc=psync_get_free_space_by_path(cachepath);
  if (unlikely(freespc==-1)){
    debug(D_WARNING, "could not get free space of path %s", cachepath);
    return 1;
  }
//  debug(D_NOTICE, "free space of %s is %lld minlocal %llu", cachepath, freespc, minlocal);
  if (freespc>=minlocal+size){
    psync_set_local_full(0);
    of->throttle=0;
    return 1;
  }
  of->throttle=1;
  pthread_mutex_unlock(&of->mutex);
  debug(D_NOTICE, "free space is %lu, less than minimum %lu+%lu", (unsigned long)freespc, (unsigned long)minlocal, (unsigned long)size);
  psync_set_local_full(1);
  if ((freespc<=minlocal/2 || minlocal<=PSYNC_FS_PAGE_SIZE || freespc<=size)){
    if (psync_pagecache_free_from_read_cache(size*2)<size*2){
      debug(D_WARNING, "free space is %lu, less than half of minimum %lu+%lu, returning error", (unsigned long)freespc, (unsigned long)minlocal, (unsigned long)size);
      psync_milisleep(5000);
#if defined(P_OS_POSIX)
      return -EINTR;
#else
      return 0;
#endif
    }
    else{
      debug(D_NOTICE, "free space is %lu, less than half of minimum %lu+%lu, but we managed to free from read cache",
            (unsigned long)freespc, (unsigned long)minlocal, (unsigned long)size);
      freespc=minlocal/2+1;
      freed=1;
    }
  }
  else if (freespc<=minlocal/4*3){
    debug(D_NOTICE, "free space is %lu, less than 3/4 of minimum %lu+%lu, will try to free read cache pages",
          (unsigned long)freespc, (unsigned long)minlocal, (unsigned long)size);
    freed=psync_pagecache_free_from_read_cache(size)>=size;
  }
  else
    freed=0;
  if (psync_status.uploadspeed==0){
    if (freed || psync_pagecache_free_from_read_cache(size)>=size){
      debug(D_NOTICE, "there is no active upload and we managed to free from cache, not throttling write");
      psync_fs_lock_file(of);
      return 1;
    }
  }
  minlocal/=2;
  mult=(freespc-minlocal)*1023/minlocal+1;
  assert(mult>=1 && mult<=1024);
  speed=psync_status.uploadspeed*3/2;
  if (speed<PSYNC_FS_MIN_INITIAL_WRITE_SHAPER)
    speed=PSYNC_FS_MIN_INITIAL_WRITE_SHAPER;
  speed=speed*mult/1024;
  debug(D_NOTICE, "limiting write speed to %luKb (%lub)/sec, speed multiplier %lu", (unsigned long)speed/1024, (unsigned long)speed, (unsigned long)mult);
  psync_fs_throttle(size, speed);
  debug(D_NOTICE, "continuing write");
  psync_fs_lock_file(of);
  return 1;
}

static int psync_fs_check_write_space(psync_openfile_t *of, size_t size, fuse_off_t offset){
  if (!of->throttle && of->writeid%64!=0)
    return 1;
  if (of->currentsize>=offset+size){
//    if (of->newfile)
//      return 1;
    if (of->modified && psync_fs_check_modified_file_write_space(of, size, offset))
      return 1;
  }
  return psync_fs_do_check_write_space(of, size);
}

static int psync_fs_write_modified(psync_openfile_t *of, const char *buf, size_t size, fuse_off_t offset){
  psync_fs_index_record rec;
  uint64_t ioff;
  ssize_t bw;
  if (unlikely_log(psync_fs_modfile_check_size_ok(of, offset)))
    return -EIO;
  ioff=of->indexoff++;
  bw=psync_file_pwrite(of->datafile, buf, size, offset);
  if (unlikely_log(bw==-1))
    return -EIO;
  rec.offset=offset;
  rec.length=bw;
  if (unlikely_log(psync_file_pwrite(of->indexfile, &rec, sizeof(rec), sizeof(rec)*ioff+sizeof(psync_fs_index_header))!=sizeof(rec)))
    return -EIO;
  psync_interval_tree_add(&of->writeintervals, offset, offset+bw);
  if (of->currentsize<offset+size)
    of->currentsize=offset+size;
  return bw;
}

static int psync_fs_write_newfile(psync_openfile_t *of, const char *buf, size_t size, fuse_off_t offset){
  ssize_t bw;
  bw=psync_file_pwrite(of->datafile, buf, size, offset);
  if (of->currentsize<offset+size && bw!=-1)
    of->currentsize=offset+size;
  return bw;
}

static int psync_fs_write(const char *path, const char *buf, size_t size, fuse_off_t offset, struct fuse_file_info *fi){
  psync_openfile_t *of;
  int ret;
  psync_fs_set_thread_name();
//  debug(D_NOTICE, "write to %s of %lu at %lu", path, (unsigned long)size, (unsigned long)offset);
  of=fh_to_openfile(fi->fh);
  psync_fs_lock_file(of);
  ret=psync_fs_check_write_space(of, size, offset);
  if (unlikely_log(ret<=0))
    return ret;
  psync_fs_inc_writeid_locked(of);
retry:
  if (of->newfile){
    if (of->encrypted)
      return psync_fs_crypto_write_newfile_locked(of, buf, size, offset);
    else
      ret=psync_fs_write_newfile(of, buf, size, offset);
    pthread_mutex_unlock(&of->mutex);
    if (unlikely_log(ret==-1))
      return -EIO;
    else
      return ret;
  }
  else{
    if (unlikely(!of->modified)){
      ret=psync_fs_reopen_file_for_writing(of);
      if (ret==1)
        goto retry;
      else if (ret<0){
        pthread_mutex_unlock(&of->mutex);
        return ret;
      }
    }
    if (of->encrypted)
      return psync_fs_crypto_write_modified_locked(of, buf, size, offset);
    else{
      debug(D_NOTICE, "write of %lu bytes at offset %lu", (unsigned long)size, (unsigned long)offset);
      if (unlikely(of->staticfile)){
        ret=psync_fs_reopen_static_file_for_writing(of);
        if (ret==1)
          goto retry;
        else{
          pthread_mutex_unlock(&of->mutex);
          return ret;
        }
      }
      else
        ret=psync_fs_write_modified(of, buf, size, offset);
    }
    pthread_mutex_unlock(&of->mutex);
    return ret;
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
  else if (fpath->flags&(PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST|PSYNC_FOLDER_FLAG_BACKUP_DEVICE))
    ret=-EACCES;
  else if (fpath->flags&PSYNC_FOLDER_FLAG_ENCRYPTED && psync_crypto_isexpired())
    ret=-PSYNC_FS_ERR_CRYPTO_EXPIRED;
  else
    ret=psync_fstask_mkdir(fpath->folderid, fpath->name, fpath->flags);
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
    ret=psync_fstask_can_rmdir(fpath->folderid, fpath->flags, fpath->name);
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
    ret=psync_fstask_rmdir(fpath->folderid, fpath->flags,  fpath->name);
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

  if ((fpath->flags & PSYNC_FOLDER_FLAG_BACKUP) && ret == 0) {
    //Send async event to UI to notify the user that he is deleting a backedup file.
    debug(D_NOTICE, "Backedup file deleted in P drive. Send event. Flags: [%d]", fpath->flags);
    psync_run_thread1("psync_async_sync_delete", psync_async_ui_callback, PEVENT_BKUP_F_DEL_DRIVE);
  }

  psync_free(fpath);
  debug(D_NOTICE, "unlink %s=%d", path, ret);
  return ret;
}

static int psync_fs_rename_static_file(psync_fstask_folder_t *srcfolder, psync_fstask_creat_t *srccr, psync_fsfolderid_t to_folderid, const char *new_name){
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  psync_fstask_folder_t *dstfolder;
  size_t len, addlen;
  dstfolder=psync_fstask_get_or_create_folder_tasks_locked(to_folderid);
  cr=psync_fstask_find_creat(dstfolder, new_name, 0);
  if (unlikely(cr)){
    debug(D_NOTICE, "renaming over creat of file %s in folderid %ld", new_name, (long)to_folderid);
    un=psync_fstask_find_unlink(dstfolder, new_name, cr->taskid);
    if (un){
      psync_tree_del(&dstfolder->unlinks, &un->tree);
      psync_free(un);
      dstfolder->taskscnt--;
    }
    psync_tree_del(&dstfolder->creats, &cr->tree);
    psync_free(cr);
    dstfolder->taskscnt--;
  }
  len=strlen(new_name)+1;
  un=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  un->fileid=0;
  un->taskid=srccr->taskid;
  memcpy(un->name, new_name, len);
  psync_fstask_inject_unlink(dstfolder, un);
  addlen=psync_fstask_creat_local_offset(len-1);
  cr=(psync_fstask_creat_t *)psync_malloc(addlen+sizeof(psync_fstask_local_creat_t));
  cr->fileid=0;
  cr->rfileid=0;
  cr->taskid=srccr->taskid;
  memcpy(cr->name, new_name, len);
  memcpy(((char *)cr)+addlen, psync_fstask_creat_get_local(srccr), sizeof(psync_fstask_local_creat_t));
  psync_fstask_inject_creat(dstfolder, cr);
  psync_fstask_release_folder_tasks_locked(dstfolder);
  un=psync_fstask_find_unlink(srcfolder, srccr->name, srccr->taskid);
  if (likely_log(un)){
    psync_tree_del(&srcfolder->unlinks, &un->tree);
    psync_free(un);
    srcfolder->taskscnt--;
  }
  psync_tree_del(&srcfolder->creats, &srccr->tree);
  psync_free(srccr);
  srcfolder->taskscnt--;
  return 0;
}

static int psync_fs_can_move(psync_fsfolderid_t fromfolderid, uint32_t frompermissions, psync_fsfolderid_t tofolderid, uint32_t topermissions, int sameshare){
  if (fromfolderid==tofolderid)
    return (frompermissions&PSYNC_PERM_MODIFY)==PSYNC_PERM_MODIFY;
  if ((frompermissions&PSYNC_PERM_ALL)==PSYNC_PERM_ALL && (topermissions&PSYNC_PERM_ALL)==PSYNC_PERM_ALL)
    return 1;
  if ((frompermissions&(PSYNC_PERM_DELETE|PSYNC_PERM_MODIFY))==0 || (topermissions&(PSYNC_PERM_CREATE|PSYNC_PERM_MODIFY))==0)
    return 0;
  if (sameshare)
    return (frompermissions&PSYNC_PERM_MODIFY)!=0;
  else
    return (frompermissions&PSYNC_PERM_DELETE) && (topermissions&PSYNC_PERM_CREATE);
}

static int psync_fs_rename_folder(psync_fsfolderid_t folderid, psync_fsfolderid_t parentfolderid, const char *name, uint32_t srcpermissions,
                                  psync_fsfolderid_t to_folderid, const char *new_name, uint32_t targetperms, uint32_t targetflags, int sameshare){
  if (!psync_fs_can_move(folderid, srcpermissions, to_folderid, targetperms, sameshare))
    return -EACCES;
  return psync_fstask_rename_folder(folderid, parentfolderid, name, to_folderid, new_name, targetflags);
}

static int psync_fs_rename_file(psync_fsfileid_t fileid, psync_fsfolderid_t parentfolderid, const char *name, uint32_t srcpermissions,
                                  psync_fsfolderid_t to_folderid, const char *new_name, uint32_t targetperms, int sameshare){
  if (!psync_fs_can_move(parentfolderid, srcpermissions, to_folderid, targetperms, sameshare))
    return -EACCES;
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

static int psync_fs_is_nonempty_folder(psync_fsfolderid_t parent_folderid, const char *name){
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  int ret;

  folder=psync_fstask_get_folder_tasks_locked(parent_folderid);

  if (folder){
    if ((mk = psync_fstask_find_mkdir(folder, name, 0))) {
      ret = psync_fs_is_folder_nonempty(mk->folderid) + 1;
    }
    else if (psync_fstask_find_rmdir(folder, name, 0)) {
      ret = 1;
    }
    else {
      ret = 0;
    }

    psync_fstask_release_folder_tasks_locked(folder);

    if (ret)
      return ret-1;
  }

  res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, parent_folderid);
  psync_sql_bind_string(res, 2, name);
  
  if ((row = psync_sql_fetch_rowint(res))) {
    ret = psync_fs_is_folder_nonempty(row[0]);
  }
  else{
    ret=0;
  }

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
  uint64_t flags;

  psync_fsfolderid_t new_fid, old_fid;

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
    ret=-PSYNC_FS_ERR_MOVE_ACROSS_CRYPTO;
    goto finish;
  }
  
  if (fold_path->folderid!=fnew_path->folderid && ((fold_path->flags|fnew_path->flags)&(PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST|PSYNC_FOLDER_FLAG_BACKUP_DEVICE))){
    ret=-EACCES;
    goto finish;
  }
  
  folder=psync_fstask_get_folder_tasks_locked(fold_path->folderid);

  new_fid = psync_get_folderid(fnew_path->folderid, fnew_path->name);
  old_fid = psync_get_folderid(fold_path->folderid, fold_path->name);

  if (folder){
    if ((mkdir=psync_fstask_find_mkdir(folder, fold_path->name, 0))){
      if (psync_fs_is_file(fnew_path->folderid, fnew_path->name)){
        ret=-ENOTDIR;
      }
      else if (psync_fs_is_nonempty_folder(fnew_path->folderid, fnew_path->name) && (new_fid != old_fid)) {
        ret = -ENOTEMPTY;
      }
      else {
        ret = psync_fs_rename_folder(mkdir->folderid, fold_path->folderid, fold_path->name, fold_path->permissions,
          fnew_path->folderid, fnew_path->name, fnew_path->permissions, fnew_path->flags, fold_path->shareid == fnew_path->shareid);
      }

      goto finish;
    }
    else if ((creat=psync_fstask_find_creat(folder, fold_path->name, 0))){
      if (psync_fs_is_folder(fnew_path->folderid, fnew_path->name))
        ret=-EISDIR;
      else if (unlikely(creat->fileid==0))
        ret=psync_fs_rename_static_file(folder, creat, fnew_path->folderid, fnew_path->name);
      else
        ret=psync_fs_rename_file(creat->fileid, fold_path->folderid, fold_path->name, fold_path->permissions,
                                 fnew_path->folderid, fnew_path->name, fnew_path->permissions, fold_path->shareid==fnew_path->shareid);
      goto finish;
    }
  }

  if (!folder || !psync_fstask_find_rmdir(folder, fold_path->name, 0)){
    res=psync_sql_query("SELECT id, flags FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fold_path->folderid);
    psync_sql_bind_string(res, 2, fold_path->name);

    if ((row=psync_sql_fetch_rowint(res))){
      fid=row[0];
      flags=row[1];
      psync_sql_free_result(res);

      if (fold_path->folderid!=fnew_path->folderid && (flags&(PSYNC_FOLDER_FLAG_PUBLIC_ROOT|PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST|PSYNC_FOLDER_FLAG_BACKUP_DEVICE|PSYNC_FOLDER_FLAG_BACKUP_ROOT)))
        ret=-EPERM;
      else if (psync_fs_is_file(fnew_path->folderid, fnew_path->name))
        ret=-ENOTDIR;
      else if (psync_fs_is_nonempty_folder(fnew_path->folderid, fnew_path->name) && (new_fid != old_fid)){
        ret=-ENOTEMPTY;
      }
      else
        ret=psync_fs_rename_folder(fid, fold_path->folderid, fold_path->name, fold_path->permissions,
                                   fnew_path->folderid, fnew_path->name, fnew_path->permissions, fnew_path->flags, fold_path->shareid==fnew_path->shareid);
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
        ret=psync_fs_rename_file(fid, fold_path->folderid, fold_path->name, fold_path->permissions,
                                 fnew_path->folderid, fnew_path->name, fnew_path->permissions, fold_path->shareid==fnew_path->shareid);
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
  return PRINT_RETURN_FORMAT(ret, " for rename from %s to %s", old_path, new_path);
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

static int psync_fs_set_filetime_locked(psync_fsfileid_t fileid, const struct timespec *tv, int crtime, uint64_t current){
  if (fileid>0)
    return psync_fstask_set_mtime(fileid, current, tv->tv_sec, crtime);
  else{
    char fileidhex[sizeof(psync_fsfileid_t)*2+2], *filename;
    const char *cachepath;
    psync_tree *tr;
    psync_openfile_t *fl;
    int64_t d;
    int ret;
    tr=openfiles;
    fl=NULL;
    while (tr){
      d=fileid-psync_tree_element(tr, psync_openfile_t, tree)->fileid;
      if (d<0)
        tr=tr->left;
      else if (d>0)
        tr=tr->right;
      else{
        fl=psync_tree_element(tr, psync_openfile_t, tree);
        break;
      }
    }
    fileid=-fileid;
    psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
    fileidhex[sizeof(psync_fsfileid_t)]='d';
    fileidhex[sizeof(psync_fsfileid_t)+1]=0;
    cachepath=psync_setting_get_string(_PS(fscachepath));
    filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    if (fl && fl->datafile!=INVALID_HANDLE_VALUE){
      debug(D_NOTICE, "found open file for file id %ld", (long)fl->fileid);
      if (crtime)
        ret=psync_set_crtime_mtime_by_fd(fl->datafile, filename, tv->tv_sec, 0);
      else
        ret=psync_set_crtime_mtime_by_fd(fl->datafile, filename, 0, tv->tv_sec);
    }
    else{
      if (crtime)
        ret=psync_set_crtime_mtime(filename, tv->tv_sec, 0);
      else
        ret=psync_set_crtime_mtime(filename, 0, tv->tv_sec);
    }
    debug(D_NOTICE, "setting %s time of %s to %lu=%d", crtime?"creation":"modification", filename, (unsigned long)tv->tv_sec, ret);
    psync_free(filename);
    return ret?-EACCES:0;
  }
}

static int psync_fs_set_foldertime_locked(psync_fsfolderid_t folderid, const struct timespec *tv, int crtime, uint64_t current){
  debug(D_NOTICE, "request to set time of folderid %ld ignored", (long)folderid);
  return 0;
}

static int psync_fs_set_time_locked(psync_fsfolderid_t folderid, const char *name, const struct timespec *tv, int crtime){
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *creat;
  psync_fstask_mkdir_t *mkdir;
  psync_fstask_unlink_t *un;
  psync_fstask_rmdir_t *rm;
  psync_sql_res *res;
  psync_uint_row row;
  folder=psync_fstask_get_folder_tasks_rdlocked(folderid);
  if (folder){
    if ((creat=psync_fstask_find_creat(folder, name, 0))){
      if (creat->fileid>0){
        res=psync_sql_query_nolock("SELECT mtime, ctime FROM file WHERE id=?");
        psync_sql_bind_uint(res, 1, creat->fileid);
        if ((row=psync_sql_fetch_rowint(res))){
          uint64_t ctm=row[crtime];
          psync_sql_free_result(res);
          return psync_fs_set_filetime_locked(creat->fileid, tv, crtime, ctm);
        }
        else{
          psync_sql_free_result(res);
          debug(D_WARNING, "found creat in folderid %lu for %s with fileid %lu not present in the database",
                (unsigned long)folderid, name, (unsigned long)creat->fileid);
          return -ENOENT;
        }
      }
      else
        return psync_fs_set_filetime_locked(creat->fileid, tv, crtime, 0);
    }
    if ((mkdir=psync_fstask_find_mkdir(folder, name, 0)))
      return psync_fs_set_foldertime_locked(mkdir->folderid, tv, crtime, 0);
    un=psync_fstask_find_unlink(folder, name, 0);
    rm=psync_fstask_find_rmdir(folder, name, 0);
  }
  else{
    un=NULL;
    rm=NULL;
  }
  if (!un && folderid>=0){
    res=psync_sql_query_nolock("SELECT id, mtime, ctime FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_string(res, 2, name);
    if ((row=psync_sql_fetch_rowint(res))){
      uint64_t fileid=row[0];
      uint64_t ctm=row[1+crtime];
      psync_sql_free_result(res);
      return psync_fs_set_filetime_locked(fileid, tv, crtime, ctm);
    }
    psync_sql_free_result(res);
  }
  if (!rm && folderid>=0){
    res=psync_sql_query_nolock("SELECT id, permissions, mtime, ctime FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_string(res, 2, name);
    if ((row=psync_sql_fetch_rowint(res))){
      uint64_t folderid=row[0];
      uint64_t permissions=row[1];
      uint64_t ctm=row[2+crtime];
      psync_sql_free_result(res);
      if (!(permissions&PSYNC_PERM_MODIFY))
        return -EACCES;
      return psync_fs_set_foldertime_locked(folderid, tv, crtime, ctm);
    }
    psync_sql_free_result(res);
  }
  return -ENOENT;
}

static int psync_fs_set_time(const char *path, const struct timespec *tv, int crtime){
  psync_fspath_t *fpath;
  int ret;
  psync_sql_lock();
  CHECK_LOGIN_LOCKED();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath)
    ret=-ENOENT;
  else if (!(fpath->permissions&PSYNC_PERM_MODIFY))
    ret=-EACCES;
  else
    ret=psync_fs_set_time_locked(fpath->folderid, fpath->name, tv, crtime);
  psync_sql_unlock();
  psync_free(fpath);
  return ret;
}

#if defined(FUSE_HAS_SETCRTIME)
static int psync_fs_setcrtime(const char *path, const struct timespec *tv){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "setcrtime %s %lu", path, tv->tv_sec);
  return psync_fs_set_time(path, tv, 1);
}
#endif

static int psync_fs_utimens(const char *path, const struct timespec tv[2]){
  psync_fs_set_thread_name();
  debug(D_NOTICE, "utimens %s %lu", path, tv[1].tv_sec);
  return psync_fs_set_time(path, &tv[1], 0);
}

static int psync_fs_ftruncate_of_locked(psync_openfile_t *of, fuse_off_t size){
  int ret;
  if (of->currentsize==size){
    debug(D_NOTICE, "not truncating as size is already %lu", (long unsigned)size);
    return 0;
  }
  psync_fs_inc_writeid_locked(of);
retry:
  if (unlikely(!of->newfile && !of->modified)){
    ret=psync_fs_reopen_file_for_writing(of);
    if (ret==1)
      goto retry;
    else if (ret<0)
      return ret;
  }
  if (of->encrypted)
    return psync_fs_crypto_ftruncate(of, size);
  else{
    if (psync_fs_modfile_check_size_ok(of, size))
      ret=-PRINT_RETURN_CONST(EIO);
    else if (of->currentsize!=size && (psync_file_seek(of->datafile, size, P_SEEK_SET)==-1 || psync_file_truncate(of->datafile)))
      ret=-PRINT_RETURN_CONST(EIO);
    else{
      ret=0;
      of->currentsize=size;
    }
  }
  return ret;
}

static int psync_fs_ftruncate(const char *path, fuse_off_t size, struct fuse_file_info *fi){
  psync_openfile_t *of;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "ftruncate %s %lu", path, (unsigned long)size);
  of=fh_to_openfile(fi->fh);
  psync_fs_lock_file(of);
  ret=psync_fs_ftruncate_of_locked(of, size);
  pthread_mutex_unlock(&of->mutex);
  return PRINT_RETURN_FORMAT(ret, " for ftruncate of %s to %lu", path, (unsigned long)size);
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

static void psync_fs_start_callback_timer(psync_timer_t timer, void *ptr){
  psync_generic_callback_t callback;
  psync_timer_stop(timer);
  callback=psync_start_callback;
  if (callback)
    psync_run_thread("fs start callback", callback);
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
  conn->max_readahead=1024*1024;
#if !defined(P_OS_LINUX)
  conn->max_write=FS_MAX_WRITE;
#endif
  if (psync_start_callback)
    psync_timer_register(psync_fs_start_callback_timer, 1, NULL);
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
    if (fd!=INVALID_HANDLE_VALUE){
      psync_file_close(fd);
      psync_file_delete(fpath);
    }
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

void psync_fs_register_start_callback(psync_generic_callback_t callback){
  psync_start_callback=callback;
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

#if IS_DEBUG

static void psync_fs_dump_internals() {
  psync_openfile_t *of;
  debug(D_NOTICE, "dumping internal state");
  psync_sql_rdlock();
  psync_tree_for_each_element(of, openfiles, psync_openfile_t, tree)
    debug(D_NOTICE, "open file %s fileid %ld folderid %ld", of->currentname, (long)of->fileid, (long)of->currentfolder->folderid);
  psync_fstask_dump_state();
  psync_sql_rdunlock();
}

#endif

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

#if defined(P_OS_LINUX)
	char *mp;
	mp = psync_fuse_get_mountpoint();
	fuse_unmount(mp, psync_fuse_channel);
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
#if IS_DEBUG
    psync_fs_dump_internals();
#endif
  }
  pthread_mutex_unlock(&start_mutex);
}

void psync_fs_stop(){
  psync_fs_do_stop();
}

#if defined(P_OS_POSIX)

static void psync_signal_handler(int sig){
  debug(D_NOTICE, "got signal %d", sig);
  psync_fs_do_stop();
  exit(1);
}

#if IS_DEBUG
static void psync_usr1_handler(int sig){
//  debug(D_NOTICE, "got signal %d", sig);
  psync_run_thread("dump signal", psync_fs_dump_internals);
}
#endif

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
#if IS_DEBUG
  psync_set_signal(SIGUSR1, psync_usr1_handler);
#endif
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
  psync_fsstatic_add_files();
  psync_fstask_add_banned_folders();
}

static void psync_fuse_thread(){
  int fr;
  pthread_mutex_lock(&start_mutex);
  if (!initonce){
    psync_fs_init_once();
    initonce=1;
  }
  pthread_mutex_unlock(&start_mutex);
  debug(D_NOTICE, "running fuse_loop_mt");
  fr=fuse_loop_mt(psync_fuse);
  debug(D_NOTICE, "fuse_loop_mt exited with code %d, running fuse_destroy", fr);
  pthread_mutex_lock(&start_mutex);
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

// Returns true if FUSE 3 is installed on the user's machine.
// Returns false if FUSE version is less than 3.
static char is_fuse3_installed_on_system()
{
  // Assuming that fusermount3 is only available on FUSE 3.
  FILE* pipe = popen("which fusermount3", "r");

  if (!pipe) {
    return 0;
  }

  char output[1024];
  memset(output, 0, sizeof(output));

  char* o = fgets(output, sizeof(output), pipe);

  pclose(pipe);
  size_t outlen = strlen(output);

  return outlen > 0;
}


static int psync_fs_do_start(){
  char *mp;
  struct fuse_operations psync_oper;
  struct fuse_args args=FUSE_ARGS_INIT(0, NULL);

// it seems that fuse option parser ignores the first argument
// it is ignored as it's like in the exec() parameters, argv[0] is the program

#if defined(P_OS_LINUX)
  fuse_opt_add_arg(&args, "argv");
  fuse_opt_add_arg(&args, "-oauto_unmount");
//  fuse_opt_add_arg(&args, "-ouse_ino");
  fuse_opt_add_arg(&args, "-ofsname="DEFAULT_FUSE_MOUNT_POINT".fs");
  if (!is_fuse3_installed_on_system()) {
    fuse_opt_add_arg(&args, "-ononempty");
  }
  fuse_opt_add_arg(&args, "-ohard_remove");
//  fuse_opt_add_arg(&args, "-d");
#endif

#if defined(P_OS_MACOSX)
  fuse_opt_add_arg(&args, "argv");
  fuse_opt_add_arg(&args, "-ovolname="DEFAULT_FUSE_VOLUME_NAME);
  fuse_opt_add_arg(&args, "-ofsname="DEFAULT_FUSE_MOUNT_POINT".fs");
  //fuse_opt_add_arg(&args, "-olocal");
  if (psync_user_is_admin())
    fuse_opt_add_arg(&args, "-oallow_root");
  fuse_opt_add_arg(&args, "-onolocalcaches");
  fuse_opt_add_arg(&args, "-ohard_remove");
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

#if defined(FUSE_HAS_SETCRTIME)
  psync_oper.setcrtime=psync_fs_setcrtime;
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

void psync_fs_clean_tasks(){
  psync_fstask_clean();
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
