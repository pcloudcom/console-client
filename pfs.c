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
#include "pfsfolder.h"
#include "pcompat.h"
#include "plibs.h"
#include "psettings.h"
#include "pfsfolder.h"
#include "pcache.h"
#include "ppagecache.h"
#include "ptimer.h"
#include "pfstasks.h"

#if defined(P_OS_POSIX)
#include <signal.h>
#endif

#define fh_to_openfile(x) ((psync_openfile_t *)((uintptr_t)x))
#define openfile_to_fh(x) ((uintptr_t)x)

#define FS_BLOCK_SIZE 4096
#define FS_MAX_WRITE  256*1024

typedef struct {
  uint64_t offset;
  uint64_t length;
} index_record;

typedef struct {
  uint64_t copyfromoriginal;
} index_header;

static struct fuse_chan *psync_fuse_channel=0;
static struct fuse *psync_fuse=0;
static char *psync_current_mountpoint=0;

static pthread_mutex_t start_mutex=PTHREAD_MUTEX_INITIALIZER;
static int started=0;
static int initonce=0;

static uid_t myuid=0;
static gid_t mygid=0;

static psync_tree *openfiles=PSYNC_TREE_EMPTY;
static pthread_mutex_t openfiles_mutex=PTHREAD_MUTEX_INITIALIZER;

static void psync_row_to_folder_stat(psync_variant_row row, struct stat *stbuf){
  memset(stbuf, 0, sizeof(struct stat));
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=psync_get_number(row[2]);
  stbuf->st_ctime=psync_get_number(row[3]);
  stbuf->st_mtime=stbuf->st_ctime;
#else
  stbuf->st_ctime=psync_get_number(row[2]);
  stbuf->st_mtime=psync_get_number(row[3]);
#endif
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

static void psync_row_to_file_stat(psync_variant_row row, struct stat *stbuf){
  uint64_t size;
  size=psync_get_number(row[1]);
  memset(stbuf, 0, sizeof(struct stat));
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=psync_get_number(row[2]);
  stbuf->st_ctime=psync_get_number(row[3]);
  stbuf->st_mtime=stbuf->st_ctime;
#else
  stbuf->st_ctime=psync_get_number(row[2]);
  stbuf->st_mtime=psync_get_number(row[3]);
#endif
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

static void psync_mkdir_to_folder_stat(psync_fstask_mkdir_t *mk, struct stat *stbuf){
  memset(stbuf, 0, sizeof(struct stat));
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=mk->ctime;
  stbuf->st_ctime=mk->mtime;
  stbuf->st_mtime=mk->mtime;
#else
  stbuf->st_ctime=mk->ctime;
  stbuf->st_mtime=mk->mtime;
#endif
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

static int psync_creat_db_to_file_stat(psync_fileid_t fileid, struct stat *stbuf){
  psync_sql_res *res;
  psync_variant_row row;
  res=psync_sql_query("SELECT name, size, ctime, mtime FROM file WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  if ((row=psync_sql_fetch_row(res)))
    psync_row_to_file_stat(row, stbuf);
  psync_sql_free_result(res);
  return row?0:-1;
}

static int psync_creat_local_to_file_stat(psync_fstask_creat_t *cr, struct stat *stbuf){
  psync_stat_t st;
  psync_fsfileid_t fileid;
  uint64_t size, osize;
  const char *cachepath;
  char *filename;
  psync_file_t fd;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  int stret;
  fileid=cr->taskid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)]='d';
  fileidhex[sizeof(psync_fsfileid_t)+1]=0;
  cachepath=psync_setting_get_string(_PS(fscachepath));
  filename=psync_strcat(cachepath, PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
  stret=psync_stat(filename, &st);
  psync_free(filename);
  if (stret)
    return -1;
  if (cr->newfile)
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
  }
  memset(stbuf, 0, sizeof(struct stat));
#ifdef _DARWIN_FEATURE_64_BIT_INODE
  stbuf->st_birthtime=st->st_birthtime;
  stbuf->st_ctime=st->st_ctime;
  stbuf->st_mtime=st->st_mtime;
#else
  stbuf->st_ctime=psync_stat_ctime(&st);
  stbuf->st_mtime=psync_stat_mtime(&st);
#endif
  stbuf->st_mode=S_IFREG | 0644;
  stbuf->st_nlink=1;
  size=psync_stat_size(&st);
  if (osize>size)
    size=osize;
  stbuf->st_size=size;
#if defined(P_OS_POSIX)
  stbuf->st_blocks=(stbuf->st_size+511)/512;
  stbuf->st_blksize=FS_BLOCK_SIZE;
#endif
  stbuf->st_uid=myuid;
  stbuf->st_gid=mygid;
  return 0;
}

static int psync_creat_to_file_stat(psync_fstask_creat_t *cr, struct stat *stbuf){
  if (cr->fileid>=0)
    return psync_creat_db_to_file_stat(cr->fileid, stbuf);
  else
    return psync_creat_local_to_file_stat(cr, stbuf);
}

static int psync_fs_getrootattr(struct stat *stbuf){
  psync_sql_res *res;
  psync_variant_row row;
  res=psync_sql_query("SELECT 0, 0, 0, 0, subdircnt FROM folder WHERE id=0");
  if ((row=psync_sql_fetch_row(res)))
    psync_row_to_folder_stat(row, stbuf);
  psync_sql_free_result(res);
  return 0;
}

static int psync_fs_getattr(const char *path, struct stat *stbuf){
  psync_sql_res *res;
  psync_variant_row row;
  psync_fspath_t *fpath;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  int crr;
//  debug(D_NOTICE, "getattr %s", path);
  if (path[0]=='/' && path[1]==0)
    return psync_fs_getrootattr(stbuf);
  psync_sql_lock();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    psync_sql_unlock();
    return -ENOENT;
  }
  folder=psync_fstask_get_folder_tasks_locked(fpath->folderid);
  if (!folder || !psync_fstask_find_rmdir(folder, fpath->name)){
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
    mk=psync_fstask_find_mkdir(folder, fpath->name);
    if (mk){
      psync_mkdir_to_folder_stat(mk, stbuf);
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      return 0;
    }
  }
  res=psync_sql_query("SELECT name, size, ctime, mtime FROM file WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, fpath->folderid);
  psync_sql_bind_string(res, 2, fpath->name);
  if ((row=psync_sql_fetch_row(res)))
    psync_row_to_file_stat(row, stbuf);
  psync_sql_free_result(res);
  if (folder){
    if (psync_fstask_find_unlink(folder, fpath->name))
      row=NULL;
    if (!row && (cr=psync_fstask_find_creat(folder, fpath->name)))
      crr=psync_creat_to_file_stat(cr, stbuf);
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

static int psync_fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi){
  psync_sql_res *res;
  psync_variant_row row;
  psync_fsfolderid_t folderid;
  psync_fstask_folder_t *folder;
  psync_tree *trel;
  const char *name;
  struct stat st;
  debug(D_NOTICE, "readdir %s", path);
  psync_sql_lock();
  folderid=psync_fsfolderid_by_path(path);
  if (unlikely_log(folderid==PSYNC_INVALID_FSFOLDERID)){
    psync_sql_unlock();
    return -ENOENT;
  }
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folderid>=0){
    res=psync_sql_query("SELECT name, permissions, ctime, mtime, subdircnt FROM folder WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, folderid);
    while ((row=psync_sql_fetch_row(res))){
      name=psync_get_string(row[0]);
      if (folder && (psync_fstask_find_rmdir(folder, name) || psync_fstask_find_mkdir(folder, name)))
        continue;
      psync_row_to_folder_stat(row, &st);
      filler(buf, name, &st, 0);
    }
    psync_sql_free_result(res);
    res=psync_sql_query("SELECT name, size, ctime, mtime FROM file WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, folderid);
    while ((row=psync_sql_fetch_row(res))){
      name=psync_get_string(row[0]);
      if (folder && psync_fstask_find_unlink(folder, name))
        continue;
      psync_row_to_file_stat(row, &st);
      filler(buf, name, &st, 0);
    }
    psync_sql_free_result(res);
  }
  if (folder){
    psync_tree_for_each(trel, folder->mkdirs){
      psync_mkdir_to_folder_stat(psync_tree_element(trel, psync_fstask_mkdir_t, tree), &st);
      filler(buf, psync_tree_element(trel, psync_fstask_mkdir_t, tree)->name, &st, 0);
    }
    psync_tree_for_each(trel, folder->creats){
      if (!psync_creat_to_file_stat(psync_tree_element(trel, psync_fstask_creat_t, tree), &st))
        filler(buf, psync_tree_element(trel, psync_fstask_creat_t, tree)->name, &st, 0);
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
  psync_sql_unlock();
  return 0;
}

static psync_openfile_t *psync_fs_create_file(psync_fsfileid_t fileid, uint64_t size, uint64_t hash, int lock){
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  pthread_mutex_lock(&openfiles_mutex);
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
      psync_fs_inc_of_refcnt(fl);
      if (lock)
        pthread_mutex_lock(&fl->mutex);
      pthread_mutex_unlock(&openfiles_mutex);
      debug(D_NOTICE, "found open file %ld", (long int)fileid);
      return fl;
    }
  }
  fl=psync_new(psync_openfile_t);
  if (d<0)
    psync_tree_add_before(&openfiles, tr, &fl->tree);
  else
    psync_tree_add_after(&openfiles, tr, &fl->tree);
  fl->urls=NULL;
  fl->writeintervals=NULL;
  fl->fileid=fileid;
  fl->hash=hash;
  fl->initialsize=size;
  fl->currentsize=size;
  fl->laststreamid=0;
  fl->datafile=INVALID_HANDLE_VALUE;
  fl->indexfile=INVALID_HANDLE_VALUE;
  fl->refcnt=1;
  fl->condwaiters=0;
  fl->runningreads=0;
  fl->modified=fileid<0?1:0;
  fl->urlsstatus=0;
  fl->newfile=0;
  memset(fl->streams, 0, sizeof(fl->streams));
  pthread_mutex_init(&fl->mutex, NULL);
  pthread_cond_init(&fl->cond, NULL);
  if (lock)
    pthread_mutex_lock(&fl->mutex);
  pthread_mutex_unlock(&openfiles_mutex);
  return fl;
}

static int open_write_files(psync_openfile_t *of, int trunc){
  psync_fsfileid_t fileid;
  char *filename;
  char fileidhex[sizeof(psync_fsfileid_t)*2+2];
  fileid=-of->fileid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)]='d';
  fileidhex[sizeof(psync_fsfileid_t)+1]=0;
  if (of->datafile==INVALID_HANDLE_VALUE){
    filename=psync_strcat(psync_setting_get_string(_PS(fscachepath)), PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    of->datafile=psync_file_open(filename, P_O_RDWR, P_O_CREAT|(trunc?P_O_TRUNC:0));
    psync_free(filename);
    if (of->datafile==INVALID_HANDLE_VALUE){
      debug(D_ERROR, "could not open cache file %s", filename);
      return -EIO;
    }
  }
  if (!of->newfile && of->indexfile==INVALID_HANDLE_VALUE){
    fileidhex[sizeof(psync_fsfileid_t)]='i';
    filename=psync_strcat(psync_setting_get_string(_PS(fscachepath)), PSYNC_DIRECTORY_SEPARATOR, fileidhex, NULL);
    of->indexfile=psync_file_open(filename, P_O_RDWR, P_O_CREAT|(trunc?P_O_TRUNC:0));
    psync_free(filename);
    if (of->indexfile==INVALID_HANDLE_VALUE){
      debug(D_ERROR, "could not open cache file %s", filename);
      return -EIO;
    }
  }
  return 0;
}

static int psync_fs_open(const char *path, struct fuse_file_info *fi){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fileid_t fileid;
  uint64_t size, hash;
  psync_fspath_t *fpath;
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  psync_openfile_t *of;
  debug(D_NOTICE, "open %s", path);
  psync_sql_lock();
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
  folder=psync_fstask_get_folder_tasks_locked(fpath->folderid);
  if (fpath->folderid>=0){ // TODO: when there are unlinks, change to if !find_unlink
    res=psync_sql_query("SELECT id, size, hash FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fpath->folderid);
    psync_sql_bind_string(res, 2, fpath->name);
    row=psync_sql_fetch_rowint(res);
    if (row){
      fileid=row[0];
      size=row[1];
      hash=row[2];
    }
    psync_sql_free_result(res);
  }
  else
    row=NULL;
  if (!row && folder && (cr=psync_fstask_find_creat(folder, fpath->name))){
    if (cr->fileid>=0){
      res=psync_sql_query("SELECT id, size, hash FROM file WHERE id=?");
      psync_sql_bind_uint(res, 1, cr->fileid);
      row=psync_sql_fetch_rowint(res);
      if (row){
        fileid=row[0];
        size=row[1];
        hash=row[2];
      }
      psync_sql_free_result(res);
    }
    else if (cr->newfile){
      int ret;
      fileid=cr->fileid;
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      of=psync_fs_create_file(fileid, 0, 0, 1);
      of->newfile=1;
      ret=open_write_files(of, fi->flags&O_TRUNC);
      pthread_mutex_unlock(&of->mutex);
      fi->fh=openfile_to_fh(of);
      if (ret){
        psync_fs_dec_of_refcnt(of);
        return ret;
      }
      else
        return ret;
    }
    else{
      fileid=cr->fileid;
      psync_fstask_release_folder_tasks_locked(folder);
      psync_sql_unlock();
      psync_free(fpath);
      return -ENOSYS;
    }
  }
  if (folder)
    psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
  psync_free(fpath);
  if (row){
    of=psync_fs_create_file(fileid, size, hash, 0);
    fi->fh=openfile_to_fh(of);
    return 0;
  }
  else
    return -ENOENT;
}

static int psync_fs_creat(const char *path, mode_t mode, struct fuse_file_info *fi){
  psync_fspath_t *fpath;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_openfile_t *of;
  int ret;
  debug(D_NOTICE, "creat %s", path);
  psync_sql_lock();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
    psync_sql_unlock();
    return -ENOENT;
  }
  if (!(fpath->permissions&PSYNC_PERM_CREATE)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  folder=psync_fstask_get_or_create_folder_tasks_locked(fpath->folderid);
  //TODO: check if file exists
  cr=psync_fstask_add_creat(folder, fpath->name);
  of=psync_fs_create_file(cr->fileid, 0, 0, 1);
  psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
  of->newfile=1;
  of->modified=1;
  ret=open_write_files(of, 1);
  pthread_mutex_unlock(&of->mutex);
  if (unlikely_log(ret)){
    psync_sql_lock();
    folder=psync_fstask_get_or_create_folder_tasks_locked(fpath->folderid);
    if (folder){
      if ((cr=psync_fstask_find_creat(folder, fpath->name))){
        psync_tree_del(&folder->creats, &cr->tree);
        psync_free(cr);
      }
      psync_fstask_release_folder_tasks_locked(folder);
    }
    psync_sql_unlock();
    psync_fs_dec_of_refcnt(of);
    psync_free(fpath);
    return ret;
  }
  psync_free(fpath);
  fi->fh=openfile_to_fh(of);
  return 0;
}

void psync_fs_inc_of_refcnt(psync_openfile_t *of){
  pthread_mutex_lock(&of->mutex);
  of->refcnt++;
  pthread_mutex_unlock(&of->mutex);
}

static void psync_fs_free_openfile(psync_openfile_t *of){
  debug(D_NOTICE, "releasing file");
  if (of->urls){
    time_t ctime, etime;
    ctime=psync_timer_time();
    etime=psync_find_result(of->urls, "expires", PARAM_NUM)->num;
    if (etime>ctime+3600){
      char buff[64];
      sprintf(buff, "urls-%"PRIu64, of->hash);
      debug(D_NOTICE, "freeing urls of %lu to cache", (unsigned long)of->hash);
      psync_cache_add(buff, of->urls, etime-ctime-3600, psync_free, 2);
    }
    else
      psync_free(of->urls);
  }
  if (of->datafile!=INVALID_HANDLE_VALUE)
    psync_file_close(of->datafile);
  if (of->indexfile!=INVALID_HANDLE_VALUE)
    psync_file_close(of->indexfile);
  if (of->writeintervals)
    psync_interval_tree_free(of->writeintervals);
  psync_free(of);
}

void psync_fs_dec_of_refcnt(psync_openfile_t *of){
  pthread_mutex_lock(&openfiles_mutex);
  pthread_mutex_lock(&of->mutex);
  if (--of->refcnt==0)
    psync_tree_del(&openfiles, &of->tree);
  pthread_mutex_unlock(&of->mutex);
  pthread_mutex_unlock(&openfiles_mutex);
  if (!of->refcnt)
    psync_fs_free_openfile(of);
}

void psync_fs_inc_of_refcnt_and_readers(psync_openfile_t *of){
  pthread_mutex_lock(&of->mutex);
  of->refcnt++;
  of->runningreads++;
  pthread_mutex_unlock(&of->mutex);
}

void psync_fs_dec_of_refcnt_and_readers(psync_openfile_t *of){
  pthread_mutex_lock(&openfiles_mutex);
  pthread_mutex_lock(&of->mutex);
  of->runningreads--;
  if (--of->refcnt==0)
    psync_tree_del(&openfiles, &of->tree);
  pthread_mutex_unlock(&of->mutex);
  pthread_mutex_unlock(&openfiles_mutex);
  if (!of->refcnt)
    psync_fs_free_openfile(of);
}

static int psync_fs_release(const char *path, struct fuse_file_info *fi){
  debug(D_NOTICE, "release %s", path);
  psync_fs_dec_of_refcnt(fh_to_openfile(fi->fh));
  return 0;
}

static int psync_fs_flush(const char *path, struct fuse_file_info *fi){
  psync_openfile_t *of;
  debug(D_NOTICE, "flush %s", path);
  of=fh_to_openfile(fi->fh);
  if (of->newfile){
    psync_sql_res *res;
    debug(D_NOTICE, "releasing new file %s for upload", path);
    res=psync_sql_prep_statement("UPDATE fstask SET status=0 WHERE id=?");
    psync_sql_bind_uint(res, 1, -of->fileid);
    psync_sql_run_free(res);
  }
  return 0;
}

static int psync_fs_fsync(const char *path, int datasync, struct fuse_file_info *fi){
  psync_openfile_t *of;
  debug(D_NOTICE, "fsync %s", path);
  of=fh_to_openfile(fi->fh);
  if (!of->modified)
    return 0;
  if (unlikely_log(psync_file_sync(of->datafile)))
    return -EIO;
  if (unlikely_log(!of->newfile && psync_file_sync(of->indexfile)))
    return -EIO;
  return 0;
}

static int psync_read_newfile(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset){
  ssize_t br=psync_file_pread(of->datafile, buf, size, offset);
  if (br==-1)
    return -EIO;
  else
    return br;
}

static int psync_fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
  psync_openfile_t *of;
  of=fh_to_openfile(fi->fh);
  if (of->newfile)
    return psync_read_newfile(of, buf, size, offset);
  pthread_mutex_lock(&of->mutex);
  if (of->modified)
    return psync_pagecache_read_modified_locked(of, buf, size, offset);
  else{
    pthread_mutex_unlock(&of->mutex);
    return psync_pagecache_read_unmodified(of, buf, size, offset);
  }
}

static int psync_fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
  psync_openfile_t *of;
  ssize_t bw;
  uint64_t ioff;
  index_record rec;
  int ret;
  of=fh_to_openfile(fi->fh);
  if (of->newfile){
    bw=psync_file_pwrite(of->datafile, buf, size, offset);
    if (unlikely_log(bw==-1))
      return -EIO;
    else
      return bw;
  }
  else{
    pthread_mutex_lock(&of->mutex);
    if (unlikely(!of->modified)){
      ret=open_write_files(of, 0);
      if (unlikely_log(ret)){
        pthread_mutex_unlock(&of->mutex);
        return ret;
      }
      of->modified=1;
      of->indexoff=0;
    }
    ioff=of->indexoff++;
    pthread_mutex_unlock(&of->mutex);
    bw=psync_file_pwrite(of->datafile, buf, size, offset);
    if (unlikely_log(bw==-1))
      return -EIO;
    rec.offset=offset;
    rec.length=bw;
    if (unlikely_log(psync_file_pwrite(of->indexfile, &rec, sizeof(rec), sizeof(rec)*ioff+sizeof(index_header))!=sizeof(rec)))
      return -EIO;
    pthread_mutex_lock(&of->mutex);
    psync_interval_tree_add(&of->writeintervals, offset, offset+bw);
    pthread_mutex_unlock(&of->mutex);
    return 0;
  }
}

static int psync_fs_mkdir(const char *path, mode_t mode){
  psync_fspath_t *fpath;
  int ret;
  debug(D_NOTICE, "mkdir %s", path);
  psync_sql_lock();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    psync_sql_unlock();
    debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
    return -ENOENT;
  }
  if (!(fpath->permissions&PSYNC_PERM_CREATE)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  ret=psync_fstask_mkdir(fpath->folderid, fpath->name);
  psync_sql_unlock();
  psync_free(fpath);
  return ret;
}

static int psync_fs_rmdir(const char *path){
  psync_fspath_t *fpath;
  int ret;
  debug(D_NOTICE, "rmdir %s", path);
  psync_sql_lock();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    psync_sql_unlock();
    debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
    return -ENOENT;
  }
  if (!(fpath->permissions&PSYNC_PERM_DELETE)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  ret=psync_fstask_rmdir(fpath->folderid, fpath->name);
  psync_sql_unlock();
  psync_free(fpath);
  return ret;
}

static int psync_fs_unlink(const char *path){
  psync_fspath_t *fpath;
  int ret;
  debug(D_NOTICE, "unlink %s", path);
  psync_sql_lock();
  fpath=psync_fsfolder_resolve_path(path);
  if (!fpath){
    psync_sql_unlock();
    debug(D_NOTICE, "returning ENOENT for %s, folder not found", path);
    return -ENOENT;
  }
  if (!(fpath->permissions&PSYNC_PERM_DELETE)){
    psync_sql_unlock();
    psync_free(fpath);
    return -EACCES;
  }
  ret=psync_fstask_unlink(fpath->folderid, fpath->name);
  psync_sql_unlock();
  psync_free(fpath);
  return ret;
}

static int psync_fs_statfs(const char *path, struct statvfs *stbuf){
  uint64_t q, uq;
  debug(D_NOTICE, "statfs %s", path);
/* TODO:
   return -ENOENT if path is invalid if fuse does not call getattr first
   */
  memset(stbuf, 0, sizeof(struct statvfs));
  q=psync_get_uint_value("quota");
  uq=psync_get_uint_value("usedquota");
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
  return 0;
}

static int psync_fs_utimens(const char *path, const struct timespec tv[2]){
  return 0;
}

void *psync_fs_init(struct fuse_conn_info *conn){
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


static struct fuse_operations psync_oper;

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

static void psync_fs_do_stop(void){
  debug(D_NOTICE, "stopping");
  pthread_mutex_lock(&start_mutex);
  if (started){
    debug(D_NOTICE, "running fuse_unmount");
    fuse_unmount(psync_current_mountpoint, psync_fuse_channel);
    debug(D_NOTICE, "fuse_unmount existed, running fuse_destroy");
    fuse_destroy(psync_fuse);
    debug(D_NOTICE, "fuse_destroy existed");
    psync_free(psync_current_mountpoint);
    started=0;
    psync_pagecache_flush();
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
  debug(D_NOTICE, "fuse_loop_mt existed");
}

int psync_fs_start(){
  char *mp;
  struct fuse_args args=FUSE_ARGS_INIT(0, NULL);

  psync_oper.init     = psync_fs_init;
  psync_oper.getattr  = psync_fs_getattr;
  psync_oper.readdir  = psync_fs_readdir;
  psync_oper.open     = psync_fs_open;
  psync_oper.create   = psync_fs_creat;
  psync_oper.release  = psync_fs_release;
  psync_oper.flush    = psync_fs_flush;
  psync_oper.fsync    = psync_fs_fsync;
  psync_oper.read     = psync_fs_read;
  psync_oper.write    = psync_fs_write;
  psync_oper.mkdir    = psync_fs_mkdir;
  psync_oper.rmdir    = psync_fs_rmdir;
  psync_oper.unlink   = psync_fs_unlink;
  psync_oper.statfs   = psync_fs_statfs;
  psync_oper.chmod    = psync_fs_chmod;
  psync_oper.utimens  = psync_fs_utimens;

#if defined(P_OS_POSIX)
  myuid=getuid();
  mygid=getgid();
#endif
  pthread_mutex_lock(&start_mutex);
  if (started)
    goto err00;
  mp=psync_fuse_get_mountpoint();
  psync_fuse_channel=fuse_mount(mp, &args);
  if (unlikely_log(!psync_fuse_channel))
    goto err0;
  psync_fuse=fuse_new(psync_fuse_channel, &args, &psync_oper, sizeof(psync_oper), NULL);
  if (unlikely_log(!psync_fuse))
    goto err1;
  psync_current_mountpoint=mp;
  started=1;
  pthread_mutex_unlock(&start_mutex);
  psync_run_thread("fuse", psync_fuse_thread);
  return 0;
err1:
  fuse_unmount(mp, psync_fuse_channel);
err0:
  psync_free(mp);
err00:
  pthread_mutex_unlock(&start_mutex);
  return -1;
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
