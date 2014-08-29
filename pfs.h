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

#ifndef _PSYNC_FS_H
#define _PSYNC_FS_H

#include "psynclib.h"
#include "ptree.h"
#include "pintervaltree.h"
#include "papi.h"
#include "psettings.h"
#include "pfsfolder.h"
#include "pfstasks.h"
#include "pcompat.h"
#include <pthread.h>

#if defined(P_OS_POSIX)
#define psync_fs_need_per_folder_refresh() psync_fs_need_per_folder_refresh_f()
#define psync_fs_need_per_folder_refresh_const() 1
#else
#define psync_fs_need_per_folder_refresh() (psync_invalidate_os_cache_needed() && psync_fs_need_per_folder_refresh_f())
#define psync_fs_need_per_folder_refresh_const() 1
#endif

typedef struct {
  uint64_t frompage;
  uint64_t topage;
  uint64_t length;
  uint64_t requestedto;
  uint64_t id;
  time_t lastuse;
} psync_file_stream_t;

typedef struct {
  psync_tree tree;
  psync_file_stream_t streams[PSYNC_FS_FILESTREAMS_CNT];
  pthread_mutex_t mutex;
  psync_interval_tree_t *writeintervals;
  psync_fstask_folder_t *currentfolder;
  char *currentname;
  psync_fsfileid_t fileid;
  psync_fsfileid_t remotefileid;
  uint64_t hash;
  uint64_t initialsize;
  uint64_t currentsize;
  uint64_t laststreamid;
  uint64_t indexoff;
  uint64_t writeid;
  time_t currentsec;
  psync_file_t datafile;
  psync_file_t indexfile;
  uint32_t refcnt;
  uint32_t condwaiters;
  uint32_t runningreads;
  uint32_t currentspeed;
  uint32_t bytesthissec;
  unsigned char modified;
  unsigned char newfile;
  unsigned char releasedforupload;
} psync_openfile_t;

int psync_fs_update_openfile(uint64_t taskid, uint64_t writeid, psync_fileid_t newfileid, uint64_t hash, uint64_t size);
//void psync_fs_uploading_openfile(uint64_t taskid);
int psync_fs_rename_openfile_locked(psync_fsfileid_t fileid, psync_fsfolderid_t folderid, const char *name);
int64_t psync_fs_get_file_writeid(uint64_t taskid);
int64_t psync_fs_load_interval_tree(psync_file_t fd, uint64_t size, psync_interval_tree_t **tree);
int psync_fs_remount();
void psync_fs_inc_of_refcnt_locked(psync_openfile_t *of);
void psync_fs_inc_of_refcnt(psync_openfile_t *of);
void psync_fs_dec_of_refcnt(psync_openfile_t *of);
void psync_fs_inc_of_refcnt_and_readers(psync_openfile_t *of);
void psync_fs_dec_of_refcnt_and_readers(psync_openfile_t *of);

void psync_fs_refresh();
int psync_fs_need_per_folder_refresh_f();
void psync_fs_refresh_folder(psync_folderid_t folderid);

#endif