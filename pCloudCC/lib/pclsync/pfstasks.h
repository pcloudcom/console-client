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

#ifndef _PSYNC_FSTASKS_H
#define _PSYNC_FSTASKS_H

#include "pfsfolder.h"
#include "ptree.h"
#include "psynclib.h"
#include "plibs.h"
#include <time.h>
#include <stddef.h>
#include <string.h>

#define PSYNC_FS_TASK_MKDIR          1
#define PSYNC_FS_TASK_RMDIR          2
#define PSYNC_FS_TASK_CREAT          3
#define PSYNC_FS_TASK_UNLINK         4
#define PSYNC_FS_TASK_RENFILE_FROM   5
#define PSYNC_FS_TASK_RENFILE_TO     6
#define PSYNC_FS_TASK_RENFOLDER_FROM 7
#define PSYNC_FS_TASK_RENFOLDER_TO   8
#define PSYNC_FS_TASK_MODIFY         9
#define PSYNC_FS_TASK_UN_SET_REV    10
#define PSYNC_FS_TASK_SET_FILE_MOD  11
#define PSYNC_FS_TASK_SET_FILE_CR   12

typedef struct {
  psync_tree tree;
  psync_fsfolderid_t folderid;
  uint64_t taskid;
  time_t ctime;
  time_t mtime;
  uint32_t subdircnt;
  uint32_t flags;
  char name[];
} psync_fstask_mkdir_t;

typedef struct {
  psync_tree tree;
  psync_fsfolderid_t folderid;
  uint64_t taskid;
  char name[];
} psync_fstask_rmdir_t;

typedef struct {
  psync_tree tree;
  psync_fsfileid_t fileid;
  psync_fileid_t rfileid; // fileid of an uploaded file, reopened for writing, 0 if this is a new file
  uint64_t taskid;
  char name[];
} psync_fstask_creat_t;

typedef struct {
  const void *data;
  size_t datalen;
  time_t ctime;
} psync_fstask_local_creat_t;

typedef struct {
  psync_tree tree;
  psync_fsfileid_t fileid;
  uint64_t taskid;
  char name[];
} psync_fstask_unlink_t;

typedef struct {
  psync_tree tree;
  psync_fsfolderid_t folderid;
  psync_tree *mkdirs;
  psync_tree *rmdirs;
  psync_tree *creats;
  psync_tree *unlinks;
  time_t mtime;
  uint32_t taskscnt;
  uint32_t refcnt;
} psync_fstask_folder_t;

static inline size_t psync_fstask_creat_local_offset(size_t namelen){
  return (offsetof(psync_fstask_creat_t, name)+namelen+psync_alignof(psync_fstask_local_creat_t))/
      psync_alignof(psync_fstask_local_creat_t)*psync_alignof(psync_fstask_local_creat_t);
}

static inline psync_fstask_local_creat_t *psync_fstask_creat_len_get_local(psync_fstask_creat_t *cr, size_t namelen){
  return (psync_fstask_local_creat_t *)(((char *)cr)+psync_fstask_creat_local_offset(namelen));
}

static inline psync_fstask_local_creat_t *psync_fstask_creat_get_local(psync_fstask_creat_t *cr){
  return psync_fstask_creat_len_get_local(cr, strlen(cr->name));
}

void psync_fstask_init();

psync_fstask_folder_t *psync_fstask_get_or_create_folder_tasks(psync_fsfolderid_t folderid);
psync_fstask_folder_t *psync_fstask_get_folder_tasks(psync_fsfolderid_t folderid);
void psync_fstask_release_folder_tasks(psync_fstask_folder_t *folder);
psync_fstask_folder_t *psync_fstask_get_ref_locked(psync_fstask_folder_t *folder);
psync_fstask_folder_t *psync_fstask_get_or_create_folder_tasks_locked(psync_fsfolderid_t folderid);
psync_fstask_folder_t *psync_fstask_get_folder_tasks_locked(psync_fsfolderid_t folderid);
psync_fstask_folder_t *psync_fstask_get_folder_tasks_rdlocked(psync_fsfolderid_t folderid);
void psync_fstask_release_folder_tasks_locked(psync_fstask_folder_t *folder);

void psync_fstask_folder_created(psync_folderid_t parentfolderid, uint64_t taskid, psync_folderid_t folderid, const char *name);
void psync_fstask_folder_deleted(psync_folderid_t parentfolderid, uint64_t taskid, const char *name);
void psync_fstask_file_created(psync_folderid_t parentfolderid, uint64_t taskid, const char *name, psync_fileid_t fileid);
void psync_fstask_file_modified(psync_folderid_t parentfolderid, uint64_t taskid, const char *name, psync_fileid_t fileid);
void psync_fstask_file_deleted(psync_folderid_t parentfolderid, uint64_t taskid, const char *name);
void psync_fstask_file_renamed(psync_folderid_t folderid, uint64_t taskid, const char *name, uint64_t frtaskid);
void psync_fstask_folder_renamed(psync_folderid_t parentfolderid, uint64_t taskid, const char *name, uint64_t frtaskid);

psync_fstask_mkdir_t *psync_fstask_find_mkdir(psync_fstask_folder_t *folder, const char *name, uint64_t taskid);
psync_fstask_rmdir_t *psync_fstask_find_rmdir(psync_fstask_folder_t *folder, const char *name, uint64_t taskid);
psync_fstask_creat_t *psync_fstask_find_creat(psync_fstask_folder_t *folder, const char *name, uint64_t taskid);
psync_fstask_unlink_t *psync_fstask_find_unlink(psync_fstask_folder_t *folder, const char *name, uint64_t taskid);

psync_fstask_mkdir_t *psync_fstask_find_mkdir_by_folderid(psync_fstask_folder_t *folder, psync_fsfolderid_t folderid);
psync_fstask_creat_t *psync_fstask_find_creat_by_fileid(psync_fstask_folder_t *folder, psync_fsfileid_t fileid);

int psync_fstask_mkdir(psync_fsfolderid_t folderid, const char *name, uint32_t folderflags);
int psync_fstask_can_rmdir(psync_fsfolderid_t folderid, uint32_t parentflags, const char *name);
int psync_fstask_rmdir(psync_fsfolderid_t folderid, uint32_t parentflags, const char *name);
psync_fstask_creat_t *psync_fstask_add_creat(psync_fstask_folder_t *folder, const char *name, psync_fsfileid_t fileid, const char *encsymkey, size_t encsymkeylen);
void psync_fstask_inject_creat(psync_fstask_folder_t *folder, psync_fstask_creat_t *cr);
void psync_fstask_inject_unlink(psync_fstask_folder_t *folder, psync_fstask_unlink_t *un);
psync_fstask_creat_t *psync_fstask_add_modified_file(psync_fstask_folder_t *folder, const char *name, psync_fsfileid_t fileid,
                                                     uint64_t hash, const char *encsymkey, size_t encsymkeylen);
int psync_fstask_set_mtime(psync_fileid_t fileid, uint64_t oldtm, uint64_t newtm, int is_ctime);

int psync_fstask_add_local_creat_static(psync_fsfolderid_t folderid, const char *name, const void *data, size_t datalen);


int psync_fstask_can_unlink(psync_fsfolderid_t folderid, const char *name);
int psync_fstask_unlink(psync_fsfolderid_t folderid, const char *name);
int psync_fstask_rename_file(psync_fsfileid_t fileid, psync_fsfolderid_t parentfolderid, const char *name,  psync_fsfolderid_t to_folderid, const char *new_name);
int psync_fstask_rename_folder(psync_fsfolderid_t folderid, psync_fsfolderid_t parentfolderid, const char *name,  psync_fsfolderid_t to_folderid,
                               const char *new_name, uint32_t targetflags);

void psync_fstask_clean();

void psync_fstask_add_banned_folders();

#if IS_DEBUG
void psync_fstask_dump_state();
#endif

#endif
