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

#include "pcompat.h"
#include "pfstasks.h"
#include "plibs.h"
#include "ptimer.h"
#include "pfsupload.h"
#include "psettings.h"
#include "pcache.h"
#include "pfolder.h"
#include "pfs.h"
#include "pcloudcrypto.h"
#include "ppathstatus.h"
#include <string.h>
#include <stddef.h>
#include <stdio.h>

typedef struct {
  psync_folderid_t folderid;
  char name[];
} file_history_record;

static psync_tree *folders=PSYNC_TREE_EMPTY;
static uint64_t psync_local_taskid=UINT64_MAX;

psync_fstask_folder_t *psync_fstask_get_or_create_folder_tasks(psync_fsfolderid_t folderid){
  psync_fstask_folder_t *folder;
  psync_sql_lock();
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  psync_sql_unlock();
  return folder;
}

psync_fstask_folder_t *psync_fstask_get_folder_tasks(psync_fsfolderid_t folderid){
  psync_fstask_folder_t *folder;
  psync_sql_lock();
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  psync_sql_unlock();
  return folder;
}

void psync_fstask_release_folder_tasks(psync_fstask_folder_t *folder){
  psync_sql_lock();
  psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
}

psync_fstask_folder_t *psync_fstask_get_ref_locked(psync_fstask_folder_t *folder){
  folder->refcnt++;
  return folder;
}

psync_fstask_folder_t *psync_fstask_get_or_create_folder_tasks_locked(psync_fsfolderid_t folderid){
  psync_fstask_folder_t *folder;
  psync_tree *tr;
  int64_t d;
  tr=folders;
  d=-1;
  while (tr){
    folder=psync_tree_element(tr, psync_fstask_folder_t, tree);
    d=folderid-folder->folderid;
    if (d<0){
      if (tr->left)
        tr=tr->left;
      else
        break;
    }
    else if (d>0)
      if (tr->right)
        tr=tr->right;
      else
        break;
    else{
      folder->refcnt++;
      return folder;
    }
  }
  folder=psync_new(psync_fstask_folder_t);
  memset(folder, 0, sizeof(psync_fstask_folder_t));
  if (d<0)
    psync_tree_add_before(&folders, tr, &folder->tree);
  else
    psync_tree_add_after(&folders, tr, &folder->tree);
  folder->folderid=folderid;
  folder->refcnt=1;
  return folder;
}

psync_fstask_folder_t *psync_fstask_get_folder_tasks_locked(psync_fsfolderid_t folderid){
  psync_fstask_folder_t *folder;
  psync_tree *tr;
  tr=folders;
  while (tr){
    folder=psync_tree_element(tr, psync_fstask_folder_t, tree);
    if (folderid<folder->folderid)
      tr=tr->left;
    else if (folderid>folder->folderid)
      tr=tr->right;
    else{
      folder->refcnt++;
      return folder;
    }
  }
  return NULL;
}

psync_fstask_folder_t *psync_fstask_get_folder_tasks_rdlocked(psync_fsfolderid_t folderid){
  psync_fstask_folder_t *folder;
  psync_tree *tr;
  tr=folders;
  while (tr){
    folder=psync_tree_element(tr, psync_fstask_folder_t, tree);
    if (folderid<folder->folderid)
      tr=tr->left;
    else if (folderid>folder->folderid)
      tr=tr->right;
    else
      return folder;
  }
  return NULL;
}

void psync_fstask_release_folder_tasks_locked(psync_fstask_folder_t *folder){
#if IS_DEBUG
  if ((!!folder->taskscnt)!=(folder->creats || folder->mkdirs || folder->rmdirs || folder->unlinks))
    debug(D_ERROR, "taskcnt=%u, c=%p, m=%p, r=%p, u=%p", (unsigned)folder->taskscnt, folder->creats, folder->mkdirs, folder->rmdirs, folder->unlinks);
#endif
  if (--folder->refcnt==0 && !folder->taskscnt){
    debug(D_NOTICE, "releasing folder id %ld", (long int)folder->folderid);
    psync_tree_del(&folders, &folder->tree);
    psync_free(folder);
  }
}

static psync_tree *psync_fstask_search_tree(psync_tree *tree, size_t nameoff, const char *name, uint64_t taskid, size_t taskidoff){
  int c;
  while (tree){
    c=psync_filename_cmp(name, ((char *)tree)+nameoff);
    if (c<0)
      tree=tree->left;
    else if (c>0)
      tree=tree->right;
    else
      break;
  }
  if (!tree || !taskid || *((uint64_t *)(((char *)tree)+taskidoff))==taskid)
    return tree;
  else{
    psync_tree *tn;
    tn=psync_tree_get_prev(tree);
    while (tn){
      if (psync_filename_cmp(name, ((char *)tn)+nameoff))
        break;
      if (*((uint64_t *)(((char *)tn)+taskidoff))==taskid)
        return tn;
      tn=psync_tree_get_prev(tn);
    }
    tn=psync_tree_get_next(tree);
    while (tn){
      if (psync_filename_cmp(name, ((char *)tn)+nameoff))
        break;
      if (*((uint64_t *)(((char *)tn)+taskidoff))==taskid)
        return tn;
      tn=psync_tree_get_next(tn);
    }
    return NULL;
  }
}

static psync_tree *psync_fstask_walk_tree(psync_tree *tree, uint64_t taskid, size_t taskidoff){
  tree=psync_tree_get_first(tree);
  while (tree){
    if (*((uint64_t *)(((char *)tree)+taskidoff))==taskid)
      return tree;
    tree=psync_tree_get_next(tree);
  }
  return NULL;
}

static void psync_fstask_insert_into_tree(psync_tree **tree, size_t nameoff, psync_tree *element){
  const char *name;
  psync_tree *node;
  int c;
  if (!*tree){
    psync_tree_add_after(tree, NULL, element);
    return;
  }
  name=((char *)element)+nameoff;
  node=*tree;
  while (1){
    c=psync_filename_cmp(name, ((char *)node)+nameoff);
    if (c<0){
      if (node->left)
        node=node->left;
      else{
        psync_tree_add_before(tree, node, element);
        return;
      }
    }
    else{
      if (c==0)
        debug(D_WARNING, "duplicate entry %s, should not happen", name);
      if (node->right)
        node=node->right;
      else{
        psync_tree_add_after(tree, node, element);
        return;
      }
    }
  }
}

psync_fstask_mkdir_t *psync_fstask_find_mkdir(psync_fstask_folder_t *folder, const char *name, uint64_t taskid){
  return psync_tree_element(
    psync_fstask_search_tree(folder->mkdirs, offsetof(psync_fstask_mkdir_t, name), name, taskid, offsetof(psync_fstask_mkdir_t, taskid)),
    psync_fstask_mkdir_t, tree);
}

psync_fstask_rmdir_t *psync_fstask_find_rmdir(psync_fstask_folder_t *folder, const char *name, uint64_t taskid){
  return psync_tree_element(
    psync_fstask_search_tree(folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), name, taskid, offsetof(psync_fstask_rmdir_t, taskid)),
    psync_fstask_rmdir_t, tree);
}

psync_fstask_creat_t *psync_fstask_find_creat(psync_fstask_folder_t *folder, const char *name, uint64_t taskid){
  return psync_tree_element(
    psync_fstask_search_tree(folder->creats, offsetof(psync_fstask_creat_t, name), name, taskid, offsetof(psync_fstask_creat_t, taskid)),
    psync_fstask_creat_t, tree);
}

psync_fstask_unlink_t *psync_fstask_find_unlink(psync_fstask_folder_t *folder, const char *name, uint64_t taskid){
  return psync_tree_element(
    psync_fstask_search_tree(folder->unlinks, offsetof(psync_fstask_unlink_t, name), name, taskid, offsetof(psync_fstask_unlink_t, taskid)),
    psync_fstask_unlink_t, tree);
}

psync_fstask_mkdir_t *psync_fstask_find_mkdir_by_folderid(psync_fstask_folder_t *folder, psync_fsfolderid_t folderid){
  return psync_tree_element(
    psync_fstask_walk_tree(folder->mkdirs, folderid, offsetof(psync_fstask_mkdir_t, folderid)),
    psync_fstask_mkdir_t, tree);
}

psync_fstask_creat_t *psync_fstask_find_creat_by_fileid(psync_fstask_folder_t *folder, psync_fsfileid_t fileid){
  return psync_tree_element(
    psync_fstask_walk_tree(folder->creats, fileid, offsetof(psync_fstask_creat_t, fileid)),
    psync_fstask_creat_t, tree);
}

static void psync_fstask_depend(uint64_t taskid, uint64_t dependontaskid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT OR IGNORE INTO fstaskdepend (fstaskid, dependfstaskid) VALUES (?, ?)");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_bind_uint(res, 2, dependontaskid);
  psync_sql_run_free(res);
}

static uint32_t psync_fstask_depend_on_name(uint64_t taskid, psync_fsfolderid_t folderid, const char *name, size_t len){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT OR IGNORE INTO fstaskdepend (fstaskid, dependfstaskid) SELECT ?, id FROM fstask "
                               "WHERE folderid=? AND text1=? AND id!=? AND status!=3");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_bind_int(res, 2, folderid);
  psync_sql_bind_lstring(res, 3, name, len);
  psync_sql_bind_uint(res, 4, taskid);
  psync_sql_run_free(res);
  return psync_sql_affected_rows();
}

static uint32_t psync_fstask_depend_on_name2(uint64_t taskid, uint64_t taskid2,psync_fsfolderid_t folderid, const char *name, size_t len){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT OR IGNORE INTO fstaskdepend (fstaskid, dependfstaskid) SELECT ?, id FROM fstask "
                               "WHERE folderid=? AND text1=? AND id NOT IN (?, ?) AND status!=3");
  psync_sql_bind_uint(res, 1, taskid);
  psync_sql_bind_int(res, 2, folderid);
  psync_sql_bind_lstring(res, 3, name, len);
  psync_sql_bind_uint(res, 4, taskid);
  psync_sql_bind_uint(res, 5, taskid2);
  psync_sql_run_free(res);
  return psync_sql_affected_rows();
}

int psync_fstask_mkdir(psync_fsfolderid_t folderid, const char *name, uint32_t folderflags){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *task;
  uint64_t taskid;
  char *key;
  size_t len, klen;
  time_t ctime;
  uint32_t depend;
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  len=strlen(name);
  if (folderid>=0){
    res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, len);
    row=psync_sql_fetch_rowint(res);
    psync_sql_free_result(res);
    if (row && !psync_fstask_find_rmdir(folder, name, 0)){
      psync_fstask_release_folder_tasks_locked(folder);
      return -PRINT_RETURN_CONST(EEXIST);
    }
  }
  if ((task=psync_fstask_find_mkdir(folder, name, 0))){
    depend=task->flags;
    psync_fstask_release_folder_tasks_locked(folder);
    if (depend&PSYNC_FOLDER_FLAG_INVISIBLE)
      return -PRINT_RETURN_CONST(EACCES);
    else
      return -PRINT_RETURN_CONST(EEXIST);
  }
  ctime=psync_timer_time();
  if (folderflags&PSYNC_FOLDER_FLAG_ENCRYPTED){
    key=psync_cloud_crypto_get_new_encoded_key(PSYNC_CRYPTO_SYM_FLAG_ISDIR, &klen);
    if (psync_crypto_is_error(key)){
      psync_fstask_release_folder_tasks_locked(folder);
      return -psync_fs_crypto_err_to_errno(psync_crypto_to_error(key));
    }
  }
  else
    key=NULL;
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, sfolderid, text1, text2, int1) VALUES ("NTO_STR(PSYNC_FS_TASK_MKDIR)", 0, ?, ?, ?, ?, ?)");
  psync_sql_bind_int(res, 1, folderid);
  psync_sql_bind_int(res, 2, folderid);
  psync_sql_bind_lstring(res, 3, name, len);
  if (key)
    psync_sql_bind_lstring(res, 4, key, klen);
  else
    psync_sql_bind_null(res, 4);
  psync_sql_bind_uint(res, 5, ctime);
  psync_sql_run_free(res);
  taskid=psync_sql_insertid();
  if (folderid<0){
    psync_fstask_depend(taskid, -folderid);
    depend=1;
  }
  else
    depend=0;
  depend+=psync_fstask_depend_on_name(taskid, folderid, name, len);
  if (unlikely_log(psync_sql_commit_transaction())){
    psync_fstask_release_folder_tasks_locked(folder);
    return -EIO;
  }
  len++;
  task=(psync_fstask_mkdir_t *)psync_malloc(offsetof(psync_fstask_mkdir_t, name)+len);
  task->taskid=taskid;
  task->ctime=task->mtime=ctime;
  task->folderid=-(psync_fsfolderid_t)taskid;
  task->subdircnt=0;
  task->flags=folderflags&PSYNC_FOLDER_FLAG_ENCRYPTED;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->mkdirs, offsetof(psync_fstask_mkdir_t, name), &task->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
  if (!depend)
    psync_fsupload_wake();
  if (folderid>=0)
    psync_path_status_drive_folder_changed(folderid);
  return 0;
}

int psync_fstask_can_rmdir(psync_fsfolderid_t folderid, uint32_t parentflags, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  psync_str_row srow;
  psync_fstask_folder_t *folder, *cfolder;
  psync_fstask_mkdir_t *mk;
  psync_fsfolderid_t cfolderid;
  size_t len;
  len=strlen(name);
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder && (mk=psync_fstask_find_mkdir(folder, name, 0)))
    cfolderid=mk->folderid;
  else{
    res=psync_sql_query("SELECT id, flags FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, len);
    row=psync_sql_fetch_rowint(res);
    if (!row || (folder && psync_fstask_find_rmdir(folder, name, 0))){
      psync_sql_free_result(res);
      psync_fstask_release_folder_tasks_locked(folder);
      return -ENOENT;
    }
    cfolderid=row[0];
    if ((row[1]&PSYNC_FOLDER_FLAG_ENCRYPTED) && !(parentflags&PSYNC_FOLDER_FLAG_ENCRYPTED)){
      psync_sql_free_result(res);
      if (folder)
        psync_fstask_release_folder_tasks_locked(folder);
      debug(D_WARNING, "attempt to delete encrypted folder %s in folderid %lu rejected", name, (unsigned long)folderid);
      return -EACCES;
    }
    psync_sql_free_result(res);
  }
  cfolder=psync_fstask_get_folder_tasks_locked(cfolderid);
  if (cfolder && (cfolder->creats || cfolder->mkdirs)){
    psync_fstask_release_folder_tasks_locked(cfolder);
    if (folder)
      psync_fstask_release_folder_tasks_locked(folder);
    debug(D_NOTICE, "returning ENOTEMPTY for folder name %s", name);
    return -ENOTEMPTY;
  }
  if (cfolderid>=0){
    res=psync_sql_query("SELECT name FROM file WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, cfolderid);
    while ((srow=psync_sql_fetch_rowstr(res)))
      if (!cfolder || !psync_fstask_find_unlink(cfolder, srow[0], 0)){
        psync_sql_free_result(res);
        if (cfolder)
          psync_fstask_release_folder_tasks_locked(cfolder);
        if (folder)
          psync_fstask_release_folder_tasks_locked(folder);
        debug(D_NOTICE, "returning ENOTEMPTY for folder name %s", name);
        return -ENOTEMPTY;
      }
    psync_sql_free_result(res);
    res=psync_sql_query("SELECT name FROM folder WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, cfolderid);
    while ((srow=psync_sql_fetch_rowstr(res)))
      if (!cfolder || !psync_fstask_find_rmdir(cfolder, srow[0], 0)){
        psync_sql_free_result(res);
        if (cfolder)
          psync_fstask_release_folder_tasks_locked(cfolder);
        if (folder)
          psync_fstask_release_folder_tasks_locked(folder);
        debug(D_NOTICE, "returning ENOTEMPTY for folder name %s", name);
        return -ENOTEMPTY;
      }
    psync_sql_free_result(res);
  }
  if (cfolder)
    psync_fstask_release_folder_tasks_locked(cfolder);
  if (folder)
    psync_fstask_release_folder_tasks_locked(folder);
  return 0;
}

int psync_fstask_rmdir(psync_fsfolderid_t folderid, uint32_t parentflags, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  psync_str_row srow;
  psync_fstask_folder_t *folder, *cfolder;
  psync_fstask_rmdir_t *task;
  psync_fstask_mkdir_t *mk;
  uint64_t depend, taskid;
  psync_fsfolderid_t cfolderid;
  size_t len;
  len=strlen(name);
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  mk=psync_fstask_find_mkdir(folder, name, 0);
  if (mk==NULL){
    res=psync_sql_query("SELECT id, flags FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, len);
    row=psync_sql_fetch_rowint(res);
    if (!row || psync_fstask_find_rmdir(folder, name, 0)){
      psync_sql_free_result(res);
      psync_fstask_release_folder_tasks_locked(folder);
      return -ENOENT;
    }
    cfolderid=row[0];
    if ((row[1]&PSYNC_FOLDER_FLAG_ENCRYPTED) && !(parentflags&PSYNC_FOLDER_FLAG_ENCRYPTED)){
      psync_sql_free_result(res);
      psync_fstask_release_folder_tasks_locked(folder);
      debug(D_WARNING, "attempt to delete encrypted folder %s in folderid %lu rejected", name, (unsigned long)folderid);
      return -EACCES;
    }
    psync_sql_free_result(res);
    depend=0;
  }
  else{
    depend=mk->taskid;
    cfolderid=mk->folderid;
    folder->taskscnt--;
  }
  cfolder=psync_fstask_get_folder_tasks_locked(cfolderid);
  if (cfolder && (cfolder->creats || cfolder->mkdirs)){
    psync_fstask_release_folder_tasks_locked(cfolder);
    psync_fstask_release_folder_tasks_locked(folder);
    debug(D_NOTICE, "returning ENOTEMPTY for folder name %s", name);
    return -ENOTEMPTY;
  }
  if (cfolderid>=0){
    res=psync_sql_query("SELECT name FROM file WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, cfolderid);
    while ((srow=psync_sql_fetch_rowstr(res)))
      if (!cfolder || !psync_fstask_find_unlink(cfolder, srow[0], 0)){
        psync_sql_free_result(res);
        if (cfolder)
          psync_fstask_release_folder_tasks_locked(cfolder);
        psync_fstask_release_folder_tasks_locked(folder);
        debug(D_NOTICE, "returning ENOTEMPTY for folder name %s", name);
        return -ENOTEMPTY;
      }
    psync_sql_free_result(res);
    res=psync_sql_query("SELECT name FROM folder WHERE parentfolderid=?");
    psync_sql_bind_uint(res, 1, cfolderid);
    while ((srow=psync_sql_fetch_rowstr(res)))
      if (!cfolder || !psync_fstask_find_rmdir(cfolder, srow[0], 0)){
        psync_sql_free_result(res);
        if (cfolder)
          psync_fstask_release_folder_tasks_locked(cfolder);
        psync_fstask_release_folder_tasks_locked(folder);
        debug(D_NOTICE, "returning ENOTEMPTY for folder name %s", name);
        return -ENOTEMPTY;
      }
    psync_sql_free_result(res);
  }
  if (mk) {
    psync_tree_del(&folder->mkdirs, &mk->tree);
    psync_free(mk);
  }
  if (cfolder)
    psync_fstask_release_folder_tasks_locked(cfolder);
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, sfolderid, text1) VALUES ("NTO_STR(PSYNC_FS_TASK_RMDIR)", 0, ?, ?, ?)");
  psync_sql_bind_int(res, 1, folderid);
  psync_sql_bind_int(res, 2, cfolderid);
  psync_sql_bind_lstring(res, 3, name, len);
  psync_sql_run_free(res);
  taskid=psync_sql_insertid();
  if (depend)
    psync_fstask_depend(taskid, depend);
  res=psync_sql_query("SELECT id FROM fstask WHERE folderid=?");
  psync_sql_bind_int(res, 1, cfolderid);
  while ((row=psync_sql_fetch_rowint(res))){
    psync_fstask_depend(taskid, row[0]);
    depend++;
  }
  psync_sql_free_result(res);
  psync_fstask_depend_on_name(taskid, folderid, name, len);
  if (unlikely_log(psync_sql_commit_transaction())){
    psync_fstask_release_folder_tasks_locked(folder);
    return -EIO;
  }
  len++;
  task=(psync_fstask_rmdir_t *)psync_malloc(offsetof(psync_fstask_rmdir_t, name)+len);
  task->taskid=taskid;
  task->folderid=cfolderid;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), &task->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
  if (depend==0)
    psync_fsupload_wake();
  return 0;
}

psync_fstask_creat_t *psync_fstask_add_creat(psync_fstask_folder_t *folder, const char *name, psync_fsfileid_t fileid, const char *encsymkey, size_t encsymkeylen){
  psync_sql_res *res;
  psync_fstask_creat_t *task;
  psync_fstask_unlink_t *un;
  uint64_t taskid;
  size_t len;
  assert(fileid>=0);
  len=strlen(name);
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, fileid, sfolderid, text1, text2, int1) "
                                           "VALUES ("NTO_STR(PSYNC_FS_TASK_CREAT)", 1, ?, ?, ?, ?, ?, 0)");
  psync_sql_bind_int(res, 1, folder->folderid);
  psync_sql_bind_int(res, 2, fileid);
  psync_sql_bind_int(res, 3, folder->folderid);
  psync_sql_bind_lstring(res, 4, name, len);
  if (encsymkey)
    psync_sql_bind_lstring(res, 5, encsymkey, encsymkeylen);
  else
    psync_sql_bind_null(res, 5);
  psync_sql_run_free(res);
  taskid=psync_sql_insertid();
  if (folder->folderid<0)
    psync_fstask_depend(taskid, -folder->folderid);
  psync_fstask_depend_on_name(taskid, folder->folderid, name, len);
  if (unlikely_log(psync_sql_commit_transaction()))
    return NULL;
  len++;
  un=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  un->fileid=-(psync_fsfileid_t)taskid;
  un->taskid=taskid;
  memcpy(un->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &un->tree);
  task=(psync_fstask_creat_t *)psync_malloc(offsetof(psync_fstask_creat_t, name)+len);
  task->fileid=-(psync_fsfileid_t)taskid;
  task->rfileid=fileid;
  task->taskid=taskid;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &task->tree);
  folder->taskscnt+=2;
  if (folder->folderid>=0)
    psync_path_status_drive_folder_changed(folder->folderid);
  return task;
}

void psync_fstask_inject_creat(psync_fstask_folder_t *folder, psync_fstask_creat_t *cr){
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &cr->tree);
  folder->taskscnt++;
}

void psync_fstask_inject_unlink(psync_fstask_folder_t *folder, psync_fstask_unlink_t *un){
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_creat_t, name), &un->tree);
  folder->taskscnt++;
}

psync_fstask_creat_t *psync_fstask_add_modified_file(psync_fstask_folder_t *folder, const char *name, psync_fsfileid_t fileid,
                                                     uint64_t hash, const char *encsymkey, size_t encsymkeylen){
  psync_sql_res *res;
  psync_fstask_unlink_t *un;
  psync_fstask_creat_t *task;
  uint64_t taskid;
  size_t len;
  len=strlen(name);
  assert(fileid>0);
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, fileid, sfolderid, text1, text2, int1, int2) "
                               "VALUES ("NTO_STR(PSYNC_FS_TASK_MODIFY)", 1, ?, ?, ?, ?, ?, 0, ?)");
  psync_sql_bind_int(res, 1, folder->folderid);
  psync_sql_bind_int(res, 2, fileid);
  psync_sql_bind_int(res, 3, folder->folderid);
  psync_sql_bind_lstring(res, 4, name, len);
  if (encsymkey)
    psync_sql_bind_lstring(res, 5, encsymkey, encsymkeylen);
  else
    psync_sql_bind_null(res, 5);
  psync_sql_bind_uint(res, 6, hash);
  psync_sql_run_free(res);
  taskid=psync_sql_insertid();
  if (folder->folderid<0)
    psync_fstask_depend(taskid, -folder->folderid);
  psync_fstask_depend_on_name(taskid, folder->folderid, name, len);
  task=psync_fstask_find_creat(folder, name, 0);
  if (task){
    psync_fstask_depend(taskid, task->taskid);
    psync_tree_del(&folder->creats, &task->tree);
    psync_free(task);
    folder->taskscnt--;
  }
  if (unlikely_log(psync_sql_commit_transaction()))
    return NULL;
  len++;
  un=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  un->fileid=fileid;
  un->taskid=taskid;
  memcpy(un->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &un->tree);
  task=(psync_fstask_creat_t *)psync_malloc(offsetof(psync_fstask_creat_t, name)+len);
  task->fileid=-(psync_fsfileid_t)taskid;
  task->rfileid=fileid;
  task->taskid=taskid;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &task->tree);
  if (folder->folderid>=0)
    psync_path_status_drive_folder_changed(folder->folderid);
  folder->taskscnt+=2;
  return task;
}

int psync_fstask_set_mtime(psync_fileid_t fileid, uint64_t oldtm, uint64_t newtm, int is_ctime){
  psync_sql_res *res;
  psync_sql_start_transaction();
  if (is_ctime)
    res=psync_sql_prep_statement("UPDATE file SET ctime=? WHERE id=?");
  else
    res=psync_sql_prep_statement("UPDATE file SET mtime=? WHERE id=?");
  psync_sql_bind_uint(res, 1, newtm);
  psync_sql_bind_uint(res, 2, fileid);
  psync_sql_run_free(res);
  // folderid is ignored for these tasks
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, fileid, int1, int2) VALUES (?, 0, 0, ?, ?, ?)");
  psync_sql_bind_int(res, 1, is_ctime?PSYNC_FS_TASK_SET_FILE_CR:PSYNC_FS_TASK_SET_FILE_MOD);
  psync_sql_bind_int(res, 2, fileid);
  psync_sql_bind_int(res, 3, oldtm);
  psync_sql_bind_int(res, 4, newtm);
  psync_sql_run_free(res);
  if (unlikely_log(psync_sql_commit_transaction()))
    return -EIO;
  psync_fsupload_wake();
  return 0;
}

int psync_fstask_add_local_creat_static(psync_fsfolderid_t folderid, const char *name, const void *data, size_t datalen){
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  psync_fstask_local_creat_t *lc;
  psync_sql_res *res;
  psync_uint_row row;
  size_t len, addlen;
  int ret;
  ret=-1;
  len=strlen(name);
  psync_sql_lock();
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  cr=psync_fstask_find_creat(folder, name, 0);
  if (cr){
    debug(D_NOTICE, "not adding file %s to folderid %ld as creat already exists", name, (long)folderid);
    goto ex;
  }
  if (folderid>=0 && !psync_fstask_find_unlink(folder, name, 0)){
    res=psync_sql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, len);
    row=psync_sql_fetch_rowint(res);
    psync_sql_free_result(res);
    if (row){
      debug(D_NOTICE, "not adding file %s to folderid %ld as it already exists in the database", name, (long)folderid);
      goto ex;
    }
  }
  debug(D_NOTICE, "adding file %s to folderid %ld, datalen %lu", name, (long)folderid, (unsigned long)datalen);
  len++;
  un=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  un->taskid=psync_local_taskid;
  un->fileid=0;
  memcpy(un->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &un->tree);
  addlen=psync_fstask_creat_local_offset(len-1);
  cr=(psync_fstask_creat_t *)psync_malloc(addlen+sizeof(psync_fstask_local_creat_t));
  cr->fileid=0;
  cr->rfileid=0;
  cr->taskid=psync_local_taskid;
  memcpy(cr->name, name, len);
  lc=(psync_fstask_local_creat_t *)(((char *)cr)+addlen);
  lc->data=data;
  lc->datalen=datalen;
  lc->ctime=psync_timer_time();
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &cr->tree);
  psync_local_taskid--;
  folder->taskscnt+=2;
  ret=0;
ex:
  psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
  return ret;
}

static psync_fsfileid_t get_file_at_old_location(psync_fsfileid_t fileid){
  file_history_record *rec;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_sql_res *res;
  psync_uint_row row;
  psync_fsfileid_t ret;
  char key[16];
  if (fileid<0)
    return 0;
  psync_get_string_id(key, "HLOC", fileid);
  rec=(file_history_record *)psync_cache_get(key);
  if (!rec)
    return 0;
  folder=psync_fstask_get_folder_tasks_locked(rec->folderid);
  if (folder){
    cr=psync_fstask_find_creat(folder, rec->name, 0);
    if (cr){
      psync_free(rec);
      psync_fstask_release_folder_tasks_locked(folder);
      return cr->fileid;
    }
    if (psync_fstask_find_unlink(folder, rec->name, 0)){
      psync_free(rec);
      psync_fstask_release_folder_tasks_locked(folder);
      return 0;
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
  res=psync_sql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
  psync_sql_bind_uint(res, 1, rec->folderid);
  psync_sql_bind_string(res, 2, rec->name);
  if ((row=psync_sql_fetch_rowint(res)))
    ret=row[0];
  else
    ret=0;
  psync_sql_free_result(res);
  psync_free(rec);
  return ret;
}

void psync_fstask_stop_and_delete_file(psync_fsfileid_t fileid){
  psync_sql_res *res;
  debug(D_NOTICE, "trying to stop upload of task %lu", (unsigned long)-fileid);
  if (psync_fsupload_in_current_small_uploads_batch_locked(-fileid)){
    debug(D_NOTICE, "file is in current small uploads batch");
    return;
  }
  psync_fsupload_stop_upload_locked(-fileid);
  res=psync_sql_prep_statement("UPDATE fstask SET status=11 WHERE id=?");
  psync_sql_bind_uint(res, 1, -fileid);
  psync_sql_run_free(res);
  res=psync_sql_prep_statement("UPDATE fstask SET status=11 WHERE fileid=? AND status!=10");
  psync_sql_bind_int(res, 1, fileid);
  psync_sql_run_free(res);
  psync_fs_mark_openfile_deleted(-fileid);
}

int psync_fstask_can_unlink(psync_fsfolderid_t folderid, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fstask_folder_t *folder;
  size_t len;
  len=strlen(name);
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder && psync_fstask_find_creat(folder, name, 0))
    psync_fstask_release_folder_tasks_locked(folder);
  else{
    res=psync_sql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, len);
    row=psync_sql_fetch_rowint(res);
    if (!row || (folder && psync_fstask_find_unlink(folder, name, 0))){
      psync_sql_free_result(res);
      if (folder)
        psync_fstask_release_folder_tasks_locked(folder);
      return -ENOENT;
    }
    psync_sql_free_result(res);
    if (folder)
      psync_fstask_release_folder_tasks_locked(folder);
  }
  return 0;
}

int psync_fstask_unlink(psync_fsfolderid_t folderid, const char *name){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fstask_folder_t *folder;
  psync_fstask_unlink_t *task;
  psync_fstask_creat_t *cr;
  uint64_t depend, taskid;
  psync_fsfileid_t fileid, revoffileid;
  psync_fileid_t rfileid;
  size_t len;
  len=strlen(name);
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  cr=psync_fstask_find_creat(folder, name, 0);
  if (cr==NULL){
    res=psync_sql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, len);
    row=psync_sql_fetch_rowint(res);
    if (!row || psync_fstask_find_unlink(folder, name, 0)){
      psync_sql_free_result(res);
      psync_fstask_release_folder_tasks_locked(folder);
      return -ENOENT;
    }
    fileid=row[0];
    psync_sql_free_result(res);
    depend=0;
    rfileid=0;
  }
  else{
    rfileid=cr->rfileid;
    if (unlikely(cr->fileid==0)){
      task=psync_fstask_find_unlink(folder, cr->name, cr->taskid);
      if (likely_log(task)){
        psync_tree_del(&folder->unlinks, &task->tree);
        folder->taskscnt--;
        psync_free(task);
      }
      psync_tree_del(&folder->creats, &cr->tree);
      psync_free(cr);
      folder->taskscnt--;
      psync_fstask_release_folder_tasks_locked(folder);
      return 0;
    }
    depend=cr->taskid;
    fileid=cr->fileid;
    psync_tree_del(&folder->creats, &cr->tree);
    psync_free(cr);
    folder->taskscnt--;
    if (folder->folderid>=0)
      psync_path_status_drive_folder_changed(folder->folderid);
  }
  revoffileid=get_file_at_old_location(fileid);
  psync_sql_start_transaction();
  if (fileid<0)
    psync_fstask_stop_and_delete_file(fileid);
  if (revoffileid){
    res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, fileid, int1, text1, int2) VALUES "
                                 "("NTO_STR(PSYNC_FS_TASK_UN_SET_REV)", 0, ?, ?, ?, ?, ?)");
    psync_sql_bind_int(res, 1, folderid);
    psync_sql_bind_int(res, 2, revoffileid);
    psync_sql_bind_int(res, 3, fileid);
    psync_sql_bind_lstring(res, 4, name, len);
    psync_sql_bind_uint(res, 5, rfileid);
    psync_sql_run_free(res);
  }
  else{
    res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, fileid, text1, int2) VALUES ("NTO_STR(PSYNC_FS_TASK_UNLINK)", ?, ?, ?, ?, ?)");
    psync_sql_bind_int(res, 1, fileid<0?11:0);
    psync_sql_bind_int(res, 2, folderid);
    psync_sql_bind_int(res, 3, fileid);
    psync_sql_bind_lstring(res, 4, name, len);
    psync_sql_bind_uint(res, 5, rfileid);
    psync_sql_run_free(res);
  }
  taskid=psync_sql_insertid();
  if (depend)
    psync_fstask_depend(taskid, depend);
  if (revoffileid<0)
    psync_fstask_depend(taskid, -revoffileid);
  if (fileid<0 && -fileid!=depend)
    psync_fstask_depend(taskid, -fileid);
  psync_fstask_depend_on_name(taskid, folderid, name, len);
  if (unlikely_log(psync_sql_commit_transaction())){
    psync_fstask_release_folder_tasks_locked(folder);
    return -EIO;
  }
  len++;
  task=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  task->taskid=taskid;
  task->fileid=fileid;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &task->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
  if (depend==0 || fileid<0)
    psync_fsupload_wake();
  return 0;
}

static void add_history_record(psync_fileid_t fileid, psync_folderid_t folderid, const char *name){
  file_history_record *rec;
  size_t len;
  char key[16];
  psync_get_string_id(key, "HLOC", fileid);
  while ((rec=(file_history_record *)psync_cache_get(key)))
    psync_free(rec);
  len=strlen(name)+1;
  rec=(file_history_record *)psync_malloc(offsetof(file_history_record, name)+len);
  rec->folderid=folderid;
  memcpy(rec->name, name, len);
  psync_cache_add(key, rec, PSYNC_FS_FILE_LOC_HIST_SEC, psync_free, 1);
}

int psync_fstask_rename_file(psync_fsfileid_t fileid, psync_fsfolderid_t parentfolderid, const char *name, psync_fsfolderid_t to_folderid, const char *new_name){
  psync_sql_res *res;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *rm;
  psync_fileid_t rfileid;
  size_t nlen, nnlen;
  uint64_t ftaskid, ttaskid;
  nlen=strlen(name);
  if (new_name)
    nnlen=strlen(new_name);
  else{
    new_name=name;
    nnlen=nlen;
  }
  folder=psync_fstask_get_or_create_folder_tasks_locked(parentfolderid);
  cr=psync_fstask_find_creat(folder, name, 0);
  if (cr)
    rfileid=cr->rfileid;
  else
    rfileid=0;
  debug(D_NOTICE, "renaming file %ld from %ld/%s to %ld/%s", (long)fileid, (long)parentfolderid, name, (long)to_folderid, new_name);
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, fileid, text1) VALUES ("NTO_STR(PSYNC_FS_TASK_RENFILE_FROM)", 10, ?, ?, ?)");
  psync_sql_bind_int(res, 1, parentfolderid);
  psync_sql_bind_int(res, 2, fileid);
  psync_sql_bind_lstring(res, 3, name, nlen);
  psync_sql_run_free(res);
  ftaskid=psync_sql_insertid();
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, fileid, text1, int1, int2) VALUES ("NTO_STR(PSYNC_FS_TASK_RENFILE_TO)", 0, ?, ?, ?, ?, ?)");
  psync_sql_bind_int(res, 1, to_folderid);
  psync_sql_bind_int(res, 2, fileid);
  psync_sql_bind_lstring(res, 3, new_name, nnlen);
  psync_sql_bind_uint(res, 4, ftaskid);
  psync_sql_bind_uint(res, 5, rfileid);
  psync_sql_run_free(res);
  ttaskid=psync_sql_insertid();
  if (fileid<0){
    res=psync_sql_prep_statement("UPDATE fstask SET sfolderid=? WHERE id=?");
    psync_sql_bind_int(res, 1, to_folderid);
    psync_sql_bind_uint(res, 2, -fileid);
    psync_sql_run_free(res);
    psync_fstask_depend(ttaskid, -fileid);
  }
  if (parentfolderid<0)
    psync_fstask_depend(ttaskid, -parentfolderid);
  if (to_folderid<0 && to_folderid!=parentfolderid)
    psync_fstask_depend(ttaskid, -to_folderid);
  psync_fstask_depend_on_name2(ttaskid, ftaskid, parentfolderid, name, nlen);
  psync_fstask_depend_on_name(ttaskid, to_folderid, new_name, nnlen);
  if (cr)
    psync_fstask_depend(ttaskid, cr->taskid);
  if (unlikely_log(psync_sql_commit_transaction())){
    psync_fstask_release_folder_tasks_locked(folder);
    return -EIO;
  }
  if (cr){
    psync_tree_del(&folder->creats, &cr->tree);
    psync_free(cr);
    folder->taskscnt--;
    if (folder->folderid>=0)
      psync_path_status_drive_folder_changed(folder->folderid);
  }
  psync_fs_rename_openfile_locked(fileid, to_folderid, new_name);
  nlen++;
  rm=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+nlen);
  rm->taskid=ftaskid;
  rm->fileid=fileid;
  memcpy(rm->name, name, nlen);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &rm->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);

  folder=psync_fstask_get_or_create_folder_tasks_locked(to_folderid);
  nnlen++;
  cr=psync_fstask_find_creat(folder, new_name, 0);
  if (cr){
    debug(D_NOTICE, "renaming over creat of file %s(%ld) in folder %lu", new_name, (long)cr->fileid, (unsigned long)to_folderid);
    if (cr->fileid<0)
      psync_fstask_stop_and_delete_file(cr->fileid);
    psync_tree_del(&folder->creats, &cr->tree);
    psync_free(cr);
    folder->taskscnt--;
  }
  rm=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+nnlen);
  rm->fileid=fileid;
  rm->taskid=ttaskid;
  memcpy(rm->name, new_name, nnlen);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &rm->tree);
  cr=(psync_fstask_creat_t *)psync_malloc(offsetof(psync_fstask_creat_t, name)+nnlen);
  cr->fileid=fileid;
  cr->rfileid=rfileid;
  cr->taskid=ttaskid;
  memcpy(cr->name, new_name, nnlen);
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &cr->tree);
  folder->taskscnt+=2;
  psync_fstask_release_folder_tasks_locked(folder);
  psync_fsupload_wake();
  if (fileid>0 && parentfolderid>=0)
    add_history_record(fileid, parentfolderid, name);
  else if (rfileid>0 && parentfolderid>=0)
    add_history_record(rfileid, parentfolderid, name);
  if (folder->folderid>=0)
    psync_path_status_drive_folder_changed(folder->folderid);
  return 0;
}

static void fill_mkdir_data(psync_fsfolderid_t folderid, psync_fstask_mkdir_t *mkdir){
  psync_sql_res *res;
  psync_uint_row row;
  mkdir->ctime=mkdir->mtime=psync_timer_time();
  mkdir->subdircnt=0;
  if (folderid<0){
    res=psync_sql_query("SELECT int1 FROM fstask WHERE id=?");
    psync_sql_bind_uint(res, 1, -folderid);
    if ((row=psync_sql_fetch_rowint(res)))
      mkdir->ctime=mkdir->mtime=row[0];
    psync_sql_free_result(res);
  }
  else{
    res=psync_sql_query("SELECT ctime, mtime, subdircnt FROM folder WHERE id=?");
    psync_sql_bind_uint(res, 1, folderid);
    if ((row=psync_sql_fetch_rowint(res))){
      mkdir->ctime=row[0];
      mkdir->mtime=row[1];
      mkdir->subdircnt=row[2];
    }
    psync_sql_free_result(res);
  }
}

static uint64_t psync_fstask_delete_folder_if_ex(psync_fsfolderid_t folderid, const char *name){
  psync_sql_res *res;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_fsfolderid_t cfolderid;
  psync_uint_row row;
  uint64_t depend, taskid;
  size_t len;
  cfolderid=0;
  depend=0;
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder){
    if ((mk=psync_fstask_find_mkdir(folder, name, 0))){
      cfolderid=mk->folderid;
      depend=mk->taskid;
    }
    else if (psync_fstask_find_rmdir(folder, name, 0)){
      psync_fstask_release_folder_tasks_locked(folder);
      return 0;
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
  len=strlen(name);
  if (cfolderid==0){
    if (folderid<0)
      return 0;
    res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, folderid);
    psync_sql_bind_lstring(res, 2, name, len);
    if ((row=psync_sql_fetch_rowint(res)))
      cfolderid=row[0];
    psync_sql_free_result(res);
    if (cfolderid==0)
      return 0;
  }
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, sfolderid, text1) VALUES ("NTO_STR(PSYNC_FS_TASK_RMDIR)", 0, ?, ?, ?)");
  psync_sql_bind_int(res, 1, folderid);
  psync_sql_bind_int(res, 2, cfolderid);
  psync_sql_bind_lstring(res, 3, name, len);
  psync_sql_run_free(res);
  taskid=psync_sql_insertid();
  if (depend)
    psync_fstask_depend(taskid, depend);
  if (cfolderid<0)
    psync_fstask_depend(taskid, -cfolderid);
  return taskid;
}

int psync_fstask_rename_folder(psync_fsfolderid_t folderid, psync_fsfolderid_t parentfolderid, const char *name,  psync_fsfolderid_t to_folderid,
                               const char *new_name, uint32_t targetflags){
  psync_sql_res *res;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_fstask_rmdir_t *rm;
  size_t nlen, nnlen;
  uint64_t ftaskid, ttaskid, rmtask;
  nlen=strlen(name);
  if (new_name)
    nnlen=strlen(new_name);
  else{
    new_name=name;
    nnlen=nlen;
  }
  psync_sql_start_transaction();
  rmtask=psync_fstask_delete_folder_if_ex(to_folderid, new_name);
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, sfolderid, text1) VALUES ("NTO_STR(PSYNC_FS_TASK_RENFOLDER_FROM)", 10, ?, ?, ?)");
  psync_sql_bind_int(res, 1, parentfolderid);
  psync_sql_bind_int(res, 2, folderid);
  psync_sql_bind_lstring(res, 3, name, nlen);
  psync_sql_run_free(res);
  ftaskid=psync_sql_insertid();
  res=psync_sql_prep_statement("INSERT INTO fstask (type, status, folderid, sfolderid, text1, int1, int2) VALUES ("NTO_STR(PSYNC_FS_TASK_RENFOLDER_TO)", 0, ?, ?, ?, ?, ?)");
  psync_sql_bind_int(res, 1, to_folderid);
  psync_sql_bind_int(res, 2, folderid);
  psync_sql_bind_lstring(res, 3, new_name, nnlen);
  psync_sql_bind_uint(res, 4, ftaskid);
  psync_sql_bind_uint(res, 5, targetflags);
  psync_sql_run_free(res);
  ttaskid=psync_sql_insertid();
  if (folderid<0){
    res=psync_sql_prep_statement("UPDATE fstask SET sfolderid=? WHERE id=?");
    psync_sql_bind_int(res, 1, to_folderid);
    psync_sql_bind_int(res, 2, -folderid);
    psync_sql_run_free(res);
    psync_fstask_depend(ttaskid, -folderid);
  }
  if (rmtask)
    psync_fstask_depend(ttaskid, rmtask);
  if (parentfolderid<0)
    psync_fstask_depend(ttaskid, -parentfolderid);
  if (to_folderid<0 && to_folderid!=parentfolderid)
    psync_fstask_depend(ttaskid, -to_folderid);
  psync_fstask_depend_on_name2(ttaskid, ftaskid, parentfolderid, name, nlen);
  psync_fstask_depend_on_name(ttaskid, folderid, new_name, nnlen);
  folder=psync_fstask_get_or_create_folder_tasks_locked(parentfolderid);
  mk=psync_fstask_find_mkdir(folder, name, 0);
  if (mk)
    psync_fstask_depend(ttaskid, mk->taskid);
  if (unlikely_log(psync_sql_commit_transaction())){
    psync_fstask_release_folder_tasks_locked(folder);
    return -EIO;
  }
  if (mk){
    psync_tree_del(&folder->mkdirs, &mk->tree);
    psync_free(mk);
    folder->taskscnt--;
  }
  nlen++;
  rm=(psync_fstask_rmdir_t *)psync_malloc(offsetof(psync_fstask_rmdir_t, name)+nlen);
  rm->taskid=ftaskid;
  rm->folderid=folderid;
  memcpy(rm->name, name, nlen);
  psync_fstask_insert_into_tree(&folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), &rm->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
  folder=psync_fstask_get_or_create_folder_tasks_locked(to_folderid);
  mk=psync_fstask_find_mkdir(folder, name, 0);
  if (mk){
    debug(D_NOTICE, "renaming over mkdir %s", name);
    psync_tree_del(&folder->mkdirs, &mk->tree);
    psync_free(mk);
    folder->taskscnt--;
  }
  nnlen++;
  rm=(psync_fstask_rmdir_t *)psync_malloc(offsetof(psync_fstask_rmdir_t, name)+nnlen);
  rm->taskid=ttaskid;
  rm->folderid=folderid;
  memcpy(rm->name, new_name, nnlen);
  psync_fstask_insert_into_tree(&folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), &rm->tree);
  mk=(psync_fstask_mkdir_t *)psync_malloc(offsetof(psync_fstask_mkdir_t, name)+nnlen);
  mk->taskid=ttaskid;
  mk->folderid=folderid;
  mk->flags=targetflags;
  memcpy(mk->name, new_name, nnlen);
  fill_mkdir_data(folderid, mk);
  psync_fstask_insert_into_tree(&folder->mkdirs, offsetof(psync_fstask_mkdir_t, name), &mk->tree);
  folder->taskscnt+=2;
  psync_fstask_release_folder_tasks_locked(folder);
  psync_fsupload_wake();
  if (to_folderid>=0)
    psync_path_status_drive_folder_changed(to_folderid);
  return 0;
}

static int folder_cmp(const psync_tree *t1, const psync_tree *t2){
  int64_t d=psync_tree_element(t1, psync_fstask_folder_t, tree)->folderid-psync_tree_element(t2, psync_fstask_folder_t, tree)->folderid;
  if (d<0)
    return -1;
  else if (d>0)
    return 1;
  else
    return 0;
}

void psync_fstask_folder_created(psync_folderid_t parentfolderid, uint64_t taskid, psync_folderid_t folderid, const char *name){
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  int pchg;
  pchg=0;
  folder=psync_fstask_get_folder_tasks_locked(parentfolderid);
  if (folder){
    mk=psync_fstask_find_mkdir(folder, name, taskid);
    if (mk){
      psync_tree_del(&folder->mkdirs, &mk->tree);
      psync_free(mk);
      folder->taskscnt--;
      pchg=1;
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
  if (!folder || !mk){
    psync_sql_res *res;
    psync_uint_row row;
    psync_fsfolderid_t sfolderid;
    debug(D_NOTICE, "could not find mkdir (taskid %lu) for created folder %s in folder %lu", (unsigned long)taskid, name, (unsigned long)parentfolderid);
    res=psync_sql_query("SELECT sfolderid FROM fstask WHERE id=?");
    psync_sql_bind_uint(res, 1, taskid);
    row=psync_sql_fetch_rowint(res);
    if (unlikely_log(!row))
      psync_sql_free_result(res);
    else{
      sfolderid=row[0];
      psync_sql_free_result(res);
      folder=psync_fstask_get_folder_tasks_locked(sfolderid);
      if (folder){
        mk=psync_fstask_find_mkdir_by_folderid(folder, -(psync_fsfolderid_t)taskid);
        if (mk){
          debug(D_NOTICE, "found taskid %lu in folderid %ld as %s", (unsigned long)taskid, (long)sfolderid, mk->name);
          mk->folderid=folderid;
        }
        psync_fstask_release_folder_tasks_locked(folder);
      }
    }
  }
  folder=psync_fstask_get_folder_tasks_locked(-(psync_fsfolderid_t)taskid);
  if (folder){
    debug(D_NOTICE, "re-inserting into tree folder diffs of folder %ld as %lu", (long)folder->folderid, (unsigned long)folderid);
    psync_tree_del(&folders, &folder->tree);
    folder->folderid=folderid;
    psync_tree_add(&folders, &folder->tree, folder_cmp);
    psync_fstask_release_folder_tasks_locked(folder);
    psync_path_status_drive_folder_changed(folderid);
  }
  if (pchg)
    psync_path_status_drive_folder_changed(parentfolderid);
}

void psync_fstask_folder_deleted(psync_folderid_t parentfolderid, uint64_t taskid, const char *name){
  psync_fstask_folder_t *folder;
  psync_fstask_rmdir_t *rm;
  folder=psync_fstask_get_folder_tasks_locked(parentfolderid);
  if (folder){
    rm=psync_fstask_find_rmdir(folder, name, taskid);
    if (rm){
      psync_tree_del(&folder->rmdirs, &rm->tree);
      psync_free(rm);
      folder->taskscnt--;
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
}

static void psync_fstask_look_for_creat_in_db(psync_folderid_t parentfolderid, uint64_t taskid, const char *name, psync_fileid_t fileid){
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_sql_res *res;
  psync_uint_row row;
  psync_fsfolderid_t sfolderid;
  debug(D_NOTICE, "could not find creat (taskid %lu) for uploaded file %s in folder %lu", (unsigned long)taskid, name, (unsigned long)parentfolderid);
  res=psync_sql_query("SELECT sfolderid FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, taskid);
  row=psync_sql_fetch_rowint(res);
  if (unlikely_log(!row)){
    psync_sql_free_result(res);
    return;
  }
  sfolderid=row[0];
  psync_sql_free_result(res);
  folder=psync_fstask_get_folder_tasks_locked(sfolderid);
  if (folder){
    cr=psync_fstask_find_creat_by_fileid(folder, -(psync_fsfileid_t)taskid);
    if (cr){
      debug(D_NOTICE, "found taskid %lu in folderid %ld as %s", (unsigned long)taskid, (long)sfolderid, cr->name);
      cr->fileid=fileid;
    }
    else
      debug(D_NOTICE, "could not find creat (taskid %lu) for uploaded file %s in folder %lu even after looking in db", (unsigned long)taskid, name, (unsigned long)parentfolderid);
    psync_fstask_release_folder_tasks_locked(folder);
  }
}

void psync_fstask_file_created(psync_folderid_t parentfolderid, uint64_t taskid, const char *name, psync_fileid_t fileid){
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  folder=psync_fstask_get_folder_tasks_locked(parentfolderid);
  if (folder){
    cr=psync_fstask_find_creat(folder, name, taskid);
    if (cr){
      psync_tree_del(&folder->creats, &cr->tree);
      psync_free(cr);
      folder->taskscnt--;
    }
    un=psync_fstask_find_unlink(folder, name, taskid);
    if (un){
      psync_tree_del(&folder->unlinks, &un->tree);
      psync_free(un);
      folder->taskscnt--;
    }
    else
      debug(D_NOTICE, "could not find unlink for file %s in folderid %lu", name, (unsigned long)parentfolderid);
    psync_fstask_release_folder_tasks_locked(folder);
    if (cr)
      psync_path_status_drive_folder_changed(parentfolderid);
  }
  else
    debug(D_NOTICE, "could not find unlink for file %s in folderid %lu", name, (unsigned long)parentfolderid);
  if (!folder || !cr)
    psync_fstask_look_for_creat_in_db(parentfolderid, taskid, name, fileid);
}

void psync_fstask_file_modified(psync_folderid_t parentfolderid, uint64_t taskid, const char *name, psync_fileid_t fileid){
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  folder=psync_fstask_get_folder_tasks_locked(parentfolderid);
  if (folder){
    cr=psync_fstask_find_creat(folder, name, taskid);
    if (cr){
      psync_tree_del(&folder->creats, &cr->tree);
      psync_free(cr);
      folder->taskscnt--;
    }
    un=psync_fstask_find_unlink(folder, name, taskid);
    if (un){
      psync_tree_del(&folder->unlinks, &un->tree);
      psync_free(un);
      folder->taskscnt--;
    }
    psync_fstask_release_folder_tasks_locked(folder);
    if (cr)
      psync_path_status_drive_folder_changed(parentfolderid);
  }
  if (!folder || !cr)
    psync_fstask_look_for_creat_in_db(parentfolderid, taskid, name, fileid);
}

void psync_fstask_file_deleted(psync_folderid_t parentfolderid, uint64_t taskid, const char *name){
  psync_fstask_folder_t *folder;
  psync_fstask_unlink_t *un;
  folder=psync_fstask_get_folder_tasks_locked(parentfolderid);
  if (folder){
    un=psync_fstask_find_unlink(folder, name, taskid);
    if (un){
      psync_tree_del(&folder->unlinks, &un->tree);
      psync_free(un);
      folder->taskscnt--;
    }
    psync_fstask_release_folder_tasks_locked(folder);
  }
}

void psync_fstask_file_renamed(psync_folderid_t folderid, uint64_t taskid, const char *name, uint64_t frtaskid){
  psync_sql_res *res;
  psync_fstask_folder_t *folder;
  psync_fstask_unlink_t *un;
  psync_fstask_creat_t *cr;
  psync_variant_row row;
  folder=psync_fstask_get_folder_tasks_locked(folderid);
  if (folder){
    un=psync_fstask_find_unlink(folder, name, taskid);
    if (un){
      psync_tree_del(&folder->unlinks, &un->tree);
      psync_free(un);
      folder->taskscnt--;
    }
    cr=psync_fstask_find_creat(folder, name, taskid);
    if (cr){
      psync_tree_del(&folder->creats, &cr->tree);
      psync_free(cr);
      folder->taskscnt--;
    }
    psync_fstask_release_folder_tasks_locked(folder);
    if (cr)
      psync_path_status_drive_folder_changed(folderid);
  }
  res=psync_sql_query("SELECT id, folderid, text1 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, frtaskid);
  if (likely_log(row=psync_sql_fetch_row(res))){
    folder=psync_fstask_get_folder_tasks_locked(psync_get_snumber(row[1]));
    if (folder){
      un=psync_fstask_find_unlink(folder, psync_get_string(row[2]), psync_get_number(row[0]));
      if (un){
        psync_tree_del(&folder->unlinks, &un->tree);
        psync_free(un);
        folder->taskscnt--;
      }
      psync_fstask_release_folder_tasks_locked(folder);
    }
  }
  psync_sql_free_result(res);
  res=psync_sql_prep_statement("DELETE FROM fstaskdepend WHERE dependfstaskid=?");
  psync_sql_bind_uint(res, 1, frtaskid);
  psync_sql_run_free(res);
  if (psync_sql_affected_rows())
    psync_fsupload_wake();
  res=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, frtaskid);
  psync_sql_run_free(res);
}

void psync_fstask_folder_renamed(psync_folderid_t parentfolderid, uint64_t taskid, const char *name, uint64_t frtaskid){
  psync_sql_res *res;
  psync_fstask_folder_t *folder;
  psync_fstask_rmdir_t *rm;
  psync_fstask_mkdir_t *mk;
  psync_variant_row row;
  folder=psync_fstask_get_folder_tasks_locked(parentfolderid);
  if (folder){
    mk=psync_fstask_find_mkdir(folder, name, taskid);
    if (mk){
      psync_tree_del(&folder->mkdirs, &mk->tree);
      psync_free(mk);
      folder->taskscnt--;
    }
    rm=psync_fstask_find_rmdir(folder, name, taskid);
    if (rm){
      psync_tree_del(&folder->rmdirs, &rm->tree);
      psync_free(rm);
      folder->taskscnt--;
    }
    psync_fstask_release_folder_tasks_locked(folder);
    if (mk)
      psync_path_status_drive_folder_changed(parentfolderid);
  }
  res=psync_sql_query("SELECT id, folderid, text1 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, frtaskid);
  if (likely_log(row=psync_sql_fetch_row(res))){
    folder=psync_fstask_get_folder_tasks_locked(psync_get_snumber(row[1]));
    if (folder){
      rm=psync_fstask_find_rmdir(folder, psync_get_string(row[2]), psync_get_number(row[0]));
      if (rm){
        psync_tree_del(&folder->rmdirs, &rm->tree);
        psync_free(rm);
        folder->taskscnt--;
      }
      psync_fstask_release_folder_tasks_locked(folder);
    }
  }
  psync_sql_free_result(res);
  res=psync_sql_prep_statement("DELETE FROM fstaskdepend WHERE dependfstaskid=?");
  psync_sql_bind_uint(res, 1, frtaskid);
  psync_sql_run_free(res);
  if (psync_sql_affected_rows())
    psync_fsupload_wake();
  res=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, frtaskid);
  psync_sql_run_free(res);
}

static void psync_init_task_mkdir(psync_variant_row row){
  uint64_t taskid;
  psync_fsfolderid_t folderid;
  const char *name;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *task;
  time_t ctime;
  size_t len;
  taskid=psync_get_number(row[0]);
  folderid=psync_get_snumber(row[2]);
  name=psync_get_lstring(row[4], &len);
  ctime=psync_get_number(row[6]);
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  len++;
  task=(psync_fstask_mkdir_t *)psync_malloc(offsetof(psync_fstask_mkdir_t, name)+len);
  task->taskid=taskid;
  task->ctime=task->mtime=ctime;
  task->folderid=-(psync_fsfolderid_t)taskid;
  task->subdircnt=0;
  task->flags=psync_is_null(row[5])?0:PSYNC_FOLDER_FLAG_ENCRYPTED;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->mkdirs, offsetof(psync_fstask_mkdir_t, name), &task->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
  if (folderid>=0)
    psync_path_status_drive_folder_changed(folderid);
}

static void psync_init_task_rmdir(psync_variant_row row){
  uint64_t taskid;
  psync_fsfolderid_t cfolderid, folderid;
  const char *name;
  psync_fstask_folder_t *folder;
  psync_fstask_rmdir_t *task;
  psync_fstask_mkdir_t *mk;
  size_t len;
  taskid=psync_get_number(row[0]);
  folderid=psync_get_snumber(row[2]);
  name=psync_get_lstring(row[4], &len);
  cfolderid=psync_get_snumber(row[8]);
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  mk=psync_fstask_find_mkdir(folder, name, 0);
  if (mk){
    psync_tree_del(&folder->mkdirs, &mk->tree);
    psync_free(mk);
    folder->taskscnt--;
  }
  len++;
  task=(psync_fstask_rmdir_t *)psync_malloc(offsetof(psync_fstask_rmdir_t, name)+len);
  task->taskid=taskid;
  task->folderid=cfolderid;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), &task->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
}

static void psync_init_task_creat(psync_variant_row row){
  uint64_t taskid;
  psync_fstask_unlink_t *un;
  psync_fstask_creat_t *task;
  psync_fstask_folder_t *folder;
  const char *name;
  psync_fsfolderid_t folderid;
  size_t len;
  taskid=psync_get_number(row[0]);
  folderid=psync_get_snumber(row[2]);
  name=psync_get_lstring(row[4], &len);
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  len++;
  un=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  un->fileid=-(psync_fsfileid_t)taskid;
  un->taskid=taskid;
  memcpy(un->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &un->tree);
  task=(psync_fstask_creat_t *)psync_malloc(offsetof(psync_fstask_creat_t, name)+len);
  task->fileid=-(psync_fsfileid_t)taskid;
  task->rfileid=psync_get_number(row[3]);
  task->taskid=taskid;
  memcpy(task->name, name, len);
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &task->tree);
  folder->taskscnt+=2;
  psync_fstask_release_folder_tasks_locked(folder);
  if (folderid>=0)
    psync_path_status_drive_folder_changed(folderid);
}


static void psync_init_do_task_unlink(uint64_t taskid, psync_fsfolderid_t folderid, const char *name, size_t namelen, psync_fsfileid_t fileid){
  psync_fstask_folder_t *folder;
  psync_fstask_unlink_t *task;
  psync_fstask_creat_t *cr;
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  cr=psync_fstask_find_creat(folder, name, 0);
  if (cr){
    psync_tree_del(&folder->creats, &cr->tree);
    psync_free(cr);
    folder->taskscnt--;
  }
  namelen++;
  task=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+namelen);
  task->taskid=taskid;
  task->fileid=fileid;
  memcpy(task->name, name, namelen);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &task->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
}

static void psync_init_task_unlink(psync_variant_row row){
  const char *name;
  size_t len;
  name=psync_get_lstring(row[4], &len);
  psync_init_do_task_unlink(psync_get_number(row[0]), psync_get_snumber(row[2]), name, len, psync_get_snumber(row[3]));
}

static void psync_init_task_unlink_set_rev(psync_variant_row row){
  const char *name;
  size_t len;
  name=psync_get_lstring(row[4], &len);
  psync_init_do_task_unlink(psync_get_number(row[0]), psync_get_snumber(row[2]), name, len, psync_get_snumber(row[6]));
}

static void psync_init_task_renfile_from(psync_variant_row row){
  const char *name;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *rm;
  size_t len;
  name=psync_get_lstring(row[4], &len);
  folder=psync_fstask_get_or_create_folder_tasks_locked(psync_get_number(row[2]));
  if ((cr=psync_fstask_find_creat(folder, name, 0))){
    psync_tree_del(&folder->creats, &cr->tree);
    psync_free(cr);
    folder->taskscnt--;
  }
  len++;
  rm=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  rm->taskid=psync_get_number(row[0]);
  rm->fileid=psync_get_snumber(row[3]);
  memcpy(rm->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &rm->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
}

static void psync_init_task_renfile_to(psync_variant_row row){
  const char *name;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  psync_fstask_folder_t *folder;
  psync_fsfolderid_t folderid;
  uint64_t taskid;
  psync_fsfileid_t fileid;
  size_t len;
  name=psync_get_lstring(row[4], &len);
  folderid=psync_get_snumber(row[2]);
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  cr=psync_fstask_find_creat(folder, name, 0);
  if (cr){
    psync_tree_del(&folder->creats, &cr->tree);
    folder->taskscnt--;
    psync_free(cr);
  }
  len++;
  taskid=psync_get_number(row[0]);
  fileid=psync_get_snumber(row[3]);
  un=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  un->fileid=fileid;
  un->taskid=taskid;
  memcpy(un->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_creat_t, name), &un->tree);
  cr=(psync_fstask_creat_t *)psync_malloc(offsetof(psync_fstask_creat_t, name)+len);
  cr->fileid=fileid;
  cr->rfileid=psync_get_number(row[7]);
  cr->taskid=taskid;
  memcpy(cr->name, name, len);
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &cr->tree);
  folder->taskscnt+=2;
  psync_fstask_release_folder_tasks_locked(folder);
  psync_fs_rename_openfile_locked(cr->fileid, folderid, name);
  if (folderid>=0)
    psync_path_status_drive_folder_changed(folderid);
}

static void psync_init_task_renfolder_from(psync_variant_row row){
  const char *name;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_fstask_rmdir_t *rm;
  size_t len;
  name=psync_get_lstring(row[4], &len);
  folder=psync_fstask_get_or_create_folder_tasks_locked(psync_get_number(row[2]));
  if ((mk=psync_fstask_find_mkdir(folder, name, 0))){
    psync_tree_del(&folder->mkdirs, &mk->tree);
    psync_free(mk);
    folder->taskscnt--;
  }
  len++;
  rm=(psync_fstask_rmdir_t *)psync_malloc(offsetof(psync_fstask_rmdir_t, name)+len);
  rm->taskid=psync_get_number(row[0]);
  rm->folderid=psync_get_snumber(row[8]);
  memcpy(rm->name, name, len);
  psync_fstask_insert_into_tree(&folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), &rm->tree);
  folder->taskscnt++;
  psync_fstask_release_folder_tasks_locked(folder);
}

static void psync_init_task_renfolder_to(psync_variant_row row){
  const char *name;
  psync_fstask_mkdir_t *mk;
  psync_fstask_rmdir_t *rm;
  psync_fstask_folder_t *folder;
  psync_fsfolderid_t folderid;
  uint64_t taskid;
  size_t len;
  name=psync_get_lstring(row[4], &len);
  folder=psync_fstask_get_or_create_folder_tasks_locked(psync_get_number(row[2]));
  len++;
  taskid=psync_get_number(row[0]);
  folderid=psync_get_snumber(row[8]);
  rm=(psync_fstask_rmdir_t *)psync_malloc(offsetof(psync_fstask_rmdir_t, name)+len);
  rm->taskid=taskid;
  rm->folderid=folderid;
  memcpy(rm->name, name, len);
  psync_fstask_insert_into_tree(&folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), &rm->tree);
  mk=(psync_fstask_mkdir_t *)psync_malloc(offsetof(psync_fstask_mkdir_t, name)+len);
  mk->taskid=taskid;
  mk->folderid=folderid;
  mk->flags=psync_get_number(row[7]);
  memcpy(mk->name, name, len);
  fill_mkdir_data(mk->folderid, mk);
  psync_fstask_insert_into_tree(&folder->mkdirs, offsetof(psync_fstask_mkdir_t, name), &mk->tree);
  folder->taskscnt+=2;
  psync_fstask_release_folder_tasks_locked(folder);
  if (folderid>=0)
    psync_path_status_drive_folder_changed(folderid);
}

static void psync_init_task_modify(psync_variant_row row){
  psync_fstask_unlink_t *un;
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  uint64_t taskid;
  const char *name;
  size_t len;
  name=psync_get_lstring(row[4], &len);
  folder=psync_fstask_get_or_create_folder_tasks_locked(psync_get_number(row[2]));
  taskid=psync_get_number(row[0]);
  cr=psync_fstask_find_creat(folder, name, 0);
  if (cr){
    psync_tree_del(&folder->creats, &cr->tree);
    psync_free(cr);
    folder->taskscnt--;
  }
  len++;
  un=(psync_fstask_unlink_t *)psync_malloc(offsetof(psync_fstask_unlink_t, name)+len);
  un->fileid=psync_get_snumber(row[3]);
  un->taskid=taskid;
  memcpy(un->name, name, len);
  psync_fstask_insert_into_tree(&folder->unlinks, offsetof(psync_fstask_unlink_t, name), &un->tree);
  cr=(psync_fstask_creat_t *)psync_malloc(offsetof(psync_fstask_creat_t, name)+len);
  cr->fileid=-(psync_fsfileid_t)cr->taskid;
  cr->rfileid=psync_get_number(row[3]);
  cr->taskid=taskid;
  memcpy(cr->name, name, len);
  psync_fstask_insert_into_tree(&folder->creats, offsetof(psync_fstask_creat_t, name), &cr->tree);
  folder->taskscnt+=2;
  if (folder->folderid>=0)
    psync_path_status_drive_folder_changed(folder->folderid);
  psync_fstask_release_folder_tasks_locked(folder);
}

typedef void (*psync_init_task_ptr)(psync_variant_row);

static psync_init_task_ptr psync_init_task_func[]={
  NULL,
  psync_init_task_mkdir,
  psync_init_task_rmdir,
  psync_init_task_creat,
  psync_init_task_unlink,
  psync_init_task_renfile_from,
  psync_init_task_renfile_to,
  psync_init_task_renfolder_from,
  psync_init_task_renfolder_to,
  psync_init_task_modify,
  psync_init_task_unlink_set_rev
};

static void psync_fstask_free_tree(psync_tree *tr){
  psync_tree *ntr;
  tr=psync_tree_get_first_safe(tr);
  while (tr){
    ntr=psync_tree_get_next_safe(tr);
    psync_free(tr);
    tr=ntr;
  }
}

void psync_fstask_clean(){
  psync_fstask_folder_t *folder;
  psync_tree *tr;
  psync_sql_lock();
  tr=psync_tree_get_first(folders);
  while (tr){
    folder=psync_tree_element(tr, psync_fstask_folder_t, tree);
    tr=psync_tree_get_next(tr);
    psync_fstask_free_tree(folder->creats);
    psync_fstask_free_tree(folder->unlinks);
    psync_fstask_free_tree(folder->mkdirs);
    psync_fstask_free_tree(folder->rmdirs);
    if (folder->refcnt==0){
      psync_tree_del(&folders, &folder->tree);
      psync_free(folder);
    }
    else{
      folder->creats=PSYNC_TREE_EMPTY;
      folder->unlinks=PSYNC_TREE_EMPTY;
      folder->mkdirs=PSYNC_TREE_EMPTY;
      folder->rmdirs=PSYNC_TREE_EMPTY;
      folder->taskscnt=0;
    }
  }
  psync_sql_unlock();
}

void psync_fstask_add_banned_folder(psync_fsfolderid_t folderid, const char *name){
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_fstask_rmdir_t *rm;
  size_t len;
  len=strlen(name)+1;
  mk=(psync_fstask_mkdir_t *)psync_malloc(offsetof(psync_fstask_mkdir_t, name)+len);
  mk->taskid=0;
  mk->ctime=mk->mtime=0;
  mk->folderid=0;
  mk->subdircnt=0;
  mk->flags=PSYNC_FOLDER_FLAG_INVISIBLE;
  memcpy(mk->name, name, len);
  rm=(psync_fstask_rmdir_t *)psync_malloc(offsetof(psync_fstask_rmdir_t, name)+len);
  rm->taskid=0;
  rm->folderid=0;
  memcpy(rm->name, name, len);
  psync_sql_lock();
  folder=psync_fstask_get_or_create_folder_tasks_locked(folderid);
  psync_fstask_insert_into_tree(&folder->mkdirs, offsetof(psync_fstask_mkdir_t, name), &mk->tree);
  psync_fstask_insert_into_tree(&folder->rmdirs, offsetof(psync_fstask_rmdir_t, name), &rm->tree);
  folder->taskscnt+=2;
  psync_fstask_release_folder_tasks_locked(folder);
  psync_sql_unlock();
}

void psync_fstask_add_banned_folders(){
#if defined(P_OS_MACOSX)
  psync_fstask_add_banned_folder(0, ".TemporaryItems");
#endif
}

void psync_fstask_init(){
  psync_uint_t tp;
  psync_sql_res *res;
  psync_variant_row row;
  res=psync_sql_prep_statement("UPDATE fstask SET status=0 WHERE status IN (1, 2)");
  psync_sql_run_free(res);
  res=psync_sql_prep_statement("UPDATE fstask SET status=11 WHERE status=12");
  psync_sql_run_free(res);
  res=psync_sql_query("SELECT id, type, folderid, fileid, text1, text2, int1, int2, sfolderid FROM fstask WHERE status NOT IN (3) ORDER BY id");
  while ((row=psync_sql_fetch_row(res))){
    tp=psync_get_number(row[1]);
    if (!tp || tp>=ARRAY_SIZE(psync_init_task_func)){
      debug(D_BUG, "invalid fstask type %lu", (long unsigned)tp);
      continue;
    }
    psync_init_task_func[tp](row);
  }
  psync_sql_free_result(res);
  psync_fsupload_init();
}

#if IS_DEBUG

void psync_fstask_dump_state(){
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_fstask_rmdir_t *rm;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  uint32_t cnt;
  psync_tree_for_each_element(folder, folders, psync_fstask_folder_t, tree){
    debug(D_NOTICE, "open folderid %ld taskcnt %u refcnt %u", (long)folder->folderid, (unsigned)folder->taskscnt, (unsigned)folder->refcnt);
    cnt=0;
    psync_tree_for_each_element(mk, folder->mkdirs, psync_fstask_mkdir_t, tree){
      debug(D_NOTICE, "  mkdir %s folderid %ld taskid %lu", mk->name, (long)mk->folderid, (unsigned long)mk->taskid);
      cnt++;
    }
    psync_tree_for_each_element(rm, folder->rmdirs, psync_fstask_rmdir_t, tree){
      debug(D_NOTICE, "  mkdir %s folderid %ld taskid %lu", rm->name, (long)rm->folderid, (unsigned long)rm->taskid);
      cnt++;
    }
    psync_tree_for_each_element(cr, folder->creats, psync_fstask_creat_t, tree){
      debug(D_NOTICE, "  creat %s fileid %ld taskid %lu", cr->name, (long)cr->fileid, (unsigned long)cr->taskid);
      cnt++;
    }
    psync_tree_for_each_element(un, folder->unlinks, psync_fstask_unlink_t, tree){
      debug(D_NOTICE, "  unlink %s fileid %ld taskid %lu", un->name, (long)un->fileid, (unsigned long)un->taskid);
      cnt++;
    }
    if (cnt!=folder->taskscnt)
      debug(D_ERROR, "inconsistency found, counted taskcnt %u != taskcnt %u", (unsigned)cnt, (unsigned)folder->taskscnt);
  }
}

#endif
