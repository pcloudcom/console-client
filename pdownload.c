/* Copyright (c) 2013 Anton Titov.
 * Copyright (c) 2013 pCloud Ltd.
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

#include "pdownload.h"
#include "pstatus.h"
#include "ptimer.h"
#include "plibs.h"
#include "ptasks.h"
#include "pstatus.h"
#include "psettings.h"
#include "pnetlibs.h"
#include "pcallbacks.h"
#include "pfolder.h"
#include "psyncer.h"

static pthread_mutex_t download_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t download_cond=PTHREAD_COND_INITIALIZER;
static uint32_t download_wakes=0;
static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE)
};

static int task_mkdir(const char *path){
  while (1){
    if (likely(!psync_mkdir(path))){
      psync_set_local_full(0);
      return 0;
    }
    if (psync_fs_err()==P_NOSPC || psync_fs_err()==P_DQUOT){
      psync_set_local_full(1);
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
    }
    else {
      psync_set_local_full(0);
      if (psync_fs_err()==P_NOENT)
        return 0; // do we have a choice? the user deleted the directory
      else if (psync_fs_err()==P_EXIST){
        psync_stat_t st;
        if (psync_stat(path, &st)){
          debug(D_BUG, "mkdir failed with EEXIST, but stat returned error. race?");
          return -1;
        }
        if (psync_stat_isfolder(&st))
          return 0;
        if (psync_rename_conflicted_file(path))
          return -1;
      }
      else
        return -1;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  }
}

static int task_rmdir(const char *path){
  if (likely(!psync_rmdir_with_trashes(path)))
    return 0;
  if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
    return -1;
  return 0;
//  if (psync_fs_err()==P_NOENT || psync_fs_err()==P_NOTDIR || psync_fs_err()==P_NOTEMPTY || psync_fs_err()==P_EXIST)
//    return 0;
}

static int task_rmdir_rec(const char *path){
  if (likely(!psync_rmdir_recursive(path)))
    return 0;
  if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
    return -1;
  return 0;
}

static void do_move(void *ptr, psync_pstat *st){
  const char **arr;
  char *oldpath, *newpath;
  arr=(const char **)ptr;
  oldpath=psync_strcat(arr[0], st->name, NULL);
  newpath=psync_strcat(arr[1], st->name, NULL);
  if (st->isfolder)
    psync_rendir(oldpath, newpath);
  else
    psync_file_rename(oldpath, newpath);
  psync_free(newpath);
  psync_free(oldpath);
}

static int move_folder_contents(const char *oldpath, const char *newpath){
  const char *arr[2];
  arr[0]=oldpath;
  arr[1]=newpath;
  psync_list_dir(oldpath, do_move, (void *)arr);
  return psync_rmdir_with_trashes(oldpath);
}

static int task_renamedir(const char *oldpath, const char *newpath){
  while (1){
    if (likely(!psync_rendir(oldpath, newpath))){
      psync_set_local_full(0);
      return 0;
    }
    if (psync_fs_err()==P_NOSPC || psync_fs_err()==P_DQUOT){
      psync_set_local_full(1);
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
    }
    else {
      psync_set_local_full(0);
      if (psync_fs_err()==P_BUSY || psync_fs_err()==P_ROFS)
        return -1;
      if (psync_fs_err()==P_NOENT)
        return 0;
      else if (psync_fs_err()==P_EXIST || psync_fs_err()==P_NOTEMPTY || psync_fs_err()==P_NOTDIR){
        psync_stat_t st;
        if (psync_stat(newpath, &st)){
          debug(D_BUG, "rename failed with EEXIST, but stat returned error. race?");
          return -1;
        }
        if (psync_stat_isfolder(&st))
          return move_folder_contents(oldpath, newpath);
        if (psync_rename_conflicted_file(newpath))
          return -1;
      }
      else
        return -1;
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  }
}

static void update_local_folder_mtime(const char *localpath, psync_folderid_t localfolderid){
  psync_stat_t st;
  psync_sql_res *res;
  if (psync_stat(localpath, &st)){
    debug(D_ERROR, "stat failed for %s", localpath);
    return;
  }
  res=psync_sql_prep_statement("UPDATE localfolder SET inode=?, mtime=? WHERE id=?");
  psync_sql_bind_uint(res, 1, psync_stat_inode(&st));
  psync_sql_bind_uint(res, 2, psync_stat_mtime(&st));
  psync_sql_bind_uint(res, 3, localfolderid);
  psync_sql_run(res);
  psync_sql_free_result(res);
}

static int call_func_for_folder(psync_folderid_t localfolderid, psync_folderid_t folderid, psync_syncid_t syncid, psync_eventtype_t event, 
                                int (*func)(const char *), int updatemtime, const char *debug){
  char *localpath;
  int res;
  localpath=psync_local_path_for_local_folder(localfolderid, syncid, NULL);
  if (likely(localpath)){
    res=func(localpath);
    if (!res){
      psync_send_event_by_id(event, syncid, localpath, folderid);
      if (updatemtime)
        update_local_folder_mtime(localpath, localfolderid);
      psync_decrease_local_folder_taskcnt(localfolderid);
      debug(D_NOTICE, "%s %s", debug, localpath);
    }
    psync_free(localpath);
  }
  else{
    debug(D_ERROR, "could not get path for local folder id %lu, syncid %u", (long unsigned)localfolderid, (unsigned)syncid);
    res=0;
  }
  return res;
}

static void delete_local_folder_from_db(psync_folderid_t localfolderid){
  psync_sql_res *res;
  if (likely(localfolderid)){
    res=psync_sql_prep_statement("DELETE FROM localfolder WHERE id=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    psync_sql_run(res);
    psync_sql_free_result(res);
  }
}

static int task_renamefolder(psync_syncid_t newsyncid, psync_folderid_t folderid, psync_folderid_t localfolderid,
                             psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  uint64_t *row;
  char *oldpath, *newpath;
  psync_syncid_t oldsyncid;
  int ret;
  assert(newname!=NULL);
  res=psync_sql_query("SELECT syncid FROM localfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  row=psync_sql_fetch_rowint(res);
  if (unlikely(!row)){
    psync_sql_free_result(res);
    debug(D_ERROR, "could not find local folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  oldsyncid=row[0];
  psync_sql_free_result(res);
  oldpath=psync_local_path_for_local_folder(localfolderid, oldsyncid, NULL);
  if (unlikely(!oldpath)){
    debug(D_ERROR, "could not get local path for folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("UPDATE localfolder SET syncid=?, localparentfolderid=?, name=? WHERE id=?");
  psync_sql_bind_uint(res, 1, newsyncid);
  psync_sql_bind_uint(res, 2, newlocalparentfolderid);
  psync_sql_bind_string(res, 3, newname);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_run(res);
  psync_sql_free_result(res);
  newpath=psync_local_path_for_local_folder(localfolderid, newsyncid, NULL);
  if (unlikely(!newpath)){
    psync_sql_rollback_transaction();
    psync_free(oldpath);
    debug(D_ERROR, "could not get local path for folder id %lu", (unsigned long)localfolderid);
    return 0;
  }
  ret=task_renamedir(oldpath, newpath);
  if (ret)
    psync_sql_rollback_transaction();
  else{
    psync_decrease_local_folder_taskcnt(localfolderid);
    psync_sql_commit_transaction();
    psync_send_event_by_id(PEVENT_LOCAL_FOLDER_RENAMED, newsyncid, newpath, folderid);
    debug(D_NOTICE, "local folder renamed from %s ro %s", oldpath, newpath);
  }
  psync_free(newpath);
  psync_free(oldpath);
  return ret;
}
  
static int download_task(uint32_t type, psync_syncid_t syncid, uint64_t itemid, uint64_t localitemid, uint64_t newitemid, const char *name){
  int res;
  if (type==PSYNC_CREATE_LOCAL_FOLDER)
    res=call_func_for_folder(localitemid, itemid, syncid, PEVENT_LOCAL_FOLDER_CREATED, task_mkdir, 1, "local folder created");
  else if (type==PSYNC_DELETE_LOCAL_FOLDER){
    res=call_func_for_folder(localitemid, itemid, syncid, PEVENT_LOCAL_FOLDER_DELETED, task_rmdir, 0, "local folder deleted");
    if (!res)
      delete_local_folder_from_db(localitemid);
  }
  else if (type==PSYNC_DELREC_LOCAL_FOLDER){
    res=call_func_for_folder(localitemid, itemid, syncid, PEVENT_LOCAL_FOLDER_DELETED, task_rmdir_rec, 0, "local folder deleted recursively");
    if (!res)
      delete_local_folder_from_db(localitemid);
  }
  else if (type==PSYNC_RENAME_LOCAL_FOLDER)
    res=task_renamefolder(syncid, itemid, localitemid, newitemid, name);
  else{
    debug(D_BUG, "invalid task type %u", (unsigned)type);
    res=0;
  }
  if (res)
    debug(D_WARNING, "task of type %u, syncid %u, id %lu localid %lu failed", (unsigned)type, (unsigned)syncid, (unsigned long)itemid, (unsigned long)localitemid);
  return res;
}

static void download_thread(){
  psync_sql_res *res;
  psync_variant *row;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    
    row=psync_sql_row("SELECT id, type, syncid, itemid, localitemid, newitemid, name FROM task WHERE type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_DOWNLOAD)" ORDER BY id LIMIT 1");
    if (row){
      if (!download_task(psync_get_number(row[1]), 
                         psync_get_number(row[2]), 
                         psync_get_number(row[3]), 
                         psync_get_number(row[4]), 
                         psync_get_number_or_null(row[5]),                          
                         psync_get_string_or_null(row[6]))){
        res=psync_sql_prep_statement("DELETE FROM task WHERE id=?");
        psync_sql_bind_uint(res, 1, psync_get_number(row[0]));
        psync_sql_run(res);
        psync_sql_free_result(res);
      }
      else
        psync_milisleep(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
      psync_free(row);
      continue;
    }

    pthread_mutex_lock(&download_mutex);
    if (!download_wakes)
      pthread_cond_wait(&download_cond, &download_mutex);
    download_wakes=0;
    pthread_mutex_unlock(&download_mutex);
  }
}

void psync_wake_download(){
  pthread_mutex_lock(&download_mutex);
  if (!download_wakes++)
    pthread_cond_signal(&download_cond);
  pthread_mutex_unlock(&download_mutex);  
}

void psync_download_init(){
  psync_timer_exception_handler(psync_wake_download);
  psync_run_thread(download_thread);
}
