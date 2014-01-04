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
  
static int download_task(uint32_t type, psync_syncid_t syncid, uint64_t itemid, const char *localpath, const char *localpathnew){
  int res;
  if (type==PSYNC_CREATE_LOCAL_FOLDER){
    res=task_mkdir(localpath);
    if (!res){
      psync_send_event_by_id(PEVENT_LOCAL_FOLDER_CREATED, syncid, localpath, itemid);
      debug(D_NOTICE, "local folder created %s", localpath);
    }
  }
  else if (type==PSYNC_DELETE_LOCAL_FOLDER){
    res=task_rmdir(localpath);
    if (!res){
      psync_send_event_by_id(PEVENT_LOCAL_FOLDER_DELETED, syncid, localpath, itemid);
      debug(D_NOTICE, "local folder deleted %s", localpath);
    }
  }
  else if (type==PSYNC_DELREC_LOCAL_FOLDER){
    res=task_rmdir_rec(localpath);
    if (!res){
      psync_send_event_by_id(PEVENT_LOCAL_FOLDER_DELETED, syncid, localpath, itemid);
      debug(D_NOTICE, "local folder deleted recursively %s", localpath);
    }
  }
  else if (type==PSYNC_RENAME_LOCAL_FOLDER){
    assert(localpathnew!=NULL);
    res=task_renamedir(localpath, localpathnew);
    if (!res){
      psync_send_event_by_id(PEVENT_LOCAL_FOLDER_RENAMED, syncid, localpath, itemid);
      debug(D_NOTICE, "local folder renamed from %s ro %s", localpath, localpathnew);
    }
  }
  else{
    debug(D_BUG, "invalid task type %u", (unsigned)type);
    res=0;
  }
  if (res)
    debug(D_WARNING, "task of type %u, syncid %u, id %lu failed for path %s", (unsigned)type, (unsigned)syncid, (unsigned long)itemid, localpath);
  return res;
}

static void download_thread(){
  psync_sql_res *res;
  psync_variant *row;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    
    row=psync_sql_row("SELECT id, type, syncid, itemid, localpath, newlocalpath FROM task WHERE type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_DOWNLOAD)" ORDER BY id LIMIT 1");
    if (row){
      if (!download_task(psync_get_number(row[1]), psync_get_number(row[2]), psync_get_number(row[3]), psync_get_string(row[4]), psync_get_string_or_null(row[5]))){
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
