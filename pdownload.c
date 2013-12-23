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

static pthread_mutex_t download_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t download_cond=PTHREAD_COND_INITIALIZER;
static uint32_t download_wakes=0;
static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE)
};

static void set_space(int over){
  static int isover=0;
  if (over!=isover){
    isover=over;
    if (isover)
      psync_set_status(PSTATUS_TYPE_DISKFULL, PSTATUS_DISKFULL_FULL);
    else
      psync_set_status(PSTATUS_TYPE_DISKFULL, PSTATUS_DISKFULL_OK);
  }
}

static int task_mkdir(const char *path){
  while (1){
    if (!psync_mkdir(path)){
      set_space(0);
      return 0;
    }
    if (psync_fs_err()==P_NOSPC || psync_fs_err()==P_DQUOT){
      set_space(1);
      psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
    }
    else {
      set_space(0);
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
  
static int download_task(uint32_t type, psync_syncid_t syncid, uint64_t itemid, const char *localpath){
  if (type==PSYNC_CREATE_LOCAL_FOLDER)
    return task_mkdir(localpath);
  else{
    debug(D_BUG, "invalid task type %u", (unsigned)type);
    return 0;
  }
}

static void download_thread(){
  psync_sql_res *res;
  psync_variant *row;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    
    row=psync_sql_row("SELECT id, type, syncid, itemid, localpath FROM task WHERE type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_DOWNLOAD)" ORDER BY id");
    if (row){
      if (!download_task(psync_get_number(row[1]), psync_get_number(row[2]), psync_get_number(row[3]), psync_get_string(row[4]))){
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
