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

#include "plibs.h"
#include "pstatus.h"
#include "ptimer.h"
#include "psettings.h"
#include "pfsupload.h"
#include "plist.h"
#include "pnetlibs.h"
#include "pfstasks.h"
#include "pfileops.h"
#include <string.h>

typedef struct {
  psync_list list;
  binresult *res;
  uint64_t id;
  uint64_t type;
  psync_folderid_t folderid;
  const char *text1;
  const char *text2;
  int64_t int1;
  int64_t int2;
} fsupload_task_t;

static pthread_mutex_t upload_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t upload_cond=PTHREAD_COND_INITIALIZER;
static uint32_t upload_wakes=0;

static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED),
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE),
  PSTATUS_COMBINE(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK)
};

static int psync_send_task_mkdir(psync_socket *api, fsupload_task_t *task){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", task->folderid), P_STR("name", task->text1), P_STR("timeformat", "timestamp")};
  if (likely_log(send_command_no_res(api, "createfolderifnotexists", params)==PTR_OK))
    return 0;
  else
    return -1;
}

static void handle_mkdir_api_error(uint64_t result, fsupload_task_t *task){
  psync_sql_res *res;
  debug(D_ERROR, "createfolderifnotexists returned error %u", (unsigned)result);
  switch (result){
    case 2002: /* parent does not exists */
    case 2003: /* access denied */
      res=psync_sql_prep_statement("UPDATE fstask SET folderid=0 WHERE id=?");
      psync_sql_bind_uint(res, 1, task->id);
      psync_sql_run_free(res);
      break;
    case 2001: /* invalid name */
      res=psync_sql_prep_statement("UPDATE fstask SET text1=\"Invalid Name Requested\" WHERE id=?");
      psync_sql_bind_uint(res, 1, task->id);
      psync_sql_run_free(res);
      break;
    default:
      break;
  }
}

static int psync_process_task_mkdir(fsupload_task_t *task){
  const binresult *meta;
  uint64_t result;
  psync_folderid_t folderid;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result){
    handle_mkdir_api_error(result, task);
    return -1;
  }
  meta=psync_find_result(task->res, "metadata", PARAM_HASH);
  folderid=psync_find_result(meta, "folderid", PARAM_NUM)->num;
  task->int2=folderid;
  psync_ops_create_folder_in_db(meta);
  psync_fstask_folder_created(task->folderid, task->id, folderid);
  return 0;
}

static int psync_send_task_rmdir(psync_socket *api, fsupload_task_t *task){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", task->int1)};
  if (likely_log(send_command_no_res(api, "deletefolder", params)==PTR_OK))
    return 0;
  else
    return -1;
}

static int handle_rmdir_api_error(uint64_t result, fsupload_task_t *task){
  debug(D_ERROR, "deletefolder returned error %u", (unsigned)result);
  switch (result){
    case 2005: /* folder does not exist, kind of success */
      psync_ops_delete_folder_from_db(task->int1);
      psync_fstask_folder_deleted(task->folderid, task->id);
      return 0;
    case 2003: /* access denied, skip*/
    case 2006: /* not empty */
    case 2028: /* folder is shared */
      psync_fstask_folder_deleted(task->folderid, task->id);
      return 0;
    default:
      return -1;
  }
}

static int psync_process_task_rmdir(fsupload_task_t *task){
  uint64_t result;
  result=psync_find_result(task->res, "result", PARAM_NUM)->num;
  if (result)
    return handle_rmdir_api_error(result, task);
  psync_ops_delete_folder_from_db(task->int1);
  psync_fstask_folder_deleted(task->folderid, task->id);
  return 0;
}

typedef int (*psync_send_task_ptr)(psync_socket *, fsupload_task_t *);
typedef int (*psync_process_task_ptr)(fsupload_task_t *);

static psync_send_task_ptr psync_send_task_func[]={
  NULL,
  psync_send_task_mkdir,
  psync_send_task_rmdir
};

static psync_process_task_ptr psync_process_task_func[]={
  NULL,
  psync_process_task_mkdir,
  psync_process_task_rmdir
};

static void psync_fsupload_process_tasks(psync_list *tasks){
  fsupload_task_t *task;
  psync_sql_res *del, *dep, *fol;
  psync_sql_start_transaction();
  del=psync_sql_prep_statement("DELETE FROM fstask WHERE id=?");
  dep=psync_sql_prep_statement("UPDATE fstask SET depend=0 WHERE depend=?");
  fol=psync_sql_prep_statement("UPDATE fstask SET folderid=? WHERE folderid=?");
  psync_list_for_each_element (task, tasks, fsupload_task_t, list)
    if (task->res){
      if (psync_process_task_func[task->type](task))
        debug(D_WARNING, "processing task %lu of type %lu failed", (unsigned long)task->id, (unsigned long)task->type);
      else{
        if (task->type==PSYNC_FS_TASK_MKDIR){
          psync_sql_bind_uint(fol, 1, task->int2);
          psync_sql_bind_int(fol, 2, -task->id);
          psync_sql_run(fol);
        }
        psync_sql_bind_uint(dep, 1, task->id);
        psync_sql_run(dep);
        if (psync_sql_affected_rows())
          upload_wakes++;
        psync_sql_bind_uint(del, 1, task->id);
        psync_sql_run(del);
      }
      psync_free(task->res);
    }
  psync_sql_free_result(fol);
  psync_sql_free_result(dep);
  psync_sql_free_result(del);
  psync_sql_commit_transaction();
}

static void psync_fsupload_run_tasks(psync_list *tasks){
  psync_socket *api;
  fsupload_task_t *task, *rtask;
  api=psync_apipool_get();
  if (!api)
    return;
  rtask=psync_list_element(tasks->next, fsupload_task_t, list);
  psync_list_for_each_element (task, tasks, fsupload_task_t, list){
    if (!task->type || task->type>=ARRAY_SIZE(psync_send_task_func)){
      debug(D_BUG, "bad task type %lu", (unsigned long)task->type);
      continue;
    }
    if (psync_send_task_func[task->type](api, task))
      goto err0;
    if (psync_select_in(&api->sock, 1, 0)==0){
      rtask->res=get_result(api);
      if (unlikely_log(!rtask->res))
        goto err0;
      rtask=psync_list_element(rtask->list.next, fsupload_task_t, list);
    }
  }
  while (&rtask->list!=tasks){
    rtask->res=get_result(api);
    if (unlikely_log(!rtask->res))
      goto err0;
    rtask=psync_list_element(rtask->list.next, fsupload_task_t, list);
  }
  psync_apipool_release(api);
  psync_fsupload_process_tasks(tasks);
  return;
err0:
  psync_apipool_release_bad(api);
  psync_fsupload_process_tasks(tasks);
}

static void psync_fsupload_check_tasks(){
  fsupload_task_t *task;
  psync_sql_res *res;
  psync_variant_row row;
  char *end;
  psync_list tasks;
  size_t size;
  psync_list_init(&tasks);
  res=psync_sql_query("SELECT id, type, folderid, text1, text2, int1, int2 FROM fstask WHERE depend=0 AND status=0 ORDER BY id LIMIT "NTO_STR(PSYNC_FSUPLOAD_NUM_TASKS_PER_RUN));
  while ((row=psync_sql_fetch_row(res))){
    size=sizeof(fsupload_task_t);
    if (row[3].type==PSYNC_TSTRING)
      size+=row[3].length+1;
    if (row[4].type==PSYNC_TSTRING)
      size+=row[4].length+1;
    task=(fsupload_task_t *)psync_malloc(size);
    end=(char *)(task+1);
    task->res=NULL;
    task->id=psync_get_number(row[0]);
    task->type=psync_get_number(row[1]);
    task->folderid=psync_get_number(row[2]);
    if (row[3].type==PSYNC_TSTRING){
      memcpy(end, row[3].str, row[3].length+1);
      task->text1=end;
      end+=row[3].length+1;
    }
    else
      task->text1=NULL;
    if (row[4].type==PSYNC_TSTRING){
      memcpy(end, row[4].str, row[4].length+1);
      task->text2=end;
    }
    else
      task->text2=NULL;
    task->int1=psync_get_snumber_or_null(row[5]);
    task->int2=psync_get_snumber_or_null(row[6]);
    psync_list_add_tail(&tasks, &task->list);
  }
  psync_sql_free_result(res);
  if (!psync_list_isempty(&tasks))
    psync_fsupload_run_tasks(&tasks);
  psync_list_for_each_element_call(&tasks, fsupload_task_t, list, psync_free);
}

static void psync_fsupload_thread(){
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    psync_fsupload_check_tasks();
    pthread_mutex_lock(&upload_mutex);
    if (!upload_wakes)
      pthread_cond_wait(&upload_cond, &upload_mutex);
    upload_wakes=0;
    pthread_mutex_unlock(&upload_mutex);
  }
}

void psync_fsupload_init(){
  psync_timer_exception_handler(psync_fsupload_wake);
  psync_run_thread("fsupload main", psync_fsupload_thread);
}

void psync_fsupload_wake(){
  pthread_mutex_lock(&upload_mutex);
  if (!upload_wakes++)
    pthread_cond_signal(&upload_cond);
  pthread_mutex_unlock(&upload_mutex); 
}
