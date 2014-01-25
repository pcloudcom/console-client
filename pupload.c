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

#include "pupload.h"
#include "pstatus.h"
#include "ptimer.h"
#include "plibs.h"
#include "ptasks.h"
#include "psettings.h"
#include "pnetlibs.h"
#include "papi.h"

static pthread_mutex_t upload_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t upload_cond=PTHREAD_COND_INITIALIZER;
static uint32_t upload_wakes=0;

static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE),
  PSTATUS_COMBINE(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK)
};

static int do_run_command(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt){
  psync_socket *api;
  binresult *res;
  uint64_t result;
  api=psync_apipool_get();
  if (unlikely(!api))
    return -1;
  res=do_send_command(api, cmd, cmdlen, params, paramscnt, -1, 1);
  if (likely(res))
    psync_apipool_release(api);
  else{
    psync_apipool_release_bad(api);
    return -1;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  if (unlikely(result)){
    debug(D_WARNING, "command %s returned code %u", cmd, (unsigned)result);
    return psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL?-1:0;
  }
  else
    return 0;
}

#define run_command(cmd, params) do_run_command(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam))

static int task_renameremotefile(psync_fileid_t fileid, psync_folderid_t newparentfolderid, const char *newname){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("tofolderid", newparentfolderid), P_STR("toname", newname)};
  int ret;
  ret=run_command("renamefile", params);
  if (likely(!ret))
    debug(D_NOTICE, "remote fileid %lu moved/renamed to (%lu)/%s", (long unsigned)fileid, (long unsigned)newparentfolderid, newname);
  return 0;
}

static int task_renamefile(psync_syncid_t syncid, psync_fileid_t localfileid, psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  psync_uint_row row;
  psync_fileid_t fileid;
  psync_folderid_t folderid;
  res=psync_sql_query("SELECT fileid FROM localfile WHERE id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  if ((row=psync_sql_fetch_rowint(res)))
    fileid=row[0];
  else
    fileid=0;
  psync_sql_free_result(res);
  res=psync_sql_query("SELECT folderid FROM syncedfolder WHERE syncid=? AND localfolderid=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, newlocalparentfolderid);
  if ((row=psync_sql_fetch_rowint(res)))
    folderid=row[0];
  else
    folderid=0;
  psync_sql_free_result(res);
  if (unlikely_log(!fileid) || unlikely_log(!folderid))
    return 0;
  else
    return task_renameremotefile(fileid, folderid, newname);
}

static int task_deletefile(psync_fileid_t fileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid)};
  int ret;
  ret=run_command("deletefile", params);
  if (likely(!ret))
    debug(D_NOTICE, "remote fileid %lu deleted", (long unsigned)fileid);
  return ret;
}

static int upload_task(uint32_t type, psync_syncid_t syncid, uint64_t itemid, uint64_t localitemid, uint64_t newitemid, const char *name,
                                        psync_syncid_t newsyncid){
  int res;
  switch (type){
    case PSYNC_RENAME_REMOTE_FILE:
      res=task_renamefile(newsyncid, localitemid, newitemid, name);
      break;
    case PSYNC_DELETE_REMOTE_FILE:
      res=task_deletefile(itemid);
      break;
    default:
      debug(D_BUG, "invalid task type %u", (unsigned)type);
      res=0;
      break;
  }
  if (res)
    debug(D_WARNING, "task of type %u, syncid %u, id %lu localid %lu failed", (unsigned)type, (unsigned)syncid, (unsigned long)itemid, (unsigned long)localitemid);
  return res;
}

static void upload_thread(){
  psync_sql_res *res;
  psync_variant *row;
  uint32_t type;
  while (psync_do_run){
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    
    row=psync_sql_row("SELECT id, type, syncid, itemid, localitemid, newitemid, name, newsyncid FROM task WHERE type&"NTO_STR(PSYNC_TASK_DWLUPL_MASK)"="NTO_STR(PSYNC_TASK_UPLOAD)" ORDER BY id LIMIT 1");
    if (row){
      type=psync_get_number(row[1]);
      if (!upload_task(type, 
                         psync_get_number(row[2]), 
                         psync_get_number(row[3]), 
                         psync_get_number(row[4]), 
                         psync_get_number_or_null(row[5]),                          
                         psync_get_string_or_null(row[6]),
                         psync_get_number_or_null(row[7]))){
        res=psync_sql_prep_statement("DELETE FROM task WHERE id=?");
        psync_sql_bind_uint(res, 1, psync_get_number(row[0]));
        psync_sql_run_free(res);
      }
      else
        psync_milisleep(PSYNC_SLEEP_ON_FAILED_UPLOAD);
      psync_free(row);
      continue;
    }
    
    pthread_mutex_lock(&upload_mutex);
    if (!upload_wakes)
      pthread_cond_wait(&upload_cond, &upload_mutex);
    upload_wakes=0;
    pthread_mutex_unlock(&upload_mutex);
  }
}

void psync_wake_upload(){
  pthread_mutex_lock(&upload_mutex);
  if (!upload_wakes++)
    pthread_cond_signal(&upload_cond);
  pthread_mutex_unlock(&upload_mutex);  
}

void psync_upload_init(){
  psync_timer_exception_handler(psync_wake_upload);
  psync_run_thread(upload_thread);
}

void psync_delete_upload_tasks_for_file(psync_fileid_t localfileid){
}
