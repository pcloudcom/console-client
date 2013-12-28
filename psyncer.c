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

#include "psyncer.h"
#include "plibs.h"
#include "psettings.h"
#include "ptasks.h"

static int running=0;

static void psync_add_folder_for_downloadsync(psync_syncid_t syncid, uint64_t folderid, const char *localpath){
  psync_sql_res *res;
  psync_variant *row;
  const char *name;
  char *path;
  uint64_t cfolderid;
  res=psync_sql_prep_statement("INSERT INTO syncfolderdown (syncid, folderid, localpath) VALUES (?, ?, ?)");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, folderid);
  psync_sql_bind_string(res, 3, localpath);
  psync_sql_run(res);
  psync_sql_free_result(res);
  res=psync_sql_query("SELECT id, permissions, name FROM folder WHERE parentfolderid=?");
  psync_sql_bind_uint(res, 1, folderid);
  while ((row=psync_sql_fetch_row(res))){
    if (psync_get_number(row[1])&PSYNC_PERM_READ){
      name=psync_get_string(row[2]);
      if (psync_is_name_to_ignore(name))
        continue;
      cfolderid=psync_get_number(row[0]);
      path=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, name, NULL);
      psync_add_folder_for_downloadsync(syncid, cfolderid, path);
      psync_task_create_local_folder(path, cfolderid, syncid);
      psync_free(path);
    }
  }
  psync_sql_free_result(res);
  res=psync_sql_query("SELECT id, name FROM file WHERE parentfolderid=?");
  psync_sql_bind_uint(res, 1, folderid);
  while ((row=psync_sql_fetch_row(res))){
    name=psync_get_string(row[1]);
    if (psync_is_name_to_ignore(name))
      continue;
    cfolderid=psync_get_number(row[0]);
    path=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, name, NULL);
    psync_task_download_file(path, cfolderid, syncid);
    psync_free(path);
  }
  psync_sql_free_result(res);
}

static void psync_sync_newsyncedfolder(psync_syncid_t syncid){
  psync_sql_res *res;
  psync_variant *row;
  uint64_t folderid;
  char *localpath;
  psync_synctype_t synctype;
  psync_sql_start_transaction();
  res=psync_sql_query("SELECT folderid, localpath, synctype FROM syncfolder WHERE id=? AND flags=0");
  psync_sql_bind_uint(res, 1, syncid);
  row=psync_sql_fetch_row(res);
  if (!row){
    psync_sql_rollback_transaction();
    return;
  }
  folderid=psync_get_number(row[0]);
  localpath=psync_strdup(psync_get_string(row[1]));
  synctype=psync_get_number(row[2]);
  psync_sql_free_result(res);
  if (synctype&PSYNC_DOWNLOAD_ONLY)
    psync_add_folder_for_downloadsync(syncid, folderid, localpath);
  res=psync_sql_prep_statement("UPDATE syncfolder SET flags=1 WHERE flags=0 AND id=?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_run(res);
  psync_sql_free_result(res);
  psync_free(localpath);
  if (psync_sql_affected_rows())
    psync_sql_commit_transaction();
  else
    psync_sql_rollback_transaction();
}

static void psync_do_sync_thread(void *ptr){
  psync_sync_newsyncedfolder(*((psync_syncid_t *)ptr));
  psync_free(ptr);
}

void psync_syncer_new(psync_syncid_t syncid){
  if (running){
    psync_syncid_t *psid;
    psid=(psync_syncid_t *)psync_malloc(sizeof(psync_syncid_t));
    *psid=syncid;
    psync_run_thread1(psync_do_sync_thread, psid);
  }
}

static void psync_syncer_thread(){
  int64_t syncid;
  psync_sql_lock();
  running=1;
  while ((syncid=psync_sql_cellint("SELECT id FROM syncfolder WHERE flags=0", -1))!=-1)
    psync_sync_newsyncedfolder(syncid);
  psync_sql_unlock();
}

void psync_syncer_init(){
  psync_run_thread(psync_syncer_thread);
}
