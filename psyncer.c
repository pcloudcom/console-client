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

#include <string.h>
#include "psyncer.h"
#include "plibs.h"
#include "psettings.h"
#include "ptasks.h"

static psync_folderid_t *synced_down_folders[PSYNC_DIR_HASH_SIZE];
static uint32_t synced_down_folders_cnt[PSYNC_DIR_HASH_SIZE];

static pthread_mutex_t sync_down_mutex=PTHREAD_MUTEX_INITIALIZER;

static int running=0;

void psync_add_folder_to_downloadlist(psync_folderid_t folderid){
  psync_folderid_t *a;
  size_t h;
  uint32_t i, c;
  h=folderid%PSYNC_DIR_HASH_SIZE;
  pthread_mutex_lock(&sync_down_mutex);
  c=synced_down_folders_cnt[h];
  a=synced_down_folders[h];
  for (i=0; i<c; i++)
    if (unlikely(a[i]==folderid)){
      pthread_mutex_unlock(&sync_down_mutex);
      return;
    }
  a=psync_realloc(a, sizeof(psync_folderid_t)*(c+1));
  a[c]=folderid;
  synced_down_folders_cnt[h]=c+1;
  synced_down_folders[h]=a;
  pthread_mutex_unlock(&sync_down_mutex);
}

void psync_del_folder_from_downloadlist(psync_folderid_t folderid){
  psync_folderid_t *a, *b;
  size_t h;
  uint32_t i, c;
  h=folderid%PSYNC_DIR_HASH_SIZE;
  pthread_mutex_lock(&sync_down_mutex);
  c=synced_down_folders_cnt[h];
  a=synced_down_folders[h];
  for (i=0; i<c; i++)
    if (a[i]==folderid){
      if (c==1)
        b=NULL;
      else{
        b=psync_new_cnt(psync_folderid_t, c-1);
        memcpy(b, a, sizeof(psync_folderid_t)*i);
        memcpy(b+i, a+i+1, sizeof(psync_folderid_t)*(c-i-1));
      }
      synced_down_folders[h]=b;
      synced_down_folders_cnt[h]=c-1;
      psync_free(a);
      pthread_mutex_unlock(&sync_down_mutex);
      return;
    }
  pthread_mutex_unlock(&sync_down_mutex);
}

int psync_is_folder_in_downloadlist(psync_folderid_t folderid){
  psync_folderid_t *a;
  size_t h;
  uint32_t i, c;
  h=folderid%PSYNC_DIR_HASH_SIZE;
  pthread_mutex_lock(&sync_down_mutex);
  c=synced_down_folders_cnt[h];
  a=synced_down_folders[h];
  for (i=0; i<c; i++)
    if (a[i]==folderid){
      pthread_mutex_unlock(&sync_down_mutex);
      return 1;
    }
  pthread_mutex_unlock(&sync_down_mutex);
  return 0;
}

static void psync_add_folder_for_downloadsync(psync_syncid_t syncid, uint64_t folderid, const char *localpath){
  psync_sql_res *res;
  psync_variant *row;
  const char *name;
  char *path;
  uint64_t cfolderid;
  res=psync_sql_prep_statement("INSERT INTO syncfolderdown (syncid, folderid) VALUES (?, ?)");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, folderid);
  psync_sql_run(res);
  psync_sql_free_result(res);
  psync_add_folder_to_downloadlist(folderid);
  res=psync_sql_query("SELECT id, permissions, name FROM folder WHERE parentfolderid=?");
  psync_sql_bind_uint(res, 1, folderid);
  while ((row=psync_sql_fetch_row(res))){
    if (psync_get_number(row[1])&PSYNC_PERM_READ){
      name=psync_get_string(row[2]);
      if (psync_is_name_to_ignore(name))
        continue;
      cfolderid=psync_get_number(row[0]);
      path=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, name, NULL);
      psync_task_create_local_folder(path, cfolderid, syncid);
      psync_add_folder_for_downloadsync(syncid, cfolderid, path);
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
  if (unlikely(!row)){
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
  psync_sql_res *res;
  uint64_t *row;
  memset(synced_down_folders, 0, sizeof(synced_down_folders));
  memset(synced_down_folders_cnt, 0, sizeof(synced_down_folders_cnt));
  res=psync_sql_query("SELECT folderid FROM syncfolderdown");
  while ((row=psync_sql_fetch_rowint(res)))
    psync_add_folder_to_downloadlist(row[0]);
  psync_sql_free_result(res);
  psync_run_thread(psync_syncer_thread);
}
