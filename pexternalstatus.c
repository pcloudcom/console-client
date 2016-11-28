/* Copyright (c) 2014 pCloud Ltd.
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

#include <stddef.h>
#include <string.h>

#include "pcompat.h"
#include "pexternalstatus.h"
#include "pfsfolder.h"
#include "pfstasks.h"
#include "plibs.h"
#include "pstatus.h"
#include "psynclib.h"
#include "pcompat.h"
#include "pfolder.h"

#define MAX_RECURS_DEPTH 31

#ifdef P_OS_WINDOWS
#define SLASHCHAR '\\'
#else
#define SLASHCHAR '/'
#endif

static int sync_offline() {
  if  (psync_status_is_offline() || 
       (psync_status_get(PSTATUS_TYPE_ACCFULL) == PSTATUS_ACCFULL_OVERQUOTA) || 
       (psync_status_get(PSTATUS_TYPE_DISKFULL) == PSTATUS_DISKFULL_FULL) ||
       (psync_status_get(PSTATUS_TYPE_RUN) == PSTATUS_RUN_PAUSE))
    return 1;
  else return 0;
}

static int folder_in_sync_nolock(psync_fsfolderid_t folderid) {
  psync_sql_res *res = NULL;
  psync_uint_row row;
  uint64_t result;
  
  if ((folderid == 0)||(folderid == PSYNC_INVALID_FSFOLDERID))
    return 0;
  
  res=psync_sql_query_nolock("select id from syncfolder where folderid = ?;");
  psync_sql_bind_uint(res, 1, folderid);
  while ((row = psync_sql_fetch_rowint(res))) {
    result = row[0];
    psync_sql_free_result(res);
    return result;
  }
  
  psync_sql_free_result(res);
  
  res = psync_sql_query_nolock("select parentfolderid from folder where id = ?;");
  psync_sql_bind_uint(res, 1, folderid);
  while ((row = psync_sql_fetch_rowint(res))) {
    result = folder_in_sync_nolock(row[0]);
    psync_sql_free_result(res);
    return result;
  }
  psync_sql_free_result(res);
   
  return 0;
}

static int task_for_sync_nolock(int syncid){
  psync_sql_res *res = NULL;
  psync_uint_row row;
  uint64_t ret;
  
  res=psync_sql_query_nolock("select 1 from localfile as f, task as t, localfolder as fl where t.syncid = ? and t.localitemid = f.id and f.localparentfolderid = fl.id limit 1;");
  psync_sql_bind_uint(res, 1, syncid);
  while ((row = psync_sql_fetch_rowint(res))) {
    ret = row[0];
    psync_sql_free_result(res);
    return ret;
    
  }
  
  psync_sql_free_result(res);
  return 0; 
}

static int fsexternal_status_folderid(psync_fsfolderid_t folder_id, int level)
{
  psync_fstask_folder_t *tasksp;
  psync_sql_res *res = NULL;
  int result = 0;
  int syncid = 0;
  psync_uint_row row;
    int synctsk = 0;
  
  if (level >= MAX_RECURS_DEPTH)
    return 0;
  
  tasksp =  psync_fstask_get_folder_tasks_rdlocked(folder_id);
  if (tasksp && (tasksp->creats || tasksp->mkdirs)) {
    if (psync_status_get(PSTATUS_TYPE_ACCFULL) == PSTATUS_ACCFULL_OVERQUOTA)
      return 1;
    return 2;
  }
  
  syncid = folder_in_sync_nolock(folder_id);
  if (syncid) {
    synctsk = task_for_sync_nolock(syncid);
    if (synctsk > 0) {
      if (level  == 1) {
        if (sync_offline())
            return 1;
        else return 2; 
      } else {  
        if ((psync_sync_status_folderid(folder_id, syncid) != INSYNC)) {
          if (sync_offline())
              return 1;
          else return 2;
        }
      }
    }
  }
  ++level;
  res=psync_sql_query_nolock("SELECT id FROM folder WHERE parentfolderid=?");
  psync_sql_bind_int(res, 1, folder_id);
  while ((row = psync_sql_fetch_rowint(res))) {
    result = fsexternal_status_folderid(row[0], level);
    if (result)
      break;
  }
  psync_sql_free_result(res);
  
  return result;
}

external_status psync_external_status_folderid(psync_fsfolderid_t folder_id)
{
  int stat = 0;
  
  if (folder_id == PSYNC_INVALID_FSFOLDERID) {
    return NOSYNC;
  }
  if (folder_id >= 0) {
    psync_sql_rdlock();
    stat = fsexternal_status_folderid(folder_id, 0);
    psync_sql_rdunlock();
  }
  else 
    stat = 2;
  
  switch (stat)
  {
    case 1: return NOSYNC; break;
    case 2: 
      if (sync_offline())
        return NOSYNC;
      else
        return INPROG;
      break;
    case 0: return INSYNC; break;
    default: return INSYNC; break;
  }
}

static char *replace_sync_folder(const char *path, int *syncid /*OUT*/) {
  psync_sql_res *res = NULL;
  psync_variant_row row;
  size_t len;
  char *rootpath;
  char *drivepath;
  const char *rest;
  psync_fsfolderid_t folderid;
  const char *syncfolder;
  int i =0;
  char *ret = NULL;
  int rootlen = 0, reslen = 0;
  
  psync_sql_rdlock();
  res=psync_sql_query_nolock("select localpath, id, folderid from syncfolder;");
  while ((row = psync_sql_fetch_row(res))){
    syncfolder = psync_get_lstring(row[0], &len);
    i = strncmp(syncfolder, path, len);
    if (i == 0 && ((path[len] == '\0') || (path[len] == SLASHCHAR))) {
      (*syncid) = psync_get_snumber(row[1]);
      folderid = psync_get_snumber(row[2]);
      rootpath = psync_get_path_by_folderid(folderid, 0);
      if ((path[len] == '\0') || ((path[len] == SLASHCHAR) && (path[len + 1] == '\0'))) {
        ret = rootpath;
        break;
      }
      rest = path + len + 1;
      reslen = strlen(rest);
      if(rootpath) {
        rootlen = strlen(rootpath);
        drivepath = (char *)psync_malloc(rootlen + reslen + 2); // Slash and null terminator
        memcpy(drivepath, rootpath, rootlen);
        memset(drivepath + rootlen, SLASHCHAR, 1);
        memcpy(drivepath + rootlen + 1, rest, reslen + 1); //Copy also the null terminator 
        //debug(D_NOTICE,"Sync folder replace result: %s", drivepath);
        
        psync_free(rootpath);
        ret = drivepath;
        break;
      }
    }
  }
  psync_sql_free_result(res);
  psync_sql_rdunlock();
  return ret;
} 

external_status psync_sync_status_folderid(psync_fsfolderid_t folderid, int syncid) {
  
  psync_sql_res *res = NULL;
  psync_uint_row row;
  uint32_t offline;
  external_status result = INSYNC;
  //debug(D_NOTICE, "Psync folderid %" PRIu64 " syncid %d", folderid, syncid);
  offline = psync_status_is_offline();
  //upload
  res=psync_sql_query_nolock(
    "select 1 from localfile as f, task as t, localfolder as fl where t.syncid = ? and fl.folderid = ? and t.localitemid = f.id and f.localparentfolderid = fl.id limit 1;");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, folderid);
  while ((row = psync_sql_fetch_rowint(res)))
    if (row[0] > 0) {
      if (offline || (psync_status_get(PSTATUS_TYPE_ACCFULL) == PSTATUS_ACCFULL_OVERQUOTA))
        result = NOSYNC;
      else 
        result = INPROG;
      psync_sql_free_result(res);
      return result;
    }
  psync_sql_free_result(res);
  //download
  res=psync_sql_query_nolock("select 1 from task as t, localfolder as lf where t.localitemid = lf.id and t.syncid = ? and lf.folderid = ? and t.type = 2 limit 1;");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, folderid);
  while((row = psync_sql_fetch_rowint(res)))
    if (row[0] > 0) {
      if (offline || (psync_status_get(PSTATUS_TYPE_DISKFULL) == PSTATUS_DISKFULL_FULL))
        result = NOSYNC;
      else 
        result = INPROG;
      break;
    }
  
  psync_sql_free_result(res);  
  return result;
  
}

external_status psync_sync_status_folder(const char *path, int syncid){
psync_fsfolderid_t folderid;
external_status result = INSYNC;
  
  folderid = psync_fsfolderid_by_path(path, 0);
  if (folderid != PSYNC_INVALID_FSFOLDERID) {
    psync_sql_rdlock();
    result = psync_sync_status_folderid(folderid, syncid);
    psync_sql_rdunlock();
  }
  return result;
}

external_status psync_sync_status_file(const char *name, psync_fsfolderid_t folderid, int syncid) {
  
  psync_sql_res *res = NULL;
  psync_uint_row row;
  uint32_t offline;
  external_status result = INSYNC;
  
  psync_sql_rdlock();
  offline = psync_status_is_offline();
  //upload
  res=psync_sql_query_nolock(
    "select 1 from localfile as f, task as t, localfolder as fl where t.syncid = ? and fl.folderid = ? and t.localitemid = f.id and f.localparentfolderid = fl.id and t.name = ?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, folderid);
  psync_sql_bind_string(res, 3, name);
  while((row = psync_sql_fetch_rowint(res)))
    if (row[0] == 1) {
      if (offline || (psync_status_get(PSTATUS_TYPE_ACCFULL) == PSTATUS_ACCFULL_OVERQUOTA))
        result = NOSYNC;
      else 
        result = INPROG;
      psync_sql_free_result(res);
      psync_sql_rdunlock();
      return result;
    }
  psync_sql_free_result(res);
  //download
  res=psync_sql_query_nolock("select 1 from task as t, localfolder as lf where t.localitemid = lf.id and t.syncid = ? and lf.folderid = ? and t.type = 2 and t.name = ?");
  psync_sql_bind_uint(res, 1, syncid);
  psync_sql_bind_uint(res, 2, folderid);
  psync_sql_bind_string(res, 3, name);
  while((row = psync_sql_fetch_rowint(res)))
    if (row[0] == 1) {
      if (offline || (psync_status_get(PSTATUS_TYPE_DISKFULL) == PSTATUS_DISKFULL_FULL))
        result = NOSYNC;
      else 
        result = INPROG;
      psync_sql_free_result(res);
      psync_sql_rdunlock();
      return result;
    }
    
  psync_sql_free_result(res); 
  // sync
  res=psync_sql_query_nolock("select 1 from file as f where f.parentfolderid = ? and f.name = ? ");
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_string(res, 2, name);
  if((!psync_sql_fetch_rowint(res))) {
    if (sync_offline())
      result = NOSYNC;
    else
      result = INPROG;
  }
  psync_sql_free_result(res);
  psync_sql_rdunlock(); 

  return result;
}

external_status do_psync_external_status_file(const char *path)
{
  psync_fstask_folder_t *taskp;
  psync_fspath_t *filep;
  external_status result = INVSYNC;
  int syncid;
  
  if (!path)
    return INVSYNC;
  psync_sql_rdlock();
  filep = psync_fsfolder_resolve_path(path);
  if (filep) {
    if ((syncid = folder_in_sync_nolock(filep->folderid))) {
      result = psync_sync_status_file(filep->name, filep->folderid, syncid);
    } else {
      taskp = psync_fstask_get_folder_tasks_rdlocked(filep->folderid);
      if (taskp) {
        if (psync_fstask_find_creat(taskp, filep->name, 0)) {
          if (sync_offline())
            result = NOSYNC;
          else
            result = INPROG;
        } else result = INSYNC;
      } else result = INSYNC;
    }
  }
  psync_sql_rdunlock();
  return result;
}


external_status do_psync_external_status_folder(const char *path) {
psync_fsfolderid_t folderid;
external_status result = INVSYNC;
  
  if (!path)
    return INVSYNC;
  folderid = psync_fsfolderid_by_path(path, 0);
  if (folderid != PSYNC_INVALID_FSFOLDERID) {
    result = psync_external_status_folderid(folderid);
  } else
    debug(D_WARNING, "Sync folder folderid not found! Called on no actual path ?");
  return result;
}

/*
static void do_normalize_path(char * path) {
  int i = 0;
  int to_move = 0;
  int new_ind = 0;
  int path_size = strlen(path);
  for (; i < (path_size - to_move); ++i) {
    if ((path[i] == '\\') && (path[i + 1] == '\\')) {
      path[i] = '/';
      ++to_move;
      i += 2;
      if (i >= path_size)
        break;
    }
    if (to_move) {
      new_ind = i - to_move;
      if (new_ind > 0)
        path[new_ind] = path[i];
    }
  }
  path[path_size - to_move] = '\0';
}
*/
static void do_normalize_path(char * path) {
  int i = 0;
  int path_size = strlen(path);
  for (; i < path_size; ++i)
    if (path[i] == '\\')
      path[i] = '/';
}
     
external_status do_psync_external_status(char *path)
{
  char *fsroot = NULL;
  char *folder = NULL;
  int syncid = 0, rootlen = 0;
  psync_stat_t st;
  external_status result = INVSYNC;
  char *pcpath = NULL;
  
  fsroot = psync_fs_getmountpoint();
  if (fsroot) {
    rootlen = strlen(fsroot);
  }
  else 
    debug(D_WARNING, "Not mounted!!!");
  if (fsroot && rootlen && !strncmp(fsroot, path, rootlen)) {
    pcpath = path + rootlen;
    // debug(D_NOTICE, "Drive root replace result: %s", pcpath);
  }else {
    folder = replace_sync_folder(path, &syncid);
    if (folder)
      pcpath = folder;
    else {
      // debug(D_NOTICE, "No sync nor drive folder! Called on no pCloud item?");
      return result;
    }
  }
  do_normalize_path(pcpath);
  if (!psync_stat(path, &st)) {
    if (!psync_stat_isfolder(&st)) {
      result = do_psync_external_status_file(pcpath);
      if (syncid && (result == INVSYNC))
        result = NOSYNC;
    } else { 
      result = do_psync_external_status_folder(pcpath);
       if (syncid && (result == INVSYNC))
        result = NOSYNC;
    }
  }
  
  if (folder)
    free(folder);
  if (fsroot)
    free(fsroot); 
  
  return result;
}

string_list_t *sync_get_sync_folders() {
  psync_sql_res *res = NULL;
  psync_str_row srow;
  string_list_t *result;
  
  result = (string_list_t *)psync_malloc(sizeof(string_list_t));
  psync_list_init(&result->list);
  psync_sql_rdlock();
  res=psync_sql_query_rdlock("select localpath from syncfolder;");
  while ((srow=psync_sql_fetch_rowstr(res))){
    string_list_t *name;
    name=psync_new(string_list_t);
    name->str = psync_strdup(srow[0]);
    psync_list_add_tail(&result->list, &name->list);
  }
  psync_sql_free_result(res);
  psync_sql_rdunlock();
  return result;
}
