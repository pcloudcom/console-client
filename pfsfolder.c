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

#include "pfsfolder.h"
#include "plibs.h"
#include "psettings.h"
#include "pfstasks.h"
#include <string.h>

psync_fspath_t *psync_fsfolder_resolve_path(const char *path){
  psync_fsfolderid_t cfolderid;
  psync_fspath_t *ret;
  const char *sl;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  size_t len;
  uint32_t permissions;
  int hasit;
  res=NULL;
  if (*path!='/')
    return NULL;
  cfolderid=0;
  permissions=PSYNC_PERM_ALL;
  while (1){
    while (*path=='/')
      path++;
    if (*path==0){
      if (res)
        psync_sql_free_result(res);
      return NULL;
    }
    sl=strchr(path, '/');
    if (sl)
      len=sl-path;
    else{
      if (res)
        psync_sql_free_result(res);
      ret=psync_new(psync_fspath_t);
      ret->folderid=cfolderid;
      ret->name=path;
      ret->permissions=permissions;
      return ret;
    }
    if (!res)
      res=psync_sql_query("SELECT id, permissions FROM folder WHERE parentfolderid=? AND name=?");
    else
      psync_sql_reset(res);
    psync_sql_bind_int(res, 1, cfolderid);
    psync_sql_bind_lstring(res, 2, path, len);
    row=psync_sql_fetch_rowint(res);
    folder=psync_fstask_get_folder_tasks_locked(cfolderid);
    if (folder){
      char *name=psync_strndup(path, len);
      if (row && !psync_fstask_find_rmdir(folder, name)){
        cfolderid=row[0];
        permissions&=row[1];
        hasit=1;
      }
      else if ((mk=psync_fstask_find_mkdir(folder, name))){
        cfolderid=mk->folderid;
        hasit=1;
      }
      else
        hasit=0;
      psync_fstask_release_folder_tasks_locked(folder);
      psync_free(name);
    }
    else{
      if (row){
        cfolderid=row[0];
        permissions=row[1];
        hasit=1;
      }
      else
        hasit=0;
    }
    if (!hasit)
      break;
    path+=len;
  }
  if (res)
    psync_sql_free_result(res);
  return NULL;
}

psync_fsfolderid_t psync_fsfolderid_by_path(const char *path){
  psync_fsfolderid_t cfolderid;
  const char *sl;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  size_t len;
  int hasit;
  res=NULL;
  if (*path!='/')
    return PSYNC_INVALID_FSFOLDERID;
  cfolderid=0;
  while (1){
    while (*path=='/')
      path++;
    if (*path==0){
      if (res)
        psync_sql_free_result(res);
      return cfolderid;
    }
    sl=strchr(path, '/');
    if (sl)
      len=sl-path;
    else
      len=strlen(path);
    if (!res)
      res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
    else
      psync_sql_reset(res);
    psync_sql_bind_int(res, 1, cfolderid);
    psync_sql_bind_lstring(res, 2, path, len);
    row=psync_sql_fetch_rowint(res);
    folder=psync_fstask_get_folder_tasks_locked(cfolderid);
    if (folder){
      char *name=psync_strndup(path, len);
      if (row && !psync_fstask_find_rmdir(folder, name)){
        cfolderid=row[0];
        hasit=1;
      }
      else if ((mk=psync_fstask_find_mkdir(folder, name))){
        cfolderid=mk->folderid;
        hasit=1;
      }
      else
        hasit=0;
      psync_fstask_release_folder_tasks_locked(folder);
      psync_free(name);
    }
    else{
      if (row){
        cfolderid=row[0];
        hasit=1;
      }
      else
        hasit=0;
    }
    if (!hasit)
      break;
    path+=len;
  }
  if (res)
    psync_sql_free_result(res);
  return PSYNC_INVALID_FSFOLDERID;
}