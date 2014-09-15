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
#include "pfolder.h"
#include "pcloudcrypto.h"
#include "pfs.h"
#include <string.h>

static char *get_encname_for_folder(psync_fsfolderid_t folderid, const char *path, size_t len){
  char *name, *encname;
  psync_crypto_aes256_text_encoder_t enc;
  enc=psync_cloud_crypto_get_folder_encoder(folderid);
  if (psync_crypto_is_error(enc))
    return NULL;
  name=psync_strndup(path, len);
  encname=psync_cloud_crypto_encode_filename(enc, name);
  psync_cloud_crypto_release_folder_encoder(folderid, enc);
  psync_free(name);
  return encname;
}

static psync_fspath_t *ret_folder_data(psync_fsfolderid_t folderid, const char *name, uint32_t permissions, uint32_t flags){
  psync_fspath_t *ret;
  if (flags&PSYNC_FOLDER_FLAG_ENCRYPTED && strncmp(psync_fake_prefix, name, psync_fake_prefix_len)){
    psync_crypto_aes256_text_encoder_t enc;
    char *encname;
    size_t len;
    enc=psync_cloud_crypto_get_folder_encoder(folderid);
    if (psync_crypto_is_error(enc))
      return NULL;
    encname=psync_cloud_crypto_encode_filename(enc, name);
    psync_cloud_crypto_release_folder_encoder(folderid, enc);
    len=strlen(encname);
    ret=(psync_fspath_t *)psync_malloc(sizeof(psync_fspath_t)+len+1);
    memcpy(ret+1, encname, len+1);
    psync_free(encname);
    ret->folderid=folderid;
    ret->name=(char *)(ret+1);
    ret->permissions=permissions;
    ret->flags=flags;
  }
  else{
    ret=psync_new(psync_fspath_t);
    ret->folderid=folderid;
    ret->name=name;
    ret->permissions=permissions;
    ret->flags=flags;
  }
  return ret;
}

psync_fspath_t *psync_fsfolder_resolve_path(const char *path){
  psync_fsfolderid_t cfolderid;
  const char *sl;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  char *ename;
  size_t len, elen;
  uint32_t permissions, flags;
  int hasit;
  res=NULL;
  if (*path!='/')
    return NULL;
  cfolderid=0;
  permissions=PSYNC_PERM_ALL;
  flags=0;
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
      return ret_folder_data(cfolderid, path, permissions, flags);
    }
    if (!res)
      res=psync_sql_query("SELECT id, permissions, flags FROM folder WHERE parentfolderid=? AND name=?");
    else
      psync_sql_reset(res);
    psync_sql_bind_int(res, 1, cfolderid);
    if (flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
      ename=get_encname_for_folder(cfolderid, path, len);
      if (!ename)
        break;
      elen=strlen(ename);
      psync_sql_bind_lstring(res, 2, ename, elen);
    }
    else{
      psync_sql_bind_lstring(res, 2, path, len);
      ename=(char *)path;
      elen=len;
    }
    row=psync_sql_fetch_rowint(res);
    folder=psync_fstask_get_folder_tasks_locked(cfolderid);
    if (folder){
      char *name=psync_strndup(ename, elen);
      if ((mk=psync_fstask_find_mkdir(folder, name, 0))){
        cfolderid=mk->folderid;
        flags=mk->flags;
        hasit=1;
      }
      else if (row && !psync_fstask_find_rmdir(folder, name, 0)){
        cfolderid=row[0];
        permissions&=row[1];
        flags=row[2];
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
        flags=row[2];
        hasit=1;
      }
      else
        hasit=0;
    }
    if (ename!=path)
      psync_free(ename);
    if (!hasit)
      break;
    path+=len;
  }
  if (res)
    psync_sql_free_result(res);
  return NULL;
}

psync_fsfolderid_t psync_fsfolderid_by_path(const char *path, uint32_t *pflags){
  psync_fsfolderid_t cfolderid;
  const char *sl;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  char *ename;
  size_t len, elen;
  uint32_t flags;
  int hasit;
  res=NULL;
  if (*path!='/')
    return PSYNC_INVALID_FSFOLDERID;
  cfolderid=0;
  flags=0;
  while (1){
    while (*path=='/')
      path++;
    if (*path==0){
      if (res)
        psync_sql_free_result(res);
      if (pflags)
        *pflags=flags;
      return cfolderid;
    }
    sl=strchr(path, '/');
    if (sl)
      len=sl-path;
    else
      len=strlen(path);
    if (!res)
      res=psync_sql_query("SELECT id, flags FROM folder WHERE parentfolderid=? AND name=?");
    else
      psync_sql_reset(res);
    psync_sql_bind_int(res, 1, cfolderid);
    if (flags&PSYNC_FOLDER_FLAG_ENCRYPTED){
      ename=get_encname_for_folder(cfolderid, path, len);
      if (!ename)
        break;
      elen=strlen(ename);
      psync_sql_bind_lstring(res, 2, ename, elen);
    }
    else{
      psync_sql_bind_lstring(res, 2, path, len);
      ename=(char *)path;
      elen=len;
    }
    row=psync_sql_fetch_rowint(res);
    folder=psync_fstask_get_folder_tasks_locked(cfolderid);
    if (folder){
      char *name=psync_strndup(ename, elen);
      if ((mk=psync_fstask_find_mkdir(folder, name, 0))){
        cfolderid=mk->folderid;
        flags=mk->flags;
        hasit=1;
      }
      else if (row && !psync_fstask_find_rmdir(folder, name, 0)){
        cfolderid=row[0];
        flags=row[1];
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
        flags=row[1];
        hasit=1;
      }
      else
        hasit=0;
    }
    if (ename!=path)
      psync_free(ename);
    if (!hasit)
      break;
    path+=len;
  }
  if (res)
    psync_sql_free_result(res);
  return PSYNC_INVALID_FSFOLDERID;
}