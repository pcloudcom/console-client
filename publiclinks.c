/* Copyright (c) 2013-2015 pCloud Ltd.
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
#include "publiclinks.h"
#include "papi.h"
#include "pnetlibs.h"
#include "pfsfolder.h"
#include <string.h>
#include <stdio.h>

#define FOLDERID_ENTRY_SIZE 18


static void init_param_str(binparam* t, const char *name, const char *val) {
  //{PARAM_STR, strlen(name), strlen(val), (name), {(uint64_t)((uintptr_t)(val))}}
  t->paramtype  = PARAM_STR;
  t->paramnamelen = strlen(name);
  t->opts = strlen(val);
  t->paramname = name;
  t->str = val;
}

static void init_param_num(binparam* t, const char *name, uint64_t val) {
  //{PARAM_NUM, strlen(name), 0, (name), {(val)}}
  t->paramtype  = PARAM_NUM;
  t->paramnamelen = strlen(name);
  t->opts = 0;
  t->paramname = name;
  t->num = val;
}


int64_t do_psync_file_public_link(const char *path, char **code /*OUT*/, char **err /*OUT*/, uint64_t expire, int maxdownloads, int maxtraffic) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  
  *err  = 0;
  *code = 0;
  if (!expire && !maxdownloads && !maxtraffic) {
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("path", path)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      return -2;
    }
    
    bres = send_command(api, "getfilepublink", params);
  } else {
    binparam* t;
    int numparam = 2 + !!expire + !!maxdownloads + !!maxtraffic;
    int pind = 1;
    
    t = (binparam *) psync_malloc(numparam*sizeof(binparam));
    init_param_str(t, "auth", psync_my_auth);
    init_param_str(t + pind++, "path", path);
    if (expire) 
      init_param_num(t + pind++, "expire", expire);
    if (maxdownloads) 
      init_param_num(t + pind++, "maxdownloads", maxdownloads);
    if (maxtraffic) 
      init_param_num(t + pind++, "maxtraffic", maxtraffic);
    api=psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      return -2;
    }
    bres =  do_send_command(api, "getfilepublink", sizeof("getfilepublink") - 1, t, pind, -1, 1);
    psync_free(t);
  }
     
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command getfilepublink returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return -1;
  }
  
  rescode = psync_find_result(bres, "code", PARAM_STR)->str;
  *code = psync_strndup(rescode, strlen(rescode));
  
  result = 0;
  result = psync_find_result(bres, "linkid", PARAM_NUM)->num;
  
  psync_free(bres);
  
  return result;
}

int64_t do_psync_folder_public_link(const char *path, char **code /*OUT*/, char **err /*OUT*/, uint64_t expire, int maxdownloads, int maxtraffic) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  
  *err  = 0;
  *code = 0;

  if (!expire && !maxdownloads && !maxtraffic) {
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("path", path)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      return -2;
    }
    
    bres = send_command(api, "getfolderpublink", params);
 
  } else {
    binparam* t;
    int numparam = 2 + !!expire + !!maxdownloads + !!maxtraffic;
    int pind = 1;
    
    t = (binparam *) psync_malloc(numparam*sizeof(binparam));
    init_param_str(t, "auth", psync_my_auth);
    init_param_str(t + pind++, "path", path);
    if (expire) 
      init_param_num(t + pind++, "expire", expire);
    if (maxdownloads) 
      init_param_num(t + pind++, "maxdownloads", maxdownloads);
    if (maxtraffic) 
      init_param_num(t + pind++, "maxtraffic", maxtraffic);
    api=psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      return -2;
    }
    bres =  do_send_command(api, "getfolderpublink", sizeof("getfolderpublink") - 1, t, pind, -1, 1);
    psync_free(t);
  }
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command getfilepublink returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return -1;
  }
  
  rescode = psync_find_result(bres, "code", PARAM_STR)->str;
  *code = psync_strndup(rescode, strlen(rescode));

  
  result = 0;
  result = psync_find_result(bres, "linkid", PARAM_NUM)->num;
  
  psync_free(bres);
  
  return result;
  
}

int64_t do_psync_tree_public_link(const char *linkname, const char *root, char **folders, int numfolders, char **files, int numfiles, 
                                  char **code /*OUT*/, char **err /*OUT*/, uint64_t expire, int maxdownloads, int maxtraffic) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  int64_t id = 0;
  char *ids = NULL;
  char *ids1 = NULL;
  char *ids2 = NULL;
  char *idsp = 0;
  int i,pind = 1, numparam = 2,k;
  binparam* t;
  *err  = 0;
  *code = 0;
  
  numparam += !!root + !!numfolders + !!numfiles + !!expire + !!maxdownloads + !!maxtraffic;
  
  if (unlikely(!(!!root + !!numfolders + !!numfiles)))
    return -3;
    
  t = (binparam *) psync_malloc(numparam*sizeof(binparam));
  
  init_param_str(t, "auth", psync_my_auth);
  
  init_param_str(t + pind++, "name", linkname);
  
  if (root) {
    ids = (char *) psync_malloc(FOLDERID_ENTRY_SIZE);
    id = psync_fsfolderid_by_path(root, 0);
    k = sprintf(ids, "%lld", (long long) id);
    init_param_str(t + pind++, "folderid", ids);
  }
  
  if (numfolders) {
    ids1 = (char *) psync_malloc(numfolders*FOLDERID_ENTRY_SIZE);
    idsp = ids1;
    for (i = 0; i < numfolders; ++i) {
      id = psync_fsfolderid_by_path(folders[i], 0);
      k = sprintf(idsp, "%lld", (long long) id);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';
    init_param_str(t + pind++, "folderids", ids1);
  }
  
  if (numfiles) {
     psync_sql_res *res = NULL;
     psync_uint_row row;
     psync_fspath_t *filep;
     
    ids2 = (char *) psync_malloc(numfiles*FOLDERID_ENTRY_SIZE);
    idsp = ids2;
    for (i = 0; i < numfiles; ++i) {
      psync_sql_rdlock();
      filep = psync_fsfolder_resolve_path(files[i]);
      if (filep) {
        res=psync_sql_query_nolock("select id from file where parentfolderid = ? and name = ? limit 1");
        psync_sql_bind_uint(res, 1, filep->folderid);
        psync_sql_bind_string(res, 2, filep->name);
        row = psync_sql_fetch_rowint(res);
        id = row[0];
      } else {
        psync_sql_rdunlock();
        continue;
      }
      psync_sql_free_result(res);
      psync_sql_rdunlock();
      
      k = sprintf(idsp, "%lld", (long long) id);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';
    init_param_str(t + pind++, "fileids", ids2);
  }
  
  
  if (expire) 
    init_param_num(t + pind++, "expire", expire);
  
  if (maxdownloads) 
    init_param_num(t + pind++, "maxdownloads", maxdownloads);
  
  if (maxtraffic) 
    init_param_num(t + pind++, "maxtraffic", maxtraffic);
   
  api=psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return -2;
  }
  
  bres =  do_send_command(api, "gettreepublink", sizeof("gettreepublink") - 1, t, pind, -1, 1);
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command gettreepublink returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return -1;
  }
  
  rescode = psync_find_result(bres, "code", PARAM_STR)->str;
  *code = psync_strndup(rescode, strlen(rescode));
  
  result = 0;
  result = psync_find_result(bres, "linkid", PARAM_NUM)->num;
  
  if (ids)
    psync_free(ids);
   if (ids1)
    psync_free(ids1);
    if (ids2)
    psync_free(ids2);
  
  psync_free(bres);
  psync_free(t);
  
  return result;
  
}

static int chache_links(char **err /*OUT*/) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  const char *charfiled;
  const binresult *publinks, *meta;
  binresult *link;
  int i, linkscnt;
  plink_info_list_t * info;
  
  *err  = 0;
 
  binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp")};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return -2;
  }
  
  bres = send_command(api, "listpublinks", params);
     
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return 0;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command listpublinks returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return 0;
  }
  
  publinks=psync_find_result(bres, "publinks", PARAM_ARRAY);
  
  linkscnt = publinks->length;
  if (!linkscnt){
    psync_free(bres);
    return 0;
  }
  
  info = (plink_info_list_t *) psync_malloc(sizeof(link_info_t)*linkscnt + sizeof(size_t));
  info->entrycnt = linkscnt;

  psync_sql_res *q;
  for (i = 0; i < linkscnt; ++i) {
    link = publinks->array[i];

    q=psync_sql_prep_statement("REPLACE INTO links  (id, code, comment, traffic, maxspace, downloads, created,"
                                 " modified, name,  isfolder, folderid, fileid, isincomming)"
                               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    psync_sql_bind_uint(q, 1, psync_find_result(link, "linkid", PARAM_NUM)->num);
    charfiled = psync_find_result(link, "code", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 2, charfiled, strlen(charfiled));
    psync_sql_bind_uint(q, 3, 0);
    psync_sql_bind_uint(q, 4, psync_find_result(link, "traffic", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 5, 0);
    psync_sql_bind_uint(q, 6, psync_find_result(link, "downloads", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 7, psync_find_result(link, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 8, psync_find_result(link, "modified", PARAM_NUM)->num);
    meta=psync_find_result(link, "metadata", PARAM_HASH);
    charfiled =  psync_find_result(meta, "name", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 9, charfiled, strlen(charfiled));
    if (psync_find_result(meta, "isfolder", PARAM_STR)->str[0] == 't') {
      psync_sql_bind_uint(q, 10, 1);
      psync_sql_bind_uint(q, 11, psync_find_result(link, "folderid", PARAM_NUM)->num);
      psync_sql_bind_uint(q, 12, 0);
    } else {
      psync_sql_bind_uint(q, 10, 0);
      psync_sql_bind_uint(q, 11, 0);
      psync_sql_bind_uint(q, 12, psync_find_result(link, "fileid", PARAM_NUM)->num);
    }
    psync_sql_run_free(q);
  }
  return linkscnt;
}

int do_psync_delete_link(int64_t linkid, char **err /*OUT*/) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  
  *err  = 0;
 
  binparam params[] = {P_STR("auth", psync_my_auth), P_NUM("linkid", linkid)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return -2;
  }
  
  bres = send_command(api, "deletepublink", params);
     
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command deletepublink returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return -1;
  }
 
  
  psync_free(bres);
  
  return 0;
}

int64_t do_psync_upload_link(const char *path, const char *comment, char **code /*OUT*/, char **err /*OUT*/, uint64_t expire, int maxspace, int maxfiles) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  
  *err  = 0;
  *code = 0;

  if (!expire && !maxspace && !maxfiles) {
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("path", path), P_STR("comment", comment)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      return -2;
    }
    
    bres = send_command(api, "createuploadlink", params);
 
  } else {
    binparam* t;
    int numparam = 3 + !!expire + !!maxspace + !!maxfiles;
    int pind = 1;
    
    t = (binparam *) psync_malloc(numparam*sizeof(binparam));
    init_param_str(t, "auth", psync_my_auth);
    init_param_str(t + pind++, "path", path);
    init_param_str(t + pind++, "comment", comment);
    if (expire) 
      init_param_num(t + pind++, "expire", expire);
    if (maxspace) 
      init_param_num(t + pind++, "maxspace", maxspace);
    if (maxfiles) 
      init_param_num(t + pind++, "maxfiles", maxfiles);
    api=psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      return -2;
    }
    bres =  do_send_command(api, "createuploadlink", sizeof("createuploadlink") - 1, t, pind, -1, 1);
    psync_free(t);
  }
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command getfilepublink returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return -1;
  }
  
  rescode = psync_find_result(bres, "code", PARAM_STR)->str;
  *code = psync_strndup(rescode, strlen(rescode));

  
  result = 0;
  result = psync_find_result(bres, "uploadlinkid", PARAM_NUM)->num;
  
  psync_free(bres);
  
  return result;
  
}

int do_psync_delete_upload_link(int64_t uploadlinkid, char **err /*OUT*/) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  
  *err  = 0;
 
  binparam params[] = {P_STR("auth", psync_my_auth), P_NUM("uploadlinkid", uploadlinkid)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return -2;
  }
  
  bres = send_command(api, "deleteuploadlink", params);
     
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command deletepublink returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return -1;
  }
 
  
  psync_free(bres);
  
  return 0;
}

void do_free_links_list (plink_info_list_t *info)
{
  int i;
  if (!info || info->entrycnt)
    debug(D_ERROR, "Empty list scheduled for deletion or double delete.");
  for (i = 0; i < info->entrycnt; ++i) {
    if (info->entries[i].code)
      psync_free(info->entries[i].code);
    if (info->entries[i].comment)
      psync_free(info->entries[i].comment);
    if (info->entries[i].meta.name)
      psync_free((char *)info->entries[i].meta.name);
  }
  psync_free(info);
}


int do_psync_list_links(plink_info_list_t **infop /*OUT*/, char **err /*OUT*/) {
  
  plink_info_list_t * info;
  int i, linkscnt = 0;
  psync_sql_res *res;
  psync_variant_row row;
  psync_uint_row irow;
  
  const char *cstr;
  size_t length = 0;
  
  *err  = 0;
  *infop = 0;
  
  psync_sql_rdlock();
  res=psync_sql_query_nolock("SELECT count(*) FROM links");
  if ((irow = psync_sql_fetch_rowint(res)))
    linkscnt = irow[0];
  psync_sql_free_result(res);
  
  if (linkscnt) {
    res=psync_sql_query_nolock("SELECT id, code, comment, traffic, maxspace, downloads, created,"
                        " modified, name,  isfolder, folderid, fileid, isincomming FROM links");
    
    info = (plink_info_list_t *) psync_malloc(sizeof(link_info_t)*linkscnt + sizeof(size_t));
    info->entrycnt = linkscnt;

    for (i = 0; i < linkscnt; ++i) {
      if ((row=psync_sql_fetch_row(res))){
        info->entries[i].linkid = psync_get_number(row[0]);
        cstr=psync_get_lstring(row[1], &length);
        info->entries[i].code = psync_strndup(cstr, length);
        cstr=psync_get_lstring(row[2], &length);
        info->entries[i].comment = psync_strndup(cstr, length);
        info->entries[i].traffic = psync_get_number(row[3]);
        info->entries[i].maxspace =  psync_get_number(row[4]);
        info->entries[i].downloads = psync_get_number(row[5]);
        info->entries[i].created = psync_get_number(row[6]);
        info->entries[i].modified = psync_get_number(row[7]);
        cstr=psync_get_lstring(row[8], &length);
        info->entries[i].meta.name = psync_strndup(cstr, length);
        info->entries[i].meta.namelen = length;
        if (psync_get_number(row[9])) {
          info->entries[i].meta.isfolder = 1;
          info->entries[i].meta.folder.folderid = psync_get_number(row[10]);
          
        } else {
          info->entries[i].meta.isfolder = 0;
          info->entries[i].meta.file.fileid = psync_get_number(row[11]);
        }
        info->entries[i].isupload = psync_get_number(row[12]);
      } else {
        debug(D_ERROR, "Counted and fetched numbers do not match.");
        info->entrycnt = i;
        free_links_list (info);
        return -2;
      }
    }
    *infop = info;
  }
  psync_sql_free_result(res);
  psync_sql_rdunlock();
  return linkscnt;
}


static int chache_upload_links(char **err /*OUT*/) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  const char *charfiled;
  const binresult *publinks, *meta;
  binresult *link;
  int i, linkscnt;
  
  *err  = 0;
 
  binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp")};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return -2;
  }
  
  bres = send_command(api, "listuploadlinks", params);
     
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command listpublinks returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
      return -result;
    else
      return -1;
  }
  
  publinks=psync_find_result(bres, "uploadlinks", PARAM_ARRAY);
  
  linkscnt = publinks->length;
  if (!linkscnt){
    psync_free(bres);
    return 0;
  }
  psync_sql_res *q;
  for (i = 0; i < linkscnt; ++i) {
    link = publinks->array[i];

    q=psync_sql_prep_statement("REPLACE INTO links  (id, code, comment, traffic, maxspace, downloads, created,"
                                 " modified, name,  isfolder, folderid, fileid, isincomming)"
                               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)");
    psync_sql_bind_uint(q, 1, psync_find_result(link, "linkid", PARAM_NUM)->num);
    charfiled = psync_find_result(link, "code", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 2, charfiled, strlen(charfiled));
    charfiled =  psync_find_result(link, "comment", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 3, charfiled, strlen(charfiled));
    psync_sql_bind_uint(q, 4, psync_find_result(link, "space", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 5, psync_find_result(link, "maxspace", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 6, psync_find_result(link, "files", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 7, psync_find_result(link, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 8, psync_find_result(link, "modified", PARAM_NUM)->num);
    charfiled =  psync_find_result(link, "name", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 9, charfiled, strlen(charfiled));
    meta=psync_find_result(link, "metadata", PARAM_HASH);
    if (psync_find_result(meta, "isfolder", PARAM_STR)->str[0] == 't') {
      psync_sql_bind_uint(q, 10, 1);
      psync_sql_bind_uint(q, 11, psync_find_result(link, "folderid", PARAM_NUM)->num);
      psync_sql_bind_uint(q, 12, 0);
    } else {
      psync_sql_bind_uint(q, 10, 0);
      psync_sql_bind_uint(q, 11, 0);
      psync_sql_bind_uint(q, 12, psync_find_result(link, "folderid", PARAM_NUM)->num);
    }
    psync_sql_run_free(q);
  }
  return linkscnt;
}

int cache_links_all(char **err /*OUT*/)
{
  int ret =0;
  ret = chache_upload_links(err);
   if (ret >= 0)
     ret += chache_links(err);
  return ret;
}