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
#include "ptimer.h"
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
typedef struct _scr_params {
  int64_t linkid;
  uint64_t delay;
} scr_params;

static void modify_screenshot_public_link(void* par) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  scr_params* linkidp = (scr_params*)par;
  
  uint64_t time =  psync_timer_time() + ((linkidp->delay)? linkidp->delay:2592000);
  time = time - time%3600;
  binparam params[] = {P_STR("auth", psync_my_auth), P_NUM("linkid", linkidp->linkid), P_NUM("expire", time )};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return;
  }

  bres = send_command(api, "changepublink", params);
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return;
  }
  
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    debug(D_WARNING, "command changepublink for link [%lld] returned error code %u msg [%s]",(long long int)linkidp->linkid ,(unsigned)result, errorret);
    psync_process_api_error(result);
    psync_handle_api_result(result);
    if (result == 2261)
      debug(D_NOTICE, "Unable to set expiration date on screen-shot link. Paid account required.");
  }

  psync_free(linkidp);
  psync_free(bres);
}

int64_t do_psync_screenshot_public_link(const char *path, int hasdelay, uint64_t delay, char **code /*OUT*/, char **err /*OUT*/) {
  scr_params *params= psync_malloc(sizeof(scr_params));
  int64_t ret =  do_psync_file_public_link(path, &params->linkid, code, err, 0, 0, 0);
  if (hasdelay) {
    params->delay = delay;
    psync_run_thread1("Modify link expiration.",modify_screenshot_public_link, params);
  } else psync_free (params);
  return ret;
}


int64_t do_psync_file_public_link(const char *path, int64_t* plinkid, char **code /*OUT*/, char **err /*OUT*/, uint64_t expire, int maxdownloads, int maxtraffic) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  int64_t linkid;

  *err  = 0;
  *code = 0;
  if (!expire && !maxdownloads && !maxtraffic) {
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("path", path)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return 2;
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
      *err = psync_strndup("Connection error.", 17);
      psync_free(t);
      return 1;
    }
    bres =  do_send_command(api, "getfilepublink", sizeof("getfilepublink") - 1, t, pind, -1, 1);
    psync_free(t);
  }


  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return 2;
  }
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = psync_find_result(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    debug(D_WARNING, "command getfilepublink returned error code %u", (unsigned)result);
    psync_process_api_error(result);
    psync_handle_api_result(result);
    goto free_ret;
  }

  rescode = psync_find_result(bres, "code", PARAM_STR)->str;
  *code = psync_strndup(rescode, strlen(rescode));
  linkid = psync_find_result(bres, "linkid", PARAM_NUM)->num;
  if (plinkid)
    *plinkid = linkid;
    
free_ret:
  psync_free(bres);
  return (int64_t)result;
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
      *err = psync_strndup("Connection error.", 17);
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
      *err = psync_strndup("Connection error.", 17);
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
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
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
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres =  do_send_command(api, "gettreepublink", sizeof("gettreepublink") - 1, t, pind, -1, 1);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
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
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
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

int cache_links(char **err /*OUT*/) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  const binresult *publinks, *meta;
  binresult *link;
  int i, linkscnt;
  psync_sql_res *q;

  q=psync_sql_prep_statement("DELETE FROM links WHERE isincomming = 0 ");
  psync_sql_run_free(q);

  *err  = 0;
  if(psync_my_auth[0]) {
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_STR("iconformat","id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = send_command(api, "listpublinks", params);
  } else if (psync_my_user  && psync_my_pass) {

    binparam params[] = {P_STR("username", psync_my_user), P_STR("password", psync_my_pass), P_STR("timeformat", "timestamp"),  P_STR("iconformat","id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = send_command(api, "listpublinks", params);
  } else return -1;
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
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
    else {
      *err = psync_strndup("Connection error.", 17);
      return 0;
    }
  }

  publinks=psync_find_result(bres, "publinks", PARAM_ARRAY);

  linkscnt = publinks->length;
  if (!linkscnt){
    psync_free(bres);
    return 0;
  }

  for (i = 0; i < linkscnt; ++i) {
    link = publinks->array[i];

    q=psync_sql_prep_statement("REPLACE INTO links  (id, code, comment, traffic, maxspace, downloads, created,"
                                 " modified, name,  isfolder, folderid, fileid, isincomming, icon)"
                               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)");
    psync_sql_bind_uint(q, 1, psync_find_result(link, "linkid", PARAM_NUM)->num);
    psync_sql_bind_string(q, 2, psync_find_result(link, "code", PARAM_STR)->str);
    psync_sql_bind_uint(q, 3, 0);
    psync_sql_bind_uint(q, 4, psync_find_result(link, "traffic", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 5, 0);
    psync_sql_bind_uint(q, 6, psync_find_result(link, "downloads", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 7, psync_find_result(link, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 8, psync_find_result(link, "modified", PARAM_NUM)->num);
    meta=psync_find_result(link, "metadata", PARAM_HASH);
    psync_sql_bind_string(q, 9, psync_find_result(meta, "name", PARAM_STR)->str);
    if (psync_find_result(meta, "isfolder", PARAM_BOOL)->num) {
      psync_sql_bind_uint(q, 10, 1);
      psync_sql_bind_uint(q, 11, psync_find_result(meta, "folderid", PARAM_NUM)->num);
      psync_sql_bind_uint(q, 12, 0);
    } else {
      psync_sql_bind_uint(q, 10, 0);
      psync_sql_bind_uint(q, 11, 0);
      psync_sql_bind_uint(q, 12, psync_find_result(meta, "fileid", PARAM_NUM)->num);
    }
    psync_sql_bind_uint(q, 13, psync_find_result(meta, "icon", PARAM_NUM)->num);
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
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = send_command(api, "deletepublink", params);


  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
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
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
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
      *err = psync_strndup("Connection error.", 17);
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
      *err = psync_strndup("Connection error.", 17);
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
    *err = psync_strndup("Connection error.", 17);
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
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
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
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = send_command(api, "deleteuploadlink", params);


  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
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
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }


  psync_free(bres);

  return 0;
}

static int create_link(psync_list_builder_t *builder, void *element, psync_variant_row row){
  link_info_t *link;
  const char *str;
  size_t len;

  link=(link_info_t *)element;
  link->linkid = psync_get_number(row[0]);
  str=psync_get_lstring(row[1], &len);
  link->code=str;
  psync_list_add_lstring_offset(builder, offsetof(link_info_t, code), len);
  str=psync_get_lstring(row[2], &len);
  link->comment=str;
  psync_list_add_lstring_offset(builder, offsetof(link_info_t, comment), len);
  link->traffic = psync_get_number(row[3]);
  link->maxspace =  psync_get_number(row[4]);
  link->downloads = psync_get_number(row[5]);
  link->created = psync_get_number(row[6]);
  link->modified = psync_get_number(row[7]);
  str=psync_get_lstring(row[8], &len);
  link->name=str;
  psync_list_add_lstring_offset(builder, offsetof(link_info_t, name), len);
  if (psync_get_number(row[9])) {
    link->isfolder = 1;
    link->itemid = psync_get_number(row[10]);

  } else {
    link->isfolder = 0;
    link->itemid = psync_get_number(row[11]);
  }
  link->isupload = psync_get_number(row[12]);
  link->icon =  psync_get_number(row[13]);
  return 0;
}

plink_info_list_t * do_psync_list_links(char **err /*OUT*/) {

  psync_list_builder_t *builder;
  psync_sql_res *res;
  *err = 0;

  builder=psync_list_builder_create(sizeof(link_info_t), offsetof(plink_info_list_t, entries));

  res=psync_sql_query_rdlock("SELECT id, code, comment, traffic, maxspace, downloads, created,"
                        " modified, name,  isfolder, folderid, fileid, isincomming, icon FROM links");

  psync_list_bulder_add_sql(builder, res, create_link);


  return (plink_info_list_t *)psync_list_builder_finalize(builder);
}

plink_contents_t *do_show_link(const char *code, char **err /*OUT*/) {
  psync_socket *api;
  binresult *bres;
  psync_list_builder_t *builder;
  link_cont_t *pcont;
  const binresult *contents = 0, *meta = 0, *link = 0, *br =0;
  uint32_t concnt = 0, i = 0;
  plink_contents_t *ret = 0;
  *err = 0;

  binparam params[] = {P_STR("auth", psync_my_auth),P_STR("timeformat", "timestamp"), P_STR("iconformat","id"), P_STR("code", code)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Can't gat api from the pool.", 29);
    return NULL;
  }

  bres = send_command(api, "showpublink", params);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return NULL;
  }

  meta=psync_find_result(bres, "metadata", PARAM_HASH);
  if (meta) {
    contents=psync_find_result(meta, "contents", PARAM_ARRAY);
    concnt = contents->length;
    if (!concnt){
      psync_free(bres);
      return 0;
    }
    builder=psync_list_builder_create(sizeof(link_cont_t), offsetof(plink_contents_t, entries));
    for (i = 0; i < concnt; ++i) {
      link = contents->array[i];
      pcont = (link_cont_t *)psync_list_bulder_add_element(builder);
      br = psync_find_result(link, "name", PARAM_STR);
      pcont->name = br->str;
      psync_list_add_lstring_offset(builder, offsetof(link_cont_t, name), br->length);
      pcont->created = psync_find_result(link, "created", PARAM_NUM)->num;
      pcont->modified = psync_find_result(link, "modified", PARAM_NUM)->num;
      if (psync_find_result(link, "isfolder", PARAM_BOOL)->num) {
        pcont->isfolder = 1;
        pcont->itemid = psync_find_result(link, "folderid", PARAM_NUM)->num;
      } else {
         pcont->isfolder = 0;
        pcont->itemid = psync_find_result(link, "fileid", PARAM_NUM)->num;
      }
      pcont->icon = psync_find_result(link, "icon", PARAM_NUM)->num;
    }
    ret = (plink_contents_t *)psync_list_builder_finalize(builder);
    psync_free(bres);
    return ret;
  }
  psync_free(bres);
  return 0;
}

int cache_upload_links(char **err /*OUT*/) {
  psync_socket *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  const binresult *publinks, *meta;
  binresult *link; const binresult *br;
  int i, linkscnt;
  psync_sql_res *q;

  *err  = 0;

  q=psync_sql_prep_statement("DELETE FROM links WHERE isincomming = 1 ");
  psync_sql_run_free(q);

  if(psync_my_auth[0]) {
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"),  P_STR("iconformat","id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = send_command(api, "listuploadlinks", params);
  } else if (psync_my_user  && psync_my_pass) {
    binparam params[] = {P_STR("username", psync_my_user), P_STR("password", psync_my_pass), P_STR("timeformat", "timestamp"),  P_STR("iconformat","id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = send_command(api, "listuploadlinks", params);
  } else return -1;
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
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
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }

  publinks=psync_find_result(bres, "uploadlinks", PARAM_ARRAY);

  linkscnt = publinks->length;
  for (i = 0; i < linkscnt; ++i) {
    link = publinks->array[i];

    q=psync_sql_prep_statement("REPLACE INTO links  (id, code, comment, traffic, maxspace, downloads, created,"
                                 " modified, name,  isfolder, folderid, fileid, isincomming, icon)"
                               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)");
    psync_sql_bind_uint(q, 1, psync_find_result(link, "uploadlinkid", PARAM_NUM)->num);
    psync_sql_bind_string(q, 2, psync_find_result(link, "code", PARAM_STR)->str);
    psync_sql_bind_string(q, 3, psync_find_result(link, "comment", PARAM_STR)->str);
    psync_sql_bind_uint(q, 4, psync_find_result(link, "space", PARAM_NUM)->num);
    if((br = psync_check_result(link, "maxspace", PARAM_NUM)))
      psync_sql_bind_uint(q, 5, br->num);
    else
      psync_sql_bind_uint(q, 5, 0);
    psync_sql_bind_uint(q, 6, psync_find_result(link, "files", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 7, psync_find_result(link, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 8, psync_find_result(link, "modified", PARAM_NUM)->num);

    meta=psync_find_result(link, "metadata", PARAM_HASH);
    psync_sql_bind_string(q, 9, psync_find_result(meta, "name", PARAM_STR)->str);
    if (psync_find_result(meta, "isfolder", PARAM_BOOL)->num) {
      psync_sql_bind_uint(q, 10, 1);
      psync_sql_bind_uint(q, 11, psync_find_result(meta, "folderid", PARAM_NUM)->num);
      psync_sql_bind_uint(q, 12, 0);
    } else {
      psync_sql_bind_uint(q, 10, 0);
      psync_sql_bind_uint(q, 11, 0);
      psync_sql_bind_uint(q, 12, psync_find_result(meta, "fileid", PARAM_NUM)->num);
    }
    psync_sql_bind_uint(q, 13, psync_find_result(meta, "icon", PARAM_NUM)->num);
    psync_sql_run_free(q);
  }

  psync_free(bres);

  return linkscnt;
}

void cache_links_all()
{
  char *err /*OUT*/ = NULL;
  int ret =0;

  ret = cache_upload_links(&err);
  if (ret >= 0)
    ret += cache_links(&err);

  if (ret < 0) {
    if (err) {
      debug(D_WARNING, "Problem cacheing links errcode %d errmsg[%s]\n", ret, err);
      psync_free(err);
    }
  }
}

int do_delete_all_links(int64_t folderid, int64_t fileid, char**err) {
  psync_sql_res *res;
  psync_uint_row row;
  int ret = 0;

  res=psync_sql_query_rdlock("SELECT id, folderid, fileid, isincomming FROM links where folderid = ? or fileid = ? ");
  psync_sql_bind_int(res, 1, folderid);
  psync_sql_bind_int(res, 2, fileid);

  while ((row=psync_sql_fetch_rowint(res))){
    if (row[3]) {
      ret = do_psync_delete_upload_link(row[0],err);
      if (ret) return ret;
    } else {
      ret = do_psync_delete_link(row[0],err);
      if (ret) return ret;
    }
  }
  return 0;
}

int do_delete_all_folder_links(psync_folderid_t folderid, char**err) {
  psync_sql_res *res;
  psync_full_result_int *rows;
  int ret = 0, i;

  res=psync_sql_query_rdlock("SELECT id, folderid, fileid, isincomming FROM links where folderid = ? ");
  psync_sql_bind_uint(res, 1, folderid);

  rows = psync_sql_fetchall_int(res);

  for (i = 0;i < rows->rows; ++i) {
    if (psync_get_result_cell(rows, i, 3)) {
      ret = do_psync_delete_upload_link(psync_get_result_cell(rows, i, 0),err);
      if (ret) return ret;
    } else {
      ret = do_psync_delete_link(psync_get_result_cell(rows, i, 0),err);
      if (ret) return ret;
    }
  }
  return 0;
}

int do_delete_all_file_links(psync_fileid_t fileid, char**err) {
  psync_sql_res *res;
  psync_full_result_int *rows;
  int ret = 0, i;

  res=psync_sql_query_rdlock("SELECT id, folderid, fileid, isincomming FROM links where fileid = ? ");
  psync_sql_bind_uint(res, 1, fileid);

  rows = psync_sql_fetchall_int(res);

  for (i = 0;i < rows->rows; ++i) {
    if (psync_get_result_cell(rows, i, 3)) {
      ret = do_psync_delete_upload_link(psync_get_result_cell(rows, i, 0), err);
      if (ret) return ret;
    } else {
      ret = do_psync_delete_link(psync_get_result_cell(rows, i, 0), err);
      if (ret) return ret;
    }
  }
  return 0;
}
