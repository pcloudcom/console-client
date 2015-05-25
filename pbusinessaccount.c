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

#include "pbusinessaccount.h"
#include "papi.h"
#include "plibs.h"
#include "pnetlibs.h"

#include <stdio.h>

#define FOLDERID_ENTRY_SIZE 18
#define INVALID_SHAREDID_RESULT 2025

static void init_param_str(binparam* t, const char *name, const char *val) {
  //{PARAM_STR, strlen(name), strlen(val), (name), {(uint64_t)((uintptr_t)(val))}}
  t->paramtype  = PARAM_STR;
  t->paramnamelen = strlen(name);
  t->opts = strlen(val);
  t->paramname = name;
  t->str = val;
}
/*
static void init_param_num(binparam* t, const char *name, uint64_t val) {
  //{PARAM_NUM, strlen(name), 0, (name), {(val)}}
  t->paramtype  = PARAM_NUM;
  t->paramnamelen = strlen(name);
  t->opts = 0;
  t->paramname = name;
  t->num = val;
}*/

static int handle_result(const binresult *bres, uint64_t result, char **err) 
{
  const char *errorret = 0;

  
  errorret = psync_find_result(bres, "error", PARAM_STR)->str;
  if(strlen(errorret) == 0)
    errorret = psync_find_result(bres, "message", PARAM_STR)->str;
    
  *err = psync_strndup(errorret, strlen(errorret));
  debug(D_WARNING, "command gettreepublink returned error code %u message %s", (unsigned)result, errorret);
  psync_process_api_error(result);
  if (psync_handle_api_result(result)==PSYNC_NET_TEMPFAIL)
    return -result;
  else
    return -1;
}

int do_account_stopshare(psync_shareid_t usershareids[], int nusershareid, psync_shareid_t teamshareids[], int nteamshareid, char **err) {
 psync_socket *api;
  binresult *bres;
  uint64_t result,userresult,teamresult;
  char *ids1 = NULL;
  char *ids2 = NULL;
  char *idsp = 0;
  int i,pind = 1, numparam = 1,k;
  binparam *t;
  const binresult *userres, *teamres, *statres;
  *err  = 0;
  
  numparam +=  !!nusershareid + !!nteamshareid;
  if (unlikely(numparam == 1))
    return -3;
    
  t = (binparam *) psync_malloc(numparam*sizeof(binparam));
  
  init_param_str(t, "auth", psync_my_auth);
  
  if (nusershareid) {
    ids1 = (char *) psync_malloc(nusershareid*FOLDERID_ENTRY_SIZE);
    idsp = ids1;
    for (i = 0; i < nusershareid; ++i) {
      k = sprintf(idsp, "%lld",(long long) usershareids[i]);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';
    debug(D_NOTICE, "usershareids %s",ids1);
    init_param_str(t + pind++, "usershareids", ids1);
  }
  
  if (nteamshareid) {
    ids2 = (char *) psync_malloc(nteamshareid*FOLDERID_ENTRY_SIZE);
    idsp = ids2;
    for (i = 0; i < nteamshareid; ++i) {
      k = sprintf(idsp, "%lld", (long long) teamshareids[i]);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';
    debug(D_NOTICE, "teamshareids %s",ids2);
    init_param_str(t + pind++, "teamshareids", ids2);
  }
  
  api=psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return -2;
  }
  
  bres =  do_send_command(api, "account_stopshare", sizeof("account_stopshare") - 1, t, pind, -1, 1);
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result))
    return handle_result(bres, result, err);
 
  statres = psync_find_result(bres, "status", PARAM_HASH);
  teamres = psync_find_result(statres, "team", PARAM_ARRAY)->array[0];
  teamresult = psync_find_result(teamres, "result", PARAM_NUM)->num;
  userres = psync_find_result(statres, "user", PARAM_ARRAY)->array[0];
  userresult = psync_find_result(userres, "result", PARAM_NUM)->num;
  if (!userresult || !teamresult)
    result = 0;
  else {
    if(userresult == INVALID_SHAREDID_RESULT && teamresult == INVALID_SHAREDID_RESULT)
      result = handle_result(userres, userresult, err); 
    else if (userresult)
      result = handle_result(userres, userresult, err); 
    else 
      result = handle_result(teamres, teamresult, err); 
  }
  
  if (ids1)
    psync_free(ids1);
  if (ids2)
    psync_free(ids2);
  
  psync_free(bres);
  psync_free(t);
  
  return result;
  
}

int do_account_modifyshare(psync_shareid_t usrshrids[], uint32_t uperms[], int nushid, 
                           psync_shareid_t tmshrids[], uint32_t tperms[], int ntmshid, char **err) {
  psync_socket *api;
  binresult *bres;
  uint64_t result,userresult,teamresult;
  char *ids1 = NULL;
  char *ids2 = NULL;
  char *perms1 = NULL;
  char *perms2 = NULL;
  char *idsp = 0;
  char *permsp = 0;
  int i,pind = 1, numparam = 1, k;
  binparam *t;
  const binresult *userres, *teamres, *statres;
  *err  = 0;
  
  numparam += 2*(!!nushid) + 2*(!!ntmshid);
  if (unlikely(numparam == 1))
    return -3;
    
  t = (binparam *) psync_malloc(numparam*sizeof(binparam));
  
  init_param_str(t, "auth", psync_my_auth);
  
  if (nushid) {
    ids1 = (char *) psync_malloc(nushid*FOLDERID_ENTRY_SIZE);
    idsp = ids1;
    perms1 = (char *) psync_malloc(nushid*FOLDERID_ENTRY_SIZE);
    permsp = perms1;
    for (i = 0; i < nushid; ++i) {
      k = sprintf(idsp, "%lld",(long long) usrshrids[i]);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
      
      k = sprintf(permsp, "%lld",(long long) uperms[i]);
      if (unlikely(k <= 0 )) break;
      permsp[k] = ',';
      permsp = permsp + k + 1;
    }
    if (i > 0) {
      *(idsp - 1) = '\0';
      *(permsp - 1) = '\0';
    }
    debug(D_NOTICE, "usershareids %s, userpermissions %s",ids1, perms1);
    init_param_str(t + pind++, "usershareids", ids1);
    init_param_str(t + pind++, "userpermissions", perms1);
  }

  if (ntmshid) {
    ids2 = (char *) psync_malloc(ntmshid*FOLDERID_ENTRY_SIZE);
    idsp = ids2;
    perms2 = (char *) psync_malloc(ntmshid*FOLDERID_ENTRY_SIZE);
    permsp = perms2;
    
    for (i = 0; i < ntmshid; ++i) {
      k = sprintf(idsp, "%lld", (long long) tmshrids[i]);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
      
      k = sprintf(permsp, "%lld",(long long) uperms[i]);
      if (unlikely(k <= 0 )) break;
      permsp[k] = ',';
      permsp = permsp + k + 1;
    }
    if (i > 0) {
      *(idsp - 1) = '\0';
      *(permsp - 1) = '\0';
    }
    debug(D_NOTICE, "teamshareids %s teampermissions %s",ids2, perms2);
    init_param_str(t + pind++, "teamshareids", ids2);
    init_param_str(t + pind++, "teampermissions", perms2);
  }
  
  api=psync_apipool_get();
  if (unlikely(!api)) {
    debug(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return -2;
  }
  
  bres =  do_send_command(api, "account_modifyshare", sizeof("account_modifyshare") - 1, t, pind, -1, 1);
  
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  
  result=psync_find_result(bres, "result", PARAM_NUM)->num;
  if (unlikely(result))
    return handle_result(bres, result, err);
 
  statres = psync_find_result(bres, "status", PARAM_HASH);
  teamres = psync_find_result(statres, "team", PARAM_ARRAY)->array[0];
  teamresult = psync_find_result(teamres, "result", PARAM_NUM)->num;
  userres = psync_find_result(statres, "user", PARAM_ARRAY)->array[0];
  userresult = psync_find_result(userres, "result", PARAM_NUM)->num;
  if (!userresult || !teamresult)
    result = 0;
  else {
    if(userresult == INVALID_SHAREDID_RESULT && teamresult == INVALID_SHAREDID_RESULT)
      result = handle_result(userres, userresult, err); 
    else if (userresult)
      result = handle_result(userres, userresult, err); 
    else 
      result = handle_result(teamres, teamresult, err); 
  }
  
  if (ids1)
    psync_free(ids1);
  if (ids2)
    psync_free(ids2);
  if (perms1)
    psync_free(perms1);
  if (perms2)
    psync_free(perms2);
  
  psync_free(bres);
  psync_free(t);
  
  return result;
}