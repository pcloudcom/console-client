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
#include "pfolder.h"

#include <stdio.h>

typedef struct _email_vis_params {
  char** email;
  size_t *length;
} email_visitor_params;

typedef struct _team_vis_params {
  char** name;
  size_t *length;
} team_visitor_params;

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
  else {
    *err = psync_strndup("Connection error.", 17);
    return -1;
  }
}

int do_psync_account_stopshare(psync_shareid_t usershareids[], int nusershareid, psync_shareid_t teamshareids[], int nteamshareid, char **err) {
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
    //debug(D_NOTICE, "usershareids %s",ids1);
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
    //debug(D_NOTICE, "teamshareids %s",ids2);
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

int do_psync_account_modifyshare(psync_shareid_t usrshrids[], uint32_t uperms[], int nushid,
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
    //debug(D_NOTICE, "usershareids %s, userpermissions %s",ids1, perms1);
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
    //debug(D_NOTICE, "teamshareids %s teampermissions %s",ids2, perms2);
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

void get_ba_member_email(uint64_t userid, char** email /*OUT*/, size_t *length /*OUT*/) {
  psync_sql_res *res;
  psync_variant_row row;
  const char *cstr;
  *length = 0;
  res=psync_sql_query("SELECT mail FROM baccountemail WHERE id=?");
  psync_sql_bind_uint(res, 1, userid);
  if ((row=psync_sql_fetch_row(res))){
      cstr=psync_get_lstring(row[0], length);
      *email=(char *)psync_malloc(*length);
      memcpy(*email, cstr, *length);
      psync_sql_free_result(res);
      return;
  } else 
    psync_sql_free_result(res);

  {
    binresult *bres;
    const binresult *users;
    const char* fname, *lname;
    
    binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_NUM("userids", userid) };
    bres = psync_api_run_command("account_users", params);

    if (!bres){
      debug(D_NOTICE, "Account users command failed! \n");
      return;
    }
    
    if (api_error_result(bres))
      return;
    
    users = psync_find_result(bres, "users", PARAM_ARRAY);
    if (!users->length) {
      psync_free(bres);
      debug(D_WARNING, "Account_users returned empty result!\n");
      return;
    } else {
      const char *resret = psync_find_result(users->array[0], "email", PARAM_STR)->str;
	  *length = strlen(resret);
	  *email = psync_strndup(resret, *length);
	  fname = psync_find_result(users->array[0], "firstname", PARAM_STR)->str;
	  lname = psync_find_result(users->array[0], "lastname", PARAM_STR)->str;
    }
    psync_free(bres);

    if (*length) {
      psync_sql_res *q;
      q=psync_sql_prep_statement("REPLACE INTO baccountemail  (id, mail, firstname, lastname) VALUES (?, ?, ?, ?)");
      psync_sql_bind_uint(q, 1, userid);
      psync_sql_bind_lstring(q, 2, *email,  *length);
	  psync_sql_bind_lstring(q, 3, fname, strlen(fname));
	  psync_sql_bind_lstring(q, 4, lname, strlen(lname));
      psync_sql_run_free(q);
    }
  
  }
}

void get_ba_team_name(uint64_t teamid, char** name /*OUT*/, size_t *length /*OUT*/) {
  psync_sql_res *res;
  psync_variant_row row;
  const char *cstr;
  
  binresult *bres;
  const binresult *teams;

  res=psync_sql_query("SELECT name FROM baccountteam WHERE id=?");
  psync_sql_bind_uint(res, 1, teamid);
  if ((row=psync_sql_fetch_row(res))){
      cstr=psync_get_lstring(row[0], length);
      *name=(char *)psync_malloc(*length);
      memcpy(*name, cstr, *length);
      psync_sql_free_result(res);
      return;
  } else
    psync_sql_free_result(res);

  //debug(D_NOTICE, "Account_teams numids %d\n", nids);
  binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_NUM("teamids", teamid), P_STR("showeveryone", "1") };
  bres = psync_api_run_command("account_teams", params);

  if (!bres) {
    debug(D_WARNING, "Send command returned in valid result.\n");
    return;
  }
  
  if (api_error_result(bres))
    return;
  
  teams = psync_find_result(bres, "teams", PARAM_ARRAY);

  //debug(D_NOTICE, "Result contains %d teams\n", users->length);

  if (!teams->length){
    psync_free(bres);
    debug(D_WARNING, "Account_teams returned empty result!\n");
    return;
  } else {    
    const char *teamret = "";
    teamret = psync_find_result(teams->array[0], "name", PARAM_STR)->str;
    *length = strlen(teamret);
    *name = psync_strndup(teamret, *length);
  }
  psync_free(bres);
 
  psync_sql_res *q;
  q=psync_sql_prep_statement("REPLACE INTO baccountteam  (id, name) VALUES (?, ?)");
  psync_sql_bind_uint(q, 1, teamid);
  psync_sql_bind_lstring(q, 2, *name,  *length);
  psync_sql_run_free(q);
  
  return; 
}

void cache_account_emails() {
  binresult *bres;
  int i;
  const binresult *users;

  if (psync_my_auth[0]) {
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp")};
    bres =  psync_api_run_command("account_users", params);
  } else if (psync_my_user  && psync_my_pass) {
    binparam params[] =  {P_STR("username", psync_my_user), P_STR("password", psync_my_pass), P_STR("timeformat", "timestamp")};
    bres =  psync_api_run_command("account_users", params);
  } else return;
    
  if (!bres) {
    debug(D_WARNING, "Send command returned invalid result.\n");
    return;
  }

  if (api_error_result(bres))
      return;

  users = psync_find_result(bres, "users", PARAM_ARRAY);

  if (!users->length) {
    debug(D_WARNING, "Account_users returned empty result!\n");
    goto end_close;
  } else {
    psync_sql_res *q;
    psync_sql_start_transaction();
    q=psync_sql_prep_statement("DELETE FROM baccountemail");
    if (unlikely(psync_sql_run_free(q))) {
      psync_sql_rollback_transaction();
      goto end_close;
    }
    
    for (i = 0; i < users->length; ++i) {
      const char *nameret = 0;
      const binresult *user = users->array[i];
      uint64_t userid = 0;
      psync_sql_res *res;
      const char* fname, *lname;
      int active = 0;
      int frozen = 0;

      active = psync_find_result(user, "active", PARAM_BOOL)->num;
      frozen = psync_find_result(user, "frozen", PARAM_BOOL)->num;
      nameret = psync_find_result(user, "email", PARAM_STR)->str;
      userid = psync_find_result(user, "id", PARAM_NUM)->num;
      fname = psync_find_result(user, "firstname", PARAM_STR)->str;
      lname = psync_find_result(user, "lastname", PARAM_STR)->str;

      if (userid && (active || frozen)) {
          res = psync_sql_prep_statement("INSERT INTO baccountemail  (id, mail, firstname, lastname) VALUES (?, ?, ?, ?)");
          psync_sql_bind_uint(res, 1, userid);
          psync_sql_bind_lstring(res, 2, nameret, strlen(nameret));
          psync_sql_bind_lstring(res, 3, fname, strlen(fname));
          psync_sql_bind_lstring(res, 4, lname, strlen(lname));
          if (unlikely(psync_sql_run_free(res))) {
            psync_sql_rollback_transaction();
            goto end_close;
          }
      }
    }
    psync_sql_commit_transaction();
  }
end_close:
  psync_free(bres);
}

void cache_account_teams() {
  binresult *bres;
  int i;
  const binresult *users;

  if (psync_my_auth[0]) {
      binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_STR("showeveryone", "1")};
      bres = psync_api_run_command("account_teams", params);
  } else if (psync_my_user && psync_my_pass) {
      binparam params[] =  {P_STR("username", psync_my_user), P_STR("password", psync_my_pass), P_STR("timeformat", "timestamp"), P_STR("showeveryone", "1")};
      bres = psync_api_run_command("account_teams", params);
  } else return;
  
  if (!bres) {
    debug(D_WARNING, "Send command returned in valid result.\n");
    return;
  }
  
  if (api_error_result(bres))
    return;
  
  users = psync_find_result(bres, "teams", PARAM_ARRAY);

  //debug(D_NOTICE, "Result contains %d teams\n", users->length);

  if (!users->length){
    psync_free(bres);
    debug(D_WARNING, "Account_teams returned empty result!\n");
    return;
  } else {
    psync_sql_res *q;
    psync_sql_start_transaction();
    q=psync_sql_prep_statement("DELETE FROM baccountteam");
    if (unlikely(psync_sql_run_free(q)))
      psync_sql_rollback_transaction();
  
    for (i = 0; i < users->length; ++i)
    {
      const char *nameret = 0;
      nameret = psync_find_result(users->array[i], "name", PARAM_STR)->str;
      uint64_t teamid = 0;
      psync_sql_res *res;
      
      teamid = psync_find_result(users->array[i], "id", PARAM_NUM)->num;
      //debug(D_NOTICE, "Team name %s team id %lld\n", nameret,(long long)teamid);
      res=psync_sql_prep_statement("INSERT INTO baccountteam  (id, name) VALUES (?, ?)");
      psync_sql_bind_uint(res, 1, teamid);
      psync_sql_bind_lstring(res, 2, nameret, strlen(nameret));
    if (unlikely(psync_sql_run_free(res)))
      psync_sql_rollback_transaction();
    }
    psync_sql_commit_transaction();
  }
  psync_free(bres);
  return;
 
}

static void cache_my_team(const binresult *team1) {
  const char *nameret = 0;
  const binresult *team;
  uint64_t teamid = 0;
  psync_sql_res *q;

  team = psync_find_result(team1, "team", PARAM_HASH);

  nameret = psync_find_result(team, "name", PARAM_STR)->str;
  teamid = psync_find_result(team, "id", PARAM_NUM)->num;
  //debug(D_NOTICE, "My Team name %s team id %lld\n", nameret,(long long)teamid);
  q=psync_sql_prep_statement("INSERT INTO myteams  (id, name) VALUES (?, ?)");
  psync_sql_bind_uint(q, 1, teamid);
  psync_sql_bind_lstring(q, 2, nameret, strlen(nameret));
  psync_sql_run_free(q);
}

void cache_ba_my_teams() {
  binresult *bres;
  const binresult *users;
  const binresult *user;
  const binresult *teams;
  psync_sql_res *q;
  int i;
  
  binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_STR("userids", "me"), P_STR("showteams", "1"), P_STR("showeveryone", "1") };
  bres = psync_api_run_command("account_users", params);
  if (!bres) {
    debug(D_WARNING, "Send command returned invalid result.\n");
    return;
  }
  
  if (api_error_result(bres))
    return;

  users = psync_find_result(bres, "users", PARAM_ARRAY);

  if (!users->length) {
    psync_free(bres);
    debug(D_WARNING, "Account_users returned empty result!\n");
    return;
  }

  psync_sql_lock();
  q=psync_sql_prep_statement("DELETE FROM myteams");
  psync_sql_run_free(q);
  user =  users->array[0];
  teams = psync_find_result(user, "teams", PARAM_ARRAY);
  for (i = 0; i < teams->length; i++)
    cache_my_team(teams->array[i]);
  psync_free(bres);
  psync_sql_unlock();
}

int api_error_result(binresult* res) {
  uint64_t result;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    psync_free(res);
    psync_process_api_error(result);
    return 1;
  }
  return 0;
}


void psync_update_cryptostatus(){
 if (psync_my_auth[0]) {
    binresult *res;
    const binresult *cres;
    psync_sql_res *q;
    uint64_t u, crexp, crsub = 0, is_business = 0;
    int crst = 0,crstat;
  
    binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat","timestamp") };
    res = psync_api_run_command("userinfo", params);
    if (!res) {
      debug(D_WARNING, "Send command returned invalid result.\n");
      return;
    }
    
    if (api_error_result(res))
      return;
    
    q=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
    
    is_business=psync_find_result(res, "business", PARAM_BOOL)->num;
    
    u=psync_find_result(res, "cryptosetup", PARAM_BOOL)->num;
    psync_sql_bind_string(q, 1, "cryptosetup");
    psync_sql_bind_uint(q, 2, u);
    psync_sql_run(q);
    if (u)
      crst = 1;
    psync_sql_bind_string(q, 1, "cryptosubscription");
    crsub =  psync_find_result(res, "cryptosubscription", PARAM_BOOL)->num;
    psync_sql_bind_uint(q, 2, crsub);
    psync_sql_run(q);
    
    cres=psync_check_result(res, "cryptoexpires", PARAM_NUM);
    crexp = cres?cres->num:0;
    psync_sql_bind_string(q, 1, "cryptoexpires");
    psync_sql_bind_uint(q, 2, crexp);
    psync_sql_run(q);

    if (is_business || crsub){
      if (crst)
        crstat = 5;
      else  crstat = 4;
    } else {
      if (!crst)
        crstat = 1;
      else 
      {
        if (psync_time() > crexp)
          crstat = 3;
        else 
          crstat = 2;
      }
    }
    psync_sql_bind_string(q, 1, "cryptostatus");
    psync_sql_bind_uint(q, 2, crstat);
    psync_sql_run(q);
    psync_sql_free_result(q);

  }
}

static int check_write_permissions (psync_folderid_t folderid) {
  psync_sql_res* res;
  psync_uint_row row;
  int  ret = 0;
  
  res=psync_sql_query("SELECT permissions, flags, name FROM folder WHERE id=?");
  psync_sql_bind_uint(res, 1, folderid);
  row=psync_sql_fetch_rowint(res);
  if (unlikely(!row))
    debug(D_ERROR, "could not find folder of folderid %lu", (unsigned long)folderid);
  else if (/*(((row[1]) & 3) != O_RDONLY) &&*/ ((row[0]&PSYNC_PERM_MODIFY)&&(row[0]&PSYNC_PERM_CREATE)))
    ret = 1;
    
   psync_sql_free_result(res);
   return ret;
}
static psync_folderid_t create_index_folder(const char * path) {
  char *buff=NULL;
  uint32_t bufflen;
  int ind = 1;
  char * err;
  psync_folderid_t folderid;
    
  while (ind < 100) {
    folderid=PSYNC_INVALID_FOLDERID;
    bufflen = strlen(path) + 1 /*zero char*/ + 3 /*parenthesis*/ + 3 /*up to 3 digit index*/;
    buff = (char *) psync_malloc(bufflen);
    snprintf(buff, bufflen - 1, "%s (%d)", path, ind);
    if (psync_create_remote_folder_by_path(buff, &err)!=0)
      debug(D_NOTICE, "Unable to create folder %s error is %s.", buff, err);
    folderid=psync_get_folderid_by_path(buff);
    if ((folderid!=PSYNC_INVALID_FOLDERID)&&check_write_permissions(folderid)) {
      psync_free(buff);
      break;
    }
    ++ind;
    if (err)
      psync_free(err);
    psync_free(buff);
  }
  return folderid;
}
psync_folderid_t psync_check_and_create_folder (const char * path) {
  psync_folderid_t folderid=psync_get_folderid_by_path(path);
  char *err;
  
  if (folderid==PSYNC_INVALID_FOLDERID) {
    if(psync_create_remote_folder_by_path(path, &err)!=0) {
      debug(D_NOTICE, "Unable to create folder %s error is %s.", path, err);
      psync_free(err);
      folderid = create_index_folder(path);
    }
  } else if (!check_write_permissions(folderid))
   folderid = create_index_folder(path);

  return folderid; 
}