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

int do_psync_account_users(psync_userid_t userids[], int nids, result_visitor vis, void *param) {
  psync_socket *sock;
  binresult *bres;
  char *ids = NULL;
  char *idsp = 0;
  int k,i;
  const binresult *users;
  
  if (nids) { 
    
    ids = (char *) psync_malloc(nids*FOLDERID_ENTRY_SIZE);
    idsp = ids;
    for (i = 0; i < nids; ++i) {
      k = sprintf(idsp, "%lld", (long long) userids[i]);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';

    {
      binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_STR("userids", ids) };
      sock = psync_apipool_get();
      bres = send_command(sock, "account_users", params);
    }
  } else {
    if (psync_my_auth[0]) {
      binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp")};
      sock = psync_apipool_get();
      bres = send_command(sock, "account_users", params);
    } else if (psync_my_user) {
      binparam params[] =  {P_STR("username", psync_my_user), P_STR("password", psync_my_pass), P_STR("timeformat", "timestamp")};
      sock = psync_apipool_get();
      bres = send_command(sock, "account_users", params);
    } else return -1;
  }
  if (likely(bres))
    psync_apipool_release(sock);
  else {
    psync_apipool_release_bad(sock);
    debug(D_WARNING, "Send command returned invalid result.\n");
    return -1;
  }
  
  
  users = psync_find_result(bres, "users", PARAM_ARRAY);
  
  if (!users->length){
    psync_free(bres);
    psync_free(ids);
    debug(D_WARNING, "Account_users returned empty result!\n");
    return -2;
  } else {
    for (i = 0; i < users->length; ++i)
       vis(i, users->array[i], param);
  }
  
  psync_free(bres);
  psync_free(ids);
  return 0;
}

static void copy_email(int i, const binresult *user, void *_this) {
  const char *emailret = "";
  email_visitor_params *params = (email_visitor_params *) _this;
  emailret = psync_find_result(user, "email", PARAM_STR)->str;
  *(params->length) = strlen(emailret);
  *(params->email) = psync_strndup(emailret, *(params->length));
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
  } else {
    psync_sql_res *q;
    psync_userid_t userids[] = {userid};
    email_visitor_params params = {email, length};
    do_psync_account_users(userids, 1, &copy_email, &params);
   
    if (*length) {
      q=psync_sql_prep_statement("INSERT INTO baccountemail  (id, mail) VALUES (?, ?)");
      psync_sql_bind_uint(q, 1, userid);
      psync_sql_bind_lstring(q, 2, *email,  *length);
      psync_sql_run_free(q);
    }
  }
  psync_sql_free_result(res);
}

int do_psync_account_teams(psync_userid_t teamids[], int nids, result_visitor vis, void *param) {
  psync_socket *sock;
  binresult *bres;
  char *ids = NULL;
  char *idsp = 0;
  int k,i;
  const binresult *users;
  
  if (nids) {
    ids = (char *) psync_malloc(nids*FOLDERID_ENTRY_SIZE);
    idsp = ids;
    for (i = 0; i < nids; ++i) {
      k = sprintf(idsp, "%lld", (long long) teamids[i]);
      if (unlikely(k <= 0 )) break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';
    
    //debug(D_NOTICE, "Account_teams numids %d\n", nids);
    
    binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"),  P_STR("teamids", ids), P_STR("showeveryone", "1")};

    sock = psync_apipool_get();
    bres = send_command(sock, "account_teams", params);
  } else {
    if (psync_my_auth[0]) {
      binparam params[] = {P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_STR("showeveryone", "1")};
      sock = psync_apipool_get();
      bres = send_command(sock, "account_teams", params);
    } else if (psync_my_user) {
      binparam params[] =  {P_STR("username", psync_my_user), P_STR("password", psync_my_pass), P_STR("timeformat", "timestamp"), P_STR("showeveryone", "1")};
      sock = psync_apipool_get();
      bres = send_command(sock, "account_teams", params);
    } else return -1;
  } 
  if (likely(bres))
    psync_apipool_release(sock);
  else {
    psync_apipool_release_bad(sock);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return -1;
  }
  
  
  users = psync_find_result(bres, "teams", PARAM_ARRAY);
  
  //debug(D_NOTICE, "Result contains %d teams\n", users->length);
  
  if (!users->length){
    psync_free(bres);
    psync_free(ids);
    debug(D_WARNING, "Account_teams returned empty result!\n");
    return -2;
  } else {
    for (i = 0; i < users->length; ++i)
      vis(i, users->array[i], param);
  } 
  psync_free(bres);
  psync_free(ids);
  return 0;
}

static void copy_team(int i, const binresult *user, void *_this) {
  const char *emailret = "";
  team_visitor_params *params = (team_visitor_params *) _this;
  emailret = psync_find_result(user, "name", PARAM_STR)->str;
  *(params->length) = strlen(emailret);
  *(params->name) = psync_strndup(emailret, *(params->length));
}


void get_ba_team_name(uint64_t teamid, char** name /*OUT*/, size_t *length /*OUT*/) {
  psync_sql_res *res;
  psync_variant_row row;
  const char *cstr;
  
  res=psync_sql_query("SELECT name FROM baccountteam WHERE id=?");
  psync_sql_bind_uint(res, 1, teamid);
  if ((row=psync_sql_fetch_row(res))){
      cstr=psync_get_lstring(row[0], length);
      *name=(char *)psync_malloc(*length);
      memcpy(*name, cstr, *length);
  } else {
    psync_sql_res *q;
    psync_userid_t teamids[] = {teamid};
    team_visitor_params params = {name, length};
    do_psync_account_teams(teamids, 1, &copy_team, &params);
   
    q=psync_sql_prep_statement("INSERT INTO baccountteam  (id, name) VALUES (?, ?)");
    psync_sql_bind_uint(q, 1, teamid);
    psync_sql_bind_lstring(q, 2, *name,  *length);
    psync_sql_run_free(q);
  }
  psync_sql_free_result(res);
}

static void insert_cache_email(int i, const binresult *user, void *_this) {
  const char *char_field = 0;
  char_field = psync_find_result(user, "email", PARAM_STR)->str;
  uint64_t id = 0;
  psync_sql_res *q;
  int active = 0;
  int frozen = 0;
  
  active = psync_find_result(user, "active", PARAM_BOOL)->num;
  frozen = psync_find_result(user, "frozen", PARAM_BOOL)->num;
  id = psync_find_result(user, "id", PARAM_NUM)->num;

  if (id && (active || frozen)) {
    q=psync_sql_prep_statement("REPLACE INTO baccountemail  (id, mail, firstname, lastname) VALUES (?, ?, ?, ?)");
    psync_sql_bind_uint(q, 1, id);
    psync_sql_bind_lstring(q, 2, char_field, strlen(char_field));
    char_field = psync_find_result(user, "firstname", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 3, char_field, strlen(char_field));
    char_field = psync_find_result(user, "lastname", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 4, char_field, strlen(char_field));
    psync_sql_run_free(q);
  }
}

void cache_account_emails() {
  psync_userid_t *userids = 0;
  void *params = 0;
  psync_sql_res *q;
  
  psync_sql_lock();
  q=psync_sql_prep_statement("DELETE FROM baccountemail ");
  psync_sql_run_free(q);
  
  do_psync_account_users(userids, 0, &insert_cache_email, params);
  psync_sql_unlock();
}

static void insert_cache_team(int i, const binresult *team, void *_this) {
  const char *nameret = 0;
  nameret = psync_find_result(team, "name", PARAM_STR)->str;
  uint64_t teamid = 0;
  psync_sql_res *q;
  
  teamid = psync_find_result(team, "id", PARAM_NUM)->num;
  
  //debug(D_NOTICE, "Team name %s team id %lld\n", nameret,(long long)teamid);
  
  q=psync_sql_prep_statement("REPLACE INTO baccountteam  (id, name) VALUES (?, ?)");
  psync_sql_bind_uint(q, 1, teamid);
  psync_sql_bind_lstring(q, 2, nameret, strlen(nameret));
  psync_sql_run_free(q);

}

void cache_account_teams() {
  psync_userid_t *teamids = 0;
  void *params = 0;
  psync_sql_res *q;
  
  psync_sql_lock();
  q=psync_sql_prep_statement("DELETE FROM baccountteam ");
  psync_sql_run_free(q);
  do_psync_account_teams(teamids, 0, &insert_cache_team, params);
  psync_sql_unlock();
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
  psync_socket *sock;
  binresult *bres;
  int i;
  const binresult *users;
  const binresult *user;
  const binresult *teams;
  psync_sql_res *q;
  psync_sql_lock();
  
  q=psync_sql_prep_statement("DELETE FROM myteams ");
  psync_sql_run_free(q);
  
  binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp"), P_STR("userids", "me"), P_STR("showteams", "1"), P_STR("showeveryone", "1") };

    sock = psync_apipool_get();
    bres = send_command(sock, "account_users", params);

  if (likely(bres))
    psync_apipool_release(sock);
  else {
    psync_apipool_release_bad(sock);
    debug(D_WARNING, "Send command returned invalid result.\n");
    return;
  }
  
  
  users = psync_find_result(bres, "users", PARAM_ARRAY);
  
  if (!users->length) {
    psync_free(bres);
    debug(D_WARNING, "Account_users returned empty result!\n");
    return;
  } else {
    user =  users->array[0];
    teams = psync_find_result(user, "teams", PARAM_ARRAY);
    if (teams->length) {
       for (i = 0; i < teams->length; ++i)
         cache_my_team(teams->array[i]);
    }
  }
  
  psync_free(bres);
  psync_sql_unlock();
}
