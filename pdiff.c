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

#include "pdiff.h"
#include "pcompat.h"
#include "pstatus.h"
#include "psettings.h"
#include "plibs.h"
#include "papi.h"

static uint64_t used_quota=0;

static psync_socket *get_connected_socket(){
  char *auth, *user, *pass;
  psync_socket *sock;
  binresult *res;
  psync_sql_res *q;
  uint64_t result, userid, luserid;
  int usessl, saveauth;
  auth=user=pass=NULL;
  while (1){
    psync_free(auth);
    psync_free(user);
    psync_free(pass);
    psync_wait_status(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN|PSTATUS_RUN_PAUSE);
    auth=psync_sql_cellstr("SELECT value FROM settings WHERE id='auth'");
    user=psync_sql_cellstr("SELECT value FROM settings WHERE id='user'");
    pass=psync_sql_cellstr("SELECT value FROM settings WHERE id='pass'");
    if (!auth && psync_my_auth)
      auth=psync_strdup(psync_my_auth);
    if (!user && psync_my_user)
      user=psync_strdup(psync_my_user);
    if (!pass && psync_my_pass)
      pass=psync_strdup(psync_my_pass);
    if (!auth && (!pass || !user)){
      psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_REQURED);
      psync_wait_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      continue;
    }
    usessl=psync_sql_cellint("SELECT value FROM settings WHERE id='usessl'", PSYNC_USE_SSL_DEFAULT);
    saveauth=psync_sql_cellint("SELECT value FROM settings WHERE id='saveauth'", 1);
    sock=psync_api_connect(usessl);
    if (!sock){
      psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_OFFLINE);
      psync_milisleep(PSYNC_SLEEP_BEFORE_RECONNECT);
      continue;
    }
    if (user && pass){
      binparam params[]={P_STR("timeformat", "timestamp"), P_STR("username", user), P_STR("password", pass), P_BOOL("getauth", 1)};
      res=send_command(sock, "userinfo", params);
    }
    else {
      binparam params[]={P_STR("timeformat", "timestamp"), P_STR("auth", auth)};
      res=send_command(sock, "userinfo", params);
    }
    if (!res){
      psync_socket_close(sock);
      psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_OFFLINE);
      psync_milisleep(PSYNC_SLEEP_BEFORE_RECONNECT);
      continue;
    }
    result=psync_find_result(res, "result", PARAM_NUM)->num;
    if (result){
      psync_socket_close(sock);
      psync_free(res);
      if (result==2000){
        psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_BADLOGIN);
        psync_wait_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      }
      else if (result==4000)
        psync_milisleep(5*60*1000);
      else
        psync_milisleep(PSYNC_SLEEP_BEFORE_RECONNECT);
      continue;
    }
    userid=psync_find_result(res, "userid", PARAM_NUM)->num;
    luserid=psync_sql_cellint("SELECT value FROM settings WHERE id='userid'", 0);
    if (luserid){
      if (luserid!=userid){
        psync_socket_close(sock);
        psync_free(res);
        psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_MISMATCH);
        psync_wait_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
        continue;
      }
    }
    else{
      used_quota=0;
      q=psync_sql_prep_statement("REPLACE INTO settings (id, value) VALUES (?, ?)");
      if (q){
        psync_sql_bind_string(q, 1, "userid");
        psync_sql_bind_uint(q, 2, userid);
        psync_sql_run(q);
        psync_sql_bind_string(q, 1, "quota");
        psync_sql_bind_uint(q, 2, psync_find_result(res, "quota", PARAM_NUM)->num);
        psync_sql_run(q);
        psync_sql_bind_string(q, 1, "usedquota");
        psync_sql_bind_uint(q, 2, 0);
        psync_sql_run(q);
        result=psync_find_result(res, "premium", PARAM_BOOL)->num;
        psync_sql_bind_string(q, 1, "premium");
        psync_sql_bind_uint(q, 2, result);
        psync_sql_run(q);
        if (result)
          result=psync_find_result(res, "premiumexpires", PARAM_BOOL)->num;
        else
          result=0;
        psync_sql_bind_string(q, 1, "premiumexpires");
        psync_sql_bind_uint(q, 2, result);
        psync_sql_run(q);
        result=psync_find_result(res, "emailverified", PARAM_BOOL)->num;
        psync_sql_bind_string(q, 1, "emailverified");
        psync_sql_bind_uint(q, 2, result);
        psync_sql_run(q);
        psync_sql_bind_string(q, 1, "username");
        psync_sql_bind_string(q, 2, psync_find_result(res, "email", PARAM_STR)->str);
        psync_sql_run(q);
        psync_sql_bind_string(q, 1, "language");
        psync_sql_bind_string(q, 2, psync_find_result(res, "language", PARAM_STR)->str);
        psync_sql_run(q);
        pthread_mutex_lock(&psync_my_auth_mutex);
        psync_free(psync_my_auth);
        psync_my_auth=psync_strdup(psync_find_result(res, "auth", PARAM_STR)->str);
        pthread_mutex_unlock(&psync_my_auth_mutex);
        if (saveauth){
          psync_sql_bind_string(q, 1, "auth");
          psync_sql_bind_string(q, 2, psync_my_auth);
          psync_sql_run(q);
        }
        psync_sql_free_result(q);
      }
    }
    pthread_mutex_lock(&psync_my_auth_mutex);
    psync_free(psync_my_pass);
    psync_my_pass=NULL;
    pthread_mutex_unlock(&psync_my_auth_mutex);
    if (saveauth)
      psync_sql_statement("DELETE FROM settings WHERE id='pass'");
    else
      psync_sql_statement("DELETE FROM settings WHERE id IN ('pass', 'auth')");
    psync_free(res);
    psync_free(auth);
    psync_free(user);
    psync_free(pass);
    return sock;
  }
}

static uint64_t process_entries(const binresult *entries, uint64_t olddiffid, uint64_t newdiffid){
}

void psync_diff_thread(){
  psync_socket *sock;
  binresult *res;
  const binresult *entries;
  uint64_t diffid, newdiffid, result;
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  psync_milisleep(2);
restart:
  sock=get_connected_socket();
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_SCANNING);
  diffid=psync_sql_cellint("SELECT value FROM settings WHERE id='diffid'", 0);
  do{
    binparam diffparams[]={P_STR("timeformat", "timestamp"), P_NUM("limit", PSYNC_DIFF_LIMIT), P_NUM("diffid", diffid)};
    res=send_command(sock, "diff", diffparams);
    if (!res){
      psync_socket_close(sock);
      goto restart;
    }
    result=psync_find_result(res, "result", PARAM_NUM)->num;
    if (result){
      debug(D_ERROR, "diff returned error %u: %s", (unsigned int)result, psync_find_result(res, "error", PARAM_STR)->str);
      psync_free(res);
      psync_socket_close(sock);
      psync_milisleep(PSYNC_SLEEP_BEFORE_RECONNECT);
      goto restart;
    }
    entries=psync_find_result(res, "entries", PARAM_ARRAY);
    if (entries->length){
      newdiffid=psync_find_result(res, "diffid", PARAM_NUM)->num;
      diffid=process_entries(entries, diffid, newdiffid);
    }
    result=entries->length;
    psync_free(res);
  } while (result);
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
}
