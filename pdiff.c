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
#include "ptimer.h"

static uint64_t used_quota=0, current_quota=0;
static psync_socket_t exceptionsockwrite=INVALID_SOCKET;

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
    auth=psync_sql_cellstr("SELECT value FROM setting WHERE id='auth'");
    user=psync_sql_cellstr("SELECT value FROM setting WHERE id='user'");
    pass=psync_sql_cellstr("SELECT value FROM setting WHERE id='pass'");
    if (!auth && psync_my_auth)
      auth=psync_strdup(psync_my_auth);
    if (!user && psync_my_user)
      user=psync_strdup(psync_my_user);
    if (!pass && psync_my_pass)
      pass=psync_strdup(psync_my_pass);
    if (!auth && (!pass || !user)){
      psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_REQUIRED);
      psync_wait_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      continue;
    }
    usessl=psync_sql_cellint("SELECT value FROM setting WHERE id='usessl'", PSYNC_USE_SSL_DEFAULT);
    saveauth=psync_sql_cellint("SELECT value FROM setting WHERE id='saveauth'", 1);
    sock=psync_api_connect(usessl);
    if (!sock){
      psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_OFFLINE);
      psync_milisleep(PSYNC_SLEEP_BEFORE_RECONNECT);
      continue;
    }
    if (user && pass){
      binparam params[]={P_STR("timeformat", "timestamp"), 
                         P_STR("filtermeta", PSYNC_DIFF_FILTER_META),  
                         P_STR("username", user), 
                         P_STR("password", pass), 
                         P_BOOL("getauth", 1)};
      res=send_command(sock, "userinfo", params);
    }
    else {
      binparam params[]={P_STR("timeformat", "timestamp"), 
                         P_STR("filtermeta", PSYNC_DIFF_FILTER_META),  
                         P_STR("auth", auth),
                         P_BOOL("getauth", 1)};
      res=send_command(sock, "userinfo", params);
    }
    if (!res){
      psync_socket_close(sock);
      psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_OFFLINE);
      psync_milisleep(PSYNC_SLEEP_BEFORE_RECONNECT);
      psync_api_conn_fail_inc();
      continue;
    }
    psync_api_conn_fail_reset();
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
    psync_my_userid=userid=psync_find_result(res, "userid", PARAM_NUM)->num;
    current_quota=psync_find_result(res, "quota", PARAM_NUM)->num;
    luserid=psync_sql_cellint("SELECT value FROM setting WHERE id='userid'", 0);
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
      q=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
      if (q){
        psync_sql_bind_string(q, 1, "userid");
        psync_sql_bind_uint(q, 2, userid);
        psync_sql_run(q);
        psync_sql_bind_string(q, 1, "quota");
        psync_sql_bind_uint(q, 2, current_quota);
        psync_sql_run(q);
        psync_sql_bind_string(q, 1, "usedquota");
        psync_sql_bind_uint(q, 2, 0);
        psync_sql_run(q);
        result=psync_find_result(res, "premium", PARAM_BOOL)->num;
        psync_sql_bind_string(q, 1, "premium");
        psync_sql_bind_uint(q, 2, result);
        psync_sql_run(q);
        if (result)
          result=psync_find_result(res, "premiumexpires", PARAM_NUM)->num;
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
      psync_sql_statement("DELETE FROM setting WHERE id='pass'");
    else
      psync_sql_statement("DELETE FROM setting WHERE id IN ('pass', 'auth')");
    psync_free(res);
    psync_free(auth);
    psync_free(user);
    psync_free(pass);
    return sock;
  }
}

static uint64_t get_permissions(const binresult *meta){
  return 
    (psync_find_result(meta, "canread", PARAM_BOOL)->num?PSYNC_PERM_READ:0)+
    (psync_find_result(meta, "canmodify", PARAM_BOOL)->num?PSYNC_PERM_MODIFY:0)+
    (psync_find_result(meta, "candelete", PARAM_BOOL)->num?PSYNC_PERM_DELETE:0)+
    (psync_find_result(meta, "cancreate", PARAM_BOOL)->num?PSYNC_PERM_CREATE:0);
}

static void process_createfolder(const binresult *entry){
  static psync_sql_res *st=NULL;
  const binresult *meta, *name;
  uint64_t userid, perms;
  if (!entry){
    if (st){
      psync_sql_free_result(st);
      st=NULL;
    }
    return;
  }
  if (!st){
    st=psync_sql_prep_statement("REPLACE INTO folder (id, parentfolderid, userid, permissons, name, ctime, mtime) VALUES (?, ?, ?, ?, ?, ?, ?)");
    if (!st)
      return;
  }
  meta=psync_find_result(entry, "metadata", PARAM_HASH);
  if (psync_find_result(meta, "ismine", PARAM_BOOL)->num){
    userid=psync_my_userid;
    perms=PSYNC_PERM_ALL;
  }
  else{
    userid=psync_find_result(meta, "userid", PARAM_NUM)->num;
    perms=get_permissions(meta);
  }
  name=psync_find_result(meta, "name", PARAM_STR);
  psync_sql_bind_uint(st, 1, psync_find_result(meta, "folderid", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 2, psync_find_result(meta, "parentfolderid", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 3, userid);
  psync_sql_bind_uint(st, 4, perms);
  psync_sql_bind_lstring(st, 5, name->str, name->length);
  psync_sql_bind_uint(st, 6, psync_find_result(meta, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 7, psync_find_result(meta, "modified", PARAM_NUM)->num);
  psync_sql_run(st);
}

static void process_modifyfolder(const binresult *entry){
  process_createfolder(entry);
}

static void process_deletefolder(const binresult *entry){
  static psync_sql_res *st=NULL;
  uint64_t folderid;
  if (!entry){
    if (st){
      psync_sql_free_result(st);
      st=NULL;
    }
    return;
  }
  if (!st){
    st=psync_sql_prep_statement("DELETE FROM folder WHERE id=?");
    if (!st)
      return;
  }
  folderid=psync_find_result(psync_find_result(entry, "metadata", PARAM_HASH), "folderid", PARAM_NUM)->num;
  psync_sql_bind_uint(st, 1, folderid);
  psync_sql_run(st);
}

static void process_createfile(const binresult *entry){
  static psync_sql_res *st=NULL;
  const binresult *meta, *name;
  uint64_t size, userid;
  if (!entry){
    if (st){
      psync_sql_free_result(st);
      st=NULL;
    }
    return;
  }
  if (!st){
    st=psync_sql_prep_statement("REPLACE INTO file (id, parentfolderid, userid, size, hash, name, ctime, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    if (!st)
      return;
  }
  meta=psync_find_result(entry, "metadata", PARAM_HASH);
  size=psync_find_result(meta, "size", PARAM_NUM)->num;
  if (psync_find_result(meta, "ismine", PARAM_BOOL)->num){
    userid=psync_my_userid;
    used_quota+=size;
  }
  else
    userid=psync_find_result(meta, "userid", PARAM_NUM)->num;
  name=psync_find_result(meta, "name", PARAM_STR);
  psync_sql_bind_uint(st, 1, psync_find_result(meta, "fileid", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 2, psync_find_result(meta, "parentfolderid", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 3, userid);
  psync_sql_bind_uint(st, 4, size);
  psync_sql_bind_uint(st, 5, psync_find_result(meta, "hash", PARAM_NUM)->num);
  psync_sql_bind_lstring(st, 6, name->str, name->length);
  psync_sql_bind_uint(st, 7, psync_find_result(meta, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 8, psync_find_result(meta, "modified", PARAM_NUM)->num);
  psync_sql_run(st);
}

static void process_modifyfile(const binresult *entry){
  static psync_sql_res *st=NULL;
  uint64_t *arr;
  if (!entry){
    if (st){
      psync_sql_free_result(st);
      st=NULL;
    }
  }
  else {
    if (st)
      psync_sql_reset(st);
    else
      st=psync_sql_query("SELECT userid, size FROM file WHERE id=?");
    if (st){
      psync_sql_bind_uint(st, 1, psync_find_result(psync_find_result(entry, "metadata", PARAM_HASH), "fileid", PARAM_NUM)->num);
      arr=psync_sql_fetch_rowint(st);
      if (arr && arr[0]==psync_my_userid)
        used_quota-=arr[1];
    }
  }
  process_createfile(entry);
}

static void process_deletefile(const binresult *entry){
  static psync_sql_res *st=NULL;
  if (!entry){
    if (st){
      psync_sql_free_result(st);
      st=NULL;
    }
    return;
  }
  if (!st){
    st=psync_sql_prep_statement("DELETE FROM file WHERE id=?");
    if (!st)
      return;
  }
  psync_sql_bind_uint(st, 1, psync_find_result(psync_find_result(entry, "metadata", PARAM_HASH), "fileid", PARAM_NUM)->num);
  psync_sql_run(st);
}

#define FN(n) {process_##n, #n, sizeof(#n)-1, 0}

static struct {
  void (*process)(const binresult *);
  const char *name;
  uint32_t len;
  uint8_t used;
} event_list[] = {
  FN(createfolder),
  FN(modifyfolder),
  FN(deletefolder),
  FN(createfile),
  FN(modifyfile),
  FN(deletefile)
};

#define event_list_size sizeof(event_list)/sizeof(event_list[0])

static void set_num_setting(const char *key, uint64_t val){
  psync_sql_res *q;
  q=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  if (q){
    psync_sql_bind_string(q, 1, key);
    psync_sql_bind_uint(q, 2, val);
    psync_sql_run(q);
    psync_sql_free_result(q);
  }
}

static uint64_t process_entries(const binresult *entries, uint64_t newdiffid){
  const binresult *entry, *etype;
  uint32_t i, j;
  psync_sql_start_transaction();
  for (i=0; i<entries->length; i++){
    entry=entries->array[i];
    etype=psync_find_result(entry, "event", PARAM_STR);
    for (j=0; j<event_list_size; j++)
      if (etype->length==event_list[j].len && !memcmp(etype->str, event_list[j].name, etype->length)){
        event_list[j].process(entry);
        event_list[j].used=1;
      }
  }
  for (j=0; j<event_list_size; j++)
    if (event_list[j].used)
      event_list[j].process(NULL);
  set_num_setting("diffid", newdiffid);
  set_num_setting("usedquota", used_quota);
  psync_sql_commit_transaction();
  used_quota=psync_sql_cellint("SELECT value FROM setting WHERE id='usedquota'", 0);
  return psync_sql_cellint("SELECT value FROM setting WHERE id='diffid'", 0);
}

static void check_overquota(){
  static int lisover=0;
  int isover=(used_quota>=current_quota);
  if (isover!=lisover){
    lisover=isover;
    if (isover)
      psync_set_status(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_OVERQUOTA);
    else
      psync_set_status(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK);
  }
}

static void diff_exception_handler(){
  debug(D_NOTICE, "exception sent");
  if (exceptionsockwrite!=INVALID_SOCKET)
    psync_pipe_write(exceptionsockwrite, "e", 1);
}

static psync_socket_t setup_exeptions(){
  psync_socket_t pfds[2];
  if (psync_pipe(pfds)==SOCKET_ERROR)
    return INVALID_SOCKET;
  exceptionsockwrite=pfds[1];
  psync_timer_exception_handler(diff_exception_handler);
  return pfds[0];
}

static void handle_exception(psync_socket **sock, char ex){
  if (ex=='r' || psync_status_get(PSTATUS_TYPE_RUN)==PSTATUS_RUN_STOP){
    psync_socket_close(*sock);
    *sock=get_connected_socket();
    psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
  }
  else if (ex=='e'){
    binparam diffparams[]={P_STR("id", "ignore")};
    if (!send_command_no_res(*sock, "nop", diffparams) || psync_select_in(&(*sock)->sock, 1, PSYNC_SOCK_TIMEOUT_ON_EXCEPTION*1000)!=0){
      psync_socket_close(*sock);
      *sock=get_connected_socket();
      psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
    }
    else
      (*sock)->pending=1;
  }
}

static int send_diff_command(psync_socket *sock, uint64_t diffid){
  binparam diffparams[]={P_STR("timeformat", "timestamp"), P_NUM("limit", PSYNC_DIFF_LIMIT), P_NUM("diffid", diffid), P_BOOL("block", 1)};
  return send_command_no_res(sock, "diff", diffparams)?0:-1;
}

static void psync_diff_thread(){
  psync_socket *sock;
  binresult *res;
  const binresult *entries;
  uint64_t diffid, newdiffid, result;
  psync_socket_t exceptionsock, socks[2];
  int sel;
  char ex;
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  psync_milisleep(2);
restart:
  sock=get_connected_socket();
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_SCANNING);
  diffid=psync_sql_cellint("SELECT value FROM setting WHERE id='diffid'", 0);
  used_quota=psync_sql_cellint("SELECT value FROM setting WHERE id='usedquota'", 0);
  do{
    binparam diffparams[]={P_STR("timeformat", "timestamp"), P_NUM("limit", PSYNC_DIFF_LIMIT), P_NUM("diffid", diffid)};
    if (!psync_do_run)
      break;
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
      diffid=process_entries(entries, newdiffid);
    }
    result=entries->length;
    psync_free(res);
  } while (result);
  check_overquota();
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
  exceptionsock=setup_exeptions();
  if (exceptionsock==INVALID_SOCKET){
    debug(D_ERROR, "could not create pipe");
    psync_socket_close(sock);
    return;
  }
  socks[0]=exceptionsock;
  socks[1]=sock->sock;
  send_diff_command(sock, diffid);
  while (psync_do_run){
    if (psync_socket_pendingdata(sock))
      sel=1;
    else
      sel=psync_select_in(socks, 2, -1);
    if (sel==0){
      if (!psync_do_run)
        break;
      if (psync_pipe_read(exceptionsock, &ex, 1)!=1)
        continue;
      handle_exception(&sock, ex);
      socks[1]=sock->sock;
    }
    else if (sel==1){
      sock->pending=1;
      res=get_result(sock);
      if (!res){
        psync_timer_notify_exception();
        handle_exception(&sock, 'r');
        socks[1]=sock->sock;
        continue;
      }
      result=psync_find_result(res, "result", PARAM_NUM)->num;
      if (result){
        debug(D_ERROR, "diff returned error %u: %s", (unsigned int)result, psync_find_result(res, "error", PARAM_STR)->str);
        psync_free(res);
        handle_exception(&sock, 'r');
        socks[1]=sock->sock;
        continue;
      }
      entries=psync_check_result(res, "entries", PARAM_ARRAY);
      if (entries){
        if (entries->length){
          newdiffid=psync_find_result(res, "diffid", PARAM_NUM)->num;
          diffid=process_entries(entries, newdiffid);
        }
        send_diff_command(sock, diffid);
      }
      psync_free(res);
    }
  }
  psync_socket_close(sock);
  psync_pipe_close(exceptionsock);
  psync_pipe_close(exceptionsockwrite);
}

void psync_diff_init(){
  psync_run_thread(psync_diff_thread);
}
