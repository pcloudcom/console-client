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

static psync_socket *get_connected_socket(){
  char *auth, *user, *pass;
  psync_socket *sock;
  binresult *res;
  uint64_t result, userid, luserid;
  int usessl;
  auth=user=pass=NULL;
  while (1){
    psync_free(auth);
    psync_free(user);
    psync_free(pass);
    psync_wait_status(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN|PSTATUS_RUN_PAUSE);
    auth=psync_sql_cellstr("SELECT value FROM settings WHERE id='auth'");
    user=psync_sql_cellstr("SELECT value FROM settings WHERE id='user'");
    pass=psync_sql_cellstr("SELECT value FROM settings WHERE id='pass'");
    if (!auth && !pass){
      psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_REQURED);
      psync_wait_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      continue;
    }
    usessl=psync_sql_cellint("SELECT value FROM settings WHERE id='usessl'", PSYNC_USE_SSL_DEFAULT);
    sock=psync_api_connect(usessl);
    if (!sock){
      psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_OFFLINE);
      psync_milisleep(PSYNC_SLEEP_BEFORE_RECONNECT);
      continue;
    }
    if (user && pass){
      binparam params[]={P_STR("username", user), P_STR("password", pass)};
      res=send_command(sock, "userinfo", params);
    }
    else {
      binparam params[]={P_STR("auth", auth)};
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
    }
    psync_free(res);
    psync_free(auth);
    psync_free(user);
    psync_free(pass);
    return sock;
  }
}

void psync_diff_thread(){
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  psync_milisleep(2);
}