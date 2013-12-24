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

#include "pnetlibs.h"
#include "psettings.h"
#include "plibs.h"
#include "ptimer.h"
#include "pstatus.h"
#include "papi.h"

static int handle_result(uint64_t result){
  if (result==2000){
    psync_set_status(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_BADLOGIN);
    psync_timer_notify_exception();
    return PSYNC_NET_TEMPFAIL;
  }
  else if (result==2003 || result==2009)
    return PSYNC_NET_PERMFAIL;
  else
    return PSYNC_NET_TEMPFAIL;
}

int psync_get_remote_file_checksum(uint64_t fileid, unsigned char *hexsum, uint64_t *fsize){
  psync_socket *api;
  binresult *res;
  const binresult *meta, *checksum;
  psync_sql_res *sres;
  char **row;
  uint64_t result;
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid)};
  sres=psync_sql_query("SELECT h.checksum FROM hashchecksum h, file f WHERE f.id=? AND f.hash=h.hash AND f.size=h.size");
  psync_sql_bind_uint(sres, 1, fileid);
  row=psync_sql_fetch_rowstr(sres);
  if (row){
    strcpy((char *)hexsum, row[0]);
    psync_sql_free_result(sres);
    return PSYNC_NET_OK;
  }
  psync_sql_free_result(sres);
  api=psync_api_connect(psync_setting_get_bool(_PS(usessl)));
  if (!api){
    psync_timer_notify_exception();
    return PSYNC_NET_TEMPFAIL;
  }
  res=send_command(api, "checksumfile", params);
  psync_socket_close(api);
  if (!res){
    psync_timer_notify_exception();
    return PSYNC_NET_TEMPFAIL;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    psync_free(res);
    handle_result(result);
  }
  meta=psync_find_result(res, "metadata", PARAM_HASH);
  checksum=psync_find_result(res, PSYNC_CHECKSUM, PARAM_STR);
  result=psync_find_result(meta, "size", PARAM_NUM)->num;
  if (fsize)
    *fsize=result;
  sres=psync_sql_prep_statement("REPLACE INTO hashchecksum (hash, size, checksum) VALUES (?, ?, ?)");
  psync_sql_bind_uint(sres, 1, psync_find_result(meta, "hash", PARAM_NUM)->num);
  psync_sql_bind_uint(sres, 2, result);
  psync_sql_bind_lstring(sres, 3, checksum->str, checksum->length);
  psync_sql_run(sres);
  psync_sql_free_result(sres);
  memcpy(hexsum, checksum->str, checksum->length+1);
  psync_free(res);
  return PSYNC_NET_OK;
}