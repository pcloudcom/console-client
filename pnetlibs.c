/* Copyright (c) 2013-2014 Anton Titov.
 * Copyright (c) 2013-2014 pCloud Ltd.
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

#include <stdio.h>
#include <ctype.h>
#include "pnetlibs.h"
#include "pssl.h"
#include "psettings.h"
#include "plibs.h"
#include "ptimer.h"
#include "pstatus.h"
#include "papi.h"

static time_t current_download_sec=0;
static psync_uint_t download_bytes_this_sec=0;
static psync_uint_t download_bytes_off=0;
static psync_uint_t download_speed=0;

struct time_bytes {
  time_t tm;
  psync_uint_t bytes;
};

static struct time_bytes download_bytes_sec[PSYNC_SPEED_CALC_AVERAGE_SEC];

static void rm_all(void *vpath, psync_pstat *st){
  char *path;
  path=psync_strcat((char *)vpath, PSYNC_DIRECTORY_SEPARATOR, st->name, NULL);
  if (st->isfolder){
    psync_list_dir(path, rm_all, path);
    psync_rmdir(path);
  }
  else
    psync_file_delete(path);
  psync_free(path);
}

static void rm_ign(void *vpath, psync_pstat *st){
  char *path;
  if (!psync_is_name_to_ignore(st->name))
    return;
  path=psync_strcat((char *)vpath, PSYNC_DIRECTORY_SEPARATOR, st->name, NULL);
  if (st->isfolder){
    psync_list_dir(path, rm_all, path);
    psync_rmdir(path);
  }
  else
    psync_file_delete(path);
  psync_free(path);
}

int psync_rmdir_with_trashes(const char *path){
  if (!psync_rmdir(path))
    return 0;
  if (psync_fs_err()!=P_NOTEMPTY && psync_fs_err()!=P_EXIST)
    return -1;
  if (psync_list_dir(path, rm_ign, (void *)path))
    return -1;
  return psync_rmdir(path);
}

int psync_rmdir_recursive(const char *path){
  if (psync_list_dir(path, rm_all, (void *)path))
    return -1;
  return psync_rmdir(path);
}

void psync_set_local_full(int over){
  static int isover=0;
  if (over!=isover){
    isover=over;
    if (isover)
      psync_set_status(PSTATUS_TYPE_DISKFULL, PSTATUS_DISKFULL_FULL);
    else
      psync_set_status(PSTATUS_TYPE_DISKFULL, PSTATUS_DISKFULL_OK);
  }
}

int psync_handle_api_result(uint64_t result){
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

int psync_get_remote_file_checksum(uint64_t fileid, unsigned char *restrict hexsum, uint64_t *restrict fsize, psync_socket *restrict useapi){
  psync_socket *api;
  binresult *res;
  const binresult *meta, *checksum;
  psync_sql_res *sres;
  psync_variant_row row;
  uint64_t result;
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid)};
  sres=psync_sql_query("SELECT h.checksum, f.size FROM hashchecksum h, file f WHERE f.id=? AND f.hash=h.hash AND f.size=h.size");
  psync_sql_bind_uint(sres, 1, fileid);
  row=psync_sql_fetch_row(sres);
  if (row){
    strcpy((char *)hexsum, psync_get_string(row[0]));
    if (fsize)
      *fsize=psync_get_number(row[1]);
    psync_sql_free_result(sres);
    return PSYNC_NET_OK;
  }
  psync_sql_free_result(sres);
  if (useapi)
    api=useapi;
  else{
    api=psync_api_connect(psync_setting_get_bool(_PS(usessl)));
    if (!api){
      psync_timer_notify_exception();
      return PSYNC_NET_TEMPFAIL;
    }
  }
  res=send_command(api, "checksumfile", params);
  if (!useapi)
    psync_socket_close(api);
  if (unlikely_log(!res)){
    psync_timer_notify_exception();
    return PSYNC_NET_TEMPFAIL;
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    debug(D_ERROR, "checksumfile returned error %lu", (unsigned long)result);
    psync_free(res);
    return psync_handle_api_result(result);
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

int psync_file_writeall_checkoverquota(psync_file_t fd, const void *buf, size_t count){
  ssize_t wr;
  while (count){
    wr=psync_file_write(fd, buf, count);
    if (wr==count){
      psync_set_local_full(0);
      return 0;
    }
    else if (wr==-1){
      if (psync_fs_err()==P_NOSPC || psync_fs_err()==P_DQUOT){
        psync_set_local_full(1);
        psync_milisleep(PSYNC_SLEEP_ON_DISK_FULL);
      }
      return -1;
    }
    buf+=wr;
    count-=wr;
  }
  return 0;
}

int psync_copy_local_file_if_checksum_matches(const char *source, const char *destination, const unsigned char *hexsum, uint64_t fsize){
  psync_file_t sfd, dfd;
  psync_hash_ctx hctx;
  void *buff;
  char *tmpdest;
  size_t rrd;
  ssize_t rd;
  unsigned char hashbin[PSYNC_HASH_DIGEST_LEN];
  char hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  sfd=psync_file_open(source, P_O_RDONLY, 0);
  if (unlikely_log(sfd==INVALID_HANDLE_VALUE))
    goto err0;
  tmpdest=psync_strcat(destination, PSYNC_APPEND_PARTIAL_FILES, NULL);
  if (unlikely_log(psync_file_size(sfd)!=fsize))
    goto err1;
  dfd=psync_file_open(tmpdest, P_O_WRONLY, P_O_CREAT|P_O_TRUNC);
  if (unlikely_log(dfd==INVALID_HANDLE_VALUE))
    goto err1;
  psync_hash_init(&hctx);
  buff=psync_malloc(PSYNC_COPY_BUFFER_SIZE);
  while (fsize){
    if (fsize>PSYNC_COPY_BUFFER_SIZE)
      rrd=PSYNC_COPY_BUFFER_SIZE;
    else
      rrd=fsize;
    rd=psync_file_read(sfd, buff, rrd);
    if (unlikely_log(rd<=0))
      goto err2;
    if (unlikely_log(psync_file_writeall_checkoverquota(dfd, buff, rd)))
      goto err2;
    psync_hash_update(&hctx, buff, rd);
    fsize-=rd;
    psync_yield_cpu();
  }
  psync_hash_final(hashbin, &hctx);
  psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
  if (unlikely_log(memcmp(hexsum, hashhex, PSYNC_HASH_DIGEST_HEXLEN)))
    goto err2;
  psync_free(buff);
  psync_file_close(dfd);
  if (unlikely_log(psync_file_rename_overwrite(tmpdest, destination)))
    goto err1;
  psync_free(tmpdest);
  psync_file_close(sfd);
  return PSYNC_NET_OK;
err2:
  psync_free(buff);
  psync_file_close(dfd);
  psync_file_delete(tmpdest);
err1:
  psync_free(tmpdest);
  psync_file_close(sfd);
err0:
  return PSYNC_NET_PERMFAIL;
}

psync_socket *psync_socket_connect_download(const char *host, int unsigned port, int usessl){
  psync_socket *sock;
  int64_t dwlspeed;
  sock=psync_socket_connect(host, port, usessl);
  if (sock){
    dwlspeed=psync_setting_get_int(_PS(maxdownloadspeed));
    if (dwlspeed!=-1 && dwlspeed<PSYNC_MAX_SPEED_RECV_BUFFER){
      if (dwlspeed==0)
        dwlspeed=PSYNC_RECV_BUFFER_SHAPED;
      psync_socket_set_recvbuf(sock, (uint32_t)dwlspeed);
    }
    psync_status_inc_downloads_count();
  }
  return sock;
}

psync_socket *psync_api_connect_download(){
  psync_socket *sock;
  int64_t dwlspeed;
  sock=psync_api_connect(psync_setting_get_bool(_PS(usessl)));
  if (sock){
    dwlspeed=psync_setting_get_int(_PS(maxdownloadspeed));
    if (dwlspeed!=-1 && dwlspeed<PSYNC_MAX_SPEED_RECV_BUFFER){
      if (dwlspeed==0)
        dwlspeed=PSYNC_RECV_BUFFER_SHAPED;
      psync_socket_set_recvbuf(sock, (uint32_t)dwlspeed);
    }
    psync_status_inc_downloads_count();
  }
  return sock;
}

void psync_socket_close_download(psync_socket *sock){
  psync_status_dec_downloads_count();
  psync_socket_close(sock);
}

static void account_downloaded_bytes(int unsigned bytes){
  if (current_download_sec==psync_current_time)
    download_bytes_this_sec+=bytes;
  else{
    uint64_t sum;
    psync_uint_t i;
    download_bytes_sec[download_bytes_off].tm=current_download_sec;
    download_bytes_sec[download_bytes_off].bytes=download_bytes_this_sec;
    download_bytes_off=(download_bytes_off+1)%PSYNC_SPEED_CALC_AVERAGE_SEC;
    current_download_sec=psync_current_time;
    download_bytes_this_sec=bytes;
    sum=0;
    for (i=0; i<PSYNC_SPEED_CALC_AVERAGE_SEC; i++)
      if (download_bytes_sec[i].tm>=psync_current_time-PSYNC_SPEED_CALC_AVERAGE_SEC)
        sum+=download_bytes_sec[i].bytes;
    download_speed=sum/PSYNC_SPEED_CALC_AVERAGE_SEC;
    psync_status_set_download_speed(download_speed);
  }
}

static psync_uint_t get_download_bytes_this_sec(){
  if (current_download_sec==psync_current_time)
    return download_bytes_this_sec;
  else
    return 0;
}

int psync_socket_readall_download(psync_socket *sock, void *buff, int num){
  psync_int_t dwlspeed, readbytes, pending, lpending, rd, rrd;
  psync_uint_t thissec, ds;
  dwlspeed=psync_setting_get_int(_PS(maxdownloadspeed));
  if (dwlspeed==0){
    lpending=psync_socket_pendingdata_buf(sock);
    if (download_speed>100*1024)
      ds=download_speed/1024;
    else
      ds=100;
    while (1){
      psync_milisleep(PSYNC_SLEEP_AUTO_SHAPER*100/ds);
      pending=psync_socket_pendingdata_buf(sock);
      if (pending==lpending)
        break;
      else
        lpending=pending;
    }
    if (pending>0)
      sock->pending=1;
  }
  else if (dwlspeed>0){
    readbytes=0;
    while (num){
      while ((thissec=get_download_bytes_this_sec())>=dwlspeed)
        psync_timer_wait_next_sec();
      if (num>dwlspeed-thissec)
        rrd=dwlspeed-thissec;
      else
        rrd=num;
      rd=psync_socket_read(sock, buff, rrd);
      if (rd<=0)
        return readbytes?readbytes:rd;
      num-=rd;
      buff+=rd;
      readbytes+=rd;
      account_downloaded_bytes(rd);
    }
    return readbytes;
  }
  readbytes=psync_socket_readall(sock, buff, num);
  if (readbytes>0)
    account_downloaded_bytes(readbytes);
  return readbytes;
}

psync_http_socket *psync_http_connect(const char *host, const char *path, uint64_t from, uint64_t to){
  psync_socket *sock;
  psync_http_socket *hsock;
  char *readbuff, *ptr;
  int usessl, rl, rb;
  usessl=psync_setting_get_bool(_PS(usessl));
  sock=psync_socket_connect_download(host, usessl?443:80, usessl);
  if (!sock)
    goto err0;
  readbuff=psync_malloc(PSYNC_HTTP_RESP_BUFFER);
  if (from || to){
    if (to)
      rl=snprintf(readbuff, PSYNC_HTTP_RESP_BUFFER, "GET %s HTTP/1.0\015\012Host: %s\015\012Range: bytes=%llu-%llu\015\012Connection: close\015\012\015\012", 
                  path, host, (unsigned long long)from, (unsigned long long)to);
    else
      rl=snprintf(readbuff, PSYNC_HTTP_RESP_BUFFER, "GET %s HTTP/1.0\015\012Host: %s\015\012Range: bytes=%llu-\015\012Connection: close\015\012\015\012", 
                  path, host, (unsigned long long)from);
  }
  else
    rl=snprintf(readbuff, PSYNC_HTTP_RESP_BUFFER, "GET %s HTTP/1.0\015\012Host: %s\015\012Connection: close\015\012\015\012", path, host);
  if (psync_socket_writeall(sock, readbuff, rl)!=rl || (rb=psync_socket_readall_download(sock, readbuff, PSYNC_HTTP_RESP_BUFFER-1))==-1)
    goto err1;
  readbuff[rb]=0;
  ptr=readbuff;
  while (*ptr && !isspace(*ptr))
    ptr++;
  while (*ptr && isspace(*ptr))
    ptr++;
  if (!isdigit(*ptr) || atoi(ptr)/10!=20)
    goto err1;
  if ((ptr=strstr(readbuff, "\015\012\015\012")))
    ptr+=4;
  else if ((ptr=strstr(readbuff, "\012\012")))
    ptr+=2;
  else
    goto err1;
  rl=ptr-readbuff;
  if (rl==rb){
    psync_free(readbuff);
    readbuff=NULL;
  }
  hsock=psync_new(psync_http_socket);
  hsock->sock=sock;
  hsock->readbuff=readbuff;
  hsock->readbuffoff=rl;
  hsock->readbuffsize=rb;
  return hsock;
err1:
  psync_free(readbuff);
  psync_socket_close_download(sock);
err0:
  return NULL;
}

void psync_http_close(psync_http_socket *http){
  psync_socket_close_download(http->sock);
  if (http->readbuff)
    psync_free(http->readbuff);
  psync_free(http);
}

int psync_http_readall(psync_http_socket *http, void *buff, int num){
  if (http->readbuff){
    int cp;
    if (num<http->readbuffsize-http->readbuffoff)
      cp=num;
    else
      cp=http->readbuffsize-http->readbuffoff;
    memcpy(buff, http->readbuff+http->readbuffoff, cp);
    http->readbuffoff+=cp;
    if (http->readbuffoff>=http->readbuffsize){
      psync_free(http->readbuff);
      http->readbuff=NULL;
    }
    if (cp==num)
      return cp;
    num=psync_socket_readall_download(http->sock, buff+cp, num-cp);
    if (num<=0)
      return cp;
    else
      return cp+num;
  }
  else
    return psync_socket_readall_download(http->sock, buff, num);
}


