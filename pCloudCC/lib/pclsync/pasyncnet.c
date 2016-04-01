/* Copyright (c) 2015 Anton Titov.
 * Copyright (c) 2015 pCloud Ltd.
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

#include <stddef.h>
#include "plibs.h"
#include "psettings.h"
#include "pcompat.h"
#include "pnetlibs.h"
#include "papi.h"
#include "pcompression.h"
#include "pasyncnet.h"
#include "ptree.h"
#include "pssl.h"

#define TASK_WITH_HEADER(t1, t2) \
  typedef struct {\
    task_header_t head;\
    t2 task;\
  } t1
#define get_len(t) (sizeof(t)-offsetof(t, task))

#define TASK_TYPE_EXIT        0
#define TASK_TYPE_FILE_DWL    1
#define TASK_TYPE_FILE_DWL_NM 2

#define STREAM_FLAG_ACTIVE 1

#define STREAM_HEADER_LEN 6 // 4 bytes stream id, 2 bytes length

typedef struct {
  uint32_t type;
  uint32_t len;
} task_header_t;

typedef struct {
  psync_fileid_t fileid;
  const char *localpath;
  psync_async_callback_t cb;
  void *cbext;
} task_file_download_t;

typedef struct {
  psync_fileid_t fileid;
  const char *localpath;
  uint64_t size;
  char sha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
  psync_async_callback_t cb;
  void *cbext;
} task_file_download_if_not_mod_t;

typedef struct {
  uint32_t error;
  uint32_t errorflags;
  uint64_t size;
  uint64_t hash;
  uint64_t mtime;
  uint64_t oldhash;
  uint64_t oldmtime;
  unsigned char sha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
} task_file_download_resp_t;

typedef struct _async_thread_params_t {
  psync_deflate_t *enc;
  psync_deflate_t *dec;
  psync_socket *api;
  psync_tree *streams;
  uint64_t datapendingsince;
  int (*process_buf)(struct _async_thread_params_t *);
  char *curreadbuff;
  psync_socket_t privsock;
  uint32_t curreadbuffrem;
  uint32_t curreadbufflen;
  uint32_t currentstreamid;
  uint32_t laststreamid;
  uint32_t pendingrequests;
  char buffer[64*1024];
} async_thread_params_t;

typedef struct _stream_t {
  psync_tree tree;
  uint32_t streamid;
  uint32_t flags;
  psync_async_callback_t cb;
  void (*free)(struct _stream_t *, uint32_t);
  void *cbext;
  int (*process_data)(struct _stream_t *, async_thread_params_t *, const char *, uint32_t);
} stream_t;

typedef struct {
  const char *localpath;
  uint64_t fileid;
  uint64_t size;
  uint64_t hash;
  unsigned char osize;
  unsigned char sha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
  unsigned char osha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
  psync_sha1_ctx sha1ctx;
  uint64_t remsize;
  psync_file_t fd;
} file_download_add_t;

TASK_WITH_HEADER(task_hdr_file_download_t, task_file_download_t);
TASK_WITH_HEADER(task_hdr_file_download_if_not_mod_t, task_file_download_if_not_mod_t);

static pthread_mutex_t amutex=PTHREAD_MUTEX_INITIALIZER;
static int running=0;
static psync_socket_t at_sock=INVALID_SOCKET;

static int send_pending_data(async_thread_params_t *prms){
  char buff[4096];
  int ret;
  while (1){
    ret=psync_deflate_read(prms->enc, buff, sizeof(buff));
    if (ret==PSYNC_DEFLATE_NODATA || ret==PSYNC_DEFLATE_EOF)
      return 0;
    if (ret>0){
      if (psync_socket_writeall(prms->api, buff, ret)!=ret){
        debug(D_WARNING, "write of %d bytes to socket failed", ret);
        return -1;
      }
      else
        debug(D_NOTICE, "sent %d bytes of compressed data to socket", ret);
    }
    else{
      debug(D_ERROR, "read from deflate compressor returned %d", ret);
      return -1;
    }
  }
}

static int flush_pending_data(async_thread_params_t *prms){
  int ret;
  ret=psync_deflate_write(prms->enc, "", 0, PSYNC_DEFLATE_FLUSH);
  if (ret!=0){
    debug(D_WARNING, "psync_deflate_write returned %d when flushing", ret);
    return -1;
  }
  prms->pendingrequests=0;
  return send_pending_data(prms);
}

static int socket_t_readall(psync_socket_t sock, void *buff, size_t len){
  ssize_t rd;
  while (len){
    if (psync_wait_socket_read_timeout(sock))
      return -1;
    rd=psync_read_socket(sock, buff, len);
    if (rd>0){
      len-=rd;
      buff=(char *)buff+rd;
    }
    else if (rd==PSYNC_SOCKET_ERROR &&(psync_sock_err()==P_INTR || psync_sock_err()==P_AGAIN || psync_sock_err()==P_WOULDBLOCK))
      continue;
    else{
      debug(D_WARNING, "read from socket of %lu bytes returned %ld, errno %d", (unsigned long)len, (long)rd, (int)psync_sock_err());
      return -1;
    }
  }
  return 0;
}

static int socket_t_writeall(psync_socket_t sock, const void *buff, size_t len){
  ssize_t wr;
  while (len){
    if (psync_wait_socket_write_timeout(sock))
      return -1;
    wr=psync_write_socket(sock, buff, len);
    if (wr>0){
      len-=wr;
      buff=(const char *)buff+wr;
    }
    else if (wr==PSYNC_SOCKET_ERROR &&(psync_sock_err()==P_INTR || psync_sock_err()==P_AGAIN || psync_sock_err()==P_WOULDBLOCK))
      continue;
    else{
      debug(D_WARNING, "write to socket of %lu bytes returned %ld, errno %d", (unsigned long)len, (long)wr, (int)psync_sock_err());
      return -1;
    }
  }
  return 0;
}

static stream_t *create_stream(async_thread_params_t *prms, size_t addsize){
  psync_tree *parent;
  stream_t *ret;
  ret=(stream_t *)psync_malloc(sizeof(stream_t)+addsize);
  ret->streamid=++prms->laststreamid;
  ret->flags=0;
  ret->free=NULL;
  parent=psync_tree_get_last(prms->streams);
  if (parent)
    parent->right=&ret->tree;
  else
    prms->streams=&ret->tree;
  psync_tree_added_at(&prms->streams, parent, &ret->tree);
  return ret;
}

static int send_data(async_thread_params_t *prms, const void *data, int len){
  int wr;
  while (len){
    wr=psync_deflate_write(prms->enc, data, len, PSYNC_DEFLATE_NOFLUSH);
    if (wr>0){
      len-=wr;
      data=(const char *)data+wr;
    }
    else if (wr!=PSYNC_DEFLATE_FULL){
      debug(D_ERROR, "write to deflate compressor of %d bytes returned %d", len, wr);
      return -1;
    }
    if (send_pending_data(prms))
      return -1;
  }
  if (!prms->pendingrequests)
    prms->datapendingsince=psync_millitime();
  prms->pendingrequests++;
  return 0;
}

static void close_stream(stream_t *s, async_thread_params_t *prms, uint32_t error){
  debug(D_NOTICE, "closing stream %u", (unsigned)s->streamid);
  psync_tree_del(&prms->streams, &s->tree);
  if (s->free)
    s->free(s, error);
  psync_free(s);
}

static void file_download_free(stream_t *s, uint32_t error){
  file_download_add_t *fda;
  fda=(file_download_add_t *)(s+1);
  if (fda->fd!=INVALID_HANDLE_VALUE){
    psync_file_close(fda->fd);
    if (error)
      psync_file_delete(fda->localpath);
  }
}

static int file_download_send_error(stream_t *s, async_thread_params_t *prms, file_download_add_t *fda, uint32_t error, uint32_t errorflags){
  psync_async_result_t r;
  if (error)
    debug(D_NOTICE, "got error %u(%u) for file %s", (unsigned)error, (unsigned)errorflags, fda->localpath);
  else
    debug(D_NOTICE, "download of %s finished", fda->localpath);
  r.error=error;
  r.errorflags=errorflags;
  r.file.size=fda->size;
  r.file.hash=fda->hash;
  memcpy(r.file.sha1hex, fda->sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  s->cb(s->cbext, &r);
  close_stream(s, prms, error);
  return 0;
}

static int file_download_checksum(file_download_add_t *fda){
  unsigned char sha1b[PSYNC_SHA1_DIGEST_LEN], sha1h[PSYNC_SHA1_DIGEST_HEXLEN];
  psync_sha1_final(sha1b, &fda->sha1ctx);
  psync_binhex(sha1h, sha1b, PSYNC_SHA1_DIGEST_LEN);
  if (memcmp(sha1h, fda->sha1hex, PSYNC_SHA1_DIGEST_HEXLEN)){
    debug(D_WARNING, "checksum verification for file %s failed, expected %40s got %40s", fda->localpath, (char *)fda->sha1hex, (char *)sha1h);
    return -1;
  }
  else
    return 0;
}

static int process_file_download_data(stream_t *s, async_thread_params_t *prms, const char *buff, uint32_t datalen){
  file_download_add_t *fda;
  ssize_t wr;
  int err;
  fda=(file_download_add_t *)(s+1);
  if (datalen>fda->remsize){
    debug(D_ERROR, "got packed of size %u for stream %u file %s when the remaining data is %lu",
          (unsigned)datalen, (unsigned)s->streamid, fda->localpath, (unsigned long)fda->remsize);
    file_download_send_error(s, prms, fda, PSYNC_ASYNC_ERROR_NET, PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS);
    return -1;
  }
  fda->remsize-=datalen;
  psync_account_downloaded_bytes(datalen);
  psync_sha1_update(&fda->sha1ctx, buff, datalen);
  while (datalen){
    wr=psync_file_write(fda->fd, buff, datalen);
    if (wr==-1){
      err=(int)psync_fs_err();
      debug(D_WARNING, "writing to file %s failed, errno %d", fda->localpath, err);
      return file_download_send_error(s, prms, fda, err==P_NOSPC?PSYNC_ASYNC_ERROR_DISK_FULL:PSYNC_ASYNC_ERROR_IO, 0);
    }
    datalen-=wr;
    buff+=wr;
  }
  if (fda->remsize==0){
    if (file_download_checksum(fda))
      return file_download_send_error(s, prms, fda, PSYNC_ASYNC_ERROR_CHECKSUM, 0);
    else
      return file_download_send_error(s, prms, fda, 0, 0);
  }
  else
    return 0;
}

static int process_file_download_headers(stream_t *s, async_thread_params_t *prms, const char *buff, uint32_t datalen){
  task_file_download_resp_t r;
  file_download_add_t *fda;
  psync_sql_res *res;
  if (unlikely(datalen<sizeof(task_file_download_resp_t))){
    debug(D_ERROR, "got packet of size %u while expecting at least %u, disconnecting", (unsigned)datalen, (unsigned)sizeof(task_file_download_resp_t));
    return -1;
  }
  memcpy(&r, buff, sizeof(task_file_download_resp_t));
  fda=(file_download_add_t *)(s+1);
  fda->size=r.size;
  fda->hash=r.hash;
  memcpy(fda->sha1hex, r.sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  if (r.error)
    return file_download_send_error(s, prms, fda, r.error+100, r.errorflags);
  debug(D_NOTICE, "got headers for file %s size %"P_PRI_U64" hash %"P_PRI_U64" sha1 %.40s", fda->localpath, fda->size, fda->hash, fda->sha1hex);
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("REPLACE INTO hashchecksum (hash, size, checksum) VALUES (?, ?, ?)");
  psync_sql_bind_uint(res, 1, r.hash);
  psync_sql_bind_uint(res, 2, r.size);
  psync_sql_bind_lstring(res, 3, (const char *)r.sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  if (r.oldmtime){
    psync_sql_run(res);
    psync_sql_bind_uint(res, 1, r.oldhash);
    psync_sql_bind_uint(res, 2, fda->osize);
    psync_sql_bind_lstring(res, 3, (const char *)fda->osha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
    psync_sql_run_free(res);
  }
  else
    psync_sql_run_free(res);
  res=psync_sql_prep_statement("REPLACE INTO filerevision (fileid, hash, ctime, size) VALUES (?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, fda->fileid);
  psync_sql_bind_uint(res, 2, r.hash);
  psync_sql_bind_uint(res, 3, r.mtime);
  psync_sql_bind_uint(res, 4, r.size);
  if (r.oldmtime){
    psync_sql_run(res);
    psync_sql_bind_uint(res, 1, fda->fileid);
    psync_sql_bind_uint(res, 2, r.oldhash);
    psync_sql_bind_uint(res, 3, r.oldmtime);
    psync_sql_bind_uint(res, 4, fda->osize);
    psync_sql_run_free(res);
  }
  else
    psync_sql_run_free(res);
  psync_sql_commit_transaction();
  fda->fd=psync_file_open(fda->localpath, P_O_WRONLY, P_O_CREAT|P_O_TRUNC);
  if (fda->fd==INVALID_HANDLE_VALUE){
    debug(D_WARNING, "could not open file %s, errno %d", fda->localpath, (int)psync_fs_err());
    return file_download_send_error(s, prms, fda, PSYNC_ASYNC_ERROR_FILE, 0);
  }
  fda->remsize=fda->size;
  if (!fda->remsize)
    return file_download_send_error(s, prms, fda, 0, 0);
  s->process_data=process_file_download_data;
  psync_sha1_init(&fda->sha1ctx);
  if (datalen>sizeof(task_file_download_resp_t))
    return process_file_download_data(s, prms, buff+sizeof(task_file_download_resp_t), datalen-sizeof(task_file_download_resp_t));
  else
    return 0;
}

static int handle_file_download(async_thread_params_t *prms, task_file_download_t *dwl){
  char buff[256];
  stream_t *s;
  file_download_add_t *fda;
  int len;
  s=create_stream(prms, sizeof(file_download_add_t));
  fda=(file_download_add_t *)(s+1);
  fda->fileid=dwl->fileid;
  s->free=file_download_free;
  s->cb=dwl->cb;
  s->cbext=dwl->cbext;
  s->process_data=process_file_download_headers;
  fda->localpath=dwl->localpath;
  fda->fd=INVALID_HANDLE_VALUE;
  len=psync_slprintf(buff, sizeof(buff), "act=dwl,strm=%"P_PRI_U64",fileid=%"P_PRI_U64"\n", (uint64_t)s->streamid, (uint64_t)dwl->fileid);
  if (send_data(prms, buff, len)){
    debug(D_WARNING, "failed to send request for fileid %lu", (unsigned long)dwl->fileid);
    return -1;
  }
  s->flags|=STREAM_FLAG_ACTIVE;
  debug(D_NOTICE, "requested data of fileid %lu to be saved in %s", (unsigned long)dwl->fileid, dwl->localpath);
  return 0;
}

static int handle_file_download_nm(async_thread_params_t *prms, task_file_download_if_not_mod_t *dwl){
  char buff[256];
  stream_t *s;
  file_download_add_t *fda;
  int len;
  s=create_stream(prms, sizeof(file_download_add_t));
  fda=(file_download_add_t *)(s+1);
  fda->fileid=dwl->fileid;
  s->free=file_download_free;
  s->cb=dwl->cb;
  s->cbext=dwl->cbext;
  s->process_data=process_file_download_headers;
  fda->osize=dwl->size;
  memcpy(fda->osha1hex, dwl->sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  fda->localpath=dwl->localpath;
  fda->fd=INVALID_HANDLE_VALUE;
  len=psync_slprintf(buff, sizeof(buff), "act=dwlnm,strm=%"P_PRI_U64",fileid=%"P_PRI_U64",sha1=%.40s\n", (uint64_t)s->streamid, (uint64_t)dwl->fileid, dwl->sha1hex);
  if (send_data(prms, buff, len)){
    debug(D_WARNING, "failed to send request for fileid %lu", (unsigned long)dwl->fileid);
    return -1;
  }
  s->flags|=STREAM_FLAG_ACTIVE;
  debug(D_NOTICE, "requested data of fileid %lu to be saved in %s", (unsigned long)dwl->fileid, dwl->localpath);
  return 0;
}

#define CHECK_LEN(l)\
  do {\
    if (unlikely(len!=l)){\
      debug(D_BUG, "wrong size for packet of type %u, expected size %u but got %u", (unsigned)type, (unsigned)l, (unsigned)len);\
      return 2;\
    }\
  } while (0)

static int handle_command_data(async_thread_params_t *prms, char *data, uint32_t type, uint32_t len){
  switch (type) {
    case TASK_TYPE_EXIT:
      CHECK_LEN(0);
      debug(D_NOTICE, "exiting");
      return -1;
    case TASK_TYPE_FILE_DWL:
      CHECK_LEN(sizeof(task_file_download_t));
      return handle_file_download(prms, (task_file_download_t *)data);
    case TASK_TYPE_FILE_DWL_NM:
      CHECK_LEN(sizeof(task_file_download_if_not_mod_t));
      return handle_file_download_nm(prms, (task_file_download_if_not_mod_t *)data);
    default:
      debug(D_BUG, "got packet of unknown type %u", (unsigned)type);
      return 1;
  }
}

static int handle_command(async_thread_params_t *prms){
  char buff[4096];
  task_header_t hdr;
  int ret;
  unsigned char r;
  if (socket_t_readall(prms->privsock, &hdr, sizeof(hdr))){
    debug(D_WARNING, "could not read header from socket pair");
    return -1;
  }
  if (hdr.len>sizeof(buff)){
    debug(D_WARNING, "too large length of packet %u provided, maximum supported is %u", (unsigned)hdr.len, (unsigned)sizeof(buff));
    return -1;
  }
  if (socket_t_readall(prms->privsock, buff, hdr.len)){
    debug(D_WARNING, "could not read %u bytes of data from socket pair", (unsigned)hdr.len);
    return -1;
  }
  ret=handle_command_data(prms, buff, hdr.type, hdr.len);
  if (ret<0){
    r=255;
    ret=-1;
  }
  else{
    r=(unsigned char)ret;
    ret=0;
  }
  if (socket_t_writeall(prms->privsock, &r, sizeof(r))){
    debug(D_WARNING, "failed to write response to socket pair");
    return -1;
  }
  return ret;
}

static int handle_decompressed_data(async_thread_params_t *prms){
  int rd;
  while (1){
    rd=psync_deflate_read(prms->dec, prms->curreadbuff, prms->curreadbuffrem);
    if (rd>0){
      prms->curreadbuff+=rd;
      prms->curreadbuffrem-=rd;
      if (!prms->curreadbuffrem && prms->process_buf(prms))
        return -1;
    }
    else if (rd==PSYNC_DEFLATE_NODATA)
      return 0;
    else{
      debug(D_ERROR, "psync_deflate_read returned %d", rd);
      return -1;
    }
  }
}

static int handle_incoming_data(async_thread_params_t *prms){
  char buff[4096];
  char *ptr;
  int rdsock, wrdecomp;
  while (1){
    rdsock=psync_socket_read_noblock(prms->api, buff, sizeof(buff));
    if (rdsock==PSYNC_SOCKET_WOULDBLOCK)
      return 0;
    else if (rdsock<=0){
      debug(D_WARNING, "read from socket returned %d", rdsock);
      return -1;
    }
    ptr=buff;
    while (rdsock){
      wrdecomp=psync_deflate_write(prms->dec, ptr, rdsock, PSYNC_DEFLATE_FLUSH);
      if (wrdecomp==PSYNC_DEFLATE_ERROR){
        debug(D_ERROR, "psync_deflate_write returned PSYNC_DEFLATE_ERROR");
        return -1;
      }
      else if (wrdecomp!=PSYNC_DEFLATE_FULL){
        assert(wrdecomp>0);
        rdsock-=wrdecomp;
        ptr+=wrdecomp;
      }
      if (handle_decompressed_data(prms))
        return -1;
    }
  }
}

static void free_stream(stream_t *s){
  debug(D_NOTICE, "freeing unfinished stream %u", (unsigned)s->streamid);
  if (s->flags&STREAM_FLAG_ACTIVE){
    psync_async_result_t ar;
    memset(&ar, 0, sizeof(ar));
    ar.error=PSYNC_ASYNC_ERROR_NET;
    ar.errorflags=PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS;
    s->cb(s->cbext, &ar);
  }
  if (s->free)
    s->free(s, PSYNC_ASYNC_ERROR_NET);
  psync_free(s);
}

static int process_stream_header(async_thread_params_t *prms);

static void read_stream_header_setup(async_thread_params_t *prms){
  prms->curreadbuff=prms->buffer;
  prms->curreadbuffrem=STREAM_HEADER_LEN;
  prms->process_buf=process_stream_header;
}

static int process_stream_data(async_thread_params_t *prms){
  psync_tree *tr;
  stream_t *s;
  int ret;
  tr=prms->streams;
  while (tr){
    s=psync_tree_element(tr, stream_t, tree);
    if (prms->currentstreamid<s->streamid)
      tr=tr->left;
    else if (prms->currentstreamid>s->streamid)
      tr=tr->right;
    else {
      ret=s->process_data(s, prms, prms->buffer, prms->curreadbufflen);
      break;
    }
  }
  if (!tr){
    debug(D_NOTICE, "throwing out %u bytes of data for unknown streamid %u", (unsigned)prms->curreadbufflen, (unsigned)prms->currentstreamid);
    ret=0;
  }
  read_stream_header_setup(prms);
  return ret;
}

static int process_stream_header(async_thread_params_t *prms){
  uint32_t len;
  memcpy(&prms->currentstreamid, prms->buffer, 4);
  len=0;
  memcpy(&len, prms->buffer+4, 2);
  prms->curreadbuff=prms->buffer;
  prms->curreadbufflen=prms->curreadbuffrem=len+1;
  prms->process_buf=process_stream_data;
  return 0;
}

static void psync_async_thread(void *ptr){
  async_thread_params_t *prms=(async_thread_params_t *)ptr;
  psync_socket_t sel[2];
  int ret;
  sel[0]=prms->api->sock;
  sel[1]=prms->privsock;
  read_stream_header_setup(prms);
  while (1){
    if (prms->pendingrequests){
      if ((prms->pendingrequests>=PSYNC_ASYNC_MAX_GROUPED_REQUESTS || prms->datapendingsince+PSYNC_ASYNC_GROUP_REQUESTS_FOR<psync_millitime()) &&
          flush_pending_data(prms))
        break;
      ret=psync_select_in(sel, 2, PSYNC_ASYNC_GROUP_REQUESTS_FOR/4);
      if (ret==-1)
        continue;
    }
    else{
      if (psync_socket_pendingdata(prms->api))
        ret=0;
      else
        ret=psync_select_in(sel, 2, PSYNC_ASYNC_THREAD_TIMEOUT);
    }
    if (ret==0){
      if (handle_incoming_data(prms))
        break;
    }
    else if (ret==1){
      if (handle_command(prms))
        break;
    }
    else{
      debug(D_NOTICE, "psync_select_in returned %d, exiting, errno %d", ret, (int)psync_sock_err());
      break;
    }
  }
  // close prms->privsock before locking as there might be somebody who keeps the mutex locked while waiting for us to reply
  psync_close_socket(prms->privsock);
  pthread_mutex_lock(&amutex);
  psync_close_socket(at_sock);
  at_sock=INVALID_SOCKET;
  running--;
  pthread_mutex_unlock(&amutex);
  psync_apipool_release_bad(prms->api);
  psync_deflate_destroy(prms->enc);
  psync_deflate_destroy(prms->dec);
  psync_tree_for_each_element_call_safe(prms->streams, stream_t, tree, free_stream);
  psync_free(prms);
}

static int psync_async_start_thread_locked(){
  /* If some form of protocol version negotiation is to be performed, here is the place to pass any needed parameters.
   * The assumption will be that server supports everything and clients inform the server what they support.
   */
  binparam params[]={P_STR("auth", psync_my_auth), P_STR("checksum", "sha1")};
  async_thread_params_t *tparams;
  psync_deflate_t *enc, *dec;
  binresult *res;
  psync_socket *api;
  psync_socket_t pair[2];
  int tries;
  tries=0;
  while (1) {
    api=psync_apipool_get();
    if (!api){
      debug(D_NOTICE, "could not connect to API, failing");
      goto err0;
    }
    res=send_command(api, "asynctransfer", params);
    if (likely(res))
      break;
    psync_apipool_release_bad(api);
    if (++tries>=5){
      debug(D_NOTICE, "failing after %d tries to send asynctransfer call", tries);
      goto err0;
    }
  }
  if (psync_find_result(res, "result", PARAM_NUM)->num){
    debug(D_WARNING, "asynctransfer returned error %d: %s", (int)psync_find_result(res, "result", PARAM_NUM)->num, psync_find_result(res, "error", PARAM_STR)->str);
    psync_process_api_error(psync_find_result(res, "result", PARAM_NUM)->num);
    psync_free(res);
    psync_apipool_release(api);
    goto err0;
  }
  psync_free(res);
  if (psync_socket_pair(pair)){
    debug(D_NOTICE, "psync_socket_pair() failed");
    goto err1;
  }
  enc=psync_deflate_init(PSYNC_DEFLATE_COMP_FAST);
  if (!enc){
    debug(D_NOTICE, "psync_deflate_init() failed");
    goto err2;
  }
  dec=psync_deflate_init(PSYNC_DEFLATE_DECOMPRESS);
  if (!dec){
    debug(D_NOTICE, "psync_deflate_init() failed");
    goto err3;
  }
  tparams=psync_new(async_thread_params_t);
  memset(tparams, 0, sizeof(async_thread_params_t));
  tparams->enc=enc;
  tparams->dec=dec;
  tparams->api=api;
  tparams->privsock=pair[1];
  at_sock=pair[0];
  psync_run_thread1("async transfer", psync_async_thread, tparams);
  running++;
  return 0;
err3:
  psync_deflate_destroy(enc);
err2:
  psync_close_socket(pair[0]);
  psync_close_socket(pair[1]);
err1:
  psync_apipool_release_bad(api);
err0:
  return -1;
}

static int psync_async_send_task_locked(const void *task, size_t len){
  unsigned char ch;
  if (socket_t_writeall(at_sock, task, len)){
    debug(D_WARNING, "failed to write %lu bytes of task to socket", (unsigned long)len);
    return -1;
  }
  if (socket_t_readall(at_sock, &ch, 1)){
    debug(D_WARNING, "failed to read response from socket");
    return -1;
  }
  if (ch==0)
    return 0;
  else{
    debug(D_WARNING, "got error %d from async thread", (int)ch);
    return -1;
  }
}

static int psync_async_send_task(const void *task, size_t len){
  int ret;
  pthread_mutex_lock(&amutex);
  if (running)
    ret=psync_async_send_task_locked(task, len);
  else{
    ret=psync_async_start_thread_locked();
    if (!ret)
      ret=psync_async_send_task_locked(task, len);
  }
  pthread_mutex_unlock(&amutex);
  return ret;
}

void psync_async_stop(){
  task_header_t task;
  task.type=TASK_TYPE_EXIT;
  task.len=0;
  pthread_mutex_lock(&amutex);
  if (running)
    psync_async_send_task_locked(&task, sizeof(task));
  pthread_mutex_unlock(&amutex);
}

int psync_async_download_file(psync_fileid_t fileid, const char *localpath, psync_async_callback_t cb, void *cbext){
  task_hdr_file_download_t task;
  task.head.type=TASK_TYPE_FILE_DWL;
  task.head.len=get_len(task_hdr_file_download_t);
  task.task.fileid=fileid;
  task.task.localpath=localpath;
  task.task.cb=cb;
  task.task.cbext=cbext;
  return psync_async_send_task(&task, sizeof(task));
}

int psync_async_download_file_if_changed(psync_fileid_t fileid, const char *localpath, uint64_t size, const void *sha1hex, psync_async_callback_t cb, void *cbext){
  task_hdr_file_download_if_not_mod_t task;
  task.head.type=TASK_TYPE_FILE_DWL_NM;
  task.head.len=get_len(task_hdr_file_download_if_not_mod_t);
  task.task.fileid=fileid;
  task.task.localpath=localpath;
  task.task.size=size;
  memcpy(task.task.sha1hex, sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  task.task.cb=cb;
  task.task.cbext=cbext;
  return psync_async_send_task(&task, sizeof(task));
}
