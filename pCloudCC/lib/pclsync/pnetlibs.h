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

#ifndef _PSYNC_NETLIBS_H
#define _PSYNC_NETLIBS_H

#include "pcompat.h"
#include "psynclib.h"
#include "plist.h"
#include "papi.h"

#define senddebug(str, ...) do {psync_send_debug(0, __FILE__, __FUNCTION__, __LINE__, str, __VA_ARGS__);} while (0)
#define sendtdebug(str, ...) do {psync_send_debug(1, __FILE__, __FUNCTION__, __LINE__, str, __VA_ARGS__);} while (0)
#define sendassert(cond) do {if (unlikely(!(cond))) { senddebug("assertion %s failed", TO_STR(cond));}} while (0)
#define sendtassert(cond) do {if (unlikely(!(cond))) { sendtdebug("assertion %s failed", TO_STR(cond));}} while (0)

#define psync_api_run_command(cmd, params) psync_do_api_run_command(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam))

#define psync_run_command(cmd, params, err) psync_do_run_command_res(cmd, strlen(cmd), params, sizeof(params)/sizeof(binparam), err)

#define PSYNC_NET_OK        0
#define PSYNC_NET_PERMFAIL -1
#define PSYNC_NET_TEMPFAIL -2

typedef uint64_t psync_uploadid_t;

typedef struct {
  psync_socket *sock;
  char *readbuff;
  int64_t contentlength;
  uint64_t readbytes;
  uint32_t keepalive;
  uint32_t readbuffoff;
  uint32_t readbuffsize;
  char cachekey[];
} psync_http_socket;

#define PSYNC_RANGE_TRANSFER 0
#define PSYNC_RANGE_COPY     1

typedef struct {
  psync_list list;
  uint64_t off;
  uint64_t len;
  uint32_t type;
  const char *filename;
} psync_range_list_t;

#define PSYNC_URANGE_UPLOAD      0
#define PSYNC_URANGE_COPY_FILE   1
#define PSYNC_URANGE_COPY_UPLOAD 2
#define PSYNC_URANGE_LAST        3

typedef struct {
  psync_list list;
  uint64_t uploadoffset;
  uint64_t off;
  uint64_t len;
  union {
    uint64_t uploadid;
    struct {
      psync_fileid_t fileid;
      uint64_t hash;
    } file;
  };
  uint32_t type;
  uint32_t id;
} psync_upload_range_list_t;

struct _psync_file_lock_t;

typedef struct _psync_file_lock_t psync_file_lock_t;

extern char apiserver[64];

void psync_netlibs_init();

void psync_apipool_set_server(const char *binapi);

psync_socket *psync_apipool_get();
psync_socket *psync_apipool_get_from_cache();
void psync_apipool_prepare();
void psync_apipool_release(psync_socket *api);
void psync_apipool_release_bad(psync_socket *api);
binresult *psync_do_api_run_command(const char *command, size_t cmdlen, const binparam *params, size_t paramcnt);

int psync_rmdir_with_trashes(const char *path);
int psync_rmdir_recursive(const char *path);

void psync_set_local_full(int over);
int psync_handle_api_result(uint64_t result);
int psync_get_remote_file_checksum(psync_fileid_t fileid, unsigned char *hexsum, uint64_t *fsize, uint64_t *hash);
int psync_get_local_file_checksum(const char *restrict filename, unsigned char *restrict hexsum, uint64_t *restrict fsize);
int psync_get_local_file_checksum_part(const char *restrict filename, unsigned char *restrict hexsum, uint64_t *restrict fsize,
                                       unsigned char *restrict phexsum, uint64_t pfsize);
int psync_copy_local_file_if_checksum_matches(const char *source, const char *destination, const unsigned char *hexsum, uint64_t fsize);
int psync_file_writeall_checkoverquota(psync_file_t fd, const void *buf, size_t count);

int psync_set_default_sendbuf(psync_socket *sock);
void psync_account_downloaded_bytes(int unsigned bytes);
int psync_socket_readall_download(psync_socket *sock, void *buff, int num);
int psync_socket_readall_download_thread(psync_socket *sock, void *buff, int num);
int psync_socket_writeall_upload(psync_socket *sock, const void *buff, int num);

psync_http_socket *psync_http_connect(const char *host, const char *path, uint64_t from, uint64_t to, const char *addhdr);
void psync_http_close(psync_http_socket *http);
int psync_http_readall(psync_http_socket *http, void *buff, int num);
void psync_http_connect_and_cache_host(const char *host);
psync_http_socket *psync_http_connect_multihost(const binresult *hosts, const char **host);
psync_http_socket *psync_http_connect_multihost_from_cache(const binresult *hosts, const char **host);
int psync_http_request_range_additional(psync_http_socket *sock, const char *host, const char *path, uint64_t from, uint64_t to, const char *addhdr);
int psync_http_request(psync_http_socket *sock, const char *host, const char *path, uint64_t from, uint64_t to, const char *addhdr);
int psync_http_next_request(psync_http_socket *sock);
int psync_http_request_readall(psync_http_socket *http, void *buff, int num);

char *psync_url_decode(const char *s);

int psync_net_download_ranges(psync_list *ranges, psync_fileid_t fileid, uint64_t filehash, uint64_t filesize, char *const *files, uint32_t filecnt);
int psync_net_scan_file_for_blocks(psync_socket *api, psync_list *rlist, psync_fileid_t fileid, uint64_t filehash, psync_file_t fd);
int psync_net_scan_upload_for_blocks(psync_socket *api, psync_list *rlist, psync_uploadid_t uploadid, psync_file_t fd);

int psync_is_revision_of_file(const unsigned char *localhashhex, uint64_t filesize, psync_fileid_t fileid, int *isrev);

psync_file_lock_t *psync_lock_file(const char *path);
void psync_unlock_file(psync_file_lock_t *lock);

int psync_get_upload_checksum(psync_uploadid_t uploadid, unsigned char *uhash, uint64_t *usize);

void psync_process_api_error(uint64_t result);

int psync_send_debug(int thread, const char *file, const char *function, int unsigned line, const char *fmt, ...)
    PSYNC_COLD PSYNC_FORMAT(printf, 5, 6)  PSYNC_NONNULL(5);

int psync_do_run_command_res(const char *cmd, size_t cmdlen, const binparam *params, size_t paramscnt, char **err);

#endif
