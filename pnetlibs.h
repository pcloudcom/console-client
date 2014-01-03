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

#define PSYNC_NET_OK        0
#define PSYNC_NET_PERMFAIL -1
#define PSYNC_NET_TEMPFAIL -2

typedef struct {
  psync_socket *sock;
  void *readbuff;
  uint32_t readbuffoff;
  uint32_t readbuffsize;
} psync_http_socket;

int psync_rmdir_with_trashes(const char *path);

void psync_set_local_full(int over);
int psync_get_remote_file_checksum(uint64_t fileid, unsigned char *hexsum, uint64_t *fsize);
int psync_socket_readall_download(psync_socket *sock, void *buff, int num);

psync_http_socket *psync_http_connect(const char *host, const char *path, uint64_t from, uint64_t to);
void psync_http_close(psync_http_socket *http);
int psync_http_readall(psync_http_socket *http, void *buff, int num);

#endif
