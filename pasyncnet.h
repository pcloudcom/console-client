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

#ifndef _PSYNC_ASYNCNET_H
#define _PSYNC_ASYNCNET_H

#include "psynclib.h"

#define PSYNC_ASYNC_ERR_FLAG_PERM        0x01 // the error is permanent(ish) and there is no reason to retry
#define PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS 0x02 // same request may succeed in the future if retried as is
#define PSYNC_ASYNC_ERR_FLAG_SUCCESS     0x04 // like no action performed because of no need - file already exists and so on

#define PSYNC_ASYNC_ERROR_NET       1
#define PSYNC_ASYNC_ERROR_FILE      2
#define PSYNC_ASYNC_ERROR_DISK_FULL 3
#define PSYNC_ASYNC_ERROR_IO        4
#define PSYNC_ASYNC_ERROR_CHECKSUM  5

#define PSYNC_SERVER_ERROR_TOO_BIG  102
#define PSYNC_SERVER_ERROR_NOT_MOD  104

typedef struct {
  uint64_t size;
  uint64_t hash;
  unsigned char sha1hex[40];
} psync_async_file_result_t;

typedef struct {
  uint32_t error;
  uint32_t errorflags;
  union {
    psync_async_file_result_t file;
  };
} psync_async_result_t;

typedef void (*psync_async_callback_t)(void *, psync_async_result_t *);

/* Important! The interface typically expect all passed pointers to be alive until the completion callback is called.
 */

void psync_async_stop();
int psync_async_download_file(psync_fileid_t fileid, const char *localpath, psync_async_callback_t cb, void *cbext);
int psync_async_download_file_if_changed(psync_fileid_t fileid, const char *localpath, uint64_t size, const void *sha1hex, psync_async_callback_t cb, void *cbext);

#endif
