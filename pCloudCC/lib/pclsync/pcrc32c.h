/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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

#ifndef _PSYNC_CRC32_H
#define _PSYNC_CRC32_H

#include <stdint.h>
#include <stddef.h>

#define PSYNC_CRC_INITIAL 0

#define PSYNC_FAST_HASH256_LEN    32
#define PSYNC_FAST_HASH256_HEXLEN 64

#define PSYNC_FAST_HASH256_BLOCK_LEN 64

typedef struct{
  uint64_t state[6];
  uint64_t length;
  union {
    uint64_t buff64[PSYNC_FAST_HASH256_BLOCK_LEN/sizeof(uint64_t)];
    unsigned char buff[PSYNC_FAST_HASH256_BLOCK_LEN];
  };
} psync_fast_hash256_ctx;

uint32_t psync_crc32c(uint32_t crc, const void *ptr, size_t len);

/* psync_fast_hash256 is supposed to be fast, non-cryptographic strength, non-collision resistant hash function
 * with large output. Think of it as CRC32 but faster, with 256bit output and for cases that you can't live with
 * the chances of CRC32 _random_ collision. It is intended for large inputs, finalization is relatively expensive.
 */

void psync_fast_hash256_init(psync_fast_hash256_ctx *ctx);
void psync_fast_hash256_init_seed(psync_fast_hash256_ctx *ctx, const void *seed, size_t seedlen);
void psync_fast_hash256_update(psync_fast_hash256_ctx *ctx, const void *data, size_t len);
void psync_fast_hash256_final(void *hash, psync_fast_hash256_ctx *ctx);

#endif
