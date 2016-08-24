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

#ifndef _PSYNC_SECURETRANSPORT_H
#define _PSYNC_SECURETRANSPORT_H

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>

typedef struct {
  SecKeyRef public_key;
  SecKeyRef private_key;
} psync_rsa_struct_t, *psync_rsa_t;

typedef SecKeyRef psync_rsa_publickey_t;
typedef SecKeyRef psync_rsa_privatekey_t;

typedef struct {
  size_t keylen;
  unsigned char key[];
} psync_symmetric_key_struct_t, *psync_symmetric_key_t;

typedef CCCryptorRef psync_aes256_encoder;
typedef CCCryptorRef psync_aes256_decoder;

#define PSYNC_INVALID_RSA NULL
#define PSYNC_INVALID_SYM_KEY NULL

#define PSYNC_SHA1_BLOCK_LEN 64
#define PSYNC_SHA1_DIGEST_LEN 20
#define PSYNC_SHA1_DIGEST_HEXLEN 40
#define psync_sha1_ctx CC_SHA1_CTX
#define psync_sha1(data, datalen, checksum) CC_SHA1(data, datalen, checksum)
#define psync_sha1_init(pctx) CC_SHA1_Init(pctx)
#define psync_sha1_update(pctx, data, datalen) CC_SHA1_Update(pctx, data, datalen)
#define psync_sha1_final(checksum, pctx) CC_SHA1_Final(checksum, pctx)

static inline void psync_aes256_encode_block(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  size_t n;
  CCCryptorUpdate(enc, src, 16, dst, 16, &n);
}

static inline void psync_aes256_decode_block(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  size_t n;
  CCCryptorUpdate(enc, src, 16, dst, 16, &n);
}


#endif