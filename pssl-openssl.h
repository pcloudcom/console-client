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

#ifndef _PSYNC_OPENSSL_H
#define _PSYNC_OPENSSL_H

#include "pcompiler.h"

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

typedef RSA *psync_rsa_t;
typedef RSA *psync_rsa_publickey_t;
typedef RSA *psync_rsa_privatekey_t;

typedef struct {
  size_t keylen;
  unsigned char key[];
} psync_symmetric_key_struct_t, *psync_symmetric_key_t;

typedef AES_KEY *psync_aes256_encoder;
typedef AES_KEY *psync_aes256_decoder;

#define PSYNC_INVALID_RSA NULL
#define PSYNC_INVALID_SYM_KEY NULL

#define PSYNC_SHA1_BLOCK_LEN 64
#define PSYNC_SHA1_DIGEST_LEN 20
#define PSYNC_SHA1_DIGEST_HEXLEN 40
#define psync_sha1_ctx SHA_CTX
#define psync_sha1(data, datalen, checksum) SHA1(data, datalen, checksum)
#define psync_sha1_init(pctx) SHA1_Init(pctx)
#define psync_sha1_update(pctx, data, datalen) SHA1_Update(pctx, data, datalen)
#define psync_sha1_final(checksum, pctx) SHA1_Final(checksum, pctx)

#define PSYNC_SHA512_BLOCK_LEN 128
#define PSYNC_SHA512_DIGEST_LEN 64
#define PSYNC_SHA512_DIGEST_HEXLEN 128
#define psync_sha512_ctx SHA512_CTX
#define psync_sha512(data, datalen, checksum) SHA512(data, datalen, checksum)
#define psync_sha512_init(pctx) SHA512_Init(pctx)
#define psync_sha512_update(pctx, data, datalen) SHA512_Update(pctx, data, datalen)
#define psync_sha512_final(checksum, pctx) SHA512_Final(checksum, pctx)

/* AES_encrypt/AES_decrypt do not use hardware acceleration, do it ourselves */

#if defined(__GNUC__) && (defined(__amd64__) || defined(__x86_64__) || defined(__i386__))
#define PSYNC_AES_HW
#define PSYNC_AES_HW_GCC
#elif defined(_MSC_VER)
#define PSYNC_AES_HW
#define PSYNC_AES_HW_MSC
#endif

#if defined(PSYNC_AES_HW)
extern int psync_ssl_hw_aes;

void psync_aes256_encode_block_hw(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst);
void psync_aes256_decode_block_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst);
void psync_aes256_encode_2blocks_consec_hw(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst);
void psync_aes256_decode_2blocks_consec_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst);
void psync_aes256_decode_4blocks_consec_xor_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor);
void psync_aes256_decode_4blocks_consec_xor_sw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor);

static inline void psync_aes256_encode_block(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  if (likely(psync_ssl_hw_aes))
    psync_aes256_encode_block_hw(enc, src, dst);
  else
    AES_encrypt(src, dst, enc);
}

static inline void psync_aes256_decode_block(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  if (likely(psync_ssl_hw_aes))
    psync_aes256_decode_block_hw(enc, src, dst);
  else
    AES_decrypt(src, dst, enc);
}

static inline void psync_aes256_encode_2blocks_consec(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  if (likely(psync_ssl_hw_aes))
    psync_aes256_encode_2blocks_consec_hw(enc, src, dst);
  else{
    AES_encrypt(src, dst, enc);
    AES_encrypt(src+PSYNC_AES256_BLOCK_SIZE, dst+PSYNC_AES256_BLOCK_SIZE, enc);
  }
}

static inline void psync_aes256_decode_2blocks_consec(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  if (likely(psync_ssl_hw_aes))
    psync_aes256_decode_2blocks_consec_hw(enc, src, dst);
  else{
    AES_decrypt(src, dst, enc);
    AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE, dst+PSYNC_AES256_BLOCK_SIZE, enc);
  }
}

static inline void psync_aes256_decode_4blocks_consec_xor(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor){
  if (psync_ssl_hw_aes)
    psync_aes256_decode_4blocks_consec_xor_hw(enc, src, dst, bxor);
  else
    psync_aes256_decode_4blocks_consec_xor_sw(enc, src, dst, bxor);
}

#else

static inline void psync_aes256_encode_block(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  AES_encrypt(src, dst, enc);
}

static inline void psync_aes256_decode_block(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  AES_decrypt(src, dst, enc);
}

static inline void psync_aes256_decode_2blocks_consec(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  AES_decrypt(src, dst, enc);
  AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE, dst+PSYNC_AES256_BLOCK_SIZE, enc);
}

static inline void void psync_aes256_decode_4blocks_consec_xor(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor){
  unsigned long i;
  AES_decrypt(src, dst, enc);
  AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE, dst+PSYNC_AES256_BLOCK_SIZE, enc);
  AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE*2, dst+PSYNC_AES256_BLOCK_SIZE*2, enc);
  AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE*3, dst+PSYNC_AES256_BLOCK_SIZE*3, enc);
  for (i=0; i<PSYNC_AES256_BLOCK_SIZE*4/sizeof(unsigned long); i++)
    ((unsigned long *)dst)[i]^=((unsigned long *)bxor)[i];
}

#endif

#endif
