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

#ifndef _PSYNC_CRYPTO_H
#define _PSYNC_CRYPTO_H

#include "pssl.h"

#define PSYNC_CRYPTO_AUTH_SIZE (PSYNC_AES256_BLOCK_SIZE*2)

#define PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL 6

typedef struct {
  uint64_t masterauthoff;
  uint64_t plainsize;
  uint64_t lastauthsectoroff[PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL];
  uint16_t lastauthsectorlen[PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL];
  uint8_t treelevels;
  uint8_t needmasterauth;
} psync_crypto_offsets_t;

typedef unsigned char psync_crypto_sector_auth_t[PSYNC_CRYPTO_AUTH_SIZE];

typedef struct {
  psync_aes256_encoder encoder;
  union {
    long unsigned __aligner;
    unsigned char iv[PSYNC_AES256_BLOCK_SIZE];
  };
} psync_crypto_aes256_key_struct_t, *psync_crypto_aes256_ctr_encoder_decoder_t;

typedef struct {
  psync_aes256_encoder encoder;
  unsigned long ivlen;
  unsigned char iv[];
} psync_crypto_aes256_key_var_iv_struct_t, *psync_crypto_aes256_text_encoder_t, *psync_crypto_aes256_text_decoder_t;


typedef struct {
  psync_aes256_encoder encoder;
  psync_aes256_decoder decoder;
  unsigned long ivlen;
  unsigned char iv[];
} psync_crypto_aes256_enc_dec_var_iv_struct_t, *psync_crypto_aes256_sector_encoder_decoder_t;

#define psync_crypto_aes256_text_gen_key psync_crypto_aes256_ctr_gen_key
#define psync_crypto_aes256_sector_gen_key psync_crypto_aes256_ctr_gen_key

#define PSYNC_CRYPTO_INVALID_ENCODER NULL
#define PSYNC_CRYPTO_INVALID_REVISIONID ((uint32_t)-1)

psync_symmetric_key_t psync_crypto_aes256_gen_key_len(size_t len);
psync_symmetric_key_t psync_crypto_aes256_ctr_gen_key();
psync_crypto_aes256_ctr_encoder_decoder_t psync_crypto_aes256_ctr_encoder_decoder_create(psync_symmetric_key_t key);
void psync_crypto_aes256_ctr_encoder_decoder_free(psync_crypto_aes256_ctr_encoder_decoder_t enc);
void psync_crypto_aes256_ctr_encode_decode_inplace(psync_crypto_aes256_ctr_encoder_decoder_t enc, void *data, size_t datalen, uint64_t dataoffset);

psync_crypto_aes256_text_encoder_t psync_crypto_aes256_text_encoder_create(psync_symmetric_key_t key);
void psync_crypto_aes256_text_encoder_free(psync_crypto_aes256_text_encoder_t enc);
psync_crypto_aes256_text_decoder_t psync_crypto_aes256_text_decoder_create(psync_symmetric_key_t key);
void psync_crypto_aes256_text_decoder_free(psync_crypto_aes256_text_decoder_t enc);
void psync_crypto_aes256_encode_text(psync_crypto_aes256_text_encoder_t enc, const unsigned char *txt, size_t txtlen, unsigned char **out, size_t *outlen);
unsigned char *psync_crypto_aes256_decode_text(psync_crypto_aes256_text_decoder_t enc, const unsigned char *data, size_t datalen);

psync_crypto_aes256_sector_encoder_decoder_t psync_crypto_aes256_sector_encoder_decoder_create(psync_symmetric_key_t key);
void psync_crypto_aes256_sector_encoder_decoder_free(psync_crypto_aes256_sector_encoder_decoder_t enc);
void psync_crypto_aes256_encode_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen, 
                                       unsigned char *out, psync_crypto_sector_auth_t authout, uint64_t sectorid);
int psync_crypto_aes256_decode_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen, 
                                       unsigned char *out, const psync_crypto_sector_auth_t auth, uint64_t sectorid);
void psync_crypto_sign_auth_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen, psync_crypto_sector_auth_t authout);
#endif
