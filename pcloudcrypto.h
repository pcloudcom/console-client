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

#ifndef _PCLOUD_CRYPTO_H
#define _PCLOUD_CRYPTO_H

#include "pcompiler.h"
#include "pfs.h"
#include "pcrypto.h"
#include "papi.h"

#define PSYNC_CRYPTO_SYM_FLAG_ISDIR 1

#define PSYNC_CRYPTO_SECTOR_SIZE 4096

#define PSYNC_CRYPTO_MAX_ERROR 511

#define PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER ((psync_crypto_aes256_sector_encoder_decoder_t)(PSYNC_CRYPTO_MAX_ERROR+1))
#define PSYNC_CRYPTO_LOADING_SECTOR_ENCODER  ((psync_crypto_aes256_sector_encoder_decoder_t)(PSYNC_CRYPTO_MAX_ERROR+2))
#define PSYNC_CRYPTO_FAILED_SECTOR_ENCODER   ((psync_crypto_aes256_sector_encoder_decoder_t)(PSYNC_CRYPTO_MAX_ERROR+3))

void psync_cloud_crypto_clean_cache();

int psync_cloud_crypto_setup(const char *password, const char *hint);
int psync_cloud_crypto_get_hint(char **hint);
int psync_cloud_crypto_start(const char *password);
int psync_cloud_crypto_stop();
int psync_cloud_crypto_isstarted();
int psync_cloud_crypto_reset();
int psync_cloud_crypto_mkdir(psync_folderid_t folderid, const char *name, const char **err, psync_folderid_t *newfolderid);

psync_crypto_aes256_text_decoder_t psync_cloud_crypto_get_folder_decoder(psync_fsfolderid_t folderid);
void psync_cloud_crypto_release_folder_decoder(psync_fsfolderid_t folderid, psync_crypto_aes256_text_decoder_t decoder);
char *psync_cloud_crypto_decode_filename(psync_crypto_aes256_text_decoder_t decoder, const char *name);

psync_crypto_aes256_text_encoder_t psync_cloud_crypto_get_folder_encoder(psync_fsfolderid_t folderid);
void psync_cloud_crypto_release_folder_encoder(psync_fsfolderid_t folderid, psync_crypto_aes256_text_encoder_t encoder);
char *psync_cloud_crypto_encode_filename(psync_crypto_aes256_text_encoder_t encoder, const char *name);

psync_crypto_aes256_sector_encoder_decoder_t psync_cloud_crypto_get_file_encoder(psync_fsfileid_t fileid, uint64_t hash, int nonetwork);
psync_crypto_aes256_sector_encoder_decoder_t psync_cloud_crypto_get_file_encoder_from_binresult(psync_fileid_t fileid, binresult *res);
void psync_cloud_crypto_release_file_encoder(psync_fsfileid_t fileid, uint64_t hash, psync_crypto_aes256_sector_encoder_decoder_t encoder);

char *psync_cloud_crypto_get_file_encoded_key(psync_fsfileid_t fileid, uint64_t hash, size_t *keylen);
char *psync_cloud_crypto_get_new_encoded_key(uint32_t flags, size_t *keylen);
char *psync_cloud_crypto_get_new_encoded_and_plain_key(uint32_t flags, size_t *keylen, psync_symmetric_key_t *deckey);

static inline int psync_crypto_is_error(const void *ptr){
  return (uintptr_t)ptr<=PSYNC_CRYPTO_MAX_ERROR;
}

static inline int psync_crypto_to_error(const void *ptr){
  return -((int)(uintptr_t)ptr);
}


#endif
