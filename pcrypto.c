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

#include "plibs.h"
#include "pcrypto.h"
#include <string.h>

static void xor16_unaligned_inplace(void *data, const void *key){
  psync_uint_t i;
  for (i=0; i<PSYNC_AES256_BLOCK_SIZE; i++)
    ((unsigned char *)data)[i]^=((const unsigned char *)key)[i];
}

#define LONG_DEREF(x, a) ((unsigned long *)(x))[a]

static void xor16_aligned_inplace(void *data, const void *key){
  if (sizeof(unsigned long)==8){
    LONG_DEREF(data, 0)^=LONG_DEREF(key, 0);
    LONG_DEREF(data, 1)^=LONG_DEREF(key, 1);
  }
  else if (sizeof(unsigned long)==4){
    LONG_DEREF(data, 0)^=LONG_DEREF(key, 0);
    LONG_DEREF(data, 1)^=LONG_DEREF(key, 1);
    LONG_DEREF(data, 2)^=LONG_DEREF(key, 2);
    LONG_DEREF(data, 3)^=LONG_DEREF(key, 3);
  }
  else 
    xor16_unaligned_inplace(data, key);
}

static void xor_cnt_inplace(void *data, const void *key, size_t count){
  size_t i;
  for (i=0; i<count; i++)
    ((unsigned char *)data)[i]^=((const unsigned char *)key)[i];
}

static void copy_iv_and_xor_with_counter(void *dest, const void *iv, uint64_t counter){
  if (sizeof(unsigned long)==8){
    LONG_DEREF(dest, 0)=LONG_DEREF(iv, 0)^LONG_DEREF(&counter, 0);
  }
  else if (sizeof(unsigned long)==4){
    LONG_DEREF(dest, 0)=LONG_DEREF(iv, 0)^LONG_DEREF(&counter, 0);
    LONG_DEREF(dest, 1)=LONG_DEREF(iv, 1)^LONG_DEREF(&counter, 1);
  }
}

psync_crypto_aes256_ctr_encoder_decoder_t psync_crypto_aes256_ctr_encoder_decoder_create(psync_symmetric_key_t key){
  psync_aes256_encoder enc;
  psync_crypto_aes256_ctr_encoder_decoder_t ret;
  if (unlikely_log(key->keylen<PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc=psync_ssl_aes256_create_encoder(key);
  if (unlikely_log(enc==PSYNC_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret=psync_new(psync_crypto_aes256_ctr_encoder_decoder_struct_t);
  ret->encoder=enc;
  memcpy(ret->iv, key->key+PSYNC_AES256_KEY_SIZE, PSYNC_AES256_BLOCK_SIZE);
  return ret;
}

void psync_crypto_aes256_ctr_encoder_decoder_free(psync_crypto_aes256_ctr_encoder_decoder_t enc){
  psync_ssl_aes256_free_encoder(enc->encoder);
  memset(enc->iv, 0, PSYNC_AES256_BLOCK_SIZE);
}

void psync_crypto_aes256_ctr_encode_decode_inplace(psync_crypto_aes256_ctr_encoder_decoder_t enc, void *data, size_t datalen, uint64_t dataoffset){
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3], *aessrc, *aesdst;
  uint64_t counter;
  size_t blocksrem;
  aessrc=(unsigned char *)((((uintptr_t)buff+PSYNC_AES256_BLOCK_SIZE-1)/PSYNC_AES256_BLOCK_SIZE)*PSYNC_AES256_BLOCK_SIZE);
  aesdst=aessrc+PSYNC_AES256_BLOCK_SIZE;
  counter=dataoffset/PSYNC_AES256_BLOCK_SIZE;
  memcpy(aessrc+sizeof(uint64_t), enc->iv+sizeof(uint64_t), PSYNC_AES256_BLOCK_SIZE-sizeof(uint64_t));
  dataoffset%=PSYNC_AES256_BLOCK_SIZE;
  if (dataoffset){
    copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
    psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
    blocksrem=PSYNC_AES256_BLOCK_SIZE-dataoffset;
    xor_cnt_inplace(data, aesdst+dataoffset, blocksrem);
    datalen-=blocksrem;
    counter++;
    data=(char *)data+blocksrem;
  }
  blocksrem=datalen/PSYNC_AES256_BLOCK_SIZE;
  datalen-=blocksrem*PSYNC_AES256_BLOCK_SIZE;
  if (((uintptr_t)data)%sizeof(unsigned long)==0){
    while (blocksrem){
      copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      xor16_aligned_inplace(data, aesdst);
      blocksrem--;
      counter++;
      data=(char *)data+PSYNC_AES256_BLOCK_SIZE;
    }
  }
  else{
    while (blocksrem){
      copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      xor16_unaligned_inplace(data, aesdst);
      blocksrem--;
      counter++;
      data=(char *)data+PSYNC_AES256_BLOCK_SIZE;
    }
  }
  if (datalen){
    copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
    psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
    xor_cnt_inplace(data, aesdst, datalen);
  }
}
