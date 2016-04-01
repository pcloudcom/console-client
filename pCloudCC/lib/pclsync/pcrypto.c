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
#include "psettings.h"
#include "pmemlock.h"
#include <string.h>
#include <stddef.h>

typedef struct {
  psync_sha512_ctx sha1ctx;
  unsigned char final[PSYNC_SHA512_BLOCK_LEN+PSYNC_SHA512_DIGEST_LEN];
} psync_hmac_sha512_ctx;

static void psync_hmac_sha512_init(psync_hmac_sha512_ctx *ctx, const unsigned char *key, size_t keylen){
  unsigned char keyxor[PSYNC_SHA512_BLOCK_LEN];
  size_t i;
  if (keylen>PSYNC_SHA512_BLOCK_LEN)
    keylen=PSYNC_SHA512_BLOCK_LEN;
  for (i=0; i<keylen; i++){
    keyxor[i]=key[i]^0x36;
    ctx->final[i]=key[i]^0x5c;
  }
  for (; i<PSYNC_SHA512_BLOCK_LEN; i++){
    keyxor[i]=0x36;
    ctx->final[i]=0x5c;
  }
  psync_sha512_init(&ctx->sha1ctx);
  psync_sha512_update(&ctx->sha1ctx, keyxor, PSYNC_SHA512_BLOCK_LEN);
  psync_ssl_memclean(keyxor, PSYNC_SHA512_BLOCK_LEN);
}

static void psync_hmac_sha512_update(psync_hmac_sha512_ctx *ctx, const void *data, size_t len){
  psync_sha512_update(&ctx->sha1ctx, data, len);
}

static void psync_hmac_sha512_final(unsigned char *result, psync_hmac_sha512_ctx *ctx){
  psync_sha512_final(ctx->final+PSYNC_SHA512_BLOCK_LEN, &ctx->sha1ctx);
  psync_sha512(ctx->final, PSYNC_SHA512_BLOCK_LEN+PSYNC_SHA512_DIGEST_LEN, result);
  psync_ssl_memclean(ctx->final, PSYNC_SHA512_BLOCK_LEN+PSYNC_SHA512_DIGEST_LEN);
}

static void psync_hmac_sha512(const unsigned char *msg, size_t msglen, const unsigned char *key, size_t keylen, unsigned char *result){
  psync_sha512_ctx sha1ctx;
  unsigned char keyxor[PSYNC_SHA512_BLOCK_LEN], final[PSYNC_SHA512_BLOCK_LEN+PSYNC_SHA512_DIGEST_LEN];
  size_t i;
  if (keylen>PSYNC_SHA512_BLOCK_LEN)
    keylen=PSYNC_SHA512_BLOCK_LEN;
  for (i=0; i<keylen; i++){
    keyxor[i]=key[i]^0x36;
    final[i]=key[i]^0x5c;
  }
  for (; i<PSYNC_SHA512_BLOCK_LEN; i++){
    keyxor[i]=0x36;
    final[i]=0x5c;
  }
  psync_sha512_init(&sha1ctx);
  psync_sha512_update(&sha1ctx, keyxor, PSYNC_SHA512_BLOCK_LEN);
  psync_sha512_update(&sha1ctx, msg, msglen);
  psync_sha512_final(final+PSYNC_SHA512_BLOCK_LEN, &sha1ctx);
  psync_sha512(final, PSYNC_SHA512_BLOCK_LEN+PSYNC_SHA512_DIGEST_LEN, result);
  psync_ssl_memclean(keyxor, PSYNC_SHA512_BLOCK_LEN);
  psync_ssl_memclean(final, PSYNC_SHA512_BLOCK_LEN+PSYNC_SHA512_DIGEST_LEN);
}

#define ALIGN_A256_BS(n) ((((n)+PSYNC_AES256_BLOCK_SIZE-1)/PSYNC_AES256_BLOCK_SIZE)*PSYNC_AES256_BLOCK_SIZE)
#define ALIGN_PTR_A256_BS(ptr) ((unsigned char *)ALIGN_A256_BS((uintptr_t)(ptr)))

#define IS_WORD_ALIGNED(ptr) (((uintptr_t)ptr)%sizeof(unsigned long)==0)

static void xor16_unaligned_inplace(unsigned char *data, const unsigned char *key){
  psync_uint_t i;
  for (i=0; i<PSYNC_AES256_BLOCK_SIZE; i++)
    data[i]^=key[i];
}

#define LONG_DEREF(x, a) ((unsigned long *)(x))[a]

static void xor16_aligned_inplace(unsigned char *data, const unsigned char *key){
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

static void xor_cnt_inplace(unsigned char *data, const unsigned char *key, size_t count){
  size_t i;
  for (i=0; i<count; i++)
    data[i]^=key[i];
}

static void copy_iv_and_xor_with_counter(unsigned char *dest, const unsigned char *iv, uint64_t counter){
  if (sizeof(unsigned long)==8){
    LONG_DEREF(dest, 0)=LONG_DEREF(iv, 0)^counter;
  }
  else if (sizeof(unsigned long)==4){
    LONG_DEREF(dest, 0)=LONG_DEREF(iv, 0)^(counter&0xffffffffU);
    LONG_DEREF(dest, 1)=LONG_DEREF(iv, 1)^(counter>>32);
  }
}

psync_symmetric_key_t psync_crypto_aes256_gen_key_len(size_t len){
  psync_symmetric_key_t key;
  key=(psync_symmetric_key_t)psync_locked_malloc(offsetof(psync_symmetric_key_struct_t, key)+len);
  key->keylen=len;
  psync_ssl_rand_strong(key->key, len);
  return key;
}

psync_symmetric_key_t psync_crypto_aes256_ctr_gen_key(){
  return psync_crypto_aes256_gen_key_len(PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE);
}

psync_crypto_aes256_ctr_encoder_decoder_t psync_crypto_aes256_ctr_encoder_decoder_create(psync_symmetric_key_t key){
  psync_aes256_encoder enc;
  psync_crypto_aes256_ctr_encoder_decoder_t ret;
  if (unlikely_log(key->keylen<PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc=psync_ssl_aes256_create_encoder(key);
  if (unlikely_log(enc==PSYNC_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret=psync_new(psync_crypto_aes256_key_struct_t);
  ret->encoder=enc;
  memcpy(ret->iv, key->key+PSYNC_AES256_KEY_SIZE, PSYNC_AES256_BLOCK_SIZE);
  return ret;
}

void psync_crypto_aes256_ctr_encoder_decoder_free(psync_crypto_aes256_ctr_encoder_decoder_t enc){
  psync_ssl_aes256_free_encoder(enc->encoder);
  psync_ssl_memclean(enc->iv, PSYNC_AES256_BLOCK_SIZE);
  psync_free(enc);
}

void psync_crypto_aes256_ctr_encode_decode_inplace(psync_crypto_aes256_ctr_encoder_decoder_t enc, void *data, size_t datalen, uint64_t dataoffset){
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3], *aessrc, *aesdst;
  uint64_t counter;
  size_t blocksrem;
  aessrc=ALIGN_PTR_A256_BS(buff);
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
  if (IS_WORD_ALIGNED(data)){
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

static void copy_unaligned(unsigned char *dst, const unsigned char *src){
  memcpy(dst, src, PSYNC_AES256_BLOCK_SIZE);
}

static void copy_aligned(unsigned char *dst, const unsigned char *src){
  if (sizeof(unsigned long)==8){
    LONG_DEREF(dst, 0)=LONG_DEREF(src, 0);
    LONG_DEREF(dst, 1)=LONG_DEREF(src, 1);
  }
  else if (sizeof(unsigned long)==4){
    LONG_DEREF(dst, 0)=LONG_DEREF(src, 0);
    LONG_DEREF(dst, 1)=LONG_DEREF(src, 1);
    LONG_DEREF(dst, 2)=LONG_DEREF(src, 2);
    LONG_DEREF(dst, 3)=LONG_DEREF(src, 3);
  }
  else
    copy_unaligned(dst, src);
}

static void copy_pad(unsigned char *dst, size_t cnt, const unsigned char **restrict txt, size_t *restrict txtlen){
  if (cnt<=*txtlen){
    memcpy(dst, *txt, cnt);
    *txt+=cnt;
    *txtlen-=cnt;
  }
  else{
    memcpy(dst, *txt, *txtlen);
    dst+=*txtlen;
    memset(dst, 0, cnt-*txtlen);
    *txtlen=0;
  }
}

void psync_crypto_aes256_encode_text(psync_crypto_aes256_text_encoder_t enc, const unsigned char *txt, size_t txtlen, unsigned char **out, size_t *outlen){
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3+PSYNC_SHA512_DIGEST_LEN], *aessrc, *aesdst, *outptr, *hmac;
  size_t ol;
  aessrc=ALIGN_PTR_A256_BS(buff);
  aesdst=aessrc+PSYNC_AES256_BLOCK_SIZE;
  hmac=aessrc+PSYNC_AES256_BLOCK_SIZE*2;
  ol=ALIGN_A256_BS(txtlen);
  outptr=psync_new_cnt(unsigned char, ol);
  *out=outptr;
  *outlen=ol;
  if (txtlen<=PSYNC_AES256_BLOCK_SIZE){
    copy_pad(aessrc, PSYNC_AES256_BLOCK_SIZE, &txt, &txtlen);
    assert(enc->ivlen>=PSYNC_AES256_BLOCK_SIZE);
    xor16_aligned_inplace(aessrc, enc->iv);
    psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    return;
  }
  psync_hmac_sha512(txt+PSYNC_AES256_BLOCK_SIZE, txtlen-PSYNC_AES256_BLOCK_SIZE, enc->iv, enc->ivlen, hmac);
  copy_unaligned(aessrc, txt);
  txt+=PSYNC_AES256_BLOCK_SIZE;
  txtlen-=PSYNC_AES256_BLOCK_SIZE;
  xor16_aligned_inplace(aessrc, hmac);
  psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
  copy_aligned(outptr, aesdst);
  outptr+=PSYNC_AES256_BLOCK_SIZE;
  do {
    copy_pad(aessrc, PSYNC_AES256_BLOCK_SIZE, &txt, &txtlen);
    xor16_aligned_inplace(aessrc, aesdst);
    psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    outptr+=PSYNC_AES256_BLOCK_SIZE;
  } while (txtlen);
}

unsigned char *psync_crypto_aes256_decode_text(psync_crypto_aes256_text_decoder_t enc, const unsigned char *data, size_t datalen){
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*2+PSYNC_SHA512_DIGEST_LEN], *aessrc, *aesdst, *outptr, *ret;
  size_t len;
  const unsigned char *xorptr;
  if (unlikely_log(datalen%PSYNC_AES256_BLOCK_SIZE || !datalen))
    return NULL;
  aessrc=ALIGN_PTR_A256_BS(buff);
  aesdst=aessrc+PSYNC_AES256_BLOCK_SIZE;
  outptr=psync_new_cnt(unsigned char, datalen+1);
  ret=outptr;
  datalen/=PSYNC_AES256_BLOCK_SIZE;
  if (datalen==1){
    copy_unaligned(aessrc, data);
    psync_aes256_decode_block(enc->encoder, aessrc, aesdst);
    assert(enc->ivlen>=PSYNC_AES256_BLOCK_SIZE);
    xor16_aligned_inplace(aesdst, enc->iv);
    copy_aligned(outptr, aesdst);
    outptr+=PSYNC_AES256_BLOCK_SIZE;
    *outptr=0;
    len=strlen((char *)ret)+1;
    while (ret+len<outptr){
      if (unlikely(ret[len]!=0)){
        debug(D_WARNING, "non-zero in the padding found");
        psync_free(ret);
        return NULL;
      }
      len++;
    }
    return ret;
  }
  if (IS_WORD_ALIGNED(data)){
    copy_aligned(aessrc, data);
    psync_aes256_decode_block(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    outptr+=PSYNC_AES256_BLOCK_SIZE;
    while (--datalen){
      xorptr=data;
      data+=PSYNC_AES256_BLOCK_SIZE;
      copy_aligned(aessrc, data);
      psync_aes256_decode_block(enc->encoder, aessrc, aesdst);
      xor16_aligned_inplace(aesdst, xorptr);
      copy_aligned(outptr, aesdst);
      outptr+=PSYNC_AES256_BLOCK_SIZE;
    }
  }
  else{
    copy_unaligned(aessrc, data);
    psync_aes256_decode_block(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    outptr+=PSYNC_AES256_BLOCK_SIZE;
    while (--datalen){
      xorptr=data;
      data+=PSYNC_AES256_BLOCK_SIZE;
      copy_unaligned(aessrc, data);
      psync_aes256_decode_block(enc->encoder, aessrc, aesdst);
      xor16_unaligned_inplace(aesdst, xorptr);
      copy_aligned(outptr, aesdst);
      outptr+=PSYNC_AES256_BLOCK_SIZE;
    }
  }
  *outptr=0;
  len=strlen((char *)ret+PSYNC_AES256_BLOCK_SIZE);
  psync_hmac_sha512(ret+PSYNC_AES256_BLOCK_SIZE, len, enc->iv, enc->ivlen, aessrc);
  xor16_aligned_inplace(ret, aessrc);
  len+=PSYNC_AES256_BLOCK_SIZE+1;
  while (ret+len<outptr){
    if (unlikely(ret[len]!=0)){
      debug(D_WARNING, "non-zero in the padding found");
      psync_free(ret);
      return NULL;
    }
    len++;
  }
  return ret;
}

psync_crypto_aes256_text_encoder_t psync_crypto_aes256_text_encoder_create(psync_symmetric_key_t key){
  psync_aes256_encoder enc;
  psync_crypto_aes256_text_encoder_t ret;
  if (unlikely_log(key->keylen<PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc=psync_ssl_aes256_create_encoder(key);
  if (unlikely_log(enc==PSYNC_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret=(psync_crypto_aes256_text_encoder_t)psync_locked_malloc(offsetof(psync_crypto_aes256_key_var_iv_struct_t, iv)+key->keylen-PSYNC_AES256_KEY_SIZE);
  ret->encoder=enc;
  ret->ivlen=key->keylen-PSYNC_AES256_KEY_SIZE;
  memcpy(ret->iv, key->key+PSYNC_AES256_KEY_SIZE, ret->ivlen);
  return ret;
}

void psync_crypto_aes256_text_encoder_free(psync_crypto_aes256_text_encoder_t enc){
  psync_ssl_aes256_free_encoder(enc->encoder);
  psync_ssl_memclean(enc->iv, enc->ivlen);
  psync_locked_free(enc);
}

psync_crypto_aes256_text_decoder_t psync_crypto_aes256_text_decoder_create(psync_symmetric_key_t key){
  psync_aes256_encoder enc;
  psync_crypto_aes256_text_encoder_t ret;
  if (unlikely_log(key->keylen<PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc=psync_ssl_aes256_create_decoder(key);
  if (unlikely_log(enc==PSYNC_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret=(psync_crypto_aes256_text_encoder_t)psync_locked_malloc(offsetof(psync_crypto_aes256_key_var_iv_struct_t, iv)+key->keylen-PSYNC_AES256_KEY_SIZE);
  ret->encoder=enc;
  ret->ivlen=key->keylen-PSYNC_AES256_KEY_SIZE;
  memcpy(ret->iv, key->key+PSYNC_AES256_KEY_SIZE, ret->ivlen);
  return ret;
}

void psync_crypto_aes256_text_decoder_free(psync_crypto_aes256_text_decoder_t enc){
  psync_ssl_aes256_free_encoder(enc->encoder);
  psync_ssl_memclean(enc->iv, enc->ivlen);
  psync_locked_free(enc);
}

psync_crypto_aes256_sector_encoder_decoder_t psync_crypto_aes256_sector_encoder_decoder_create(psync_symmetric_key_t key){
  psync_aes256_encoder enc;
  psync_aes256_decoder dec;
  psync_crypto_aes256_sector_encoder_decoder_t ret;
  if (unlikely_log(key->keylen<PSYNC_AES256_KEY_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc=psync_ssl_aes256_create_encoder(key);
  if (unlikely_log(enc==PSYNC_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  dec=psync_ssl_aes256_create_decoder(key);
  if (unlikely_log(enc==PSYNC_INVALID_ENCODER)){
    psync_ssl_aes256_free_encoder(enc);
    return PSYNC_CRYPTO_INVALID_ENCODER;
  }
  ret=(psync_crypto_aes256_sector_encoder_decoder_t)psync_locked_malloc(offsetof(psync_crypto_aes256_enc_dec_var_iv_struct_t, iv)+key->keylen-PSYNC_AES256_KEY_SIZE);
  ret->encoder=enc;
  ret->decoder=dec;
  ret->ivlen=key->keylen-PSYNC_AES256_KEY_SIZE;
  memcpy(ret->iv, key->key+PSYNC_AES256_KEY_SIZE, ret->ivlen);
  return ret;
}

void psync_crypto_aes256_sector_encoder_decoder_free(psync_crypto_aes256_sector_encoder_decoder_t enc){
  psync_ssl_aes256_free_encoder(enc->encoder);
  psync_ssl_aes256_free_decoder(enc->decoder);
  psync_ssl_memclean(enc->iv, enc->ivlen);
  psync_locked_free(enc);
}

/*static void memcpy_const(unsigned char *dst, const unsigned char *src, uint32_t copycnt, uint32_t constcnt){
  uint32_t i, b;
  copycnt--;
  for (i=0; i<constcnt; i++){
    b=(copycnt-i)>>31;
    dst[i]=dst[i]*b+(src[i]&(b-1));
  }
}*/

static int memcmp_const(const unsigned char *s1, const unsigned char *s2, size_t cnt){
  size_t i;
  uint32_t r;
  r=0;
  for (i=0; i<cnt; i++)
    r|=s1[i]^s2[i];
  return (((r-1)>>8)&1)^1;
}

void psync_crypto_aes256_encode_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen,
                                       unsigned char *out, psync_crypto_sector_auth_t authout, uint64_t sectorid){
  psync_hmac_sha512_ctx ctx;
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3], hmacsha1bin[PSYNC_SHA512_DIGEST_LEN], rnd[PSYNC_AES256_BLOCK_SIZE];
  unsigned char *aessrc, *aesdst, *tmp;
  uint32_t needsteal;
  aessrc=ALIGN_PTR_A256_BS(buff);
  aesdst=aessrc+PSYNC_AES256_BLOCK_SIZE;
  assert(PSYNC_CRYPTO_AUTH_SIZE==2*PSYNC_AES256_BLOCK_SIZE);
  psync_ssl_rand_weak(rnd, PSYNC_AES256_BLOCK_SIZE);
  psync_hmac_sha512_init(&ctx, enc->iv, enc->ivlen);
  psync_hmac_sha512_update(&ctx, data, datalen);
  psync_hmac_sha512_update(&ctx, &sectorid, sizeof(sectorid));
  psync_hmac_sha512_update(&ctx, rnd, PSYNC_AES256_BLOCK_SIZE);
  psync_hmac_sha512_final(hmacsha1bin, &ctx);
  if (unlikely(datalen<PSYNC_AES256_BLOCK_SIZE)){
    memcpy(aessrc, rnd, PSYNC_AES256_BLOCK_SIZE);
    xor_cnt_inplace(aessrc, data, datalen);
    memcpy(out, rnd, datalen);
    memcpy(aesdst, hmacsha1bin, PSYNC_AES256_BLOCK_SIZE);
    psync_aes256_encode_2blocks_consec(enc->encoder, aessrc, aessrc);
    memcpy(authout, aessrc, PSYNC_AES256_BLOCK_SIZE*2);
    return;
  }
  if (unlikely(datalen%16)){
    needsteal=datalen%16;
    datalen-=needsteal+PSYNC_AES256_BLOCK_SIZE;
  }
  else
    needsteal=0;
  memcpy(aessrc, rnd, PSYNC_AES256_BLOCK_SIZE/2);
  memcpy(aessrc+PSYNC_AES256_BLOCK_SIZE/2, hmacsha1bin, PSYNC_AES256_BLOCK_SIZE);
  memcpy(aessrc+PSYNC_AES256_BLOCK_SIZE+PSYNC_AES256_BLOCK_SIZE/2, rnd+PSYNC_AES256_BLOCK_SIZE/2, PSYNC_AES256_BLOCK_SIZE/2);
  psync_aes256_encode_2blocks_consec(enc->encoder, aessrc, aessrc);
  memcpy(authout, aessrc, PSYNC_AES256_BLOCK_SIZE*2);
  memcpy(aessrc, hmacsha1bin, PSYNC_AES256_BLOCK_SIZE);
  if (IS_WORD_ALIGNED(data) && IS_WORD_ALIGNED(out))
    while (datalen){
      xor16_aligned_inplace(aessrc, data);
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      copy_aligned(out, aesdst);
      datalen-=PSYNC_AES256_BLOCK_SIZE;
      data+=PSYNC_AES256_BLOCK_SIZE;
      out+=PSYNC_AES256_BLOCK_SIZE;
      tmp=aessrc;
      aessrc=aesdst;
      aesdst=tmp;
    }
  else
    while (datalen){
      xor16_unaligned_inplace(aessrc, data);
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      copy_unaligned(out, aesdst);
      datalen-=PSYNC_AES256_BLOCK_SIZE;
      data+=PSYNC_AES256_BLOCK_SIZE;
      out+=PSYNC_AES256_BLOCK_SIZE;
      tmp=aessrc;
      aessrc=aesdst;
      aesdst=tmp;
    }
  if (unlikely(needsteal)){
    xor16_unaligned_inplace(aessrc, data);
    data+=PSYNC_AES256_BLOCK_SIZE;
    psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
    memcpy(out+PSYNC_AES256_BLOCK_SIZE, aesdst, needsteal);
    xor_cnt_inplace(aesdst, data, needsteal);
    psync_aes256_encode_block(enc->encoder, aesdst, aessrc);
    copy_unaligned(out, aessrc);
  }
}

int psync_crypto_aes256_decode_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen,
                                      unsigned char *out, const psync_crypto_sector_auth_t auth, uint64_t sectorid){
  psync_hmac_sha512_ctx ctx;
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*15], hmacsha1bin[PSYNC_SHA512_DIGEST_LEN];
  unsigned char *aessrc, *aesdst, *aesxor, *hmac, *oout, *tmp;
  size_t odatalen;
  uint32_t needsteal;
  aessrc=ALIGN_PTR_A256_BS(buff);
  aesdst=aessrc+PSYNC_AES256_BLOCK_SIZE*4;
  aesxor=aessrc+PSYNC_AES256_BLOCK_SIZE*8;
  hmac=aessrc+PSYNC_AES256_BLOCK_SIZE*12;
  memcpy(aessrc, auth, PSYNC_AES256_BLOCK_SIZE*2);
  psync_aes256_decode_2blocks_consec(enc->decoder, aessrc, hmac);
  oout=out;
  odatalen=datalen;
  if (unlikely(datalen<PSYNC_AES256_BLOCK_SIZE)){
    xor_cnt_inplace(hmac, data, datalen);
    memcpy(aessrc, data, datalen);
    memcpy(out, hmac, datalen);
    memcpy(hmac, aessrc, datalen);
  }
  else{
    if (unlikely(datalen%16)){
      needsteal=datalen%16;
      datalen-=needsteal+PSYNC_AES256_BLOCK_SIZE;
    }
    else
      needsteal=0;
    memcpy(aesxor, hmac+PSYNC_AES256_BLOCK_SIZE/2, PSYNC_AES256_BLOCK_SIZE);
    memcpy(hmac+PSYNC_AES256_BLOCK_SIZE/2, hmac+PSYNC_AES256_BLOCK_SIZE+PSYNC_AES256_BLOCK_SIZE/2, PSYNC_AES256_BLOCK_SIZE/2);
    memcpy(hmac+PSYNC_AES256_BLOCK_SIZE, aesxor, PSYNC_AES256_BLOCK_SIZE);
    while (datalen>=PSYNC_AES256_BLOCK_SIZE*4){
      memcpy(aessrc, data, PSYNC_AES256_BLOCK_SIZE*4);
      memcpy(aesxor+PSYNC_AES256_BLOCK_SIZE, aessrc, PSYNC_AES256_BLOCK_SIZE*3);
      psync_aes256_decode_4blocks_consec_xor(enc->decoder, aessrc, aesdst, aesxor);
      memcpy(out, aesdst, PSYNC_AES256_BLOCK_SIZE*4);
      memcpy(aesxor, aessrc+PSYNC_AES256_BLOCK_SIZE*3, PSYNC_AES256_BLOCK_SIZE);
      datalen-=PSYNC_AES256_BLOCK_SIZE*4;
      data+=PSYNC_AES256_BLOCK_SIZE*4;
      out+=PSYNC_AES256_BLOCK_SIZE*4;
    }
    while (datalen){
      copy_unaligned(aessrc, data);
      psync_aes256_decode_block(enc->decoder, aessrc, aesdst);
      xor16_aligned_inplace(aesdst, aesxor);
      copy_unaligned(out, aesdst);
      data+=PSYNC_AES256_BLOCK_SIZE;
      out+=PSYNC_AES256_BLOCK_SIZE;
      datalen-=PSYNC_AES256_BLOCK_SIZE;
      tmp=aesxor;
      aesxor=aessrc;
      aessrc=tmp;
    }
    if (unlikely(needsteal)){
      copy_unaligned(aessrc, data);
      psync_aes256_decode_block(enc->decoder, aessrc, aesdst);
      xor_cnt_inplace(aesdst, data+PSYNC_AES256_BLOCK_SIZE, needsteal);
      // can be done with less memcpy's, but this version supports inline decoding (e.g. data==out)
      memcpy(aessrc, data+PSYNC_AES256_BLOCK_SIZE, needsteal);
      memcpy(out+PSYNC_AES256_BLOCK_SIZE, aesdst, needsteal);
      memcpy(aesdst, aessrc, needsteal);
      psync_aes256_decode_block(enc->decoder, aesdst, aessrc);
      xor16_aligned_inplace(aessrc, aesxor);
      copy_unaligned(out, aessrc);
    }
  }
  psync_hmac_sha512_init(&ctx, enc->iv, enc->ivlen);
  psync_hmac_sha512_update(&ctx, oout, odatalen);
  psync_hmac_sha512_update(&ctx, &sectorid, sizeof(sectorid));
  psync_hmac_sha512_update(&ctx, hmac, PSYNC_AES256_BLOCK_SIZE);
  psync_hmac_sha512_final(hmacsha1bin, &ctx);
  return -memcmp_const(hmacsha1bin, hmac+PSYNC_AES256_BLOCK_SIZE, PSYNC_AES256_BLOCK_SIZE);
}

/* the following is CTR based implementation of encode/decode sector

static uint32_t psync_crypto_get_time_32(){
  struct timespec tm;
  psync_nanotime(&tm);
  return ((tm.tv_sec&0xfffffff)<<4)+tm.tv_nsec/((999999999+15)/16);
}

void psync_crypto_aes256_encode_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen,
                                       unsigned char *out, psync_crypto_sector_auth_t authout, uint64_t sectorid){
  psync_hmac_sha512_ctx ctx;
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3], hmacsha1bin[PSYNC_SHA512_DIGEST_LEN];
  unsigned char *aessrc, *aesdst;
  uint64_t *ctr;
  uint32_t u32time;
  u32time=psync_crypto_get_time_32();
  psync_hmac_sha512_init(&ctx, enc->iv, enc->ivlen);
  psync_hmac_sha512_update(&ctx, data, datalen);
  psync_hmac_sha512_update(&ctx, &sectorid, sizeof(sectorid));
  psync_hmac_sha512_update(&ctx, &u32time, sizeof(uint32_t));
  psync_hmac_sha512_final(hmacsha1bin, &ctx);
  aessrc=ALIGN_PTR_A256_BS(buff);
  aesdst=aessrc+PSYNC_AES256_BLOCK_SIZE;
  memcpy(aessrc+sizeof(uint32_t), hmacsha1bin, PSYNC_AES256_BLOCK_SIZE-sizeof(uint32_t));
  memcpy(aessrc, &u32time, sizeof(uint32_t));
  psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
  memcpy(authout, aesdst, PSYNC_AES256_BLOCK_SIZE);
  /-* Now this is slightly complicated. AES is used in CTR mode here, Sectors are by design 4096 bytes, so 256 AES blocks.
   * What we give to the AES as input is: 88 bits from the data hmac, one of those bits inverted, so there is no chance
   * that the rest of the bits get to be the same as the hmac+time in which case we could end up xor-ing plaintext with
   * the same value as authout. 32 more bits are reserved for sectorid and 8 bits for counter inside the sector. Effectively
   * this means that every AES block will be xor-ed with different value within the first 16Tb of the file (which will be too
   * big for quite some time, 16Tb=2^40*AES_BLOCK_SIZE).
   *-/
  ctr=(uint64_t *)aessrc;
  *ctr=(((*ctr)&0xffffff0000000000ULL)+((sectorid&0xffffffffUL)<<8))^0x10000000000ULL;
  if (IS_WORD_ALIGNED(data) && IS_WORD_ALIGNED(out)){
    while (datalen>=PSYNC_AES256_BLOCK_SIZE){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      (*ctr)++;
      xor16_aligned_inplace(aesdst, data);
      data+=PSYNC_AES256_BLOCK_SIZE;
      datalen-=PSYNC_AES256_BLOCK_SIZE;
      copy_aligned(out, aesdst);
      out+=PSYNC_AES256_BLOCK_SIZE;
    }
    if (datalen){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      xor_cnt_inplace(aesdst, data, datalen);
      memcpy(out, aesdst, datalen);
    }
  }
  else{
    while (datalen>=PSYNC_AES256_BLOCK_SIZE){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      (*ctr)++;
      xor16_unaligned_inplace(aesdst, data);
      data+=PSYNC_AES256_BLOCK_SIZE;
      datalen-=PSYNC_AES256_BLOCK_SIZE;
      copy_unaligned(out, aesdst);
      out+=PSYNC_AES256_BLOCK_SIZE;
    }
    if (datalen){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      xor_cnt_inplace(aesdst, data, datalen);
      memcpy(out, aesdst, datalen);
    }
  }
}

int psync_crypto_aes256_decode_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen,
                                      unsigned char *out, const psync_crypto_sector_auth_t auth, uint64_t sectorid){
  psync_hmac_sha512_ctx ctx;
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*4], hmacsha1bin[PSYNC_SHA512_DIGEST_LEN];
  unsigned char *aessrc, *aesdst, *hmac, *oout;
  uint64_t *ctr;
  size_t odatalen;
  aessrc=ALIGN_PTR_A256_BS(buff);
  aesdst=aessrc+PSYNC_AES256_BLOCK_SIZE;
  hmac=aessrc+PSYNC_AES256_BLOCK_SIZE*2;
  memcpy(aessrc, auth, PSYNC_AES256_BLOCK_SIZE);
  psync_aes256_decode_block(enc->decoder, aessrc, hmac);
  oout=out;
  odatalen=datalen;
  memcpy(aessrc, hmac, PSYNC_AES256_BLOCK_SIZE);
  ctr=(uint64_t *)aessrc;
  *ctr=(((*ctr)&0xffffff0000000000ULL)+((sectorid&0xffffffffUL)<<8))^0x10000000000ULL;
  if (IS_WORD_ALIGNED(data) && IS_WORD_ALIGNED(out)){
    while (datalen>=PSYNC_AES256_BLOCK_SIZE){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      (*ctr)++;
      xor16_aligned_inplace(aesdst, data);
      data+=PSYNC_AES256_BLOCK_SIZE;
      datalen-=PSYNC_AES256_BLOCK_SIZE;
      copy_aligned(out, aesdst);
      out+=PSYNC_AES256_BLOCK_SIZE;
    }
    if (datalen){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      xor_cnt_inplace(aesdst, data, datalen);
      memcpy(out, aesdst, datalen);
    }
  }
  else{
    while (datalen>=PSYNC_AES256_BLOCK_SIZE){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      (*ctr)++;
      xor16_unaligned_inplace(aesdst, data);
      data+=PSYNC_AES256_BLOCK_SIZE;
      datalen-=PSYNC_AES256_BLOCK_SIZE;
      copy_unaligned(out, aesdst);
      out+=PSYNC_AES256_BLOCK_SIZE;
    }
    if (datalen){
      psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
      xor_cnt_inplace(aesdst, data, datalen);
      memcpy(out, aesdst, datalen);
    }
  }
  psync_hmac_sha512_init(&ctx, enc->iv, enc->ivlen);
  psync_hmac_sha512_update(&ctx, oout, odatalen);
  psync_hmac_sha512_update(&ctx, &sectorid, sizeof(sectorid));
  psync_hmac_sha512_update(&ctx, hmac, sizeof(uint32_t));
  psync_hmac_sha512_final(hmacsha1bin, &ctx);
  return -memcmp_const(hmacsha1bin, hmac+sizeof(uint32_t), PSYNC_AES256_BLOCK_SIZE-sizeof(uint32_t));
}

*/

void psync_crypto_sign_auth_sector(psync_crypto_aes256_sector_encoder_decoder_t enc, const unsigned char *data, size_t datalen, psync_crypto_sector_auth_t authout){
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3+PSYNC_SHA512_DIGEST_LEN];
  unsigned char *aessrc, *aesdst;
  aesdst=ALIGN_PTR_A256_BS(buff);
  aessrc=aesdst+PSYNC_AES256_BLOCK_SIZE*2;
  psync_hmac_sha512(data, datalen, enc->iv, enc->ivlen, aessrc);
  psync_aes256_encode_2blocks_consec(enc->encoder, aessrc, aesdst);
  memcpy(authout, aesdst, PSYNC_AES256_BLOCK_SIZE*2);
}
