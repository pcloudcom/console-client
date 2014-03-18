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

static void psync_hmac_sha1(const unsigned char *msg, size_t msglen, const unsigned char *key, size_t keylen, unsigned char *result){
  psync_sha1_ctx sha1ctx;
  unsigned char keyxor[64], final[84];
  size_t i;
  if (keylen>64)
    keylen=64;
  memset(keyxor, 0x36, 64);
  memset(final, 0x5c, 64);
  for (i=0; i<keylen; i++){
    keyxor[i]^=key[i];
    final[i]^=key[i];
  }
  psync_sha1_init(&sha1ctx);
  psync_sha1_update(&sha1ctx, keyxor, 64);
  psync_sha1_update(&sha1ctx, msg, msglen);
  psync_sha1_final(final+64, &sha1ctx);
  psync_sha1(final, 84, result);
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
  ret=psync_new(psync_crypto_aes256_key_struct_t);
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

/*
 * public domain SipHash implementation from:
 * https://131002.net/siphash/siphash24.c
 * 
 * Written in 2012 by 
 * Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
 * Daniel J. Bernstein <djb@cr.yp.to>
 * 
 */

#define SIP_HASH_DIGEST_LEN 8

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

#define ROTL(x,b) (u64)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define U32TO8_LE(p, v)         \
    (p)[0] = (u8)((v)      ); (p)[1] = (u8)((v) >>  8); \
    (p)[2] = (u8)((v) >> 16); (p)[3] = (u8)((v) >> 24);

#define U64TO8_LE(p, v)         \
  U32TO8_LE((p),     (u32)((v)      ));   \
  U32TO8_LE((p) + 4, (u32)((v) >> 32));

#define U8TO64_LE(p) \
  (((u64)((p)[0])      ) | \
   ((u64)((p)[1]) <<  8) | \
   ((u64)((p)[2]) << 16) | \
   ((u64)((p)[3]) << 24) | \
   ((u64)((p)[4]) << 32) | \
   ((u64)((p)[5]) << 40) | \
   ((u64)((p)[6]) << 48) | \
   ((u64)((p)[7]) << 56))

#define SIPROUND            \
  do {              \
    v0 += v1; v1=ROTL(v1,13); v1 ^= v0; v0=ROTL(v0,32); \
    v2 += v3; v3=ROTL(v3,16); v3 ^= v2;     \
    v0 += v3; v3=ROTL(v3,21); v3 ^= v0;     \
    v2 += v1; v1=ROTL(v1,17); v1 ^= v2; v2=ROTL(v2,32); \
  } while(0)

int siphash(unsigned char *out, const unsigned char *in, unsigned long inlen, const unsigned char *k)
{
  /* "somepseudorandomlygeneratedbytes" */
  u64 v0 = 0x736f6d6570736575ULL;
  u64 v1 = 0x646f72616e646f6dULL;
  u64 v2 = 0x6c7967656e657261ULL;
  u64 v3 = 0x7465646279746573ULL;
  u64 b;
  u64 k0 = U8TO64_LE( k );
  u64 k1 = U8TO64_LE( k + 8 );
  u64 m;
  const u8 *end = in + inlen - ( inlen % sizeof( u64 ) );
  const int left = inlen & 7;
  b = ( ( u64 )inlen ) << 56;
  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

  for ( ; in != end; in += 8 )
  {
    m = U8TO64_LE( in );
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;
  }

  switch( left )
  {
  case 7: b |= ( ( u64 )in[ 6] )  << 48;

  case 6: b |= ( ( u64 )in[ 5] )  << 40;

  case 5: b |= ( ( u64 )in[ 4] )  << 32;

  case 4: b |= ( ( u64 )in[ 3] )  << 24;

  case 3: b |= ( ( u64 )in[ 2] )  << 16;

  case 2: b |= ( ( u64 )in[ 1] )  <<  8;

  case 1: b |= ( ( u64 )in[ 0] ); break;

  case 0: break;
  }
  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;
  v2 ^= 0xff;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  b = v0 ^ v1 ^ v2  ^ v3;
  U64TO8_LE( out, b );
  return 0;
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
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3+PSYNC_SHA1_DIGEST_LEN], *aessrc, *aesdst, *outptr, *hmac;
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
    psync_aes256_encode_block(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    return;
  }
  psync_hmac_sha1(txt+PSYNC_AES256_BLOCK_SIZE, txtlen-PSYNC_AES256_BLOCK_SIZE, enc->iv, PSYNC_AES256_BLOCK_SIZE, hmac);
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
  unsigned char buff[PSYNC_AES256_BLOCK_SIZE*3], *aessrc, *aesdst, *outptr, *ret;
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
  psync_hmac_sha1(ret+PSYNC_AES256_BLOCK_SIZE, len, enc->iv, PSYNC_AES256_BLOCK_SIZE, aessrc);
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

void psync_crypto_aes256_text_encoder_free(psync_crypto_aes256_text_encoder_t enc){
  psync_ssl_aes256_free_encoder(enc->encoder);
  memset(enc->iv, 0, PSYNC_AES256_BLOCK_SIZE);
}

psync_crypto_aes256_text_decoder_t psync_crypto_aes256_text_decoder_create(psync_symmetric_key_t key){
  psync_aes256_encoder enc;
  psync_crypto_aes256_ctr_encoder_decoder_t ret;
  if (unlikely_log(key->keylen<PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc=psync_ssl_aes256_create_decoder(key);
  if (unlikely_log(enc==PSYNC_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret=psync_new(psync_crypto_aes256_key_struct_t);
  ret->encoder=enc;
  memcpy(ret->iv, key->key+PSYNC_AES256_KEY_SIZE, PSYNC_AES256_BLOCK_SIZE);
  return ret;
}

void psync_crypto_aes256_text_decoder_free(psync_crypto_aes256_text_decoder_t enc){
  psync_ssl_aes256_free_decoder(enc->encoder);
  memset(enc->iv, 0, PSYNC_AES256_BLOCK_SIZE);
}
