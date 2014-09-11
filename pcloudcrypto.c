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
#include "pnetlibs.h"
#include "pssl.h"
#include "pcrypto.h"
#include "papi.h"
#include "pcloudcrypto.h"
#include "psettings.h"
#include <string.h>

static uint32_t crypto_started_l=0;
static psync_rsa_publickey_t crypto_pubkey=PSYNC_INVALID_RSA;
static psync_rsa_privatekey_t crypto_privkey=PSYNC_INVALID_RSA;
static pthread_rwlock_t crypto_lock=PTHREAD_RWLOCK_INITIALIZER;
static uint32_t crypto_started_un=0;

typedef struct {
  uint32_t type;
  uint32_t flags;
  unsigned char salt[PSYNC_CRYPTO_PBKDF2_SALT_LEN];
  unsigned char key[];
} priv_key_ver1;

typedef struct {
  uint32_t type;
  uint32_t flags;
  unsigned char key[];
} pub_key_ver1;

static void psync_cloud_crypto_setup_save_to_db(const unsigned char *rsapriv, size_t rsaprivlen, const unsigned char *rsapub, size_t rsapublen,
                                                const unsigned char *salt, size_t saltlen, size_t iterations){
  psync_sql_res *res;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_start_transaction();
  psync_sql_bind_string(res, 1, "crypto_private_key");
  psync_sql_bind_blob(res, 2, (const char *)rsapriv, rsaprivlen);
  psync_sql_run(res);
  psync_sql_bind_string(res, 1, "crypto_public_key");
  psync_sql_bind_blob(res, 2, (const char *)rsapub, rsapublen);
  psync_sql_run(res);
  psync_sql_bind_string(res, 1, "crypto_private_salt");
  psync_sql_bind_blob(res, 2, (const char *)salt, saltlen);
  psync_sql_run(res);
  psync_sql_bind_string(res, 1, "crypto_private_iter");
  psync_sql_bind_uint(res, 2, iterations);
  psync_sql_run_free(res);
  psync_sql_commit_transaction();
}

static int psync_cloud_crypto_setup_do_upload(const unsigned char *rsapriv, size_t rsaprivlen, const unsigned char *rsapub, size_t rsapublen){
  binparam params[]={P_STR("auth", psync_my_auth), P_LSTR("privatekey", rsapriv, rsaprivlen), P_LSTR("publickey", rsapub, rsapublen)};
  psync_socket *api;
  binresult *res;
  uint64_t result;
  int tries;
  tries=0;
  debug(D_NOTICE, "uploading keys");
  do {
    api=psync_apipool_get();
    if (!api)
      return PSYNC_CRYPTO_SETUP_CANT_CONNECT;
    res=send_command(api, "crypto_setuserkeys", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries<=5)
        continue;
      else
        return PSYNC_CRYPTO_SETUP_CANT_CONNECT;
    }
    else
      psync_apipool_release(api);
  } while (0);
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  if (result!=0)
    debug(D_WARNING, "crypto_setuserkeys returned %u", (unsigned)result);
  switch (result){
    case 0: return PSYNC_CRYPTO_SETUP_SUCCESS;
    case 1000: return PSYNC_CRYPTO_SETUP_NOT_LOGGED_IN;
    case 2110: return PSYNC_CRYPTO_SETUP_ALREADY_SETUP;
  }
  return PSYNC_CRYPTO_SETUP_UNKNOWN_ERROR;
}

static int psync_cloud_crypto_setup_upload(const unsigned char *rsapriv, size_t rsaprivlen, const unsigned char *rsapub, size_t rsapublen, const unsigned char *salt){
  priv_key_ver1 *priv;
  pub_key_ver1 *pub;
  unsigned char *b64priv, *b64pub; 
  size_t b64privlen, b64publen;
  int ret;
  priv=(priv_key_ver1 *)psync_malloc(offsetof(priv_key_ver1, key)+rsaprivlen);
  priv->type=PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
  priv->flags=0;
  memcpy(priv->salt, salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
  memcpy(priv->key, rsapriv, rsaprivlen);
  pub=(pub_key_ver1 *)psync_malloc(offsetof(pub_key_ver1, key)+rsapublen);
  pub->type=PSYNC_CRYPTO_PUB_TYPE_RSA4096;
  pub->flags=0;
  memcpy(pub->key, rsapub, rsapublen);
  b64priv=psync_base64_encode((unsigned char *)priv, offsetof(priv_key_ver1, key)+rsaprivlen, &b64privlen);
  b64pub=psync_base64_encode((unsigned char *)pub, offsetof(pub_key_ver1, key)+rsapublen, &b64publen);
  psync_free(priv);
  psync_free(pub);
  ret=psync_cloud_crypto_setup_do_upload(b64priv, b64privlen, b64pub, b64publen);
  psync_free(b64priv);
  psync_free(b64pub);
  return ret;
}

/* 
 * generate 64 byte (512 bit) salt for PBKDF2 
 * generate AES key and IV with PBKDF2
 * create RSA key and encrypt private part using CTR mode
 * upload to server salt, encrypted private and public
 * 
 */

int psync_cloud_crypto_setup(const char *password){
  unsigned char salt[PSYNC_CRYPTO_PBKDF2_SALT_LEN];
  psync_symmetric_key_t aeskey;
  psync_crypto_aes256_ctr_encoder_decoder_t enc;
  psync_rsa_t rsa;
  psync_rsa_privatekey_t rsaprivate;
  psync_rsa_publickey_t rsapublic;
  psync_binary_rsa_key_t rsaprivatebin, rsapublicbin;
  int ret;
  debug(D_NOTICE, "generating salt");
  psync_ssl_rand_strong(salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
  debug(D_NOTICE, "generating AES key from password and setting up encoder");
  aeskey=psync_ssl_gen_symmetric_key_from_pass(password, PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE, 
                                               salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS);
  enc=psync_crypto_aes256_ctr_encoder_decoder_create(aeskey);
  psync_ssl_free_symmetric_key(aeskey);
  if (unlikely(enc==PSYNC_CRYPTO_INVALID_ENCODER)){
    debug(D_WARNING, "psync_crypto_aes256_ctr_encoder_decoder_create failed");
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  }
  debug(D_NOTICE, "generating %d bit RSA key", (int)PSYNC_CRYPTO_RSA_SIZE);
  rsa=psync_ssl_gen_rsa(PSYNC_CRYPTO_RSA_SIZE);
  if (unlikely(rsa==PSYNC_INVALID_RSA)){
    debug(D_WARNING, "RSA key generation failed");
    psync_crypto_aes256_ctr_encoder_decoder_free(enc);
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  }
  else
    debug(D_NOTICE, "RSA key generated");
  rsaprivate=psync_ssl_rsa_get_private(rsa);
  rsapublic=psync_ssl_rsa_get_public(rsa);
  psync_ssl_free_rsa(rsa);
  if (unlikely(rsaprivate==PSYNC_INVALID_RSA || rsapublic==PSYNC_INVALID_RSA)){
    debug(D_WARNING, "psync_ssl_rsa_get_private or psync_ssl_rsa_get_public failed");
    if (rsaprivate!=PSYNC_INVALID_RSA)
      psync_ssl_rsa_free_private(rsaprivate);
    if (rsapublic!=PSYNC_INVALID_RSA)
      psync_ssl_rsa_free_public(rsapublic);
    psync_crypto_aes256_ctr_encoder_decoder_free(enc);
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  }
  rsaprivatebin=psync_ssl_rsa_private_to_binary(rsaprivate);
  rsapublicbin=psync_ssl_rsa_public_to_binary(rsapublic);
  psync_ssl_rsa_free_private(rsaprivate);
  psync_ssl_rsa_free_public(rsapublic);
  if (unlikely(rsaprivatebin==PSYNC_INVALID_BIN_RSA || rsaprivatebin==PSYNC_INVALID_BIN_RSA)){
    debug(D_WARNING, "psync_ssl_rsa_private_to_binary or psync_ssl_rsa_public_to_binary failed");
    if (rsaprivatebin!=PSYNC_INVALID_BIN_RSA)
      psync_ssl_rsa_free_binary(rsaprivatebin);
    if (rsapublicbin!=PSYNC_INVALID_BIN_RSA)
      psync_ssl_rsa_free_binary(rsapublicbin);
    psync_crypto_aes256_ctr_encoder_decoder_free(enc);
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  }
  debug(D_NOTICE, "encoding private key");
  psync_crypto_aes256_ctr_encode_decode_inplace(enc, rsaprivatebin->data, rsaprivatebin->datalen, 0);
  psync_crypto_aes256_ctr_encoder_decoder_free(enc);
  debug(D_NOTICE, "encoded private key, uploading keys");
  ret=psync_cloud_crypto_setup_upload(rsaprivatebin->data, rsaprivatebin->datalen, rsapublicbin->data, rsapublicbin->datalen, salt);
  if (unlikely(ret!=PSYNC_CRYPTO_SETUP_SUCCESS)){
    debug(D_WARNING, "keys upload failed with error %d", ret);
    psync_ssl_rsa_free_binary(rsaprivatebin);
    psync_ssl_rsa_free_binary(rsapublicbin);
    return ret;
  }
  debug(D_NOTICE, "keys uploaded");
  psync_cloud_crypto_setup_save_to_db(rsaprivatebin->data, rsaprivatebin->datalen, rsapublicbin->data, rsapublicbin->datalen,
                                      salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS);
  psync_ssl_rsa_free_binary(rsaprivatebin);
  psync_ssl_rsa_free_binary(rsapublicbin);
  return PSYNC_CRYPTO_SETUP_SUCCESS;
}

static int psync_cloud_crypto_download_keys(unsigned char **rsapriv, size_t *rsaprivlen, unsigned char **rsapub, size_t *rsapublen,
                                            unsigned char **salt, size_t *saltlen, size_t *iterations){
  binparam params[]={P_STR("auth", psync_my_auth)};
  psync_socket *api;
  binresult *res;
  const binresult *data;
  unsigned char *rsaprivstruct, *rsapubstruct;
  uint64_t result;
  size_t rsaprivstructlen, rsapubstructlen;
  int tries;
  tries=0;
  debug(D_NOTICE, "dowloading keys");
  do {
    api=psync_apipool_get();
    if (!api)
      return PSYNC_CRYPTO_START_CANT_CONNECT;
    res=send_command(api, "crypto_getuserkeys", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries<=5)
        continue;
      else
        return PSYNC_CRYPTO_START_CANT_CONNECT;
    }
    else
      psync_apipool_release(api);
  } while (0);
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    psync_free(res);
    switch (result){
      case 2111: return PSYNC_CRYPTO_START_NOT_SETUP;
      case 1000: return PSYNC_CRYPTO_START_NOT_LOGGED_IN;
    }
    return PSYNC_CRYPTO_START_UNKNOWN_ERROR;
  }
  data=psync_find_result(res, "privatekey", PARAM_STR);
  rsaprivstruct=psync_base64_decode((const unsigned char *)data->str, data->length, &rsaprivstructlen);
  data=psync_find_result(res, "publickey", PARAM_STR);
  rsapubstruct=psync_base64_decode((const unsigned char *)data->str, data->length, &rsapubstructlen);
  psync_free(res);
  switch (*((uint32_t *)rsapubstruct)){
    case PSYNC_CRYPTO_PUB_TYPE_RSA4096:
      if (offsetof(pub_key_ver1, key)>=rsapubstructlen)
        goto def1;
      *rsapublen=rsapubstructlen-offsetof(pub_key_ver1, key);
      *rsapub=(unsigned char *)psync_malloc(*rsapublen);
      memcpy(*rsapub, rsapubstruct+offsetof(pub_key_ver1, key), *rsapublen);
      break;
    default:
      def1:
      psync_free(rsaprivstruct);
      psync_free(rsapubstruct);
      return PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT;
  }
  switch (*((uint32_t *)rsaprivstruct)){
    case PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT:
      if (offsetof(priv_key_ver1, key)>=rsaprivstructlen)
        goto def2;
      *rsaprivlen=rsaprivstructlen-offsetof(priv_key_ver1, key);
      *rsapriv=(unsigned char *)psync_malloc(*rsaprivlen);
      memcpy(*rsapriv, rsaprivstruct+offsetof(priv_key_ver1, key), *rsaprivlen);
      *saltlen=PSYNC_CRYPTO_PBKDF2_SALT_LEN;
      *salt=(unsigned char *)psync_malloc(PSYNC_CRYPTO_PBKDF2_SALT_LEN);
      memcpy(*salt, rsaprivstruct+offsetof(priv_key_ver1, salt), PSYNC_CRYPTO_PBKDF2_SALT_LEN);
      *iterations=PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS;
      break;
    default:
      def2:
      psync_free(*rsapub);
      psync_free(rsaprivstruct);
      psync_free(rsapubstruct);
      return PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT;
  }
  psync_free(rsaprivstruct);
  psync_free(rsapubstruct);
  return PSYNC_CRYPTO_START_SUCCESS;
}

static int crypto_keys_match(){
  psync_symmetric_key_t key, deckey;
  psync_encrypted_symmetric_key_t enckey;
  int res;
  debug(D_NOTICE, "trying encrypt/decrypt operation with loaded keys");
  key=(psync_symmetric_key_t)psync_malloc(offsetof(psync_symmetric_key_struct_t, key)+64);
  key->keylen=64;
  psync_ssl_rand_weak(key->key, key->keylen);
  enckey=psync_ssl_rsa_encrypt_symmetric_key(crypto_pubkey, key);
  if (enckey==PSYNC_INVALID_ENC_SYM_KEY){
    psync_ssl_free_symmetric_key(key);
    return 0;
  }
  deckey=psync_ssl_rsa_decrypt_symmetric_key(crypto_privkey, enckey);
  psync_free(enckey);
  if (deckey==PSYNC_INVALID_SYM_KEY){
    psync_ssl_free_symmetric_key(key);
    return 0;
  }
  res=key->keylen==deckey->keylen && !memcmp(key->key, deckey->key, key->keylen);
  psync_ssl_free_symmetric_key(deckey);
  psync_ssl_free_symmetric_key(key);
  if (res)
    debug(D_NOTICE, "encrypt/decrypt operation succeeded");
  return res;
}

static void load_str_to(const psync_variant *v, unsigned char **ptr, size_t *len){
  const char *str;
  size_t l;
  str=psync_get_lstring(*v, &l);
  *ptr=(unsigned char *)psync_malloc(l);
  memcpy(*ptr, str, l);
  *len=l;
}

int psync_cloud_crypto_start(const char *password){
  psync_sql_res *res;
  psync_variant_row row;
  const char *id;
  unsigned char *rsapriv, *rsaprivdec, *rsapub, *salt;
  size_t iterations, rsaprivlen, rsapublen, saltlen;
  psync_symmetric_key_t aeskey;
  psync_crypto_aes256_ctr_encoder_decoder_t enc;
  uint32_t rowcnt;
  int ret;
  pthread_rwlock_wrlock(&crypto_lock);
  if (crypto_started_l){
    pthread_rwlock_unlock(&crypto_lock);
    return PSYNC_CRYPTO_START_ALREADY_STARTED;
  }
  rowcnt=0;
  rsapriv=rsapub=salt=NULL;
  iterations=0;
  res=psync_sql_query("SELECT id, value FROM setting WHERE id IN ('crypto_private_key', 'crypto_public_key', 'crypto_private_salt', 'crypto_private_iter')");
  while ((row=psync_sql_fetch_row(res))){
    id=psync_get_string(row[0]);
    rowcnt++;
    if (!strcmp(id, "crypto_private_key"))
      load_str_to(&row[1], &rsapriv, &rsaprivlen);
    else if (!strcmp(id, "crypto_public_key"))
      load_str_to(&row[1], &rsapub, &rsapublen);
    else if (!strcmp(id, "crypto_private_salt"))
      load_str_to(&row[1], &salt, &saltlen);
    else{
      assert(!strcmp(id, "crypto_private_iter"));
      iterations=atoi(psync_get_string(row[1]));
    }
  }
  psync_sql_free_result(res);
  if (rowcnt<4){
    if (unlikely(rowcnt!=0)){
      debug(D_BUG, "only some of records found in the database, should not happen");
      psync_free(rsapriv);
      psync_free(rsapub);
      psync_free(salt);
    }
    ret=psync_cloud_crypto_download_keys(&rsapriv, &rsaprivlen, &rsapub, &rsapublen, &salt, &saltlen, &iterations);
    if (ret!=PSYNC_CRYPTO_START_SUCCESS){
      pthread_rwlock_unlock(&crypto_lock);
      debug(D_WARNING, "downloading key failed, error %d", ret);
      return ret;
    }
    else
      debug(D_NOTICE, "dowloaded keys");
  }
  else{
    debug(D_NOTICE, "got keys from the database");
    assert(rowcnt==4);
  }
  crypto_pubkey=psync_ssl_rsa_load_public(rsapub, rsapublen);
  if (crypto_pubkey==PSYNC_INVALID_RSA){
    pthread_rwlock_unlock(&crypto_lock);
    debug(D_WARNING, "could not load public key");
    psync_free(rsapriv);
    psync_free(rsapub);
    psync_free(salt);
    return PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT;
  }
  aeskey=psync_ssl_gen_symmetric_key_from_pass(password, PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE, salt, saltlen, iterations);
  enc=psync_crypto_aes256_ctr_encoder_decoder_create(aeskey);
  psync_ssl_free_symmetric_key(aeskey);
  rsaprivdec=(unsigned char *)psync_malloc(rsaprivlen);
  memcpy(rsaprivdec, rsapriv, rsaprivlen);
  psync_crypto_aes256_ctr_encode_decode_inplace(enc, rsaprivdec, rsaprivlen, 0);
  psync_crypto_aes256_ctr_encoder_decoder_free(enc);
  crypto_privkey=psync_ssl_rsa_load_private(rsaprivdec, rsaprivlen);
  psync_ssl_memclean(rsaprivdec, rsaprivlen);
  psync_free(rsaprivdec);
  if (crypto_privkey==PSYNC_INVALID_RSA){
    psync_ssl_rsa_free_public(crypto_pubkey);
    crypto_pubkey=PSYNC_INVALID_RSA;
    pthread_rwlock_unlock(&crypto_lock);
    debug(D_NOTICE, "bad password");
    psync_free(rsapriv);
    psync_free(rsapub);
    psync_free(salt);
    return PSYNC_CRYPTO_START_BAD_PASSWORD;
  }
  if (!crypto_keys_match()){
    psync_ssl_rsa_free_public(crypto_pubkey);
    crypto_pubkey=PSYNC_INVALID_RSA;
    psync_ssl_rsa_free_private(crypto_privkey);
    crypto_privkey=PSYNC_INVALID_RSA;
    pthread_rwlock_unlock(&crypto_lock);
    debug(D_ERROR, "keys don't match");
    psync_free(rsapriv);
    psync_free(rsapub);
    psync_free(salt);
    return PSYNC_CRYPTO_START_KEYS_DONT_MATCH;
  }  
  crypto_started_l=1;
  pthread_rwlock_unlock(&crypto_lock);
  crypto_started_un=1;
  if (rowcnt<4)
    psync_cloud_crypto_setup_save_to_db(rsapriv, rsaprivlen, rsapub, rsapublen, salt, saltlen, iterations);
  psync_free(rsapriv);
  psync_free(rsapub);
  psync_free(salt);
  debug(D_NOTICE, "crypto successfully started");
  return PSYNC_CRYPTO_START_SUCCESS;
}

int psync_cloud_crypto_stop(){
  crypto_started_un=0;
  pthread_rwlock_wrlock(&crypto_lock);
  if (!crypto_started_l){
    pthread_rwlock_unlock(&crypto_lock);
    return PSYNC_CRYPTO_STOP_NOT_STARTED;
  }
  crypto_started_l=0;
  psync_ssl_rsa_free_public(crypto_pubkey);
  crypto_pubkey=PSYNC_INVALID_RSA;
  psync_ssl_rsa_free_private(crypto_privkey);
  crypto_privkey=PSYNC_INVALID_RSA;
  pthread_rwlock_unlock(&crypto_lock);
  pthread_rwlock_unlock(&crypto_lock);
  debug(D_NOTICE, "stopped crypto");
  return PSYNC_CRYPTO_STOP_SUCCESS;
}

int psync_cloud_crypto_isstarted(){
  int ret;
  pthread_rwlock_rdlock(&crypto_lock);
  ret=crypto_started_l;
  pthread_rwlock_unlock(&crypto_lock);
  return ret;
}
