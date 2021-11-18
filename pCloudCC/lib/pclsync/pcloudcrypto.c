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
#include "pfolder.h"
#include "pcache.h"
#include "pfileops.h"
#include "pmemlock.h"
#include "pstatus.h"
#include <string.h>
#include "pdiff.h"
#define PSYNC_CRYPTO_API_ERR_INTERNAL -511

static PSYNC_THREAD int crypto_api_errno;
static PSYNC_THREAD char crypto_api_err[128];


static const char *crypto_errors[]={
  "Success.",
  "Encryption is not started.",
  "Unexpected RSA encryption error.",
  "Folder not found.",
  "Invalid key.",
  "Can not connect to server.",
  "Folder is not encrypted."
};

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

typedef struct {
  uint32_t type;
  uint32_t flags;
  unsigned char aeskey[PSYNC_AES256_KEY_SIZE];
  unsigned char hmackey[PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN];
} sym_key_ver1;

void sha1_hex_null_term(const void *data, size_t len, char *out);

void psync_cloud_crypto_clean_cache(){
  const char *prefixes[]={"DKEY", "FKEY", "FLDE", "FLDD", "SEEN"};
  psync_cache_clean_starting_with_one_of(prefixes, ARRAY_SIZE(prefixes));
}

static void psync_cloud_crypto_setup_save_to_db(const unsigned char *rsapriv, size_t rsaprivlen, const unsigned char *rsapub, size_t rsapublen,
                                                const unsigned char *salt, size_t saltlen, size_t iterations, time_t expires,
                                                const char *publicsha1, const char *privatesha1, uint32_t flags){
  psync_sql_res *res;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_start_transaction();
  psync_sql_bind_string(res, 1, "cryptosetup");
  psync_sql_bind_uint(res, 2, 1);
  psync_sql_run(res);
  if (expires){
    psync_sql_bind_string(res, 1, "cryptoexpires");
    psync_sql_bind_uint(res, 2, expires);
    psync_sql_run(res);
  }
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
  psync_sql_run(res);
  psync_sql_bind_string(res, 1, "crypto_public_sha1");
  psync_sql_bind_string(res, 2, publicsha1);
  psync_sql_run(res);
  psync_sql_bind_string(res, 1, "crypto_private_sha1");
  psync_sql_bind_string(res, 2, privatesha1);
  psync_sql_run(res);
  psync_sql_bind_string(res, 1, "crypto_private_flags");
  psync_sql_bind_uint(res, 2, flags);
  psync_sql_run_free(res);
  psync_sql_commit_transaction();
}

static int psync_cloud_crypto_setup_do_upload(const unsigned char *rsapriv, size_t rsaprivlen, const unsigned char *rsapub, size_t rsapublen,
                                              const char *hint, time_t *cryptoexpires){
  binparam params[]={P_STR("auth", psync_my_auth), P_LSTR("privatekey", rsapriv, rsaprivlen), P_LSTR("publickey", rsapub, rsapublen),
                     P_STR("hint", hint), P_STR("timeformat", "timestamp")};
  psync_socket *api;
  binresult *res;
  uint64_t result;
  int tries;
  tries=0;
  debug(D_NOTICE, "uploading keys");
  while (1){
    api=psync_apipool_get();
    if (!api)
      return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
    res=send_command(api, "crypto_setuserkeys", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries>5)
        return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
    }
    else{
      psync_apipool_release(api);
      break;
    }
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (!result)
    *cryptoexpires=psync_find_result(res, "cryptoexpires", PARAM_NUM)->num;
  psync_free(res);
  if (result!=0)
    debug(D_WARNING, "crypto_setuserkeys returned %u", (unsigned)result);
  if (result==0)
    return PSYNC_CRYPTO_SETUP_SUCCESS;
  psync_process_api_error(result);
  switch (result){
    case 1000: return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_NOT_LOGGED_IN);
    case 2000: return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
    case 2110: return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_ALREADY_SETUP);
  }
  return PRINT_RETURN_CONST(PSYNC_CRYPTO_SETUP_UNKNOWN_ERROR);
}

static void load_str_to(const psync_variant *v, unsigned char **ptr, size_t *len){
  const char *str;
  size_t l;
  str=psync_get_lstring(*v, &l);
  *ptr=(unsigned char *)psync_malloc(l);
  memcpy(*ptr, str, l);
  *len=l;
}

static int psync_cloud_crypto_download_keys(unsigned char **rsapriv, size_t *rsaprivlen, unsigned char **rsapub, size_t *rsapublen,
                                            unsigned char **salt, size_t *saltlen, size_t *iterations, char *publicsha1, char *privatesha1, uint32_t *flags){
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
  while (1){
    api=psync_apipool_get();
    if (!api)
      return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_CANT_CONNECT);
    res=send_command(api, "crypto_getuserkeys", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries>5)
        return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_CANT_CONNECT);
    }
    else{
      psync_apipool_release(api);
      break;
    }
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    psync_free(res);
    psync_process_api_error(result);
    switch (result){
      case 2111: return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_NOT_SETUP);
      case 2000: return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_CANT_CONNECT);
      case 1000: return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_NOT_LOGGED_IN);
    }
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_UNKNOWN_ERROR);
  }
  data=psync_find_result(res, "privatekey", PARAM_STR);
  rsaprivstruct=psync_base64_decode((const unsigned char *)data->str, data->length, &rsaprivstructlen);
  data=psync_find_result(res, "publickey", PARAM_STR);
  rsapubstruct=psync_base64_decode((const unsigned char *)data->str, data->length, &rsapubstructlen);
  psync_free(res);
  sha1_hex_null_term(rsaprivstruct, rsaprivstructlen, privatesha1);
  sha1_hex_null_term(rsapubstruct, rsapubstructlen, publicsha1);
  debug(D_NOTICE, "rsapubstruct=%s", rsapubstruct);
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
      return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT);
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
      *flags=((priv_key_ver1*)rsaprivstruct)->flags;
      break;
    default:
      def2:
      psync_free(*rsapub);
      psync_free(rsaprivstruct);
      psync_free(rsapubstruct);
      return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT);
  }
  psync_free(rsaprivstruct);
  psync_free(rsapubstruct);
  return PSYNC_CRYPTO_START_SUCCESS;
}

static binresult *psync_get_keys_bin_auth(const char *auth){
  binparam params[]={P_STR("auth", auth)};
  psync_socket *api;
  binresult *res;
	api=psync_apipool_get();
	if (!api)
		return NULL;
	res=send_command(api, "crypto_getuserkeys", params);
	if (unlikely_log(!res)){
		psync_apipool_release_bad(api);
	}
	else{
		psync_apipool_release(api);
	}  
  return res;
}

static int psync_cloud_crypto_setup_upload(const unsigned char *rsapriv, size_t rsaprivlen, const unsigned char *rsapub, size_t rsapublen,
                                           const unsigned char *salt, const char *hint, time_t *cryptoexpires, char *publicsha1, char *privatesha1){
  priv_key_ver1 *priv;
  pub_key_ver1 *pub;
  unsigned char *b64priv, *b64pub;
  size_t b64privlen, b64publen;
  int ret;
  *cryptoexpires=0;
  priv=(priv_key_ver1 *)psync_malloc(offsetof(priv_key_ver1, key)+rsaprivlen);
  priv->type=PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
  priv->flags=0;
  memcpy(priv->salt, salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
  memcpy(priv->key, rsapriv, rsaprivlen);
  pub=(pub_key_ver1 *)psync_malloc(offsetof(pub_key_ver1, key)+rsapublen);
  pub->type=PSYNC_CRYPTO_PUB_TYPE_RSA4096;
  pub->flags=0;
  memcpy(pub->key, rsapub, rsapublen);
  sha1_hex_null_term(priv, offsetof(priv_key_ver1, key)+rsaprivlen, privatesha1);
  sha1_hex_null_term(pub, offsetof(pub_key_ver1, key)+rsapublen, publicsha1);
  b64priv=psync_base64_encode((unsigned char *)priv, offsetof(priv_key_ver1, key)+rsaprivlen, &b64privlen);
  b64pub=psync_base64_encode((unsigned char *)pub, offsetof(pub_key_ver1, key)+rsapublen, &b64publen);
  psync_free(priv);
  psync_free(pub);
  ret=psync_cloud_crypto_setup_do_upload(b64priv, b64privlen, b64pub, b64publen, hint, cryptoexpires);
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

int psync_cloud_crypto_setup(const char *password, const char *hint){
  unsigned char salt[PSYNC_CRYPTO_PBKDF2_SALT_LEN];
  char publicsha1[PSYNC_SHA1_DIGEST_HEXLEN+2], privatesha1[PSYNC_SHA1_DIGEST_HEXLEN+2];
  psync_symmetric_key_t aeskey;
  psync_crypto_aes256_ctr_encoder_decoder_t enc;
  psync_rsa_t rsa;
  psync_rsa_privatekey_t rsaprivate;
  psync_rsa_publickey_t rsapublic;
  psync_binary_rsa_key_t rsaprivatebin, rsapublicbin;
  time_t cryptoexpires;
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
  if (unlikely(rsaprivatebin==PSYNC_INVALID_BIN_RSA || rsapublic==PSYNC_INVALID_BIN_RSA)){
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
  ret=psync_cloud_crypto_setup_upload(rsaprivatebin->data, rsaprivatebin->datalen, rsapublicbin->data, rsapublicbin->datalen, salt, hint, &cryptoexpires,
                                      publicsha1, privatesha1);
  if (unlikely(ret!=PSYNC_CRYPTO_SETUP_SUCCESS)){
    debug(D_WARNING, "keys upload failed with error %d", ret);
    psync_ssl_rsa_free_binary(rsaprivatebin);
    psync_ssl_rsa_free_binary(rsapublicbin);
    return ret;
  }
  debug(D_NOTICE, "keys uploaded");
  psync_cloud_crypto_setup_save_to_db(rsaprivatebin->data, rsaprivatebin->datalen, rsapublicbin->data, rsapublicbin->datalen,
                                      salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS, cryptoexpires, publicsha1, privatesha1, 0);
  psync_ssl_rsa_free_binary(rsaprivatebin);
  psync_ssl_rsa_free_binary(rsapublicbin);
  return PSYNC_CRYPTO_SETUP_SUCCESS;
}

int psync_cloud_crypto_get_hint(char **hint){
  binparam params[]={P_STR("auth", psync_my_auth)};
  psync_socket *api;
  binresult *res;
  uint64_t result;
  int tries;
  tries=0;
  debug(D_NOTICE, "dowloading hint");
  while (1){
    api=psync_apipool_get();
    if (!api)
      return PRINT_RETURN_CONST(PSYNC_CRYPTO_HINT_CANT_CONNECT);
    res=send_command(api, "crypto_getuserhint", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries>5)
        return PRINT_RETURN_CONST(PSYNC_CRYPTO_HINT_CANT_CONNECT);
    }
    else{
      psync_apipool_release(api);
      break;
    }
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    psync_free(res);
    psync_process_api_error(result);
    switch (result){
      case 2122: return PRINT_RETURN_CONST(PSYNC_CRYPTO_HINT_NOT_PROVIDED);
      case 2000: return PRINT_RETURN_CONST(PSYNC_CRYPTO_HINT_CANT_CONNECT);
      case 1000: return PRINT_RETURN_CONST(PSYNC_CRYPTO_HINT_NOT_LOGGED_IN);
    }
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_HINT_UNKNOWN_ERROR);
  }
  *hint=psync_strdup(psync_find_result(res, "hint", PARAM_STR)->str);
  psync_free(res);
  return PSYNC_CRYPTO_HINT_SUCCESS;
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
    psync_free(key);
    return 0;
  }

  deckey= psync_ssl_rsa_decrypt_symm_key_lock(crypto_privkey, enckey);

  psync_free(enckey);
  if (deckey==PSYNC_INVALID_SYM_KEY){
    psync_free(key);
    return 0;
  }
  res=key->keylen==deckey->keylen && !memcmp(key->key, deckey->key, key->keylen);
  psync_ssl_free_symmetric_key(deckey);
  psync_free(key);
  if (res)
    debug(D_NOTICE, "encrypt/decrypt operation succeeded");
  return res;
}

int psync_cloud_crypto_start(const char *password){
  char publicsha1[PSYNC_SHA1_DIGEST_HEXLEN+2], privatesha1[PSYNC_SHA1_DIGEST_HEXLEN+2];
  psync_sql_res *res;
  psync_variant_row row;
  const char *id;
  unsigned char *rsapriv, *rsaprivdec, *rsapub, *salt;
  size_t iterations, rsaprivlen, rsapublen, saltlen;
  psync_symmetric_key_t aeskey;
  psync_crypto_aes256_ctr_encoder_decoder_t enc;
  uint32_t rowcnt, flags;
  int ret;
  flags=0;
  /*
   * Read locks of crypto_lock are taken both before and after taking sql_lock. While read locks are concurrent and can not lead
   * to deadlock it is possible to have some thread to hold sql_lock and wait for read lock. This will normally deadlock with
   * us holding writelock and waiting for sql_lock. Therefore we use sql_trylock here.
   *
   */
retry:
  pthread_rwlock_wrlock(&crypto_lock);
  if (crypto_started_l){
    pthread_rwlock_unlock(&crypto_lock);
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_ALREADY_STARTED);
  }
  rowcnt=0;
  rsapriv=rsapub=salt=NULL;
  iterations=0;
  if (psync_sql_trylock()){
    pthread_rwlock_unlock(&crypto_lock);
    psync_milisleep(1);
    goto retry;
  }
  res=psync_sql_query_nolock("SELECT id, value FROM setting WHERE id IN ('crypto_private_key', 'crypto_public_key', 'crypto_private_salt', 'crypto_private_iter')");
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
  psync_sql_unlock();
  if (rowcnt<4){
    if (unlikely(rowcnt!=0)){
      debug(D_BUG, "only some of records found in the database, should not happen");
      psync_free(rsapriv);
      psync_free(rsapub);
      psync_free(salt);
    }
    ret=psync_cloud_crypto_download_keys(&rsapriv, &rsaprivlen, &rsapub, &rsapublen, &salt, &saltlen, &iterations, publicsha1, privatesha1, &flags);
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
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT);
  }
  aeskey=psync_ssl_gen_symmetric_key_from_pass(password, PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE, salt, saltlen, iterations);
  enc=psync_crypto_aes256_ctr_encoder_decoder_create(aeskey);
  psync_ssl_free_symmetric_key(aeskey);
  rsaprivdec=(unsigned char *)psync_locked_malloc(rsaprivlen);
  memcpy(rsaprivdec, rsapriv, rsaprivlen);
  psync_crypto_aes256_ctr_encode_decode_inplace(enc, rsaprivdec, rsaprivlen, 0);
  psync_crypto_aes256_ctr_encoder_decoder_free(enc);
  crypto_privkey=psync_ssl_rsa_load_private(rsaprivdec, rsaprivlen);
  psync_ssl_memclean(rsaprivdec, rsaprivlen);
  psync_locked_free(rsaprivdec);
  if (crypto_privkey==PSYNC_INVALID_RSA){
    psync_ssl_rsa_free_public(crypto_pubkey);
    crypto_pubkey=PSYNC_INVALID_RSA;
    pthread_rwlock_unlock(&crypto_lock);
    debug(D_NOTICE, "bad password");
    psync_free(rsapriv);
    psync_free(rsapub);
    psync_free(salt);
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_BAD_PASSWORD);
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
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_START_KEYS_DONT_MATCH);
  }
  crypto_started_l=1;
  crypto_started_un=1;
  pthread_rwlock_unlock(&crypto_lock);
  if (rowcnt<4)
    psync_cloud_crypto_setup_save_to_db(rsapriv, rsaprivlen, rsapub, rsapublen, salt, saltlen, iterations, 0, publicsha1, privatesha1, flags);
  psync_free(rsapriv);
  psync_free(rsapub);
  psync_free(salt);
  debug(D_NOTICE, "crypto successfully started");
  return PSYNC_CRYPTO_START_SUCCESS;
}

static void psync_fs_refresh_crypto_folders(){
  psync_folderid_t *fids, *fid;
  fids=psync_crypto_folderids();
  fid=fids;
  while (*fid!=PSYNC_CRYPTO_INVALID_FOLDERID){
    psync_fs_refresh_folder(*fid);
    fid++;
  }
  psync_free(fids);
}

int psync_cloud_crypto_stop(){
  crypto_started_un=0;
  pthread_rwlock_wrlock(&crypto_lock);
  if (!crypto_started_l){
    pthread_rwlock_unlock(&crypto_lock);
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_STOP_NOT_STARTED);
  }
  crypto_started_l=0;
  psync_ssl_rsa_free_public(crypto_pubkey);
  crypto_pubkey=PSYNC_INVALID_RSA;
  psync_ssl_rsa_free_private(crypto_privkey);
  crypto_privkey=PSYNC_INVALID_RSA;
  pthread_rwlock_unlock(&crypto_lock);
  debug(D_NOTICE, "stopped crypto");
  psync_cloud_crypto_clean_cache();
  psync_fs_refresh_crypto_folders();
#ifdef P_OS_WINDOWS
  psync_refresh_explorer_crypto_folder();
#endif
  return PSYNC_CRYPTO_STOP_SUCCESS;
}

int psync_cloud_crypto_isstarted(){
  int ret;
  pthread_rwlock_rdlock(&crypto_lock);
  ret=crypto_started_l;
  pthread_rwlock_unlock(&crypto_lock);
  return ret;
}

int psync_cloud_crypto_reset(){
  binparam params[]={P_STR("auth", psync_my_auth)};
  psync_socket *api;
  binresult *res;
  uint32_t result;
  int tries;
/*  pthread_rwlock_rdlock(&crypto_lock);
  result=crypto_started_l;
  pthread_rwlock_unlock(&crypto_lock);
  if (result)
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_CRYPTO_IS_STARTED);*/
  if (!psync_crypto_issetup())
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_NOT_SETUP);
  debug(D_NOTICE, "resetting crypto");
  tries=0;
  while (1){
    api=psync_apipool_get();
    if (!api)
      return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_CANT_CONNECT);
    res=send_command(api, "crypto_reset", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries>5)
        return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_CANT_CONNECT);
    }
    else{
      psync_apipool_release(api);
      break;
    }
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  if (result)
    debug(D_WARNING, "crypto_reset returned error %u", (unsigned)result);
  if (result==0)
    return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_SUCCESS);
  psync_process_api_error(result);
  switch (result){
    case 2000: return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_NOT_LOGGED_IN);
    case 2111: return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_NOT_SETUP);
    default: return PRINT_RETURN_CONST(PSYNC_CRYPTO_RESET_UNKNOWN_ERROR);
  }
}

static void *err_to_ptr(int err){
  return (void *)(uintptr_t)(-err);
}

static void set_crypto_err_msg(const binresult *res){
  const binresult *msg;
  size_t l;
  msg=psync_find_result(res, "error", PARAM_STR);
  l=msg->length+1;
  if (l>=sizeof(crypto_api_err))
    l=sizeof(crypto_api_err)-1;
  memcpy(crypto_api_err, msg->str, l);
}

typedef struct {
  psync_encrypted_symmetric_key_t key;
  psync_folderid_t id;
} insert_folder_key_task;

static void save_folder_key_task(void *ptr){
  insert_folder_key_task *t;
  psync_sql_res *res;
  t=(insert_folder_key_task *)ptr;
  res=psync_sql_prep_statement("REPLACE INTO cryptofolderkey (folderid, enckey) VALUES (?, ?)");
  psync_sql_bind_uint(res, 1, t->id);
  psync_sql_bind_blob(res, 2, (const char *)t->key->data, t->key->datalen);
  psync_sql_run_free(res);
  psync_free(t->key);
  psync_free(t);
}

static void save_folder_key_to_db(psync_folderid_t folderid, psync_encrypted_symmetric_key_t enckey){
  // we are likely holding (few) read locks on the database, so executing here will deadlock
  insert_folder_key_task *t;
  t=psync_new(insert_folder_key_task);
  t->key=psync_ssl_copy_encrypted_symmetric_key(enckey);
  t->id=folderid;
  psync_run_thread1("save folder key to db task", save_folder_key_task, t);
}

typedef struct {
  psync_encrypted_symmetric_key_t key;
  psync_fileid_t id;
  uint64_t hash;
} insert_file_key_task;

static void save_file_key_task(void *ptr){
  insert_file_key_task *t;
  psync_sql_res *res;
  t=(insert_file_key_task *)ptr;
  res=psync_sql_prep_statement("REPLACE INTO cryptofilekey (fileid, hash, enckey) VALUES (?, ?, ?)");
  psync_sql_bind_uint(res, 1, t->id);
  psync_sql_bind_uint(res, 2, t->hash);
  psync_sql_bind_blob(res, 3, (const char *)t->key->data, t->key->datalen);
  psync_sql_run_free(res);
  psync_free(t->key);
  psync_free(t);
}

static void save_file_key_to_db(psync_fileid_t fileid, uint64_t hash, psync_encrypted_symmetric_key_t enckey){
  insert_file_key_task *t;
  t=psync_new(insert_file_key_task);
  t->key=psync_ssl_copy_encrypted_symmetric_key(enckey);
  t->id=fileid;
  t->hash=hash;
  psync_run_thread1("save file key to db task", save_file_key_task, t);
}

static psync_encrypted_symmetric_key_t psync_crypto_download_folder_enc_key(psync_folderid_t folderid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid)};
  psync_socket *api;
  binresult *res;
  const binresult *b64key;
  uint64_t result;
  unsigned char *key;
  psync_encrypted_symmetric_key_t ret;
  size_t keylen;
  int tries;
  tries=0;
  debug(D_NOTICE, "downloading key for folder %lu", (unsigned long)folderid);
  while (1){
    api=psync_apipool_get();
    if (!api)
      return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_CANT_CONNECT));
    res=send_command(api, "crypto_getfolderkey", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries>5)
        return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_CANT_CONNECT));
    }
    else{
      psync_apipool_release(api);
      break;
    }
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    debug(D_NOTICE, "got error %lu from crypto_getfolderkey", (unsigned long)result);
    crypto_api_errno=result;
    set_crypto_err_msg(res);
    psync_free(res);
    psync_process_api_error(result);
    return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_API_ERR_INTERNAL));
  }
  b64key=psync_find_result(res, "key", PARAM_STR);
  key=psync_base64_decode((const unsigned char *)b64key->str, b64key->length, &keylen);
  psync_free(res);
  if (!key)
    return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  ret=psync_ssl_alloc_encrypted_symmetric_key(keylen);
  memcpy(ret->data, key, keylen);
  psync_free(key);
  save_folder_key_to_db(folderid, ret);
  return ret;
}

static psync_encrypted_symmetric_key_t psync_crypto_download_file_enc_key(psync_fileid_t fileid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid)};
  psync_socket *api;
  binresult *res;
  const binresult *b64key;
  uint64_t result;
  unsigned char *key;
  psync_encrypted_symmetric_key_t ret;
  size_t keylen;
  int tries;
  tries=0;
  debug(D_NOTICE, "downloading key for file %lu", (unsigned long)fileid);
  while (1){
    api=psync_apipool_get();
    if (!api)
      return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_CANT_CONNECT));
    res=send_command(api, "crypto_getfilekey", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries>5)
        return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_CANT_CONNECT));
    }
    else{
      psync_apipool_release(api);
      break;
    }
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    debug(D_NOTICE, "got error %lu from crypto_getfilekey", (unsigned long)result);
    crypto_api_errno=result;
    set_crypto_err_msg(res);
    psync_free(res);
    return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_API_ERR_INTERNAL));
  }
  result=psync_find_result(res, "hash", PARAM_NUM)->num;
  b64key=psync_find_result(res, "key", PARAM_STR);
  key=psync_base64_decode((const unsigned char *)b64key->str, b64key->length, &keylen);
  psync_free(res);
  if (!key)
    return (psync_encrypted_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  ret=psync_ssl_alloc_encrypted_symmetric_key(keylen);
  memcpy(ret->data, key, keylen);
  psync_free(key);
  save_file_key_to_db(fileid, result, ret);
  return ret;
}

static psync_encrypted_symmetric_key_t psync_crypto_get_folder_enc_key(psync_folderid_t folderid){
  psync_encrypted_symmetric_key_t enckey;
  psync_sql_res *res;
  psync_variant_row row;
  const char *ckey;
  size_t ckeylen;
  res=psync_sql_query_rdlock("SELECT enckey FROM cryptofolderkey WHERE folderid=?");
  psync_sql_bind_uint(res, 1, folderid);
  if ((row=psync_sql_fetch_row(res))){
    ckey=psync_get_lstring(row[0], &ckeylen);
    enckey=psync_ssl_alloc_encrypted_symmetric_key(ckeylen);
    memcpy(enckey->data, ckey, ckeylen);
    psync_sql_free_result(res);
    return enckey;
  }
  psync_sql_free_result(res);
  return psync_crypto_download_folder_enc_key(folderid);
}

static psync_encrypted_symmetric_key_t psync_crypto_get_file_enc_key(psync_fileid_t fileid, uint64_t hash, int nonetwork){
  psync_encrypted_symmetric_key_t enckey;
  psync_sql_res *res;
  psync_variant_row row;
  const char *ckey;
  size_t ckeylen;
  res=psync_sql_query_rdlock("SELECT enckey FROM cryptofilekey WHERE fileid=? AND hash=?");
  psync_sql_bind_uint(res, 1, fileid);
  psync_sql_bind_uint(res, 2, hash);
  if ((row=psync_sql_fetch_row(res))){
    ckey=psync_get_lstring(row[0], &ckeylen);
    enckey=psync_ssl_alloc_encrypted_symmetric_key(ckeylen);
    memcpy(enckey->data, ckey, ckeylen);
    psync_sql_free_result(res);
    return enckey;
  }
  psync_sql_free_result(res);
  if (nonetwork){
    debug(D_NOTICE, "delaying key download for file %lu", (unsigned long)fileid);
    return (psync_encrypted_symmetric_key_t)PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER;
  }
  else
    return psync_crypto_download_file_enc_key(fileid);
}

static psync_symmetric_key_t psync_crypto_get_folder_symkey_locked(psync_folderid_t folderid){
  char buff[16];
  psync_encrypted_symmetric_key_t enckey;
  psync_symmetric_key_t symkey;
  psync_get_string_id(buff, "FKEY", folderid);
  symkey=(psync_symmetric_key_t)psync_cache_get(buff);
  if (symkey)
    return symkey;
  enckey=psync_crypto_get_folder_enc_key(folderid);
  if (psync_crypto_is_error(enckey))
    return (psync_symmetric_key_t)enckey;

  symkey = psync_ssl_rsa_decrypt_symm_key_lock(crypto_privkey, enckey);

  psync_free(enckey);
  if (symkey==PSYNC_INVALID_SYM_KEY)
    return (psync_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  return symkey;
}

static psync_symmetric_key_t psync_crypto_get_file_symkey_locked(psync_fileid_t fileid, uint64_t hash, int nonetwork){
  char buff[32];
  psync_encrypted_symmetric_key_t enckey;
  psync_symmetric_key_t symkey;
  psync_get_string_id2(buff, "DKEY", fileid, hash);
  symkey=(psync_symmetric_key_t)psync_cache_get(buff);
  if (symkey){
    debug(D_NOTICE, "got key for file %lu from cache", (unsigned long)fileid);
    return symkey;
  }
  enckey=psync_crypto_get_file_enc_key(fileid, hash, nonetwork);
  if (unlikely_log(psync_crypto_is_error(enckey)))
    return (psync_symmetric_key_t)enckey;
  if (nonetwork && enckey==(psync_encrypted_symmetric_key_t)PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)
    return (psync_symmetric_key_t)PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER;

  symkey = psync_ssl_rsa_decrypt_symm_key_lock(crypto_privkey, enckey);

  psync_free(enckey);
  if (unlikely_log(symkey==PSYNC_INVALID_SYM_KEY))
    return (psync_symmetric_key_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  return symkey;
}

static void psync_crypto_release_symkey_ptr(void *ptr){
  psync_ssl_free_symmetric_key((psync_symmetric_key_t)ptr);
}

static void psync_crypto_release_folder_symkey_locked(psync_folderid_t folderid, psync_symmetric_key_t key){
  char buff[16];
  psync_get_string_id(buff, "FKEY", folderid);
  psync_cache_add(buff, key, PSYNC_CRYPTO_CACHE_DIR_SYM_KEY, psync_crypto_release_symkey_ptr, 2);
}

static void psync_crypto_release_file_symkey_locked(psync_fileid_t fileid, uint64_t hash, psync_symmetric_key_t key){
  char buff[32];
  psync_get_string_id2(buff, "DKEY", fileid, hash);
  psync_cache_add(buff, key, PSYNC_CRYPTO_CACHE_FILE_SYM_KEY, psync_crypto_release_symkey_ptr, 2);
}

static psync_symmetric_key_t psync_crypto_sym_key_ver1_to_sym_key(sym_key_ver1 *v1){
  psync_symmetric_key_t key;
  key=(psync_symmetric_key_t)psync_locked_malloc(offsetof(psync_symmetric_key_struct_t, key)+PSYNC_AES256_KEY_SIZE+PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  key->keylen=PSYNC_AES256_KEY_SIZE+PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN;
  memcpy(key->key, v1->aeskey, PSYNC_AES256_KEY_SIZE);
  memcpy(key->key+PSYNC_AES256_KEY_SIZE, v1->hmackey, PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  return key;
}

static psync_crypto_aes256_text_encoder_t psync_crypto_get_folder_encoder_locked(psync_folderid_t folderid){
  psync_crypto_aes256_text_encoder_t enc;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  symkey=psync_crypto_get_folder_symkey_locked(folderid);
  if (psync_crypto_is_error(symkey))
    return (psync_crypto_aes256_text_encoder_t)symkey;
  skv1=(sym_key_ver1 *)symkey->key;
  switch (skv1->type){
    case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
      if (symkey->keylen!=sizeof(sym_key_ver1)){
        debug(D_WARNING, "bad size of decrypted key, expected %lu got %lu", (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
        goto def1;
      }
      if ((skv1->flags&PSYNC_CRYPTO_SYM_FLAG_ISDIR)==0){
        debug(D_WARNING, "file key found when folder key was expected for folderid %lu", (unsigned long)folderid);
        goto def1;
      }
      realkey=psync_crypto_sym_key_ver1_to_sym_key(skv1);
      psync_crypto_release_folder_symkey_locked(folderid, symkey);
      enc=psync_crypto_aes256_text_encoder_create(realkey);
      psync_ssl_free_symmetric_key(realkey);
      return enc;
    default:
      debug(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
      def1:
      psync_ssl_free_symmetric_key(symkey);
      return (psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static psync_crypto_aes256_text_encoder_t psync_crypto_get_folder_encoder_check_cache_locked(psync_folderid_t folderid){
  char buff[16];
  psync_crypto_aes256_text_encoder_t enc;
  psync_get_string_id(buff, "FLDE", folderid);
  enc=(psync_crypto_aes256_text_encoder_t)psync_cache_get(buff);
  if (enc)
    return enc;
  else
    return psync_crypto_get_folder_encoder_locked(folderid);
}

static psync_crypto_aes256_text_decoder_t psync_crypto_get_folder_decoder_locked(psync_folderid_t folderid){
  psync_crypto_aes256_text_decoder_t dec;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  symkey=psync_crypto_get_folder_symkey_locked(folderid);
  if (psync_crypto_is_error(symkey))
    return (psync_crypto_aes256_text_encoder_t)symkey;
  skv1=(sym_key_ver1 *)symkey->key;
  switch (skv1->type){
    case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
      if (symkey->keylen!=sizeof(sym_key_ver1)){
        debug(D_WARNING, "bad size of decrypted key, expected %lu got %lu", (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
        goto def1;
      }
      realkey=psync_crypto_sym_key_ver1_to_sym_key(skv1);
      psync_crypto_release_folder_symkey_locked(folderid, symkey);
      dec=psync_crypto_aes256_text_decoder_create(realkey);
      psync_ssl_free_symmetric_key(realkey);
      return dec;
    default:
      debug(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
      def1:
      psync_ssl_free_symmetric_key(symkey);
      return (psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static psync_crypto_aes256_text_encoder_t psync_crypto_get_temp_folder_encoder_locked(psync_fsfolderid_t folderid){
  psync_crypto_aes256_text_encoder_t enc;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  psync_sql_res *res;
  psync_variant_row row;
  res=psync_sql_query_rdlock("SELECT text2 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, -folderid);
  if ((row=psync_sql_fetch_row(res))){
    const unsigned char *b64enckey;
    unsigned char *enckey;
    size_t b64enckeylen, enckeylen;;
    if (psync_is_null(row[0])){
      psync_sql_free_result(res);
      return (psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
    }
    b64enckey=(const unsigned char *)psync_get_lstring(row[0], &b64enckeylen);
    enckey=psync_base64_decode(b64enckey, b64enckeylen, &enckeylen);
    psync_sql_free_result(res);
    if (enckey){
      symkey=psync_ssl_rsa_decrypt_data(crypto_privkey, enckey, enckeylen);
      psync_free(enckey);
    }
    else
      symkey=PSYNC_INVALID_SYM_KEY;
  }
  else{
    psync_sql_free_result(res);
    return (psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_FOUND));
  }
  if (symkey==PSYNC_INVALID_SYM_KEY)
    return (psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  skv1=(sym_key_ver1 *)symkey->key;
  switch (skv1->type){
    case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
      if (symkey->keylen!=sizeof(sym_key_ver1)){
        debug(D_WARNING, "bad size of decrypted key, expected %lu got %lu", (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
        goto def1;
      }
      realkey=psync_crypto_sym_key_ver1_to_sym_key(skv1);
      psync_ssl_free_symmetric_key(symkey);
      enc=psync_crypto_aes256_text_encoder_create(realkey);
      psync_ssl_free_symmetric_key(realkey);
      return enc;
    default:
      debug(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
      def1:
      psync_ssl_free_symmetric_key(symkey);
      return (psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static psync_crypto_aes256_text_decoder_t psync_crypto_get_temp_folder_decoder_locked(psync_fsfolderid_t folderid){
  psync_crypto_aes256_text_decoder_t dec;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  psync_sql_res *res;
  psync_variant_row row;
  res=psync_sql_query_rdlock("SELECT text2 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, -folderid);
  if ((row=psync_sql_fetch_row(res))){
    const unsigned char *b64enckey;
    unsigned char *enckey;
    size_t b64enckeylen, enckeylen;;
    if (psync_is_null(row[0])){
      psync_sql_free_result(res);
      return (psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
    }
    b64enckey=(const unsigned char *)psync_get_lstring(row[0], &b64enckeylen);
    enckey=psync_base64_decode(b64enckey, b64enckeylen, &enckeylen);
    psync_sql_free_result(res);
    if (enckey){
      symkey=psync_ssl_rsa_decrypt_data(crypto_privkey, enckey, enckeylen);

      psync_free(enckey);
      if (symkey==PSYNC_INVALID_SYM_KEY)
        debug(D_WARNING, "got key from database that fails rsa decrypt");
    }
    else{
      symkey=PSYNC_INVALID_SYM_KEY;
      debug(D_WARNING, "got key from database that fails base64_decode");
    }
  }
  else{
    psync_sql_free_result(res);
    return (psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_FOUND));
  }
  if (symkey==PSYNC_INVALID_SYM_KEY)
    return (psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  skv1=(sym_key_ver1 *)symkey->key;
  switch (skv1->type){
    case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
      if (symkey->keylen!=sizeof(sym_key_ver1)){
        debug(D_WARNING, "bad size of decrypted key, expected %lu got %lu", (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
        goto def1;
      }
      realkey=psync_crypto_sym_key_ver1_to_sym_key(skv1);
      psync_ssl_free_symmetric_key(symkey);
      dec=psync_crypto_aes256_text_decoder_create(realkey);
      psync_ssl_free_symmetric_key(realkey);
      return dec;
    default:
      debug(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
      def1:
      psync_ssl_free_symmetric_key(symkey);
      return (psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  }
}

psync_crypto_aes256_text_decoder_t psync_cloud_crypto_get_folder_decoder(psync_fsfolderid_t folderid){
  char buff[16];
  psync_crypto_aes256_text_decoder_t dec;
  if (!crypto_started_un)
    return (psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  if (folderid>=0){
    psync_get_string_id(buff, "FLDD", folderid);
    dec=(psync_crypto_aes256_text_decoder_t)psync_cache_get(buff);
    if (dec)
      return dec;
  }
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l)
    dec=(psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  if (folderid>0)
    dec=psync_crypto_get_folder_decoder_locked(folderid);
  else if (folderid<0)
    dec=psync_crypto_get_temp_folder_decoder_locked(folderid);
  else
    dec=(psync_crypto_aes256_text_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
  pthread_rwlock_unlock(&crypto_lock);
  return dec;
}

static void psync_crypto_free_folder_decoder(void *ptr){
  psync_crypto_aes256_text_decoder_free((psync_crypto_aes256_text_decoder_t)ptr);
}

void psync_cloud_crypto_release_folder_decoder(psync_fsfolderid_t folderid, psync_crypto_aes256_text_decoder_t decoder){
  char buff[16];
  if (crypto_started_un && folderid>=0){
    psync_get_string_id(buff, "FLDD", folderid);
    psync_cache_add(buff, decoder, PSYNC_CRYPTO_CACHE_DIR_ECODER_SEC, psync_crypto_free_folder_decoder, 2);
  }
  else
    psync_crypto_aes256_text_decoder_free(decoder);
}

char *psync_cloud_crypto_decode_filename(psync_crypto_aes256_text_decoder_t decoder, const char *name){
  unsigned char *filenameenc, *filenamedec;
  size_t filenameenclen;
  filenameenc=psync_base32_decode((const unsigned char *)name, strlen(name), &filenameenclen);
  if (!filenameenc)
    return NULL;
  filenamedec=psync_crypto_aes256_decode_text(decoder, filenameenc, filenameenclen);
  psync_free(filenameenc);
  return (char *)filenamedec;
}

static void psync_crypto_free_folder_encoder(void *ptr){
  psync_crypto_aes256_text_encoder_free((psync_crypto_aes256_text_encoder_t)ptr);
}

static void psync_crypto_release_folder_encoder_locked(psync_folderid_t folderid, psync_crypto_aes256_text_encoder_t enc){
  char buff[16];
  psync_get_string_id(buff, "FLDE", folderid);
  psync_cache_add(buff, enc, PSYNC_CRYPTO_CACHE_DIR_ECODER_SEC, psync_crypto_free_folder_encoder, 2);
}

psync_crypto_aes256_text_encoder_t psync_cloud_crypto_get_folder_encoder(psync_fsfolderid_t folderid){
  char buff[16];
  psync_crypto_aes256_text_encoder_t enc;
  if (!crypto_started_un)
    return (psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  if (folderid>=0){
    psync_get_string_id(buff, "FLDE", folderid);
    enc=(psync_crypto_aes256_text_encoder_t)psync_cache_get(buff);
    if (enc)
      return enc;
  }
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l)
    enc=(psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  if (folderid>0)
    enc=psync_crypto_get_folder_encoder_locked(folderid);
  else if (folderid<0)
    enc=psync_crypto_get_temp_folder_encoder_locked(folderid);
  else
    enc=(psync_crypto_aes256_text_encoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
  pthread_rwlock_unlock(&crypto_lock);
  return enc;
}

void psync_cloud_crypto_release_folder_encoder(psync_fsfolderid_t folderid, psync_crypto_aes256_text_encoder_t encoder){
  char buff[16];
  if (crypto_started_un && folderid>=0){
    psync_get_string_id(buff, "FLDE", folderid);
    psync_cache_add(buff, encoder, PSYNC_CRYPTO_CACHE_DIR_ECODER_SEC, psync_crypto_free_folder_encoder, 2);
  }
  else
    psync_crypto_aes256_text_encoder_free(encoder);

}

char *psync_cloud_crypto_encode_filename(psync_crypto_aes256_text_encoder_t encoder, const char *name){
  unsigned char *filenameenc, *filenameb32;
  size_t filenameenclen;
  psync_crypto_aes256_encode_text(encoder, (const unsigned char *)name, strlen(name), &filenameenc, &filenameenclen);
  filenameb32=psync_base32_encode(filenameenc, filenameenclen, &filenameenclen);
  psync_free(filenameenc);
  return (char *)filenameb32;
}

static psync_crypto_aes256_sector_encoder_decoder_t psync_crypto_get_file_encoder_locked(psync_fileid_t fileid, uint64_t hash, int nonetwork){
  psync_crypto_aes256_sector_encoder_decoder_t enc;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  symkey=psync_crypto_get_file_symkey_locked(fileid, hash, nonetwork);
  if (unlikely_log(psync_crypto_is_error(symkey)))
    return (psync_crypto_aes256_sector_encoder_decoder_t)symkey;
  if (nonetwork && (psync_crypto_aes256_sector_encoder_decoder_t)symkey==PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)
    return PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER;
  skv1=(sym_key_ver1 *)symkey->key;
  switch (skv1->type){
    case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
      if (symkey->keylen!=sizeof(sym_key_ver1)){
        debug(D_WARNING, "bad size of decrypted key, expected %lu got %lu", (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
        goto def1;
      }
      if (skv1->flags&PSYNC_CRYPTO_SYM_FLAG_ISDIR){
        debug(D_WARNING, "folder key found when file key was expected for fileid %lu", (unsigned long)fileid);
        goto def1;
      }
      realkey=psync_crypto_sym_key_ver1_to_sym_key(skv1);
      psync_crypto_release_file_symkey_locked(fileid, hash, symkey);
      enc=psync_crypto_aes256_sector_encoder_decoder_create(realkey);
      psync_ssl_free_symmetric_key(realkey);
      return enc;
    default:
      debug(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
      def1:
      psync_ssl_free_symmetric_key(symkey);
      return (psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static psync_crypto_aes256_sector_encoder_decoder_t psync_crypto_get_temp_file_encoder_locked(psync_fsfileid_t fileid, int nonetwork){
  uint64_t hash;
  psync_sql_res *res;
  psync_variant_row row;
  sym_key_ver1 *skv1;
  psync_symmetric_key_t realkey;
  psync_crypto_aes256_sector_encoder_decoder_t enc;
  const unsigned char *b64enckey;
  unsigned char *enckey;
  size_t enckeylen, b64enckeylen;
  psync_symmetric_key_t symkey;
  res=psync_sql_query_rdlock("SELECT type, fileid, text2, int1 FROM fstask WHERE id=?");
  psync_sql_bind_uint(res, 1, -fileid);
  row=psync_sql_fetch_row(res);
  if (unlikely_log(!row)){
    psync_sql_free_result(res);
    return (psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FILE_NOT_FOUND));
  }
  switch (psync_get_number(row[0])){
    case PSYNC_FS_TASK_CREAT:
      b64enckey=(const unsigned char *)psync_get_lstring(row[2], &b64enckeylen);
      enckey=psync_base64_decode(b64enckey, b64enckeylen, &enckeylen);
      psync_sql_free_result(res);
      if (enckey){
        symkey=psync_ssl_rsa_decrypt_data(crypto_privkey, enckey, enckeylen);

        psync_free(enckey);
      }
      else
        symkey=PSYNC_INVALID_SYM_KEY;
      if (symkey==PSYNC_INVALID_SYM_KEY)
        return (psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
      skv1=(sym_key_ver1 *)symkey->key;
      switch (skv1->type){
        case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
          if (symkey->keylen!=sizeof(sym_key_ver1)){
            debug(D_WARNING, "bad size of decrypted key, expected %lu got %lu", (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
            goto def1;
          }
          realkey=psync_crypto_sym_key_ver1_to_sym_key(skv1);
          psync_ssl_free_symmetric_key(symkey);
          enc=psync_crypto_aes256_sector_encoder_decoder_create(realkey);
          psync_ssl_free_symmetric_key(realkey);
          return enc;
        default:
          debug(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
          def1:
          psync_ssl_free_symmetric_key(symkey);
          return (psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
      }
    case PSYNC_FS_TASK_MODIFY:
      fileid=psync_get_number(row[1]);
      hash=psync_get_number(row[3]);
      psync_sql_free_result(res);
      return psync_crypto_get_file_encoder_locked(fileid, hash, nonetwork);
    default:
      psync_sql_free_result(res);
      return (psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INTERNAL_ERROR));
  }
}

psync_crypto_aes256_sector_encoder_decoder_t psync_cloud_crypto_get_file_encoder(psync_fsfileid_t fileid, uint64_t hash, int nonetwork){
  char buff[32];
  psync_crypto_aes256_sector_encoder_decoder_t enc;
  if (!crypto_started_un)
    return (psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  if (fileid>=0){
    psync_get_string_id2(buff, "SEEN", fileid, hash);
    enc=(psync_crypto_aes256_sector_encoder_decoder_t)psync_cache_get(buff);
    if (enc)
      return enc;
  }
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l)
    enc=(psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  if (fileid>0)
    enc=psync_crypto_get_file_encoder_locked(fileid, hash, nonetwork);
  else if (fileid<0)
    enc=psync_crypto_get_temp_file_encoder_locked(fileid, nonetwork);
  else
    enc=(psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
  pthread_rwlock_unlock(&crypto_lock);
  return enc;
}

psync_crypto_aes256_sector_encoder_decoder_t psync_cloud_crypto_get_file_encoder_from_binresult(psync_fileid_t fileid, binresult *res){
  const binresult *b64key;
  unsigned char *key;
  psync_encrypted_symmetric_key_t esym;
  psync_symmetric_key_t symkey;
  psync_crypto_aes256_sector_encoder_decoder_t enc;
  uint64_t hash;
  size_t keylen;
  b64key=psync_find_result(res, "key", PARAM_STR);
  key=psync_base64_decode((const unsigned char *)b64key->str, b64key->length, &keylen);
  if (!key)
    return (psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_INVALID_KEY));
  esym=psync_ssl_alloc_encrypted_symmetric_key(keylen);
  memcpy(esym->data, key, keylen);
  psync_free(key);
  hash=psync_find_result(res, "hash", PARAM_NUM)->num;
  save_file_key_to_db(fileid, hash, esym);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l)
    enc=(psync_crypto_aes256_sector_encoder_decoder_t)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  else{
    // save_file_key_to_db runs thread to save to db, that's why we insert decrypted key to cache, so psync_crypto_get_file_encoder_locked finds it
    symkey = psync_ssl_rsa_decrypt_symm_key_lock(crypto_privkey, esym);

    psync_crypto_release_file_symkey_locked(fileid, hash, symkey);
    enc=psync_crypto_get_file_encoder_locked(fileid, hash, 0);
  }
  pthread_rwlock_unlock(&crypto_lock);
  psync_free(esym);
  return enc;
}

static void psync_crypto_free_file_encoder(void *ptr){
  psync_crypto_aes256_sector_encoder_decoder_free((psync_crypto_aes256_sector_encoder_decoder_t)ptr);
}

void psync_cloud_crypto_release_file_encoder(psync_fsfileid_t fileid, uint64_t hash, psync_crypto_aes256_sector_encoder_decoder_t encoder){
  if (crypto_started_un && fileid>=0){
    char buff[32];
    psync_get_string_id2(buff, "SEEN", fileid, hash);
    psync_cache_add(buff, encoder, PSYNC_CRYPTO_CACHE_FILE_ECODER_SEC, psync_crypto_free_file_encoder, 2);
  }
  else
    psync_crypto_aes256_sector_encoder_decoder_free(encoder);
}

char *psync_crypto_get_name_encoded_locked(psync_folderid_t folderid, const char *name){
  psync_crypto_aes256_text_encoder_t enc;
  unsigned char *nameenc;
  char *ret;
  size_t nameenclen;
  enc=psync_crypto_get_folder_encoder_check_cache_locked(folderid);
  if (psync_crypto_is_error(enc))
    return (char *)enc;
  psync_crypto_aes256_encode_text(enc, (const unsigned char *)name, strlen(name), &nameenc, &nameenclen);
  ret=(char *)psync_base32_encode(nameenc, nameenclen, &nameenclen);
  psync_crypto_release_folder_encoder_locked(folderid, enc);
  psync_free(nameenc);
  return ret;
}

static int set_err(int ret, const char **err){
  if (ret==PSYNC_CRYPTO_API_ERR_INTERNAL){
    if (err)
      *err=crypto_api_err;
    return crypto_api_errno;
  }
  if (err){
    if (-ret<ARRAY_SIZE(crypto_errors))
      *err=crypto_errors[-ret];
    else
      *err="Unkown error.";
  }
  return ret;
}

static int get_name_for_enc_folder_locked(psync_folderid_t folderid, const char *name, char **ename, const char **err){
  char *encname;
  encname=psync_crypto_get_name_encoded_locked(folderid, name);
  if (psync_crypto_is_error(encname))
    return set_err(psync_crypto_to_error(encname), err);
  *ename=encname;
  return PSYNC_CRYPTO_SUCCESS;
}

static int get_name_for_folder_locked(psync_folderid_t folderid, const char *name, char **ename, const char **err){
  if (folderid==0){
    *ename=psync_strdup(name);
    return PSYNC_CRYPTO_SUCCESS;
  }
  else{
    psync_sql_res *res;
    psync_uint_row row;
    int enc;
    res=psync_sql_query_rdlock("SELECT flags FROM folder WHERE id=?");
    psync_sql_bind_uint(res, 1, folderid);
    if ((row=psync_sql_fetch_rowint(res)))
      enc=(row[0]&PSYNC_FOLDER_FLAG_ENCRYPTED)!=0;
    psync_sql_free_result(res);
    if (!row)
      return set_err(PRINT_RETURN_CONST(PSYNC_CRYPTO_FOLDER_NOT_FOUND), err);
    if (enc)
      return get_name_for_enc_folder_locked(folderid, name, ename, err);
    else{
      *ename=psync_strdup(name);
      return PSYNC_CRYPTO_SUCCESS;
    }
  }
}

int psync_cloud_crypto_send_mkdir(psync_folderid_t folderid, const char *name, const char **err, const char *b64key, size_t b64keylen,
                                  psync_encrypted_symmetric_key_t encsym, psync_folderid_t *newfolderid){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("folderid", folderid), P_STR("name", name), P_BOOL("encrypted", 1),
                     P_LSTR("key", b64key, b64keylen), P_STR("timeformat", "timestamp")};
  psync_socket *api;
  binresult *res;
  const binresult *meta;
  uint64_t result;
  int tries;
  tries=0;
  while (1){
    api=psync_apipool_get();
    if (!api)
      return set_err(PRINT_RETURN_CONST(PSYNC_CRYPTO_CANT_CONNECT), err);
    res=send_command(api, "createfolder", params);
    if (unlikely_log(!res)){
      psync_apipool_release_bad(api);
      if (++tries>5)
        return set_err(PRINT_RETURN_CONST(PSYNC_CRYPTO_CANT_CONNECT), err);
    }
    else{
      psync_apipool_release(api);
      break;
    }
  }
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    set_crypto_err_msg(res);
    debug(D_NOTICE, "createfolder returned error %lu %s", (unsigned long)result, crypto_api_err);
    psync_free(res);
    *err=crypto_api_err;
    psync_process_api_error(result);
    return result;
  }
  meta=psync_find_result(res, "metadata", PARAM_HASH);
  if (newfolderid)
    *newfolderid=psync_find_result(meta, "folderid", PARAM_NUM)->num;
  psync_sql_start_transaction();
  psync_ops_create_folder_in_db(meta);
  save_folder_key_to_db(psync_find_result(meta, "folderid", PARAM_NUM)->num, encsym);
  psync_sql_commit_transaction();
  psync_free(res);
  return PSYNC_CRYPTO_SUCCESS;
}

char *psync_cloud_crypto_get_file_encoded_key(psync_fsfileid_t fileid, uint64_t hash, size_t *keylen){
  psync_encrypted_symmetric_key_t encsym;
  char *ret;
  if (fileid<0)
    return (char *)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_FILE_NOT_FOUND));
  encsym=psync_crypto_get_file_enc_key(fileid, hash, 0);
  if (psync_crypto_is_error(encsym))
    return (char *)encsym;
  ret=(char *)psync_base64_encode(encsym->data, encsym->datalen, keylen);
  psync_free(encsym);
  return ret;
}

char *psync_cloud_crypto_get_new_encoded_key(uint32_t flags, size_t *keylen){
  psync_encrypted_symmetric_key_t encsym;
  sym_key_ver1 sym;
  char *ret;
  if (!crypto_started_un)
    return (char *)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  sym.type=PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC;
  sym.flags=flags;
  psync_ssl_rand_strong(sym.hmackey, PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  psync_ssl_rand_strong(sym.aeskey, PSYNC_AES256_KEY_SIZE);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l){
    pthread_rwlock_unlock(&crypto_lock);
    return (char *)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  }
  encsym=psync_ssl_rsa_encrypt_data(crypto_pubkey, (unsigned char *)&sym, sizeof(sym));
  pthread_rwlock_unlock(&crypto_lock);
  if (encsym==PSYNC_INVALID_ENC_SYM_KEY){
    debug(D_ERROR, "RSA encryption failed");
    return (char *)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_RSA_ERROR));
  }
  psync_ssl_memclean(&sym, sizeof(sym));
  ret=(char *)psync_base64_encode(encsym->data, encsym->datalen, keylen);
  psync_free(encsym);
  return ret;
}

char *psync_cloud_crypto_get_new_encoded_and_plain_key(uint32_t flags, size_t *keylen, psync_symmetric_key_t *deckey){
  psync_encrypted_symmetric_key_t encsym;
  sym_key_ver1 sym;
  char *ret;
  if (!crypto_started_un)
    return (char *)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  sym.type=PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC;
  sym.flags=flags;
  psync_ssl_rand_strong(sym.hmackey, PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  psync_ssl_rand_strong(sym.aeskey, PSYNC_AES256_KEY_SIZE);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l){
    pthread_rwlock_unlock(&crypto_lock);
    return (char *)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED));
  }
  encsym=psync_ssl_rsa_encrypt_data(crypto_pubkey, (unsigned char *)&sym, sizeof(sym));
  pthread_rwlock_unlock(&crypto_lock);
  if (encsym==PSYNC_INVALID_ENC_SYM_KEY){
    debug(D_ERROR, "RSA encryption failed");
    return (char *)err_to_ptr(PRINT_RETURN_CONST(PSYNC_CRYPTO_RSA_ERROR));
  }
  *deckey=psync_crypto_sym_key_ver1_to_sym_key(&sym);
  psync_ssl_memclean(&sym, sizeof(sym));
  ret=(char *)psync_base64_encode(encsym->data, encsym->datalen, keylen);
  psync_free(encsym);
  return ret;
}

int psync_cloud_crypto_mkdir(psync_folderid_t folderid, const char *name, const char **err, psync_folderid_t *newfolderid){
  sym_key_ver1 sym;
  psync_encrypted_symmetric_key_t encsym;
  unsigned char *b64encsym;
  size_t b64encsymlen;
  char *ename;
  int ret;
  if (!crypto_started_un)
    return set_err(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED), err);
  ename=NULL;
  sym.type=PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC;
  sym.flags=PSYNC_CRYPTO_SYM_FLAG_ISDIR;
  psync_ssl_rand_strong(sym.hmackey, PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  psync_ssl_rand_strong(sym.aeskey, PSYNC_AES256_KEY_SIZE);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l){
    pthread_rwlock_unlock(&crypto_lock);
    return set_err(PRINT_RETURN_CONST(PSYNC_CRYPTO_NOT_STARTED), err);
  }
  encsym=psync_ssl_rsa_encrypt_data(crypto_pubkey, (unsigned char *)&sym, sizeof(sym));
  psync_ssl_memclean(&sym, sizeof(sym));
  ret=get_name_for_folder_locked(folderid, name, &ename, err);
  pthread_rwlock_unlock(&crypto_lock);
  if (ret){
    if (encsym!=PSYNC_INVALID_ENC_SYM_KEY)
      psync_free(encsym);
    return ret;
  }
  if (encsym==PSYNC_INVALID_ENC_SYM_KEY){
    psync_free(ename);
    debug(D_ERROR, "RSA encryption failed");
    return set_err(PRINT_RETURN_CONST(PSYNC_CRYPTO_RSA_ERROR), err);
  }
  b64encsym=psync_base64_encode(encsym->data, encsym->datalen, &b64encsymlen);
  ret=psync_cloud_crypto_send_mkdir(folderid, ename, err, (char *)b64encsym, b64encsymlen, encsym, newfolderid);
  psync_free(encsym);
  psync_free(ename);
  psync_free(b64encsym);
  return ret;
}

int psync_pcloud_crypto_reencode_key(const unsigned char *rsapub, size_t rsapublen, const unsigned char *rsapriv, size_t rsaprivlen, const char *oldpassphrase,
                                       const char *newpassphrase, uint32_t flags, char **privenc, char **sign) {
  psync_rsa_publickey_t pub;
  psync_rsa_privatekey_t priv;
  unsigned char *newpriv;
  unsigned char newprivsha[PSYNC_SHA256_DIGEST_LEN];
  psync_rsa_signature_t rsasign;
  size_t newprivlen, dummy;
  if (unlikely(rsapublen<=sizeof(uint32_t) || rsaprivlen<=sizeof(uint32_t)))
    goto err_bk_0;

  switch (*((uint32_t *)rsapub)){
    case PSYNC_CRYPTO_PUB_TYPE_RSA4096:
      if (offsetof(pub_key_ver1, key)>=rsapublen)
        goto err_bk_0;
      pub=psync_ssl_rsa_load_public(rsapub+offsetof(pub_key_ver1, key), rsapublen-offsetof(pub_key_ver1, key));
      if (pub==PSYNC_INVALID_RSA)
        goto err_bk_0;
      break;
    default:
      goto err_bk_0;
  }

  newpriv=NULL;
  newprivlen=0;

  switch (*((uint32_t *)rsapriv)){
    case PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT:{
      psync_crypto_aes256_ctr_encoder_decoder_t enc;
      psync_symmetric_key_t aeskey;
      priv_key_ver1 *rsapriv_struct;
      unsigned char *rsaprivdec;
      if (offsetof(priv_key_ver1, key)>=rsaprivlen)
        goto err_bk_1;
      rsapriv_struct=(priv_key_ver1 *)rsapriv;
      aeskey=psync_ssl_gen_symmetric_key_from_pass(oldpassphrase, PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE,
                                                     rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, 20000);
      if (unlikely(aeskey==PSYNC_INVALID_SYM_KEY))
        goto err_nm_1;
      rsaprivlen-=offsetof(priv_key_ver1, key);
      enc=psync_crypto_aes256_ctr_encoder_decoder_create(aeskey);
      psync_ssl_free_symmetric_key(aeskey);
      if (unlikely(enc==PSYNC_CRYPTO_INVALID_ENCODER))
        goto err_nm_1;
      rsaprivdec=(unsigned char *)psync_malloc(rsaprivlen);
      if (unlikely(!rsaprivdec)){
        psync_crypto_aes256_ctr_encoder_decoder_free(enc);
        goto err_nm_1;
      }
      memcpy(rsaprivdec, rsapriv_struct->key, rsaprivlen);
      psync_crypto_aes256_ctr_encode_decode_inplace(enc, rsaprivdec, rsaprivlen, 0);
      psync_crypto_aes256_ctr_encoder_decoder_free(enc);
      newpriv=(unsigned char *)psync_malloc(offsetof(priv_key_ver1, key)+rsaprivlen);
      if (unlikely(!newpriv))
        goto err_nm_1;
      rsapriv_struct=(priv_key_ver1 *)newpriv;
      rsapriv_struct->type=PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
      rsapriv_struct->flags=flags;
      psync_ssl_rand_weak(rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
      aeskey=psync_ssl_gen_symmetric_key_from_pass(newpassphrase, PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE,
                                                     rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, 20000);
      if (unlikely(aeskey==PSYNC_INVALID_SYM_KEY))
        goto err_nm_1;
			//rsaprivlen-=offsetof(priv_key_ver1, key);
      enc=psync_crypto_aes256_ctr_encoder_decoder_create(aeskey);
      psync_ssl_free_symmetric_key(aeskey);
      if (unlikely(enc==PSYNC_CRYPTO_INVALID_ENCODER))
        goto err_nm_1;
      memcpy(rsapriv_struct->key, rsaprivdec, rsaprivlen);
      psync_crypto_aes256_ctr_encode_decode_inplace(enc, rsapriv_struct->key, rsaprivlen, 0);
      psync_crypto_aes256_ctr_encoder_decoder_free(enc);
      newprivlen=offsetof(priv_key_ver1, key)+rsaprivlen;
      priv=psync_ssl_rsa_load_private(rsaprivdec, rsaprivlen);
      psync_ssl_memclean(rsaprivdec, rsaprivlen);
      psync_free(rsaprivdec);
      if (unlikely(priv==PSYNC_INVALID_RSA))
        goto err_ph_1;   
      break;
    }
    default:
      goto err_bk_1;
  }

  if (!crypto_keys_match(pub, priv))
    goto err_ph_2;
  psync_sha256(newpriv, newprivlen, newprivsha);
  rsasign=psync_ssl_rsa_sign_sha256_hash(priv, newprivsha);
  if (psync_crypto_is_error(rsasign)){
    psync_free(newpriv);
    psync_ssl_rsa_free_public(pub);
    psync_ssl_rsa_free_private(priv);
    return psync_crypto_to_error(rsasign);
  }
  *privenc=(char *)psync_base64_encode(newpriv, newprivlen, &dummy);
  *sign=(char *)psync_base64_encode(rsasign->data, rsasign->datalen, &dummy);
  psync_free(rsasign);
  psync_free(newpriv);
  psync_ssl_rsa_free_public(pub);
  psync_ssl_rsa_free_private(priv);

  if (!*privenc || !*sign){
    psync_free(*privenc);
    psync_free(*sign);
    return PERROR_NO_MEMORY;
  }

  return PSYNC_CRYPTO_SUCCESS;
err_bk_1:
  psync_ssl_rsa_free_public(pub);
err_bk_0:
  return PSYNC_CRYPTO_BAD_KEY;
err_nm_1:
  psync_free(newpriv);
  psync_ssl_rsa_free_public(pub);
  return PERROR_NO_MEMORY;
err_ph_2:
  psync_ssl_rsa_free_private(priv);
err_ph_1:
  psync_free(newpriv);
  psync_ssl_rsa_free_public(pub);
  return PSYNC_CRYPTO_BAD_PASSPHRASE;
}

int psync_pcloud_crypto_encode_key(const char *newpassphrase, uint32_t flags, char **privenc, char **sign){
  unsigned char *newpriv;
  priv_key_ver1 *rsapriv_struct;
  psync_binary_rsa_key_t rsapriv;
  psync_crypto_aes256_ctr_encoder_decoder_t enc;
  psync_symmetric_key_t aeskey;
  size_t rsaprivlen, dummy;
  unsigned char newprivsha[PSYNC_SHA256_DIGEST_LEN];
  psync_rsa_signature_t rsasign;
  rsapriv=psync_ssl_rsa_private_to_binary(crypto_privkey);
  if (rsapriv==PSYNC_INVALID_RSA)
    goto err_nm_0;
  rsaprivlen=rsapriv->datalen;
  newpriv=(unsigned char *)psync_malloc(offsetof(priv_key_ver1, key)+rsaprivlen);
  if (unlikely(!newpriv))
    goto err_nm_1;
  rsapriv_struct=(priv_key_ver1 *)newpriv;
  rsapriv_struct->type=PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
  rsapriv_struct->flags=flags;
  psync_ssl_rand_weak(rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
  aeskey=psync_ssl_gen_symmetric_key_from_pass(newpassphrase, PSYNC_AES256_KEY_SIZE+PSYNC_AES256_BLOCK_SIZE,
                                                 rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, 20000);
  if (unlikely(aeskey==PSYNC_INVALID_SYM_KEY))
    goto err_nm_1;
  enc=psync_crypto_aes256_ctr_encoder_decoder_create(aeskey);
  psync_ssl_free_symmetric_key(aeskey);
  if (unlikely(enc==PSYNC_CRYPTO_INVALID_ENCODER))
    goto err_nm_1;
  memcpy(rsapriv_struct->key, rsapriv->data, rsaprivlen);
  psync_crypto_aes256_ctr_encode_decode_inplace(enc, rsapriv_struct->key, rsaprivlen, 0);
  psync_crypto_aes256_ctr_encoder_decoder_free(enc);
  rsaprivlen+=offsetof(priv_key_ver1, key);

  psync_sha256(newpriv, rsaprivlen, newprivsha);
  rsasign=psync_ssl_rsa_sign_sha256_hash(crypto_privkey, newprivsha);
  if (psync_crypto_is_error(rsasign)){
    psync_free(newpriv);
    psync_ssl_rsa_free_binary(rsapriv);
    return psync_crypto_to_error(rsasign);
  }
  *privenc=(char *)psync_base64_encode(newpriv, rsaprivlen, &dummy);
  *sign=(char *)psync_base64_encode(rsasign->data, rsasign->datalen, &dummy);
  psync_free(rsasign);
  psync_free(newpriv);
  psync_ssl_rsa_free_binary(rsapriv);

  if (!*privenc || !*sign){
    psync_free(*privenc);
    psync_free(*sign);
    return PERROR_NO_MEMORY;
  }

  return PSYNC_CRYPTO_SUCCESS;

err_nm_1:
  psync_free(newpriv);
  psync_ssl_rsa_free_binary(rsapriv);
err_nm_0:
  return PERROR_NO_MEMORY;
}

int  psync_crypto_change_passphrase(const char* oldpassphrase, const char* newpassphrase, uint32_t flags, char** privenc, char** sign){
  unsigned char *pubkey=NULL;
  unsigned char *privkey=NULL;
  unsigned char *salt=NULL;
  priv_key_ver1 *privatekey_struct=NULL;
  pub_key_ver1 *pubkey_struct=NULL;  
  size_t pubkeylen=0, privkeylen=0, saltlen=0;
  int cres;
  psync_sql_res *res;
  psync_variant_row row;
  const char *id;
  uint32_t rowcnt;
  binresult *bres;
  uint64_t result;
  const binresult *data;

  if (!newpassphrase||!newpassphrase[0])
    return PSYNC_CRYPTO_BAD_PASSPHRASE;  
retry:
  if (psync_sql_trylock()){
    psync_milisleep(1);
    goto retry;
  }
  rowcnt=0;
  res=psync_sql_query_nolock("SELECT id, value FROM setting WHERE id IN ('crypto_private_key', 'crypto_public_key', 'crypto_private_salt') ORDER BY id");
  if (res){
    while ((row=psync_sql_fetch_row(res))){
			id=psync_get_string(row[0]);
			rowcnt++;
			if (!strcmp(id, "crypto_private_key")){
				load_str_to(&row[1], &privkey, &privkeylen);
				privatekey_struct=(priv_key_ver1*)psync_malloc(offsetof(priv_key_ver1, key)+privkeylen);
				memset(privatekey_struct, 0, offsetof(priv_key_ver1, key)+privkeylen);
				memcpy(privatekey_struct->key, privkey, privkeylen);
				privatekey_struct->type=PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
				psync_free(privkey);
			}else if (!strcmp(id, "crypto_public_key")){
				load_str_to(&row[1], &pubkey, &pubkeylen);
				pubkey_struct=(pub_key_ver1*)psync_malloc(offsetof(pub_key_ver1, key)+pubkeylen);
				memset(pubkey_struct, 0, offsetof(pub_key_ver1, key)+pubkeylen);
				memcpy(pubkey_struct->key, pubkey, pubkeylen);
				pubkey_struct->type=PSYNC_CRYPTO_PUB_TYPE_RSA4096;
				psync_free(pubkey);
			}else if (!strcmp(id, "crypto_private_salt")){
				load_str_to(&row[1], &salt, &saltlen);
				if (!privatekey_struct){
					debug(D_ERROR, "Private key struct is not initialized yet and the salt can't be copied to it");
					continue;
				}
				memcpy(privatekey_struct->salt, salt, saltlen);
				psync_free(salt);
			}
    }
    psync_sql_free_result(res);
  }
  psync_sql_unlock();
  if (rowcnt<3){
    psync_free(privatekey_struct);
    psync_free(pubkey_struct);
    if (!psync_my_auth[0])
      return PERROR_NET_ERROR;
    debug(D_NOTICE, "downloading keys");
    bres=psync_get_keys_bin_auth(psync_my_auth);
    if (unlikely(!bres)){
      cres=PERROR_NET_ERROR;
      goto ex;
    }
    result=psync_find_result(bres, "result", PARAM_NUM)->num;
    if (unlikely(result)){
      debug(D_WARNING, "crypto_getuserkeys returned error %d: %s", (int)result, psync_find_result(bres, "error", PARAM_STR)->str);
      psync_free(bres);
      cres=(int)result;
      goto ex;
    }
    debug(D_NOTICE, "downloaded user keys");
    data=psync_find_result(bres, "privatekey", PARAM_STR);
    privkey=psync_base64_decode((const unsigned char *)data->str, data->length, &privkeylen);
    data=psync_find_result(bres, "publickey", PARAM_STR);
    pubkey=psync_base64_decode((const unsigned char *)data->str, data->length, &pubkeylen);
    data=psync_find_result(bres, "salt", PARAM_STR);
    salt=psync_base64_decode((const unsigned char *)data->str, data->length, &saltlen);    
    psync_free(bres);
    if (unlikely(!privkey || !pubkey)){
      psync_free(privkey);
      psync_free(pubkey);
      cres=PERROR_NO_MEMORY;
      goto ex;
    }
    memcpy(((priv_key_ver1*)privkey)->salt, salt, saltlen);
    cres=psync_pcloud_crypto_reencode_key(pubkey, pubkeylen, privkey, privkeylen, oldpassphrase, newpassphrase, flags, privenc, sign);
    psync_free(pubkey);
    psync_free(privkey);
    psync_free(salt);
    if (cres)
			goto ex;
  }
  else{
		assert(rowcnt==3);
		cres=psync_pcloud_crypto_reencode_key((unsigned char *)pubkey_struct, pubkeylen+offsetof(pub_key_ver1, key), (unsigned char *)privatekey_struct, privkeylen+offsetof(priv_key_ver1, key), oldpassphrase, newpassphrase, flags, privenc, sign);
		psync_free(privatekey_struct);
		psync_free(pubkey_struct);
    if (cres)
			goto ex;
  }

ex:
  return cres;
}

int psync_crypto_change_passphrase_unlocked(const char *newpassphrase, uint32_t flags, char **privenc, char **sign){
  int cres;
  if (unlikely(!psync_cloud_crypto_isstarted())){
    return PSYNC_CRYPTO_NOT_STARTED;
  }
  if (!newpassphrase||!newpassphrase[0])
    return PSYNC_CRYPTO_BAD_PASSPHRASE;
  cres=psync_pcloud_crypto_encode_key(newpassphrase, flags, privenc, sign);
  return cres;
}

void sha1_hex_null_term(const void *data, size_t len, char *out){
  unsigned char sha1bin[PSYNC_SHA1_DIGEST_LEN];
  psync_sha1((const unsigned char *)data, len, (unsigned char *)sha1bin);
  psync_binhex(out, sha1bin, PSYNC_SHA1_DIGEST_LEN);
  out[PSYNC_SHA1_DIGEST_HEXLEN]=0;
}