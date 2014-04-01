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

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <pthread.h>
#include "pssl.h"
#include "psynclib.h"
#include "plibs.h"
#include "psslcerts.h"
#include "psettings.h"

static SSL_CTX *globalctx=NULL;

static pthread_mutex_t *olocks;

PSYNC_THREAD int psync_ssl_errno;

void openssl_locking_callback(int mode, int type, const char *file, int line){
  if (mode&CRYPTO_LOCK)
    pthread_mutex_lock(&(olocks[type]));
  else
    pthread_mutex_unlock(&(olocks[type]));
}

void openssl_thread_id(CRYPTO_THREADID *id){
  static PSYNC_THREAD int i;
  CRYPTO_THREADID_set_pointer(id, &i);
}

static void openssl_thread_setup(){
  int i, n;
  n=CRYPTO_num_locks();
  olocks=psync_new_cnt(pthread_mutex_t, n);
  for (i=0; i<n; i++)
    pthread_mutex_init(&olocks[i], NULL);
  CRYPTO_THREADID_set_callback(openssl_thread_id);
  CRYPTO_set_locking_callback(openssl_locking_callback);
}

int psync_ssl_init(){
  BIO *bio;
  X509 *cert;
  psync_uint_t i;
  unsigned char seed[PSYNC_HASH_DIGEST_LEN];
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  SSL_load_error_strings();
  openssl_thread_setup();
  globalctx=SSL_CTX_new(SSLv23_method());
  if (globalctx){
    for (i=0; i<ARRAY_SIZE(psync_ssl_trusted_certs); i++){
      bio=BIO_new(BIO_s_mem());
      BIO_puts(bio, psync_ssl_trusted_certs[i]);
      cert=PEM_read_bio_X509(bio, NULL, NULL, NULL);
      BIO_free(bio);
      if (likely_log(cert!=NULL)){
        X509_STORE_add_cert(SSL_CTX_get_cert_store(globalctx), cert);
        X509_free(cert);
      }
    }
    do {
      psync_get_random_seed(seed, NULL, 0);
      RAND_seed(seed, PSYNC_HASH_DIGEST_LEN);
    } while (!RAND_status());
    return 0;
  }
  else
    return -1;
}

static void psync_set_ssl_error(int err){
  if (err==SSL_ERROR_WANT_READ)
    psync_ssl_errno=PSYNC_SSL_ERR_WANT_READ;
  else if (err==SSL_ERROR_WANT_WRITE)
    psync_ssl_errno=PSYNC_SSL_ERR_WANT_WRITE;
  else
    psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
}

static int psync_ssl_verify_cert(SSL *ssl, const char *hostname){
  X509 *cert;
  char buff[256];
  if (unlikely_log(SSL_get_verify_result(ssl)!=X509_V_OK))
    return -1;
  if (hostname){
    cert=SSL_get_peer_certificate(ssl);
    if (unlikely_log(!cert))
      return -1;
    if (unlikely_log(X509_NAME_get_text_by_NID(X509_get_subject_name(cert), OBJ_txt2nid("commonName"), buff, sizeof(buff))==-1))
      return -1;
    debug(D_NOTICE, "got certificate with commonName: %s", buff);
    if (psync_match_pattern(hostname, buff, strlen(buff)))
      return 0;
    else{
      debug(D_WARNING, "hostname %s does not match certificate common name %s", hostname, buff);
      return -1;
    }
  }
  return 0;
}

int psync_ssl_connect(psync_socket_t sock, void **sslconn, const char *hostname){
  SSL *ssl;
  int res, err;
  ssl=SSL_new(globalctx);
  if (!ssl)
    return PSYNC_SSL_FAIL;
  SSL_set_fd(ssl, sock);
  res=SSL_connect(ssl);
  if (res==1){
    if (unlikely(psync_ssl_verify_cert(ssl, hostname)))
      goto fail;
    *sslconn=ssl;
    return PSYNC_SSL_SUCCESS;
  }
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(err);
  if (likely_log(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE)){
    *sslconn=ssl;
    return PSYNC_SSL_NEED_FINISH;
  }
fail:
  SSL_free(ssl);
  return PSYNC_SSL_FAIL;
}

int psync_ssl_connect_finish(void *sslconn, const char *hostname){
  SSL *ssl;
  int res, err;
  ssl=(SSL *)sslconn;
  res=SSL_connect(ssl);
  if (res==1){
    if (unlikely(psync_ssl_verify_cert(ssl, hostname)))
      goto fail;
    return PSYNC_SSL_SUCCESS;
  }
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(err);
  if (likely_log(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
fail:
  SSL_free(ssl);
  return PSYNC_SSL_FAIL;
}

int psync_ssl_shutdown(void *sslconn){
  SSL *ssl;
  int res, err;
  ssl=(SSL *)sslconn;
  res=SSL_shutdown(ssl);
  if (res!=-1){
    SSL_free(ssl);
    return PSYNC_SSL_SUCCESS;
  }
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(err);
  if (likely_log(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
  SSL_free(ssl);
  return PSYNC_SSL_SUCCESS;
}

void psync_ssl_free(void *sslconn){
  SSL_free((SSL *)sslconn);
}

int psync_ssl_pendingdata(void *sslconn){
  return SSL_pending((SSL *)sslconn);
}

int psync_ssl_read(void *sslconn, void *buf, int num){
  SSL *ssl;
  int res, err;
  ssl=(SSL *)sslconn;
  res=SSL_read(ssl, buf, num);
  if (res>=0)
    return res;
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(err);
  return PSYNC_SSL_FAIL;
}

int psync_ssl_write(void *sslconn, const void *buf, int num){
  SSL *ssl;
  int res, err;
  ssl=(SSL *)sslconn;
  res=SSL_write(ssl, buf, num);
  if (res>=0)
    return res;
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(err);
  return PSYNC_SSL_FAIL;
}

void psync_ssl_rand_strong(unsigned char *buf, int num){
  static int seeds=0;
  int ret;
  if (seeds<5){
    unsigned char seed[PSYNC_HASH_DIGEST_LEN];
    psync_get_random_seed(seed, NULL, 0);
    RAND_seed(seed, PSYNC_HASH_DIGEST_LEN);
    seeds++;
  }
  ret=RAND_bytes(buf, num);
  if (unlikely(ret==0)){
    unsigned char seed[PSYNC_HASH_DIGEST_LEN];
    psync_uint_t cnt;
    cnt=0;
    while (ret==0 && cnt++<20){
      psync_get_random_seed(seed, NULL, 0);
      RAND_seed(seed, PSYNC_HASH_DIGEST_LEN);
      ret=RAND_bytes(buf, num);
    }
  }
  if (unlikely(ret!=1)){
    debug(D_CRITICAL, "could not generate %d random bytes, error %s, exiting", num, ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
}

void psync_ssl_rand_weak(unsigned char *buf, int num){
  int ret;
  ret=RAND_pseudo_bytes(buf, num);
  if (unlikely(ret==-1)){
    debug(D_CRITICAL, "could not generate %d weak random bytes, error %s, exiting", num, ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  else if (unlikely(ret==0))
    debug(D_WARNING, "RAND_pseudo_bytes returned weak numbers");
}

psync_rsa_t psync_ssl_gen_rsa(int bits){
  RSA *rsa;
  BIGNUM *bn;
  unsigned char seed[PSYNC_HASH_DIGEST_LEN];
  psync_get_random_seed(seed, seed, sizeof(seed));
  RAND_seed(seed, PSYNC_HASH_DIGEST_LEN);
  rsa=RSA_new();
  if (unlikely_log(!rsa))
    goto err0;
  bn=BN_new();
  if (unlikely_log(!bn))
    goto err1;
  if (unlikely_log(!BN_set_word(bn, RSA_F4)))
    goto err2;
  if (!RSA_generate_key_ex(rsa, bits, bn, NULL))
    goto err2;
  BN_free(bn);
  return rsa;
err2:
  BN_free(bn);
err1:
  RSA_free(rsa);
err0:
  return PSYNC_INVALID_RSA;
}

void psync_ssl_free_rsa(psync_rsa_t rsa){
  RSA_free(rsa);
}

psync_rsa_publickey_t psync_ssl_rsa_get_public(psync_rsa_t rsa){
  return RSAPublicKey_dup(rsa);
}

void psync_ssl_rsa_free_public(psync_rsa_publickey_t key){
  RSA_free(key);
}

psync_rsa_privatekey_t psync_ssl_rsa_get_private(psync_rsa_t rsa){
  return RSAPrivateKey_dup(rsa);
}

void psync_ssl_rsa_free_private(psync_rsa_privatekey_t key){
  RSA_free(key);
}

psync_binary_rsa_key_t psync_ssl_rsa_public_to_binary(psync_rsa_publickey_t rsa){
  psync_binary_rsa_key_t ret;
  unsigned char *p;
  int len;
  len=i2d_RSAPublicKey(rsa, NULL);
  if (unlikely_log(len<0))
    return PSYNC_INVALID_BIN_RSA;
  ret=psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+len);
  ret->datalen=len;
  p=ret->data;
  if (unlikely_log(i2d_RSAPublicKey(rsa, &p)!=len)){
    psync_free(ret);
    return PSYNC_INVALID_BIN_RSA;
  }
  return ret;
}

psync_binary_rsa_key_t psync_ssl_rsa_private_to_binary(psync_rsa_privatekey_t rsa){
  psync_binary_rsa_key_t ret;
  unsigned char *p;
  int len;
  len=i2d_RSAPrivateKey(rsa, NULL);
  if (unlikely_log(len<0))
    return PSYNC_INVALID_BIN_RSA;
  ret=psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+len);
  ret->datalen=len;
  p=ret->data;
  if (unlikely_log(i2d_RSAPrivateKey(rsa, &p)!=len)){
    psync_free(ret);
    return PSYNC_INVALID_BIN_RSA;
  }
  return ret;
}

psync_rsa_publickey_t psync_ssl_rsa_binary_to_public(psync_binary_rsa_key_t bin){
  const unsigned char *p=bin->data;
  return d2i_RSAPublicKey(NULL, &p, bin->datalen);
}

psync_rsa_privatekey_t psync_ssl_rsa_binary_to_private(psync_binary_rsa_key_t bin){
  const unsigned char *p=bin->data;
  return d2i_RSAPrivateKey(NULL, &p, bin->datalen);
}

psync_symmetric_key_t psync_ssl_gen_symmetric_key_from_pass(const char *password, size_t keylen, const char *salt, size_t saltlen){
  psync_symmetric_key_t key=(psync_symmetric_key_t)psync_malloc(keylen+offsetof(psync_symmetric_key_struct_t, key));
  key->keylen=keylen;
  PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (const unsigned char *)salt, 
                                saltlen, PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS, keylen, key->key);
  return key;
}

psync_encrypted_symmetric_key_t psync_ssl_rsa_encrypt_symmetric_key(psync_rsa_publickey_t rsa, const psync_symmetric_key_t key){
  psync_encrypted_symmetric_key_t ret;
  int len;
  ret=(psync_encrypted_symmetric_key_t)psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+RSA_size(rsa));
  len=RSA_public_encrypt(key->keylen, key->key, ret->data, rsa, RSA_PKCS1_OAEP_PADDING);
  if (unlikely_log(len==-1)){
    psync_free(ret);
    return PSYNC_INVALID_ENC_SYM_KEY;
  }
  ret->datalen=len;
  return ret;
}

psync_symmetric_key_t psync_ssl_rsa_decrypt_symmetric_key(psync_rsa_privatekey_t rsa, const psync_encrypted_symmetric_key_t enckey){
  unsigned char buff[2048];
  psync_symmetric_key_t ret;
  int len;
  len=RSA_private_decrypt(enckey->datalen, enckey->data, buff, rsa, RSA_PKCS1_OAEP_PADDING);
  if (unlikely_log(len==-1))
    return PSYNC_INVALID_SYM_KEY;
  ret=(psync_symmetric_key_t)psync_malloc(offsetof(psync_symmetric_key_struct_t, key)+len);
  ret->keylen=len;
  memcpy(ret->key, buff, len);
  return ret;
}

psync_aes256_encoder psync_ssl_aes256_create_encoder(psync_symmetric_key_t key){
  AES_KEY *aes;
  assert(key->keylen>=PSYNC_AES256_KEY_SIZE);
  aes=psync_new(AES_KEY);
  AES_set_encrypt_key(key->key, 256, aes);
  return aes;
}

void psync_ssl_aes256_free_encoder(psync_aes256_encoder aes){
  memset(aes, 0, sizeof(AES_KEY));
  psync_free(aes);
}

psync_aes256_encoder psync_ssl_aes256_create_decoder(psync_symmetric_key_t key){
  AES_KEY *aes;
  assert(key->keylen>=PSYNC_AES256_KEY_SIZE);
  aes=psync_new(AES_KEY);
  AES_set_decrypt_key(key->key, 256, aes);
  return aes;
}

void psync_ssl_aes256_free_decoder(psync_aes256_encoder aes){
  memset(aes, 0, sizeof(AES_KEY));
  psync_free(aes);
}
