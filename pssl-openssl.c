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

#include "plibs.h"
#include "pssl.h"
#include "psynclib.h"
#include "psslcerts.h"
#include "psettings.h"
#include "pcache.h"
#include "ptimer.h"
#include "pmemlock.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <pthread.h>

#define SSL_CIPHERS \
  "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"\
  "DHE-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-GCM-SHA384:"\
  "ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:"\
  "AES256-GCM-SHA384:AES256-SHA256;"


#if defined(PSYNC_AES_HW_MSC)
#include <intrin.h>
#include <wmmintrin.h>
#endif

typedef struct {
  SSL *ssl;
  int isbroken;
  char cachekey[];
} ssl_connection_t;

static SSL_CTX *globalctx=NULL;
static pthread_mutex_t *olocks;

#if defined(PSYNC_AES_HW)
int psync_ssl_hw_aes;
#endif

PSYNC_THREAD int psync_ssl_errno;

static void openssl_locking_callback(int mode, int type, const char *file, int line){
  if (mode&CRYPTO_LOCK)
    pthread_mutex_lock(&(olocks[type]));
  else
    pthread_mutex_unlock(&(olocks[type]));
}

static void openssl_thread_id(CRYPTO_THREADID *id){
  CRYPTO_THREADID_set_pointer(id, &psync_ssl_errno);
}

static int openssl_locking_default(int *num, int cnt, int type, const char *file, int line){
  openssl_locking_callback(CRYPTO_LOCK|CRYPTO_WRITE, type, file, line);
  cnt+=*num;
  *num=cnt;
  openssl_locking_callback(CRYPTO_UNLOCK|CRYPTO_WRITE, type, file, line);
  return cnt;
}

static int openssl_locking_add(int *num, int cnt, int type, const char *file, int line){
#if defined(P_OS_WINDOWS)
  if (sizeof(LONG)==sizeof(int))
    return _InterlockedAdd(num, cnt);
  else
    return openssl_locking_default(num, cnt, type, file, line);
#elif defined(__GNUC__)
  if (1)
    return __sync_add_and_fetch(num, cnt);
  else
    return openssl_locking_default(num, cnt, type, file, line);
#else
  return openssl_locking_default(num, cnt, type, file, line);
#endif
}

static void openssl_thread_setup(){
  int i, n;
  n=CRYPTO_num_locks();
  olocks=psync_new_cnt(pthread_mutex_t, n);
  for (i=0; i<n; i++)
    pthread_mutex_init(&olocks[i], NULL);
  CRYPTO_THREADID_set_callback(openssl_thread_id);
  CRYPTO_set_locking_callback(openssl_locking_callback);
  CRYPTO_set_add_lock_callback(openssl_locking_add);
}

#if defined(PSYNC_AES_HW_GCC)
static int psync_ssl_detect_aes_hw(){
  uint32_t eax, ecx;
  eax=1;
  __asm__("cpuid" 
          : "=c"(ecx)
          : "a"(eax)
          : "%ebx", "%edx");
  ecx=(ecx>>25)&1;
  if (ecx)
    debug(D_NOTICE, "hardware AES support detected");
  else
    debug(D_NOTICE, "hardware AES support not detected");
  return ecx;
}
#elif defined(PSYNC_AES_HW_MSC)
static int psync_ssl_detect_aes_hw(){
  int info[4];
  int ret;
  __cpuid(info, 1);
  ret=(info[2]>>25)&1;
  if (ret)
    debug(D_NOTICE, "hardware AES support detected");
  else
    debug(D_NOTICE, "hardware AES support not detected");
  return ret;
}
#endif

int psync_ssl_init(){
  BIO *bio;
  X509 *cert;
  psync_uint_t i;
  unsigned char seed[PSYNC_LHASH_DIGEST_LEN];
#if defined(PSYNC_AES_HW)
  psync_ssl_hw_aes=psync_ssl_detect_aes_hw();
#else
  debug(D_NOTICE, "hardware AES is not supported for this compiler");
#endif
  if (!CRYPTO_set_locked_mem_functions(psync_locked_malloc, psync_locked_free))
    debug(D_WARNING, "failed to set locked functions for OpenSSL");
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  SSL_load_error_strings();
  openssl_thread_setup();
  globalctx=SSL_CTX_new(TLSv1_2_client_method());
  if (likely_log(globalctx)){
    if (unlikely_log(SSL_CTX_set_cipher_list(globalctx, SSL_CIPHERS)!=1)){
      SSL_CTX_free(globalctx);
      globalctx=NULL;
      return -1;
    }
    SSL_CTX_set_verify(globalctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_read_ahead(globalctx, 0); // readahed breaks SSL_Pending 
    SSL_CTX_set_session_cache_mode(globalctx, SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_set_options(globalctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_mode(globalctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_mode(globalctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
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
      psync_get_random_seed(seed, NULL, 0, 0);
      RAND_seed(seed, PSYNC_LHASH_DIGEST_LEN);
    } while (!RAND_status());
    return 0;
  }
  else
    return -1;
}

void psync_ssl_memclean(void *ptr, size_t len){
  OPENSSL_cleanse(ptr, len);
}

static void psync_set_ssl_error(ssl_connection_t *conn, int err){
  if (err==SSL_ERROR_WANT_READ)
    psync_ssl_errno=PSYNC_SSL_ERR_WANT_READ;
  else if (err==SSL_ERROR_WANT_WRITE)
    psync_ssl_errno=PSYNC_SSL_ERR_WANT_WRITE;
  else{
    psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
    conn->isbroken=1;
    debug(D_NOTICE, "got error %d from OpenSSL: %s", err, ERR_error_string(err, NULL));
  }
}

// Returns non-zero when CN and hostname match.
// Does case sensititive comparison, fine for now. Replace memcmp with str(n)casecmp if case insensitivity is needed
static int psync_ssl_compare_cn_hostname(const char *cn, size_t cnlen, const char *hostname, size_t hostnamelen){
  if (cn[0]=='*' && cn[1]=='.') // assumes valid null terminated string
    return cnlen<=hostnamelen &&
    !memcmp(cn+1, hostname+hostnamelen-cnlen+1, cnlen) && //this will also compare the null byte
    !memchr(hostname, '.', hostnamelen-cnlen+1);
  else
    return cnlen==hostnamelen && !memcmp(cn, hostname, cnlen);
}

static int psync_ssl_cn_match_hostname(X509 *cert, const char *hostname){
  X509_NAME *sname;
  X509_NAME_ENTRY *cnentry;
  ASN1_STRING *cnasn;
  const char *cnstr;
  size_t cnstrlen;
  int idx;
  sname=X509_get_subject_name(cert);
  if (unlikely_log(!sname))
    return -1;
  idx=X509_NAME_get_index_by_NID(sname, NID_commonName, -1);
  if (unlikely_log(idx<0))
    return -1;
  cnentry=X509_NAME_get_entry(sname, idx);
  if (unlikely_log(!cnentry))
    return -1;
  cnasn=X509_NAME_ENTRY_get_data(cnentry);
  if (unlikely_log(!cnasn))
    return -1;
  cnstr=(const char *)ASN1_STRING_data(cnasn);
  if (unlikely_log(!cnstr))
    return -1;
  cnstrlen=strlen(cnstr);
  if (unlikely_log(ASN1_STRING_length(cnasn)!=cnstrlen))
    return -1;
  debug(D_NOTICE, "got certificate with commonName: %s", cnstr);
  if (psync_ssl_compare_cn_hostname(cnstr, cnstrlen, hostname, strlen(hostname)))
    return 0;
  else{
    debug(D_WARNING, "hostname %s does not match certificate common name %s", hostname, cnstr);
    return -1;
  }
}

static int psync_ssl_verify_cert(SSL *ssl, const char *hostname){
  X509 *cert;
  int ret;
  if (unlikely_log(SSL_get_verify_result(ssl)!=X509_V_OK))
    return -1;
  cert=SSL_get_peer_certificate(ssl);
  if (unlikely_log(!cert))
    return -1;
  ret=psync_ssl_cn_match_hostname(cert, hostname);
  X509_free(cert);
  return ret;
}

static ssl_connection_t *psync_ssl_alloc_conn(SSL *ssl, const char *hostname){
  ssl_connection_t *conn;
  size_t len;
  len=strlen(hostname)+1;
  conn=(ssl_connection_t *)psync_malloc(offsetof(ssl_connection_t, cachekey)+len+4);
  conn->ssl=ssl;
  conn->isbroken=0;
  memcpy(conn->cachekey, "SSLS", 4);
  memcpy(conn->cachekey+4, hostname, len);
  return conn;
}

int psync_ssl_connect(psync_socket_t sock, void **sslconn, const char *hostname){
  ssl_connection_t *conn;
  SSL *ssl;
  SSL_SESSION *sess;
  int res, err;
  ssl=SSL_new(globalctx);
  if (!ssl)
    return PRINT_RETURN_CONST(PSYNC_SSL_FAIL);
  SSL_set_fd(ssl, sock);
  conn=psync_ssl_alloc_conn(ssl, hostname);
  if ((sess=(SSL_SESSION *)psync_cache_get(conn->cachekey))){
    debug(D_NOTICE, "reusing cached session for %s", hostname);
    SSL_set_session(ssl, sess);
    SSL_SESSION_free(sess);
  }
  res=SSL_connect(ssl);
  if (res==1){
    if (unlikely(psync_ssl_verify_cert(ssl, hostname)))
      goto fail;
    *sslconn=conn;
    if (IS_DEBUG && SSL_session_reused(ssl))
      debug(D_NOTICE, "successfully reused session");
    return PSYNC_SSL_SUCCESS;
  }
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(conn, err);
  if (likely_log(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE)){
    *sslconn=conn;
    return PSYNC_SSL_NEED_FINISH;
  }
fail:
  SSL_free(ssl);
  psync_free(conn);
  return PRINT_RETURN_CONST(PSYNC_SSL_FAIL);
}

int psync_ssl_connect_finish(void *sslconn, const char *hostname){
  ssl_connection_t *conn;
  int res, err;
  conn=(ssl_connection_t *)sslconn;
  res=SSL_connect(conn->ssl);
  if (res==1){
    if (unlikely(psync_ssl_verify_cert(conn->ssl, hostname)))
      goto fail;
    if (IS_DEBUG && SSL_session_reused(conn->ssl))
      debug(D_NOTICE, "successfully reused session");
    return PSYNC_SSL_SUCCESS;
  }
  err=SSL_get_error(conn->ssl, res);
  psync_set_ssl_error(conn, err);
  if (likely_log(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
fail:
  SSL_free(conn->ssl);
  psync_free(conn);
  return PRINT_RETURN_CONST(PSYNC_SSL_FAIL);
}

static void psync_ssl_free_session(void *ptr){
  SSL_SESSION_free((SSL_SESSION *)ptr);
}

int psync_ssl_shutdown(void *sslconn){
  ssl_connection_t *conn;
  SSL_SESSION *sess;
  int res, err;
  conn=(ssl_connection_t *)sslconn;
  sess=SSL_get1_session(conn->ssl);
  if (sess)
    psync_cache_add(conn->cachekey, sess, PSYNC_SSL_SESSION_CACHE_TIMEOUT, psync_ssl_free_session, PSYNC_MAX_SSL_SESSIONS_PER_DOMAIN);
  if (conn->isbroken)
    goto noshutdown;
  res=SSL_shutdown(conn->ssl);
  if (res!=-1)
    goto noshutdown;
  err=SSL_get_error(conn->ssl, res);
  psync_set_ssl_error(conn, err);
  if (likely_log(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
noshutdown:
  SSL_free(conn->ssl);
  psync_free(conn);
  return PSYNC_SSL_SUCCESS;
}

void psync_ssl_free(void *sslconn){
  ssl_connection_t *conn;
  conn=(ssl_connection_t *)sslconn;
  SSL_free(conn->ssl);
  psync_free(conn);
}

int psync_ssl_pendingdata(void *sslconn){
  return SSL_pending(((ssl_connection_t *)sslconn)->ssl);
}

int psync_ssl_read(void *sslconn, void *buf, int num){
  ssl_connection_t *conn;
  int res, err;
  conn=(ssl_connection_t *)sslconn;
  res=SSL_read(conn->ssl, buf, num);
  if (res>=0)
    return res;
  err=SSL_get_error(conn->ssl, res);
  psync_set_ssl_error(conn, err);
  return PSYNC_SSL_FAIL;
}

int psync_ssl_write(void *sslconn, const void *buf, int num){
  ssl_connection_t *conn;
  int res, err;
  conn=(ssl_connection_t *)sslconn;
  res=SSL_write(conn->ssl, buf, num);
  if (res>=0)
    return res;
  err=SSL_get_error(conn->ssl, res);
  psync_set_ssl_error(conn, err);
  return PSYNC_SSL_FAIL;
}

void psync_ssl_rand_strong(unsigned char *buf, int num){
  static int seeds=0;
  int ret;
  if (seeds<2){
    unsigned char seed[PSYNC_LHASH_DIGEST_LEN];
    psync_get_random_seed(seed, buf, num, 1);
    RAND_seed(seed, PSYNC_LHASH_DIGEST_LEN);
    seeds++;
  }
  ret=RAND_bytes(buf, num);
  if (unlikely(ret==0)){
    unsigned char seed[PSYNC_LHASH_DIGEST_LEN];
    psync_uint_t cnt;
    cnt=0;
    while (ret==0 && cnt++<20){
      psync_get_random_seed(seed, NULL, 0, 0);
      RAND_seed(seed, PSYNC_LHASH_DIGEST_LEN);
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

/* this function comes from OpenSSL's crypto/rsa/rsa_lib.c, this version is not (that) buggy and reformatted */
static int RSA_memory_lock_fixed(RSA *r){
  int i, j, k, off;
  char *p;
  BIGNUM *bn, **t[6], *b;
  BN_ULONG *ul;
  if (r->d==NULL)
    return 1;
  t[0]=&r->d;
  t[1]=&r->p;
  t[2]=&r->q;
  t[3]=&r->dmp1;
  t[4]=&r->dmq1;
  t[5]=&r->iqmp;
  k=sizeof(BIGNUM)*6;
  off=k/sizeof(BN_ULONG)+1;
  j=1;
  for (i=0; i<6; i++)
    j+=(*t[i])->top;
  if ((p=OPENSSL_malloc_locked((off+j)*sizeof(BN_ULONG)))==NULL){
    RSAerr(RSA_F_RSA_MEMORY_LOCK, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  bn=(BIGNUM *)p;
  ul=(BN_ULONG *)&p[k];
  for (i=0; i<6; i++){
    b= *(t[i]);
    *(t[i])= &(bn[i]);
    memcpy((char *)&(bn[i]), (char *)b, sizeof(BIGNUM));
    bn[i].flags=BN_FLG_STATIC_DATA;
    bn[i].d=ul;
    memcpy((char *)ul, b->d, sizeof(BN_ULONG)*b->top);
    ul+=b->top;
    BN_clear_free(b);
  }
  r->flags&=~(RSA_FLAG_CACHE_PRIVATE|RSA_FLAG_CACHE_PUBLIC);
  r->bignum_data=p;
  return 1;
}

psync_rsa_t psync_ssl_gen_rsa(int bits){
  RSA *rsa;
  BIGNUM *bn;
  unsigned char seed[PSYNC_LHASH_DIGEST_LEN];
  psync_get_random_seed(seed, seed, sizeof(seed), 0);
  RAND_seed(seed, PSYNC_LHASH_DIGEST_LEN);
  rsa=RSA_new();
  if (unlikely_log(!rsa))
    goto err0;
  bn=BN_new();
  if (unlikely_log(!bn))
    goto err1;
  if (unlikely_log(!BN_set_word(bn, RSA_F4)))
    goto err2;
  if (unlikely_log(!RSA_generate_key_ex(rsa, bits, bn, NULL)))
    goto err2;
  RSA_memory_lock_fixed(rsa);
  BN_free(bn);
  return rsa;
err2:
  BN_free(bn);
err1:
  RSA_free(rsa);
err0:
  return PSYNC_INVALID_RSA;
}

static void psync_ssl_lock_rsa(RSA *rsa){
  RSA_memory_lock_fixed(rsa);
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
  RSA *rsap=RSAPrivateKey_dup(rsa);
  if (rsap)
    psync_ssl_lock_rsa(rsap);
  return rsap;
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
  ret=psync_locked_malloc(offsetof(psync_encrypted_data_struct_t, data)+len);
  ret->datalen=len;
  p=ret->data;
  if (unlikely_log(i2d_RSAPublicKey(rsa, &p)!=len)){
    psync_locked_free(ret);
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
  ret=psync_locked_malloc(offsetof(psync_encrypted_data_struct_t, data)+len);
  ret->datalen=len;
  p=ret->data;
  if (unlikely_log(i2d_RSAPrivateKey(rsa, &p)!=len)){
    psync_locked_free(ret);
    return PSYNC_INVALID_BIN_RSA;
  }
  return ret;
}

psync_rsa_publickey_t psync_ssl_rsa_load_public(const unsigned char *keydata, size_t keylen){
  return d2i_RSAPublicKey(NULL, &keydata, keylen);
}

psync_rsa_privatekey_t psync_ssl_rsa_load_private(const unsigned char *keydata, size_t keylen){
  RSA *rsa=d2i_RSAPrivateKey(NULL, &keydata, keylen);
  if (rsa)
    psync_ssl_lock_rsa(rsa);
  return rsa;
}

psync_rsa_publickey_t psync_ssl_rsa_binary_to_public(psync_binary_rsa_key_t bin){
  return psync_ssl_rsa_load_public(bin->data, bin->datalen);
}

psync_rsa_privatekey_t psync_ssl_rsa_binary_to_private(psync_binary_rsa_key_t bin){
  return psync_ssl_rsa_load_private(bin->data, bin->datalen);
}

psync_symmetric_key_t psync_ssl_gen_symmetric_key_from_pass(const char *password, size_t keylen, const unsigned char *salt, size_t saltlen, size_t iterations){
  psync_symmetric_key_t key=(psync_symmetric_key_t)psync_locked_malloc(keylen+offsetof(psync_symmetric_key_struct_t, key));
  key->keylen=keylen;
  PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 
                                saltlen, iterations, EVP_sha512(), keylen, key->key);
  return key;
}

psync_encrypted_symmetric_key_t psync_ssl_rsa_encrypt_data(psync_rsa_publickey_t rsa, const unsigned char *data, size_t datalen){
  psync_encrypted_symmetric_key_t ret;
  int len;
  ret=(psync_encrypted_symmetric_key_t)psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+RSA_size(rsa));
  len=RSA_public_encrypt(datalen, data, ret->data, rsa, RSA_PKCS1_OAEP_PADDING);
  if (unlikely_log(len==-1)){
    psync_free(ret);
    return PSYNC_INVALID_ENC_SYM_KEY;
  }
  ret->datalen=len;
  return ret;
}

psync_symmetric_key_t psync_ssl_rsa_decrypt_data(psync_rsa_privatekey_t rsa, const unsigned char *data, size_t datalen){
  unsigned char buff[2048];
  psync_symmetric_key_t ret;
  int len;
  len=RSA_private_decrypt(datalen, data, buff, rsa, RSA_PKCS1_OAEP_PADDING);
  if (unlikely(len==-1)){
#if IS_DEBUG
    unsigned long e;
    e=ERR_get_error();
    debug(D_WARNING, "could not decrypt key, RSA_private_decrypt returned error %lu: %s", e, ERR_error_string(e, (char *)buff));
#endif
    return PSYNC_INVALID_SYM_KEY;
  }
  ret=(psync_symmetric_key_t)psync_locked_malloc(offsetof(psync_symmetric_key_struct_t, key)+len);
  ret->keylen=len;
  memcpy(ret->key, buff, len);
  psync_ssl_memclean(buff, len);
  return ret;
}

psync_encrypted_symmetric_key_t psync_ssl_rsa_encrypt_symmetric_key(psync_rsa_publickey_t rsa, const psync_symmetric_key_t key){
  return psync_ssl_rsa_encrypt_data(rsa, key->key, key->keylen);
}

psync_symmetric_key_t psync_ssl_rsa_decrypt_symmetric_key(psync_rsa_privatekey_t rsa, const psync_encrypted_symmetric_key_t enckey){
  return psync_ssl_rsa_decrypt_data(rsa, enckey->data, enckey->datalen);
}

static AES_KEY *psync_ssl_get_aligned_aes_key(){
  unsigned char *m, *a;
  m=(unsigned char *)psync_locked_malloc(PSYNC_AES256_BLOCK_SIZE+sizeof(AES_KEY));
  a=(unsigned char *)(((((uintptr_t)m)+PSYNC_AES256_BLOCK_SIZE-1)/PSYNC_AES256_BLOCK_SIZE)*PSYNC_AES256_BLOCK_SIZE);
  a[sizeof(AES_KEY)]=a-m;
  return (AES_KEY *)a;
}

static void psync_ssl_free_aligned_aes_key(AES_KEY *aes){
  unsigned char *a;
  a=(unsigned char *)aes;
  a-=a[sizeof(AES_KEY)];
  psync_ssl_memclean(aes, sizeof(AES_KEY));
  psync_locked_free(a);
}

psync_aes256_encoder psync_ssl_aes256_create_encoder(psync_symmetric_key_t key){
  AES_KEY *aes;
  assert(key->keylen>=PSYNC_AES256_KEY_SIZE);
  aes=psync_ssl_get_aligned_aes_key();
  AES_set_encrypt_key(key->key, 256, aes);
  return aes;
}

void psync_ssl_aes256_free_encoder(psync_aes256_encoder aes){
  psync_ssl_free_aligned_aes_key(aes);
}

psync_aes256_encoder psync_ssl_aes256_create_decoder(psync_symmetric_key_t key){
  AES_KEY *aes;
  assert(key->keylen>=PSYNC_AES256_KEY_SIZE);
  aes=psync_ssl_get_aligned_aes_key();
  AES_set_decrypt_key(key->key, 256, aes);
  return aes;
}

void psync_ssl_aes256_free_decoder(psync_aes256_encoder aes){
  psync_ssl_free_aligned_aes_key(aes);
}

#if defined(PSYNC_AES_HW_GCC)

#define SSE2FUNC __attribute__((__target__("sse2")))

#define AESDEC      ".byte 0x66,0x0F,0x38,0xDE,"
#define AESDECLAST  ".byte 0x66,0x0F,0x38,0xDF,"
#define AESENC      ".byte 0x66,0x0F,0x38,0xDC,"
#define AESENCLAST  ".byte 0x66,0x0F,0x38,0xDD,"

#define xmm0_xmm1   "0xC8"
#define xmm0_xmm2   "0xD0"
#define xmm0_xmm3   "0xD8"
#define xmm0_xmm4   "0xE0"
#define xmm0_xmm5   "0xE8"
#define xmm1_xmm0   "0xC1"
#define xmm1_xmm2   "0xD1"
#define xmm1_xmm3   "0xD9"
#define xmm1_xmm4   "0xE1"
#define xmm1_xmm5   "0xE9"

SSE2FUNC void psync_aes256_encode_block_hw(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  asm("movdqa (%0), %%xmm0\n"
      "lea 16(%0), %0\n"
      "movdqa (%1), %%xmm1\n"
      "dec %3\n"
      "pxor %%xmm0, %%xmm1\n"
      "movdqa (%0), %%xmm0\n"
      "1:\n"
      "lea 16(%0), %0\n"
      "dec %3\n"
      AESENC xmm0_xmm1 "\n"
      "movdqa (%0), %%xmm0\n"
      "jnz 1b\n"
      AESENCLAST xmm0_xmm1 "\n"
      "movdqa %%xmm1, (%2)\n"
      :
      : "r" (enc->rd_key), "r" (src), "r" (dst),  "r" (enc->rounds)
      : "memory", "cc", "xmm0", "xmm1"
  );
}

SSE2FUNC void psync_aes256_decode_block_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  asm("movdqa (%0), %%xmm0\n"
      "lea 16(%0), %0\n"
      "movdqa (%1), %%xmm1\n"
      "dec %3\n"
      "pxor %%xmm0, %%xmm1\n"
      "movdqa (%0), %%xmm0\n"
      "1:\n"
      "lea 16(%0), %0\n"
      "dec %3\n"
      AESDEC xmm0_xmm1 "\n"
      "movdqa (%0), %%xmm0\n"
      "jnz 1b\n"
      AESDECLAST xmm0_xmm1 "\n"
      "movdqa %%xmm1, (%2)\n"
      :
      : "r" (enc->rd_key), "r" (src), "r" (dst),  "r" (enc->rounds)
      : "memory", "cc", "xmm0", "xmm1"
  );
}

SSE2FUNC void psync_aes256_encode_2blocks_consec_hw(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  asm("movdqa (%0), %%xmm0\n"
      "movdqa (%1), %%xmm1\n"
      "dec %3\n"
      "movdqa 16(%1), %%xmm2\n"
      "lea 16(%0), %0\n"
      "xorps %%xmm0, %%xmm1\n"
      "pxor %%xmm0, %%xmm2\n"
      "movdqa (%0), %%xmm0\n"
      "1:\n"
      "lea 16(%0), %0\n"
      AESENC xmm0_xmm1 "\n"
      "dec %3\n"
      AESENC xmm0_xmm2 "\n"
      "movdqa (%0), %%xmm0\n"
      "jnz 1b\n"
      AESENCLAST xmm0_xmm1 "\n"
      AESENCLAST xmm0_xmm2 "\n"
      "movdqa %%xmm1, (%2)\n"
      "movdqa %%xmm2, 16(%2)\n"
      :
      : "r" (enc->rd_key), "r" (src), "r" (dst),  "r" (enc->rounds)
      : "memory", "cc", "xmm0", "xmm1", "xmm2"
  );
}

SSE2FUNC void psync_aes256_decode_2blocks_consec_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  asm("movdqa (%0), %%xmm0\n"
      "movdqa (%1), %%xmm1\n"
      "dec %3\n"
      "movdqa 16(%1), %%xmm2\n"
      "lea 16(%0), %0\n"
      "xorps %%xmm0, %%xmm1\n"
      "pxor %%xmm0, %%xmm2\n"
      "movdqa (%0), %%xmm0\n"
      "1:\n"
      "lea 16(%0), %0\n"
      AESDEC xmm0_xmm1 "\n"
      "dec %3\n"
      AESDEC xmm0_xmm2 "\n"
      "movdqa (%0), %%xmm0\n"
      "jnz 1b\n"
      AESDECLAST xmm0_xmm1 "\n"
      AESDECLAST xmm0_xmm2 "\n"
      "movdqa %%xmm1, (%2)\n"
      "movdqa %%xmm2, 16(%2)\n"
      :
      : "r" (enc->rd_key), "r" (src), "r" (dst),  "r" (enc->rounds)
      : "memory", "cc", "xmm0", "xmm1", "xmm2"
  );
}

SSE2FUNC void psync_aes256_decode_4blocks_consec_xor_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor){
  asm("movdqa (%0), %%xmm0\n"
      "shr %4\n"
      "movdqa (%1), %%xmm2\n"
      "dec %4\n"
      "movdqa 16(%1), %%xmm3\n"
      "xorps %%xmm0, %%xmm2\n"
      "movdqa 32(%1), %%xmm4\n"
      "xorps %%xmm0, %%xmm3\n"
      "movdqa 48(%1), %%xmm5\n"
      "pxor %%xmm0, %%xmm4\n"
      "movdqa 16(%0), %%xmm1\n"
      "pxor %%xmm0, %%xmm5\n"
      "1:\n"
      "lea 32(%0), %0\n"
      "dec %4\n"
      AESDEC xmm1_xmm2 "\n"
      "movdqa (%0), %%xmm0\n"
      AESDEC xmm1_xmm3 "\n"
      AESDEC xmm1_xmm4 "\n"
      AESDEC xmm1_xmm5 "\n"
      AESDEC xmm0_xmm2 "\n"
      "movdqa 16(%0), %%xmm1\n"
      AESDEC xmm0_xmm3 "\n"
      AESDEC xmm0_xmm4 "\n"
      AESDEC xmm0_xmm5 "\n"
      "jnz 1b\n"
      AESDEC xmm1_xmm2 "\n"
      "movdqa 32(%0), %%xmm0\n"
      AESDEC xmm1_xmm3 "\n"
      AESDEC xmm1_xmm4 "\n"
      AESDEC xmm1_xmm5 "\n"
      AESDECLAST xmm0_xmm2 "\n"
      AESDECLAST xmm0_xmm3 "\n"
      AESDECLAST xmm0_xmm4 "\n"
      "pxor (%3), %%xmm2\n"
      AESDECLAST xmm0_xmm5 "\n"
      "pxor 16(%3), %%xmm3\n"
      "movdqa %%xmm2, (%2)\n"
      "pxor 32(%3), %%xmm4\n"
      "movdqa %%xmm3, 16(%2)\n"
      "pxor 48(%3), %%xmm5\n"
      "movdqa %%xmm4, 32(%2)\n"
      "movdqa %%xmm5, 48(%2)\n"
      :
      : "r" (enc->rd_key), "r" (src), "r" (dst),  "r" (bxor), "r" (enc->rounds)
      : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"
  );
}

#elif defined(PSYNC_AES_HW_MSC)

void psync_aes256_encode_block_hw(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  __m128i r0, r1;
  unsigned char *key;
  unsigned cnt;
  key=(unsigned char *)enc->rd_key;
  r0=_mm_load_si128((__m128i *)key);
  r1=_mm_load_si128((__m128i *)src);
  cnt=enc->rounds-1;
  key+=16;
  r1=_mm_xor_si128(r0, r1);
  r0=_mm_load_si128((__m128i *)key);
  do{
    key+=16;
    r1=_mm_aesenc_si128(r1, r0);
    r0=_mm_load_si128((__m128i *)key);
  } while (--cnt);
  r1=_mm_aesenclast_si128(r1, r0);
  _mm_store_si128((__m128i *)dst, r1);
}

void psync_aes256_decode_block_hw(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  __m128i r0, r1;
  unsigned char *key;
  unsigned cnt;
  key=(unsigned char *)enc->rd_key;
  r0=_mm_load_si128((__m128i *)key);
  r1=_mm_load_si128((__m128i *)src);
  cnt=enc->rounds-1;
  key+=16;
  r1=_mm_xor_si128(r0, r1);
  r0=_mm_load_si128((__m128i *)key);
  do{
    key+=16;
    r1=_mm_aesdec_si128(r1, r0);
    r0=_mm_load_si128((__m128i *)key);
  } while (--cnt);
  r1=_mm_aesdeclast_si128(r1, r0);
  _mm_store_si128((__m128i *)dst, r1);
}

void psync_aes256_encode_2blocks_consec_hw(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst){
  __m128i r0, r1, r2;
  unsigned char *key;
  unsigned cnt;
  key=(unsigned char *)enc->rd_key;
  r0=_mm_load_si128((__m128i *)key);
  r1=_mm_load_si128((__m128i *)src);
  r2=_mm_load_si128((__m128i *)(src+16));
  cnt=enc->rounds-1;
  key+=16;
  r1=_mm_xor_si128(r0, r1);
  r2=_mm_xor_si128(r0, r2);
  r0=_mm_load_si128((__m128i *)key);
  do{
    key+=16;
    r1=_mm_aesenc_si128(r1, r0);
    r2=_mm_aesenc_si128(r2, r0);
    r0=_mm_load_si128((__m128i *)key);
  } while (--cnt);
  r1=_mm_aesenclast_si128(r1, r0);
  r2=_mm_aesenclast_si128(r2, r0);
  _mm_store_si128((__m128i *)dst, r1);
  _mm_store_si128((__m128i *)(dst+16), r2);
}

void psync_aes256_decode_2blocks_consec_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst){
  __m128i r0, r1, r2;
  unsigned char *key;
  unsigned cnt;
  key=(unsigned char *)enc->rd_key;
  r0=_mm_load_si128((__m128i *)key);
  r1=_mm_load_si128((__m128i *)src);
  r2=_mm_load_si128((__m128i *)(src+16));
  cnt=enc->rounds-1;
  key+=16;
  r1=_mm_xor_si128(r0, r1);
  r2=_mm_xor_si128(r0, r2);
  r0=_mm_load_si128((__m128i *)key);
  do{
    key+=16;
    r1=_mm_aesdec_si128(r1, r0);
    r2=_mm_aesdec_si128(r2, r0);
    r0=_mm_load_si128((__m128i *)key);
  } while (--cnt);
  r1=_mm_aesdeclast_si128(r1, r0);
  r2=_mm_aesdeclast_si128(r2, r0);
  _mm_store_si128((__m128i *)dst, r1);
  _mm_store_si128((__m128i *)(dst+16), r2);
}

void psync_aes256_decode_4blocks_consec_xor_hw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor){
  __m128i r0, r1, r2, r3, r4;
  unsigned char *key;
  unsigned cnt;
  key=(unsigned char *)enc->rd_key;
  r0=_mm_load_si128((__m128i *)key);
  r1=_mm_load_si128((__m128i *)src);
  r2=_mm_load_si128((__m128i *)(src+16));
  r3=_mm_load_si128((__m128i *)(src+32));
  r4=_mm_load_si128((__m128i *)(src+48));
  cnt=enc->rounds-1;
  key+=16;
  r1=_mm_xor_si128(r0, r1);
  r2=_mm_xor_si128(r0, r2);
  r3=_mm_xor_si128(r0, r3);
  r4=_mm_xor_si128(r0, r4);
  r0=_mm_load_si128((__m128i *)key);
  do{
    key+=16;
    r1=_mm_aesdec_si128(r1, r0);
    r2=_mm_aesdec_si128(r2, r0);
    r3=_mm_aesdec_si128(r3, r0);
    r4=_mm_aesdec_si128(r4, r0);
    r0=_mm_load_si128((__m128i *)key);
  } while (--cnt);
  r1=_mm_aesdeclast_si128(r1, r0);
  r2=_mm_aesdeclast_si128(r2, r0);
  r3=_mm_aesdeclast_si128(r3, r0);
  r4=_mm_aesdeclast_si128(r4, r0);
  r0=_mm_load_si128((__m128i *)bxor);
  r1=_mm_xor_si128(r0, r1);
  r0=_mm_load_si128((__m128i *)(bxor+16));
  _mm_store_si128((__m128i *)dst, r1);
  r2=_mm_xor_si128(r0, r2);
  r0=_mm_load_si128((__m128i *)(bxor+32));
  _mm_store_si128((__m128i *)(dst+16), r2);
  r3=_mm_xor_si128(r0, r3);
  r0=_mm_load_si128((__m128i *)(bxor+48));
  _mm_store_si128((__m128i *)(dst+32), r3);
  r4=_mm_xor_si128(r0, r4);
  _mm_store_si128((__m128i *)(dst+48), r4);
}

#endif

#if defined(PSYNC_AES_HW)

void psync_aes256_decode_4blocks_consec_xor_sw(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor){
  unsigned long i;
  AES_decrypt(src, dst, enc);
  AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE, dst+PSYNC_AES256_BLOCK_SIZE, enc);
  AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE*2, dst+PSYNC_AES256_BLOCK_SIZE*2, enc);
  AES_decrypt(src+PSYNC_AES256_BLOCK_SIZE*3, dst+PSYNC_AES256_BLOCK_SIZE*3, enc);
  for (i=0; i<PSYNC_AES256_BLOCK_SIZE*4/sizeof(unsigned long); i++)
    ((unsigned long *)dst)[i]^=((unsigned long *)bxor)[i];
}

#endif
