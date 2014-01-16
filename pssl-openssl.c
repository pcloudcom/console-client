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
#include <pthread.h>
#include "pssl.h"
#include "psynclib.h"
#include "plibs.h"
#include "psslcerts.h"

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
