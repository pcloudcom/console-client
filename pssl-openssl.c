#include <openssl/ssl.h>
#include <pthread.h>
#include "pssl.h"
#include "psynclib.h"

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
  olocks=psync_malloc(n*sizeof(pthread_mutex_t));
  for (i=0; i<n; i++)
    pthread_mutex_init(&olocks[i], NULL);
  CRYPTO_THREADID_set_callback(openssl_thread_id);
  CRYPTO_set_locking_callback(openssl_locking_callback);
}

int psync_ssl_init(){
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  SSL_load_error_strings();
  openssl_thread_setup();
  globalctx=SSL_CTX_new(SSLv23_method());
  if (globalctx)
    return 0;
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

int psync_ssl_connect(psync_socket_t sock, void **sslconn){
  SSL *ssl;
  int res, err;
  ssl=SSL_new(globalctx);
  if (!ssl)
    return PSYNC_SSL_FAIL;
  SSL_set_fd(ssl, sock);
  res=SSL_connect(ssl);
  if (res==1){
    *sslconn=ssl;
    return PSYNC_SSL_SUCCESS;
  }
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(err);
  if (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE)
    return PSYNC_SSL_NEED_FINISH;
  SSL_free(ssl);
  return PSYNC_SSL_FAIL;
}

int psync_ssl_connect_finish(void *sslconn){
  SSL *ssl;
  int res, err;
  ssl=(SSL *)sslconn;
  res=SSL_connect(ssl);
  if (res==1)
    return PSYNC_SSL_SUCCESS;
  err=SSL_get_error(ssl, res);
  psync_set_ssl_error(err);
  if (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE)
    return PSYNC_SSL_NEED_FINISH;
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
  if (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE)
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
