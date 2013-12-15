#ifndef _PSYNC_SSL_H
#define _PSYNC_SSL_H

#include "pcompat.h"

#if defined(P_SSL_OPENSSL)
#include "pssl-openssl.h"
#else
#error "Please specify SSL library to use"
#endif

extern PSYNC_THREAD int psync_ssl_errno;

#define PSYNC_SSL_ERR_WANT_READ  1
#define PSYNC_SSL_ERR_WANT_WRITE 2
#define PSYNC_SSL_ERR_UNKNOWN    3

#define PSYNC_SSL_NEED_FINISH  -2
#define PSYNC_SSL_FAIL         -1
#define PSYNC_SSL_SUCCESS       0

int psync_ssl_init();
int psync_ssl_connect(psync_socket_t sock, void **sslconn);
int psync_ssl_connect_finish(void *sslconn);
void psync_ssl_free(void *sslconn);
int psync_ssl_shutdown(void *sslconn);
int psync_ssl_pendingdata(void *sslconn);
int psync_ssl_read(void *sslconn, void *buf, int num);
int psync_ssl_write(void *sslconn, const void *buf, int num);

#endif
