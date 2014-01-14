/* Copyright (c) 2013-2014 Anton Titov.
 * Copyright (c) 2013-2014 pCloud Ltd.
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

#include "pssl.h"
#include "psynclib.h"
#include "plibs.h"
#include "pcompat.h"
#include <unistd.h>
#include <Security/SecureTransport.h>

PSYNC_THREAD int psync_ssl_errno;

int psync_ssl_init(){
  return 0;
}

static OSStatus psync_myread(SSLConnectionRef conn, void *data, size_t *len){
  psync_socket_t sock=(psync_socket_t)conn;
  size_t llen=*len;
  ssize_t rd=read(sock, data, llen);
  debug(D_NOTICE, "read(%u)=%d", (unsigned)llen, (int)rd);
  if (likely(rd>0)){
    *len=rd;
    return rd==llen?noErr:errSSLWouldBlock;
  }
  else if (rd==0){
    *len=0;
    return errSSLClosedNoNotify;
  }
  else {
    *len=0;
    if (errno==EAGAIN || errno==EINTR){
      psync_ssl_errno=PSYNC_SSL_ERR_WANT_READ;
      return errSSLWouldBlock;
    }
    else
      return errSSLClosedAbort;
  }
}

static OSStatus psync_mywrite(SSLConnectionRef conn, const void *data, size_t *len){
  psync_socket_t sock=(psync_socket_t)conn;
  size_t llen=*len;
  ssize_t rd=write(sock, data, llen);
  debug(D_NOTICE, "write(%u)=%d", (unsigned)llen, (int)rd);
  if (likely(rd>=0)){
    *len=rd;
    return rd==llen?noErr:errSSLWouldBlock;
  }
  else {
    *len=0;
    if (errno==EAGAIN || errno==EINTR){
      psync_ssl_errno=PSYNC_SSL_ERR_WANT_WRITE;
      return errSSLWouldBlock;
    }
    else
      return errSSLClosedAbort;
  }
}

int psync_ssl_connect(psync_socket_t sock, void **sslconn){
  SSLContextRef ref;
  OSStatus st;
  debug(D_NOTICE, "called");
  ref=SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
  if (unlikely_log(!ref))
    goto err1;
  if (unlikely_log(SSLSetIOFuncs(ref, psync_myread, psync_mywrite)!=noErr))
    goto err2;
  if (unlikely_log(SSLSetConnection(ref, (SSLConnectionRef)(uintptr_t)sock)!=noErr))
    goto err2;
  st=SSLHandshake(ref);
  if (st==noErr){
    *sslconn=ref;
    return PSYNC_SSL_SUCCESS;
  }
  else if (st==errSSLWouldBlock){
    *sslconn=ref;
    return PSYNC_SSL_NEED_FINISH;    
  }
  debug(D_WARNING, "connection failed with status %d", (int)st);
err2:
  CFRelease(ref);
err1:
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  return PSYNC_SSL_FAIL;
}

int psync_ssl_connect_finish(void *sslconn){
  SSLContextRef ref;
  OSStatus st;
  debug(D_NOTICE, "called");
  ref=(SSLContextRef)sslconn;
  st=SSLHandshake(ref);
  if (st==noErr)
    return PSYNC_SSL_SUCCESS;
  else if (st==errSSLWouldBlock)
    return PSYNC_SSL_NEED_FINISH;
  CFRelease(ref);
  debug(D_WARNING, "connection failed with status %d", (int)st);
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  return PSYNC_SSL_FAIL;
}

int psync_ssl_shutdown(void *sslconn){
  SSLContextRef ref;
  OSStatus st;
  ref=(SSLContextRef)sslconn;
  st=SSLClose(ref);
  if (st==errSSLWouldBlock)
    return PSYNC_SSL_NEED_FINISH;
  CFRelease(ref);
  if (st==noErr)
    return PSYNC_SSL_SUCCESS;
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  return PSYNC_SSL_FAIL;
}

void psync_ssl_free(void *sslconn){
  CFRelease((SSLContextRef)sslconn);
}

int psync_ssl_pendingdata(void *sslconn){
  size_t p;
  if (SSLGetBufferedReadSize((SSLContextRef)sslconn, &p)==noErr)
    return p;
  else
    return 0;
}

int psync_ssl_read(void *sslconn, void *buf, int num){
  size_t ret;
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  if (SSLRead((SSLContextRef)sslconn, buf, num, &ret)!=noErr)
    return PSYNC_SSL_FAIL;
  else
    return ret;  
}

int psync_ssl_write(void *sslconn, const void *buf, int num){
  size_t ret;
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  if (SSLWrite((SSLContextRef)sslconn, buf, num, &ret)!=noErr)
    return PSYNC_SSL_FAIL;
  else
    return ret;
}
