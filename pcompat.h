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

#ifndef _PSYNC_COMPAT_H
#define _PSYNC_COMPAT_H

#include <stdint.h>

#if (defined(P_OS_LINUX) || defined(P_OS_MACOSX)) && !defined(P_OS_POSIX)
#define P_OS_POSIX
#endif

#if !defined(P_OS_LINUX) && !defined(P_OS_MACOSX) && !defined(P_OS_WINDOWS) && !defined(P_OS_POSIX)
#warning "You OS may not be supported, trying to build POSIX compatible source"
#define P_OS_POSIX
#endif

#if defined(P_OS_POSIX)

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#define psync_sock_err() errno
#define psync_sock_set_err(e) errno=(e)

#define P_WOULDBLOCK EWOULDBLOCK
#define P_AGAIN      EAGAIN
#define P_INPROGRESS EINPROGRESS
#define P_TIMEDOUT   ETIMEDOUT
#define P_INVAL      EINVAL
#define P_CONNRESET  ECONNRESET

typedef int psync_socket_t;

#elif defined(P_OS_WINDOWS)

#include <winsock2.h>
#include <Ws2tcpip.h>

#define psync_sock_err() WSAGetLastError()
#define psync_sock_set_err(e) WSASetLastError(e)

#define P_WOULDBLOCK WSAEWOULDBLOCK
#define P_AGAIN      WSAEWOULDBLOCK
#define P_INPROGRESS WSAEWOULDBLOCK
#define P_TIMEDOUT   WSAETIMEDOUT
#define P_INVAL      WSAEINVAL
#define P_CONNRESET  WSAECONNRESET

typedef SOCKET psync_socket_t;

#else
#error "Need to define types for your operating system"
#endif

typedef struct {
  void *ssl;
  psync_socket_t sock;
} psync_socket;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#define PSYNC_THREAD __thread

#ifdef __GNUC__
#define PSYNC_MALLOC __attribute__((malloc))
#define PSYNC_SENTINEL __attribute__ ((sentinel))
#else
#define PSYNC_MALLOC
#define PSYNC_SENTINEL
#endif

typedef void (*psync_thread_start0)();
typedef void (*psync_thread_start1)(void *);

char *psync_get_default_database_path();
void psync_run_thread(psync_thread_start0 run);
void psync_run_thread1(psync_thread_start1 run, void *ptr);
void psync_milisleep(uint64_t milisec);
void psync_yield_cpu();

psync_socket *psync_socket_connect(const char *host, int unsigned port, int ssl);
void psync_socket_close(psync_socket *sock);
int psync_socket_readall(psync_socket *sock, void *buff, int num);
int psync_socket_writeall(psync_socket *sock, const void *buff, int num);

#if defined(P_OS_WINDOWS)
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif

#endif
