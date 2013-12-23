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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#if defined(P_OS_POSIX)

#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>

#define psync_stat stat
#define psync_stat_isfolder(s) (((s)->st_mode&S_IFDIR)==S_IFDIR)
#define psync_stat_size(s) ((s)->st_size)
#define psync_stat_mtime(s) ((s)->st_mtime)
typedef struct stat psync_stat_t;

#define psync_sock_err() errno
#define psync_sock_set_err(e) errno=(e)

#define psync_fs_err() errno

#define PSYNC_DIRECTORY_SEPARATOR "/"
#define PSYNC_DIRECTORY_SEPARATORC '/'

#define P_WOULDBLOCK EWOULDBLOCK
#define P_AGAIN      EAGAIN
#define P_INPROGRESS EINPROGRESS
#define P_TIMEDOUT   ETIMEDOUT
#define P_INVAL      EINVAL
#define P_CONNRESET  ECONNRESET

#define P_NOENT      ENOENT
#define P_EXIST      EEXIST
#define P_NOSPC      ENOSPC
#define P_DQUOT      EDQUOT


typedef int psync_socket_t;

#elif defined(P_OS_WINDOWS)

#define _WIN32_WINNT 0x0400

#include <winsock2.h>
#include <ws2tcpip.h>

#define psync_stat _stat64
#define psync_stat_isfolder(s) (((s)->st_mode&_S_IFDIR)==_S_IFDIR)
#define psync_stat_size(s) ((s)->st_size)
#define psync_stat_mtime(s) ((s)->st_mtime)
typedef struct __stat64 psync_stat_t;

#define psync_sock_err() WSAGetLastError()
#define psync_sock_set_err(e) WSASetLastError(e)

#define psync_fs_err() GetLastError()

#define PSYNC_DIRECTORY_SEPARATOR "\\"
#define PSYNC_DIRECTORY_SEPARATORC '\\'

#define P_WOULDBLOCK WSAEWOULDBLOCK
#define P_AGAIN      WSAEWOULDBLOCK
#define P_INPROGRESS WSAEWOULDBLOCK
#define P_TIMEDOUT   WSAETIMEDOUT
#define P_INVAL      WSAEINVAL
#define P_CONNRESET  WSAECONNRESET

#define P_NOENT      ERROR_PATH_NOT_FOUND
#define P_EXIST      ERROR_ALREADY_EXISTS
#define P_NOSPC      ERROR_HANDLE_DISK_FULL
#define P_DQUOT      ERROR_HANDLE_DISK_FULL // is there such error?

typedef SOCKET psync_socket_t;

#else
#error "Need to define types for your operating system"
#endif

typedef struct {
  void *ssl;
  psync_socket_t sock;
  int pending;
} psync_socket;

typedef struct {
  const char *name;
  uint64_t size;
  time_t lastmod;
  uint8_t isfolder;
  uint8_t canread;
  uint8_t canwrite;
  uint8_t canmodifyparent;
} psync_pstat;

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

typedef void (*psync_list_dir_callback)(void *, psync_pstat *);
typedef void (*psync_thread_start0)();
typedef void (*psync_thread_start1)(void *);

void psync_compat_init();
int psync_stat_mode_ok(psync_stat_t *buf, unsigned int bits);
char *psync_get_default_database_path();
void psync_run_thread(psync_thread_start0 run);
void psync_run_thread1(psync_thread_start1 run, void *ptr);
void psync_milisleep(uint64_t milisec);
void psync_yield_cpu();

psync_socket *psync_socket_connect(const char *host, int unsigned port, int ssl);
void psync_socket_close(psync_socket *sock);
int psync_socket_pendingdata(psync_socket *sock);
int psync_socket_readall(psync_socket *sock, void *buff, int num);
int psync_socket_writeall(psync_socket *sock, const void *buff, int num);

/* pipefd[0] is the read end, pipefd[1] is for writing */
int psync_pipe(psync_socket_t pipefd[2]);
int psync_pipe_close(psync_socket_t pfd);
int psync_pipe_read(psync_socket_t pfd, void *buff, int num);
int psync_pipe_write(psync_socket_t pfd, const void *buff, int num);

int psync_select_in(psync_socket_t *sockets, int cnt, int64_t timeoutmilisec);

int psync_list_dir(const char *path, psync_list_dir_callback callback, void *ptr);

int psync_mkdir(const char *path);
int psync_rename(const char *oldpath, const char *newpath);

#if defined(P_OS_WINDOWS)
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif

#endif
