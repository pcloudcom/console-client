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

#ifndef _PSYNC_COMPAT_H
#define _PSYNC_COMPAT_H

#include "pcompiler.h"

#if !defined(P_OS_LINUX) && !defined(P_OS_MACOSX) && !defined(P_OS_WINDOWS) && !defined(P_OS_BSD) && !defined(P_OS_POSIX)
#if defined(__ANDROID__)
#define P_OS_LINUX
#define P_OS_POSIX
#elif defined(__APPLE__)
#define P_OS_MACOSX
#define P_OS_BSD
#define P_OS_POSIX
#elif defined(__CYGWIN__)
#define P_OS_POSIX
#elif defined(__linux__)
#define P_OS_LINUX
#define P_OS_POSIX
#elif defined(__sun)
#define P_OS_POSIX
#elif defined(__FreeBSD__)
#define P_OS_POSIX
#define P_OS_BSD
#elif defined(__DragonFly__)
#define P_OS_POSIX
#define P_OS_BSD
#elif defined(__NetBSD__)
#define P_OS_POSIX
#define P_OS_BSD
#elif defined(__OpenBSD__)
#define P_OS_POSIX
#define P_OS_BSD
#elif defined(__unix__)
#define P_OS_POSIX
#elif defined(_WIN32) || defined(WIN32)
#define P_OS_WINDOWS
#endif
#endif

#if (defined(P_OS_LINUX) || defined(P_OS_MACOSX) || defined(P_OS_BSD)) && !defined(P_OS_POSIX)
#define P_OS_POSIX
#endif

#if !defined(P_OS_LINUX) && !defined(P_OS_MACOSX) && !defined(P_OS_WINDOWS) && !defined(P_OS_POSIX)
#warning "You OS may not be supported, trying to build POSIX compatible source"
#define P_OS_POSIX
#endif

#if defined(P_OS_WINDOWS)
#define P_OS_ID 5
#elif defined(P_OS_MACOSX)
#define P_OS_ID 6
#elif defined(P_OS_LINUX)
#define P_OS_ID 7
#else
#define P_OS_ID 0
#endif

#ifdef P_OS_WINDOWS

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#endif

#if defined(P_OS_MACOSX)
#define _DARWIN_USE_64_BIT_INODE
#endif

#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

typedef long psync_int_t;
typedef unsigned long psync_uint_t;

#define P_PRI_I "ld"
#define P_PRI_U "lu"

#define psync_32to64(hi, lo) ((((uint64_t)(hi))<<32)+(lo))
#define psync_bool_to_zero(x) ((!!(x))-1)

#define NTO_STR(s) TO_STR(s)
#define TO_STR(s) #s

#if defined(P_OS_POSIX)

#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <inttypes.h>

#define P_PRI_U64 PRIu64

#define psync_stat stat
#define psync_fstat fstat
#define psync_stat_isfolder(s) S_ISDIR((s)->st_mode)
#define psync_stat_size(s) ((s)->st_size)
#define psync_stat_mtime(s) ((s)->st_mtime)

#if defined(st_mtime)
#if defined(st_mtimensec)
#define psync_stat_mtime_native(s) ((s)->st_mtime*1000000ULL+(s)->st_mtimensec/1000)
#else
#define psync_stat_mtime_native(s) \
  ((s)->st_mtime*1000000ULL+\
  ((struct timespec *)(&(s)->st_mtime))->tv_nsec/1000)
#endif
#else
#define psync_stat_mtime_native(s) ((s)->st_mtime)
#endif

#define psync_stat_inode(s) ((s)->st_ino)
#define psync_stat_device(s) ((s)->st_dev)

typedef struct stat psync_stat_t;

#define psync_sock_err() errno
#define psync_sock_set_err(e) errno=(e)

#define psync_fs_err() errno

#define psync_inode_supported(path) 1

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
#define P_NOTEMPTY   ENOTEMPTY
#define P_NOTDIR     ENOTDIR
#define P_BUSY       EBUSY
#define P_ROFS       EROFS

#define P_O_RDONLY O_RDONLY
#define P_O_WRONLY O_WRONLY
#define P_O_RDWR   O_RDWR
#define P_O_CREAT  O_CREAT
#define P_O_TRUNC  O_TRUNC
#define P_O_EXCL   O_EXCL

#define P_SEEK_SET SEEK_SET
#define P_SEEK_CUR SEEK_CUR
#define P_SEEK_END SEEK_END

typedef int psync_socket_t;
typedef int psync_file_t;

#define PSYNC_FILENAMES_CASESENSITIVE 1
#define psync_filename_cmp strcmp

#define psync_def_var_arr(name, type, size) type name[size]

#elif defined(P_OS_WINDOWS)

#include <winsock2.h>
#include <BaseTsd.h>
#if defined(__GNUC__)
#define psync_def_var_arr(name, type, size) type name[size]
#define P_PRI_U64 "I64u"
#else
#include <malloc.h>
#define psync_def_var_arr(name, type, size) type *name = (type *)alloca(sizeof(type)*size)
#define P_PRI_U64 "llu"

#define atoll _atoi64
#define snprintf _snprintf
#endif

#if !defined(_SSIZE_T_)
typedef SSIZE_T ssize_t;
#endif

#define psync_filetime_to_timet(ft) ((time_t)(psync_32to64((ft)->dwHighDateTime, (ft)->dwLowDateTime)/10000000ULL-11644473600ULL))

typedef BY_HANDLE_FILE_INFORMATION psync_stat_t;

int psync_stat(const char *path, psync_stat_t *st);
#define psync_fstat(fd, st) psync_bool_to_zero(GetFileInformationByHandle(fd, st))
#define psync_stat_isfolder(s) (((s)->dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==FILE_ATTRIBUTE_DIRECTORY)
#define psync_stat_size(s) psync_32to64((s)->nFileSizeHigh, (s)->nFileSizeLow)
#define psync_stat_mtime(s) psync_filetime_to_timet(&(s)->ftLastWriteTime)
#define psync_stat_mtime_native(s) psync_32to64((s)->ftLastWriteTime.dwHighDateTime, (s)->ftLastWriteTime.dwLowDateTime)
#define psync_stat_inode(s) psync_32to64((s)->nFileIndexHigh, (s)->nFileIndexLow)
#define psync_stat_device(s) ((s)->dwVolumeSerialNumber)

#define psync_sock_err() WSAGetLastError()
#define psync_sock_set_err(e) WSASetLastError(e)

#define psync_fs_err() GetLastError()

#define psync_inode_supported(path) 1

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
#define P_NOTEMPTY   ERROR_DIR_NOT_EMPTY
#define P_NOTDIR     ERROR_FILE_INVALID
#define P_BUSY       ERROR_PATH_BUSY
#define P_ROFS       -1


#define P_O_RDONLY GENERIC_READ
#define P_O_WRONLY GENERIC_WRITE
#define P_O_RDWR   (GENERIC_READ|GENERIC_WRITE)
#define P_O_CREAT  1
#define P_O_TRUNC  2
#define P_O_EXCL   4

#define P_SEEK_SET FILE_BEGIN
#define P_SEEK_CUR FILE_CURRENT
#define P_SEEK_END FILE_END

typedef SOCKET psync_socket_t;
typedef HANDLE psync_file_t;

#define PSYNC_FILENAMES_CASESENSITIVE 0
#define psync_filename_cmp strcasecmp

#else
#error "Need to define types for your operating system"
#endif

typedef struct {
  void *ssl;
  psync_socket_t sock;
  int pending;
} psync_socket;

typedef uint64_t psync_inode_t;

typedef struct {
  const char *name;
  const char *path;
  psync_stat_t stat;
} psync_pstat;

typedef struct {
  const char *name;
  uint8_t isfolder;
} psync_pstat_fast;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE -1
#endif

typedef void (*psync_list_dir_callback)(void *, psync_pstat *);
typedef void (*psync_list_dir_callback_fast)(void *, psync_pstat_fast *);
typedef void (*psync_thread_start0)();
typedef void (*psync_thread_start1)(void *);

void psync_compat_init();
int psync_stat_mode_ok(psync_stat_t *buf, unsigned int bits) PSYNC_PURE;
char *psync_get_default_database_path();
char *psync_get_home_dir();
void psync_run_thread(psync_thread_start0 run);
void psync_run_thread1(psync_thread_start1 run, void *ptr);
void psync_milisleep(uint64_t milisec);
time_t psync_time();
void psync_yield_cpu();

psync_socket *psync_socket_connect(const char *host, int unsigned port, int ssl);
void psync_socket_close(psync_socket *sock);
int psync_socket_set_recvbuf(psync_socket *sock, uint32_t bufsize);
int psync_socket_isssl(psync_socket *sock) PSYNC_PURE;
int psync_socket_pendingdata(psync_socket *sock);
int psync_socket_pendingdata_buf(psync_socket *sock);
int psync_socket_read(psync_socket *sock, void *buff, int num);
int psync_socket_readall(psync_socket *sock, void *buff, int num);
int psync_socket_writeall(psync_socket *sock, const void *buff, int num);

/* pipefd[0] is the read end, pipefd[1] is for writing */
int psync_pipe(psync_socket_t pipefd[2]);
int psync_pipe_close(psync_socket_t pfd);
int psync_pipe_read(psync_socket_t pfd, void *buff, int num);
int psync_pipe_write(psync_socket_t pfd, const void *buff, int num);

int psync_select_in(psync_socket_t *sockets, int cnt, int64_t timeoutmilisec);

int psync_list_dir(const char *path, psync_list_dir_callback callback, void *ptr);
int psync_list_dir_fast(const char *path, psync_list_dir_callback_fast callback, void *ptr);

int64_t psync_get_free_space_by_path(const char *path);

int psync_mkdir(const char *path);
int psync_rmdir(const char *path);
#define psync_rendir psync_file_rename
int psync_file_rename(const char *oldpath, const char *newpath);
int psync_file_rename_overwrite(const char *oldpath, const char *newpath);
int psync_file_delete(const char *path);

psync_file_t psync_file_open(const char *path, int access, int flags);
int psync_file_close(psync_file_t fd);
int psync_file_sync(psync_file_t fd);
ssize_t psync_file_read(psync_file_t fd, void *buf, size_t count);
ssize_t psync_file_write(psync_file_t fd, const void *buf, size_t count);
int64_t psync_file_seek(psync_file_t fd, uint64_t offset, int whence);
int psync_file_truncate(psync_file_t fd);
int64_t psync_file_size(psync_file_t fd) PSYNC_PURE;

#if defined(P_OS_WINDOWS)
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif

#endif
