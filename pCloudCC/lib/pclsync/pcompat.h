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
#elif defined(_WIN32) || defined(WIN32) || defined(Q_OS_WIN)
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

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif


#elif defined(P_OS_MACOSX)

#define P_OS_ID 6

#define _DARWIN_USE_64_BIT_INODE

#elif defined(P_OS_LINUX)

#define P_OS_ID 7

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#else

#define P_OS_ID 0

#endif

#ifdef P_ELECTRON
#undef P_OS_ID
#define P_OS_ID 9
#endif

#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

typedef long psync_int_t;
typedef unsigned long psync_uint_t;

#define P_PRI_I "ld"
#define P_PRI_U "lu"

#ifndef PRIu64
#define PRIu64 "I64u"
#endif


#define psync_32to64(hi, lo) ((((uint64_t)(hi))<<32)+(lo))
#define psync_bool_to_zero(x) (((int)(!!(x)))-1)

#define NTO_STR(s) TO_STR(s)
#define TO_STR(s) #s

#if defined(P_OS_POSIX)

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>

#define P_PRI_U64 PRIu64
#define P_PRI_D64 PRId64

#define psync_stat stat
#define psync_fstat fstat
#define psync_stat_isfolder(s) S_ISDIR((s)->st_mode)
#define psync_stat_size(s) ((s)->st_size)
#ifdef _DARWIN_FEATURE_64_BIT_INODE
#define psync_stat_birthtime(s) ((s)->st_birthtime)
#define PSYNC_HAS_BIRTHTIME
#else
#define psync_stat_birthtime(s) ((s)->st_mtime)
#endif
#define psync_stat_ctime(s) ((s)->st_ctime)
#define psync_stat_mtime(s) ((s)->st_mtime)

#if defined(st_mtime)
#if defined(st_mtimensec)
#define psync_stat_mtime_native(s) ((s)->st_mtime*1000000ULL+(s)->st_mtimensec/1000)
#else
#define psync_stat_mtime_native(s) \
  ((s)->st_mtime*1000000ULL+\
  ((struct timespec *)(&(s)->st_mtime))->tv_nsec/1000)
#endif
#define psync_mtime_native_to_mtime(n) ((n)/1000000ULL)
#else
#define psync_stat_mtime_native(s) ((s)->st_mtime)
#define psync_mtime_native_to_mtime(n) (n)
#endif

#define psync_stat_inode(s) ((s)->st_ino)
#if defined(P_OS_MACOSX)
#define psync_stat_device(s) ((s)->st_dev>>24)
#else
#define psync_stat_device(s) ((s)->st_dev)
#endif
#define psync_stat_device_full(s) ((s)->st_dev)
#if defined(P_OS_MACOSX)
#define psync_deviceid_short(deviceid) (deviceid>>24)
#else
#define psync_deviceid_short(deviceid) (deviceid)
#endif

typedef struct stat psync_stat_t;

#define psync_sock_err() errno
#define psync_sock_set_err(e) errno=(e)

#define psync_fs_err() errno

typedef int psync_sock_err_t;
typedef int psync_fs_err_t;

#define psync_inode_supported(path) 1

#define PSYNC_DIRECTORY_SEPARATOR "/"
#define PSYNC_DIRECTORY_SEPARATORC '/'

#define P_WOULDBLOCK EWOULDBLOCK
#define P_AGAIN      EAGAIN
#define P_INPROGRESS EINPROGRESS
#define P_TIMEDOUT   ETIMEDOUT
#define P_INVAL      EINVAL
#define P_CONNRESET  ECONNRESET
#define P_INTR       EINTR

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
#define psync_filename_cmpn memcmp

#define psync_def_var_arr(name, type, size) type name[size]

#define psync_close_socket close
#define psync_read_socket read
#define psync_write_socket write

#elif defined(P_OS_WINDOWS)

#include <ws2tcpip.h>
#include <winsock2.h>
#include <BaseTsd.h>

#define P_PRI_U64 "I64u"
#define P_PRI_D64 "I64d"

#if defined(__GNUC__)

#define psync_def_var_arr(name, type, size) type name[size]

#else

#include <malloc.h>

#define psync_def_var_arr(name, type, size) type *name=(type *)alloca(sizeof(type)*(size))
#define atoll _atoi64
#if _MSC_VER < 1900
#define snprintf _snprintf
#endif
//#define snprintf _snprintf

#endif

#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef SSIZE_T ssize_t;
#endif

#define psync_filetime_to_timet(ft) ((time_t)(psync_32to64((ft)->dwHighDateTime, (ft)->dwLowDateTime)/10000000ULL-11644473600ULL))
#define psync_filetime64_to_timet(ft) ((time_t)((ft)/10000000ULL-11644473600ULL))

typedef BY_HANDLE_FILE_INFORMATION psync_stat_t;

int psync_stat(const char *path, psync_stat_t *st);
#define psync_fstat(fd, st) psync_bool_to_zero(GetFileInformationByHandle(fd, st))
#define psync_stat_isfolder(s) (((s)->dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==FILE_ATTRIBUTE_DIRECTORY)
#define psync_stat_size(s) psync_32to64((s)->nFileSizeHigh, (s)->nFileSizeLow)
#define psync_stat_ctime(s) psync_filetime_to_timet(&(s)->ftCreationTime)
#define psync_stat_mtime(s) psync_filetime_to_timet(&(s)->ftLastWriteTime)
#define psync_stat_birthtime(s) psync_filetime_to_timet(&(s)->ftCreationTime)
#define PSYNC_HAS_BIRTHTIME
#define psync_stat_mtime_native(s) psync_32to64((s)->ftLastWriteTime.dwHighDateTime, (s)->ftLastWriteTime.dwLowDateTime)
#define psync_mtime_native_to_mtime(n) psync_filetime64_to_timet(n)
#define psync_stat_inode(s) psync_32to64((s)->nFileIndexHigh, (s)->nFileIndexLow)
#define psync_stat_device(s) ((s)->dwVolumeSerialNumber)
#define psync_stat_device_full(s) psync_stat_device(s)
#define psync_deviceid_short(deviceid) (deviceid)

#define psync_sock_err() WSAGetLastError()
#define psync_sock_set_err(e) WSASetLastError(e)

#define psync_fs_err() GetLastError()

typedef int psync_sock_err_t;
typedef DWORD psync_fs_err_t;

#define psync_inode_supported(path) 1

#define PSYNC_DIRECTORY_SEPARATOR "\\"
#define PSYNC_DIRECTORY_SEPARATORC '\\'

#define P_WOULDBLOCK WSAEWOULDBLOCK
#define P_AGAIN      WSAEWOULDBLOCK
#define P_INPROGRESS WSAEWOULDBLOCK
#define P_TIMEDOUT   WSAETIMEDOUT
#define P_INVAL      WSAEINVAL
#define P_CONNRESET  WSAECONNRESET
#define P_INTR       WSAEINTR

#define P_NOENT      ERROR_FILE_NOT_FOUND
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
#define psync_filename_cmp _stricmp
#define psync_filename_cmpn _memicmp

#define psync_close_socket closesocket
#define psync_read_socket(s, b, c) recv(s, (char *)(b), c, 0)
#define psync_write_socket(s, b, c) send(s, (const char *)(b), c, 0)

#else
#error "Need to define types for your operating system"
#endif

typedef struct _psync_socket_buffer {
  struct _psync_socket_buffer *next;
  uint32_t size;
  uint32_t woffset;
  uint32_t roffset;
  char buff[];
} psync_socket_buffer;

typedef struct {
  void *ssl;
  psync_socket_buffer *buffer;
  psync_socket_t sock;
  int pending;
  uint32_t misc;
} psync_socket;

typedef uint64_t psync_inode_t;
typedef uint64_t psync_deviceid_t;

typedef struct {
  const char *name;
  const char *path;
  psync_stat_t stat;
} psync_pstat;

#if defined(P_OS_MACOSX)
typedef psync_pstat psync_pstat_fast;
#define psync_stat_fast_isfolder(a) psync_stat_isfolder(&(a)->stat)
#else
typedef struct {
  const char *name;
  uint8_t isfolder;
} psync_pstat_fast;
#define psync_stat_fast_isfolder(a) ((a)->isfolder)
#endif

typedef struct {
  struct sockaddr_storage address;
  struct sockaddr_storage broadcast;
  struct sockaddr_storage netmask;
  int addrsize;
} psync_interface_t;

typedef struct {
  size_t interfacecnt;
  psync_interface_t interfaces[];
} psync_interface_list_t;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE -1
#endif

#define PSYNC_SOCKET_ERROR      -1
#define PSYNC_SOCKET_WOULDBLOCK -2

#if !defined(__socklen_t_defined) && !defined(HAVE_SOCKET_LEN_T) && !defined(socklen_t)
#if defined(P_OS_WINDOWS)
  typedef int socklen_t;
#else
  typedef unsigned int socklen_t;
#endif
#define __socklen_t_defined
#define HAVE_SOCKET_LEN_T
#endif

typedef void (*psync_list_dir_callback)(void *, psync_pstat *);
typedef void (*psync_list_dir_callback_fast)(void *, psync_pstat_fast *);
typedef void (*psync_thread_start0)();
typedef void (*psync_thread_start1)(void *);

extern PSYNC_THREAD const char *psync_thread_name;

extern const unsigned char psync_invalid_filename_chars[];

void psync_compat_init();
int psync_user_is_admin();
int psync_stat_mode_ok(psync_stat_t *buf, unsigned int bits) PSYNC_PURE;
char *psync_get_pcloud_path();
char *psync_get_private_dir(char *name);
char *psync_get_private_tmp_dir();
char *psync_get_default_database_path();
char *psync_get_home_dir();
void psync_run_thread(const char *name, psync_thread_start0 run);
void psync_run_thread1(const char *name, psync_thread_start1 run, void *ptr);
void psync_milisleep_nosqlcheck(uint64_t millisec);
void psync_milisleep(uint64_t millisec);
time_t psync_time();
void psync_nanotime(struct timespec *tm);
uint64_t psync_millitime();
void psync_yield_cpu();

void psync_get_random_seed(unsigned char *seed, const void *addent, size_t aelen, int fast);

psync_socket_t psync_create_socket(int domain, int type, int protocol);
psync_socket *psync_socket_connect(const char *host, int unsigned port, int ssl);
void psync_socket_close(psync_socket *sock);
void psync_socket_close_bad(psync_socket *sock);
void psync_socket_set_write_buffered(psync_socket *sock);
void psync_socket_set_write_buffered_thread(psync_socket *sock);
void psync_socket_clear_write_buffered(psync_socket *sock);
void psync_socket_clear_write_buffered_thread(psync_socket *sock);
int psync_socket_set_recvbuf(psync_socket *sock, int bufsize);
int psync_socket_set_sendbuf(psync_socket *sock, int bufsize);
int psync_socket_isssl(psync_socket *sock) PSYNC_PURE;
int psync_socket_pendingdata(psync_socket *sock);
int psync_socket_pendingdata_buf(psync_socket *sock);
int psync_socket_pendingdata_buf_thread(psync_socket *sock);
int psync_socket_try_write_buffer(psync_socket *sock);
int psync_socket_try_write_buffer_thread(psync_socket *sock);
int psync_socket_readable(psync_socket *sock);
int psync_socket_writable(psync_socket *sock);
int psync_socket_read(psync_socket *sock, void *buff, int num);
int psync_socket_read_noblock(psync_socket *sock, void *buff, int num);
int psync_socket_read_thread(psync_socket *sock, void *buff, int num);
int psync_socket_write(psync_socket *sock, const void *buff, int num);
int psync_socket_readall(psync_socket *sock, void *buff, int num);
int psync_socket_writeall(psync_socket *sock, const void *buff, int num);
int psync_socket_readall_thread(psync_socket *sock, void *buff, int num);
int psync_socket_writeall_thread(psync_socket *sock, const void *buff, int num);

psync_interface_list_t *psync_list_ip_adapters();

/* pipefd[0] is the read end, pipefd[1] is for writing */
int psync_pipe(psync_socket_t pipefd[2]);
int psync_pipe_close(psync_socket_t pfd);
int psync_pipe_read(psync_socket_t pfd, void *buff, int num);
int psync_pipe_write(psync_socket_t pfd, const void *buff, int num);

int psync_socket_pair(psync_socket_t sfd[2]);
int psync_wait_socket_write_timeout(psync_socket_t sock);
int psync_wait_socket_read_timeout(psync_socket_t sock);

int psync_socket_is_broken(psync_socket_t sock);
int psync_select_in(psync_socket_t *sockets, int cnt, int64_t timeoutmillisec);

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
int psync_file_schedulesync(psync_file_t fd);
int psync_folder_sync(const char *path);
psync_file_t psync_file_dup(psync_file_t fd);
int psync_file_set_creation(psync_file_t fd, time_t ctime);
int psync_set_crtime_mtime(const char *path, time_t crtime, time_t mtime);
int psync_set_crtime_mtime_by_fd(psync_file_t fd, const char *path, time_t crtime, time_t mtime);
int psync_file_preread(psync_file_t fd, uint64_t offset, size_t count);
int psync_file_readahead(psync_file_t fd, uint64_t offset, size_t count);
ssize_t psync_file_read(psync_file_t fd, void *buf, size_t count);
ssize_t psync_file_pread(psync_file_t fd, void *buf, size_t count, uint64_t offset);
ssize_t psync_file_write(psync_file_t fd, const void *buf, size_t count);
ssize_t psync_file_pwrite(psync_file_t fd, const void *buf, size_t count, uint64_t offset);
int64_t psync_file_seek(psync_file_t fd, uint64_t offset, int whence);
int psync_file_truncate(psync_file_t fd);
int64_t psync_file_size(psync_file_t fd);

void psync_set_software_name(const char *snm);
void psync_set_os_name(const char *osnm);
char *psync_deviceos();
const char *psync_appname();
char *psync_device_string();
char *psync_deviceid();

#if defined(P_OS_WINDOWS) && !defined(gmtime_r)
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif

int psync_run_update_file(const char *path);
int psync_invalidate_os_cache_needed();
int psync_invalidate_os_cache(const char *path);

void *psync_mmap_anon(size_t size);
void *psync_mmap_anon_safe(size_t size);
int psync_munmap_anon(void *ptr, size_t size);
void psync_anon_reset(void *ptr, size_t size);

int psync_mlock(void *ptr, size_t size);
int psync_munlock(void *ptr, size_t size);

int psync_get_page_size();

void psync_rebuild_icons();

#endif
