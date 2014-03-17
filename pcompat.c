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
 *       documentation and/or materials provided with the distribution.
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

#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include "pcompat.h"
#include "psynclib.h"
#include "plibs.h"
#include "psettings.h"
#include "pssl.h"

#if defined(P_OS_LINUX)
#include <sys/sysinfo.h>
#endif

#if defined(P_OS_POSIX)

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>

extern char **environ;

#elif defined(P_OS_WINDOWS)

#include <process.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iphlpapi.h>

#endif

typedef struct {
 psync_thread_start1 run;
  void *ptr;
} psync_run_data1;

#if defined(P_OS_POSIX)
static uid_t psync_uid;
static gid_t psync_gid;
static gid_t *psync_gids;
static int psync_gids_cnt;
#endif

void psync_compat_init(){
#if defined(P_OS_POSIX)
  signal(SIGPIPE, SIG_IGN);
  psync_uid=getuid();
  psync_gid=getgid();
  psync_gids_cnt=getgroups(0, NULL);
  psync_gids=psync_new_cnt(gid_t, psync_gids_cnt);
  if (unlikely_log(getgroups(psync_gids_cnt, psync_gids)!=psync_gids_cnt))
    psync_gids_cnt=0;
#endif
}

int psync_stat_mode_ok(psync_stat_t *buf, unsigned int bits){
#if defined(P_OS_POSIX)
  int i;
  if (psync_uid==0)
    return 1;
  if (buf->st_uid==psync_uid){
    bits<<=6;
    return (buf->st_mode&bits)==bits;
  }
  if (buf->st_gid==psync_gid){
    bits<<=3;
    return (buf->st_mode&bits)==bits;
  }
  for (i=0; i<psync_gids_cnt; i++)
    if (buf->st_gid==psync_gids[i]){
      bits<<=3;
      return (buf->st_mode&bits)==bits;
    }
  return (buf->st_mode&bits)==bits;
#else
  return 1;
#endif
}

char *psync_get_default_database_path(){
#if defined(P_OS_POSIX)
  struct stat st;
  const char *dir;
  dir=getenv("HOME");
  if (unlikely_log(!dir) || unlikely_log(stat(dir, &st)) || unlikely_log(!psync_stat_mode_ok(&st, 7))){
    struct passwd pwd;
    struct passwd *result;
    char buff[4096];
    if (unlikely_log(getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result)) || unlikely_log(stat(result->pw_dir, &st)) ||
        unlikely_log(!psync_stat_mode_ok(&st, 7)))
      return NULL;
    dir=result->pw_dir;
  }
  return psync_strcat(dir, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_POSIX_DBNAME, NULL);
#elif defined(P_OS_WINDOWS)
  const char *dir;
  dir=getenv("UserProfile");
  if (unlikely_log(!dir))
    return NULL;
  return psync_strcat(dir, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_WINDOWS_DBNAME, NULL);
#else
#error "Function not implemented for your operating system"
#endif
}

char *psync_get_home_dir(){
#if defined(P_OS_POSIX)
  struct stat st;
  const char *dir;
  dir=getenv("HOME");
  if (unlikely_log(!dir) || unlikely_log(stat(dir, &st)) || unlikely_log(!psync_stat_mode_ok(&st, 7))){
    struct passwd pwd;
    struct passwd *result;
    char buff[4096];
    if (unlikely_log(getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result)) || unlikely_log(stat(result->pw_dir, &st)) ||
        unlikely_log(!psync_stat_mode_ok(&st, 7)))
      return NULL;
    dir=result->pw_dir;
  }
  return psync_strdup(dir);
#elif defined(P_OS_WINDOWS)
  const char *dir;
  dir=getenv("UserProfile");
  if (unlikely_log(!dir))
    return NULL;
  return psync_strdup(dir);
#else
#error "Function not implemented for your operating system"
#endif
}

void psync_yield_cpu(){
#if defined(_POSIX_PRIORITY_SCHEDULING)
  sched_yield();
#elif defined(P_OS_WINDOWS)
  SwitchToThread();
#else
  psync_milisleep(1);
#endif
}

static void thread_started(){
  psync_yield_cpu();
}

static void thread_exited(){
}

static void *thread_entry0(void *ptr){
  thread_started();
  ((psync_thread_start0)ptr)();
  thread_exited();
  return NULL;
}

void psync_run_thread(psync_thread_start0 run){
  pthread_t thread;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry0, run);
  pthread_attr_destroy(&attr);
}

static void *thread_entry1(void *data){
  psync_thread_start1 run;
  void *ptr;
  run=((psync_run_data1 *)data)->run;
  ptr=((psync_run_data1 *)data)->ptr;
  psync_free(data);
  thread_started();
  run(ptr);
  thread_exited();
  return NULL;
}

void psync_run_thread1(psync_thread_start1 run, void *ptr){
  psync_run_data1 *data;
  pthread_t thread;
  pthread_attr_t attr;
  data=psync_new(psync_run_data1);
  data->run=run;
  data->ptr=ptr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry1, data);
  pthread_attr_destroy(&attr);
}

void psync_milisleep(uint64_t milisec){
#if defined(P_OS_POSIX)
  struct timespec tm;
  tm.tv_sec=milisec/1000;
  tm.tv_nsec=(milisec%1000)*1000000;
  nanosleep(&tm, NULL);
#elif defined(P_OS_WINDOWS)
  Sleep(milisec);
#else
#error "Function not implemented for your operating system"
#endif
}

time_t psync_time(){
#if defined(P_OS_MACOSX)
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec;
#elif defined(_POSIX_TIMERS) && _POSIX_TIMERS>0
  struct timespec ts;
  if (likely_log(clock_gettime(CLOCK_REALTIME, &ts)==0))
    return ts.tv_sec;
  else
    return time(NULL);
#else
  return time(NULL);
#endif
}

void psync_nanotime(struct timespec *tm){
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS>0
  clock_gettime(CLOCK_REALTIME, tm);
#elif defined(P_OS_WINDOWS)
  FILETIME ft;
  uint64_t t;
  GetSystemTimeAsFileTime(&ft);
  t=psync_32to64(ft.dwHighDateTime, ft.dwLowDateTime)-116444736000000000ULL;
  tm->tv_sec=t/10000000UL;
  tm->tv_nsec=(t%10000000UL)*100;
#elif defined(P_OS_POSIX)
  struct timeval tv;
  gettimeofday(&tv, NULL);
  tm->tv_sec=tv.tv_sec;
  tm->tv_nsec=tv.tv_usec*1000;
#else
#error "Function not implemented for your operating system"
#endif
}

#if defined(P_OS_POSIX)
static void psync_add_file_to_seed(const char *fn, psync_hash_ctx *hctx, size_t max){
  char buff[4096];
  ssize_t rd;
  int fd, mode;
  mode=O_RDONLY;
#if defined(O_NONBLOCK)
  mode+=O_NONBLOCK;
#elif defined(O_NDELAY)
  mode+=O_NDELAY;
#endif
  fd=open(fn, mode);
  if (fd!=-1){
    if (!max || max>sizeof(buff))
      max=sizeof(buff);
    rd=read(fd, buff, max);
    if (rd>0)
      psync_hash_update(hctx, buff, rd);
    close(fd);
  }
}
#endif

#if defined(P_OS_LINUX)
static void psync_get_random_seed_linux(psync_hash_ctx *hctx){
  struct sysinfo si;
  if (likely_log(!sysinfo(&si)))
    psync_hash_update(hctx, &si, sizeof(si));
  psync_add_file_to_seed("/proc/stat", hctx, 0);
  psync_add_file_to_seed("/proc/vmstat", hctx, 0);
  psync_add_file_to_seed("/proc/meminfo", hctx, 0);
  psync_add_file_to_seed("/proc/modules", hctx, 0);
  psync_add_file_to_seed("/proc/mounts", hctx, 0);
  psync_add_file_to_seed("/proc/diskstats", hctx, 0);
  psync_add_file_to_seed("/proc/interrupts", hctx, 0);
  psync_add_file_to_seed("/proc/net/dev", hctx, 0);
  psync_add_file_to_seed("/proc/net/arp", hctx, 0);
}
#endif

static void psync_get_random_seed_from_query(psync_hash_ctx *hctx, psync_sql_res *res){
  psync_variant_row row;
  int i;
  while ((row=psync_sql_fetch_row(res))){
    for (i=0; i<res->column_count; i++)
      if (row[i].type==PSYNC_TSTRING)
        psync_hash_update(hctx, row[i].str, row[i].length);
      else if (row[i].type==PSYNC_TNUMBER)
        psync_hash_update(hctx, &row[i].num, sizeof(uint64_t));
  }
  psync_sql_free_result(res);
}

static void psync_get_random_seed_from_db(psync_hash_ctx *hctx){
  psync_sql_res *res;
  struct timespec tm;
  res=psync_sql_query("SELECT * FROM setting ORDER BY RANDOM()");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query("SELECT * FROM file ORDER BY RANDOM() LIMIT 10");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query("SELECT * FROM localfile ORDER BY RANDOM() LIMIT 10");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query("SELECT * FROM folder ORDER BY RANDOM() LIMIT 5");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query("SELECT * FROM localfolder ORDER BY RANDOM() LIMIT 5");
  psync_get_random_seed_from_query(hctx, res);
  psync_nanotime(&tm);
  psync_hash_update(hctx, &tm, sizeof(&tm));
  psync_sql_statement("REPLACE INTO setting (id, value) VALUES ('random', RANDOM())");
  psync_nanotime(&tm);
  psync_hash_update(hctx, &tm, sizeof(&tm));
}

static void psync_store_seed_in_db(const unsigned char *seed){
  static const char *pass="]lasSX0Q'}#26\\q8\"zlpwnXLtJOhsJ%Ay;gn5((Yh~r|'~wBaUqri$~EE3_0EY+?";
  psync_hash_ctx hctx;
  psync_uint_t i;
  size_t l;
  psync_sql_res *res;
  unsigned char hashbin[PSYNC_HASH_DIGEST_LEN];
  char hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  l=strlen(pass);
  psync_hash_init(&hctx);
  psync_hash_update(&hctx, pass, l);
  for (i=0; i<100000; i++){
    psync_hash_update(&hctx, seed, PSYNC_HASH_DIGEST_LEN);
    psync_hash_update(&hctx, pass, l);
  }
  psync_hash_final(hashbin, &hctx);
  psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES ('randomhash', ?)");
  psync_sql_bind_lstring(res, 1, hashhex, PSYNC_HASH_DIGEST_HEXLEN);
  psync_sql_run_free(res);
}

void psync_get_random_seed(unsigned char *seed, const void *addent, size_t aelen){
  static unsigned char lastseed[PSYNC_HASH_DIGEST_LEN];
  psync_hash_ctx hctx;
  struct timespec tm;
  psync_stat_t st;
  char *home;
  void *ptr;
  psync_uint_t i, j;
  int64_t i64;
  pthread_t threadid;
  unsigned char lsc[100][PSYNC_HASH_DIGEST_LEN];
#if defined(P_OS_POSIX)
  struct utsname un;
  struct statvfs stfs;
  char **env;
  pid_t pid;
  psync_nanotime(&tm);
  psync_hash_init(&hctx);
  psync_hash_update(&hctx, &tm, sizeof(tm));
  if (likely_log(!uname(&un)))
    psync_hash_update(&hctx, &un, sizeof(un));
  pid=getpid();
  psync_hash_update(&hctx, &pid, sizeof(pid));
  if (!statvfs("/", &stfs))
    psync_hash_update(&hctx, &stfs, sizeof(stfs));
  for (env=environ; *env!=NULL; env++)
    psync_hash_update(&hctx, *env, strlen(*env));
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
  if (likely_log(!clock_gettime(CLOCK_MONOTONIC, &tm)))
    psync_hash_update(&hctx, &tm, sizeof(tm));
#endif
  psync_add_file_to_seed("/dev/random", &hctx, PSYNC_HASH_DIGEST_LEN);
#elif defined(P_OS_WINDOWS)
  SYSTEM_INFO si;
  OSVERSIONINFO osvi;
  CURSORINFO ci;
  PROCESSENTRY32 pe;
  THREADENTRY32 te;
  MODULEENTRY32 me;
  MEMORYSTATUSEX ms;
  LARGE_INTEGER li;
  TCHAR ib[1024];
  DWORD ibc;
  HCRYPTPROV cprov;
  HANDLE pr;
  psync_nanotime(&tm);
  psync_hash_init(&hctx);
  psync_hash_update(&hctx, &tm, sizeof(tm));
  if (CryptAcquireContext(&cprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)){
    if (CryptGenRandom(cprov, PSYNC_HASH_DIGEST_LEN, lsc[0]))
      psync_hash_update(&hctx, lsc[0], PSYNC_HASH_DIGEST_LEN);
    CryptReleaseContext(cprov, 0);
  }
  if ((pr=CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0))!=INVALID_HANDLE_VALUE){
    pe.dwSize=sizeof(pe);
    if (Process32First(pr, &pe))
      do {
        psync_hash_update(&hctx, &pe, sizeof(pe));
      } while(Process32Next(pr, &pe));
    te.dwSize=sizeof(te);
    if (Thread32First(pr, &te))
      do {
        psync_hash_update(&hctx, &te, sizeof(te));
      } while(Thread32Next(pr, &te));
    me.dwSize=sizeof(me);
    if (Module32First(pr, &me))
      do {
        psync_hash_update(&hctx, &me, sizeof(me));
      } while(Module32Next(pr, &me));
    CloseHandle(pr);
  }
  ms.dwLength=sizeof(ms);
  if (GlobalMemoryStatusEx(&ms))
    psync_hash_update(&hctx, &ms, sizeof(ms));
  ci.cbSize=sizeof(ci);
  if (GetCursorInfo(&ci))
    psync_hash_update(&hctx, &ci, sizeof(ci));
  GetSystemInfo(&si);
  psync_hash_update(&hctx, &si, sizeof(si));
  ibc=ARRAY_SIZE(ib);
  if (GetComputerName(ib, &ibc))
    psync_hash_update(&hctx, ib, sizeof(TCHAR)*ibc);
  ibc=ARRAY_SIZE(ib);
  if (GetUserName(ib, &ibc))
    psync_hash_update(&hctx, ib, sizeof(TCHAR)*ibc);
  memset(&osvi, 0, sizeof(OSVERSIONINFO));
  osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFO);
  if (GetVersionEx(&osvi))
    psync_hash_update(&hctx, &osvi, sizeof(osvi));
  ibc=GetCurrentProcessId();
  psync_hash_update(&hctx, &ibc, sizeof(ibc));
  ibc=GetTickCount();
  psync_hash_update(&hctx, &ibc, sizeof(ibc));
  if (QueryPerformanceCounter(&li))
    psync_hash_update(&hctx, &li, sizeof(li));
#endif
#if defined(P_OS_LINUX)
  psync_get_random_seed_linux(&hctx);
#endif
  threadid=pthread_self();
  psync_hash_update(&hctx, &threadid, sizeof(threadid));
  ptr=(void *)&ptr;
  psync_hash_update(&hctx, &ptr, sizeof(ptr));
  ptr=(void *)psync_get_random_seed;
  psync_hash_update(&hctx, &ptr, sizeof(ptr));
  ptr=(void *)&lastseed;
  psync_hash_update(&hctx, &ptr, sizeof(ptr));
  home=psync_get_home_dir();
  if (home){
    i64=psync_get_free_space_by_path(home);
    psync_hash_update(&hctx, &i64, sizeof(i64));
    psync_hash_update(&hctx, &home, sizeof(home));
    psync_hash_update(&hctx, home, strlen(home));
    if (likely_log(!psync_stat(home, &st)))
      psync_hash_update(&hctx, &st, sizeof(st));
    psync_free(home);
  }
  psync_get_random_seed_from_db(&hctx);
  if (aelen)
    psync_hash_update(&hctx, addent, aelen);
  for (i=0; i<ARRAY_SIZE(lsc); i++){
    memcpy(&lsc[i], lastseed, PSYNC_HASH_DIGEST_LEN);
    for (j=0; j<PSYNC_HASH_DIGEST_LEN; j++)
      lsc[i][j]^=(unsigned char)i;
  }
  for (j=0; j<100; j++){
    for (i=0; i<100; i++){
      psync_hash_update(&hctx, &i, sizeof(i));
      psync_hash_update(&hctx, &j, sizeof(j));
      psync_hash_update(&hctx, lsc, sizeof(lsc));
    }
    psync_nanotime(&tm);
    psync_hash_update(&hctx, &tm, sizeof(&tm));
  }
  psync_hash_final(seed, &hctx);
  memcpy(lastseed, seed, PSYNC_HASH_DIGEST_LEN);
  psync_store_seed_in_db(seed);
}

static int psync_wait_socket_writable_microsec(psync_socket_t sock, long sec, long usec){
  fd_set wfds;
  struct timeval tv;
  int res;
  tv.tv_sec=sec;
  tv.tv_usec=usec;
  FD_ZERO(&wfds);
  FD_SET(sock, &wfds);
  res=select(sock+1, NULL, &wfds, NULL, &tv);
  if (res==1)
    return 0;
  if (res==0)
    psync_sock_set_err(P_TIMEDOUT);
  return SOCKET_ERROR;
}

#define psync_wait_socket_writable(sock, sec) psync_wait_socket_writable_microsec(sock, sec, 0)
#define psync_wait_socket_write_timeout(sock) psync_wait_socket_writable(sock, PSYNC_SOCK_WRITE_TIMEOUT)

static int psync_wait_socket_readable_microsec(psync_socket_t sock, long sec, long usec){
  fd_set rfds;
  struct timeval tv;
  int res;
  tv.tv_sec=sec;
  tv.tv_usec=usec;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  res=select(sock+1, &rfds, NULL, NULL, &tv);
  if (res==1)
    return 0;
  if (res==0)
    psync_sock_set_err(P_TIMEDOUT);
  return SOCKET_ERROR;
}

#define psync_wait_socket_readable(sock, sec) psync_wait_socket_readable_microsec(sock, sec, 0)
#define psync_wait_socket_read_timeout(sock) psync_wait_socket_readable(sock, PSYNC_SOCK_READ_TIMEOUT)

static psync_socket_t connect_res(struct addrinfo *res){
  psync_socket_t sock;
#if defined(P_OS_WINDOWS)
  static const unsigned long non_blocking_mode=1;
#endif
#if defined(SOCK_NONBLOCK)
#if defined(SOCK_CLOEXEC)
#define PSOCK_TYPE_OR (SOCK_NONBLOCK|SOCK_CLOEXEC)
#else
#define PSOCK_TYPE_OR SOCK_NONBLOCK
#endif
#else
#define PSOCK_TYPE_OR 0
#define PSOCK_NEED_NOBLOCK
#endif
  while (res){
    sock=socket(res->ai_family, res->ai_socktype|PSOCK_TYPE_OR, res->ai_protocol);
    if (likely_log(sock!=INVALID_SOCKET)){
#if defined(PSOCK_NEED_NOBLOCK)
#if defined(P_OS_WINDOWS)
      unsigned long mode = non_blocking_mode;
      ioctlsocket(sock, FIONBIO, &mode);
#elif defined(P_OS_POSIX)
      fcntl(sock, F_SETFD, FD_CLOEXEC);
      fcntl(sock, F_SETFL, fcntl(sock, F_GETFL)|O_NONBLOCK);
#else
#error "Need to set non-blocking for your OS"
#endif
#endif
      if ((connect(sock, res->ai_addr, res->ai_addrlen)!=SOCKET_ERROR) ||
          (psync_sock_err()==P_INPROGRESS && !psync_wait_socket_writable(sock, PSYNC_SOCK_CONNECT_TIMEOUT)))
        return sock;
      psync_close_socket(sock);
    }
    res=res->ai_next;
  }
  return INVALID_SOCKET;
}

psync_socket_t psync_create_socket(int domain, int type, int protocol){
  int ret;
  ret=socket(domain, type, protocol);
#if defined(P_OS_WINDOWS)
  if (unlikely(ret==INVALID_SOCKET && WSAGetLastError()==WSANOTINITIALISED)){
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
      return INVALID_SOCKET;
    ret=socket(domain, type, protocol);
  }
#endif
  return ret;
}

static psync_socket_t connect_socket(const char *host, const char *port){
  struct addrinfo *res=NULL;
  struct addrinfo hints;
  psync_socket_t sock;
  int rc;
  debug(D_NOTICE, "connecting to %s:%s", host, port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family=AF_UNSPEC;
  hints.ai_socktype=SOCK_STREAM;
  rc=getaddrinfo(host, port, &hints, &res);
#if defined(P_OS_WINDOWS)
  if (unlikely(rc==WSANOTINITIALISED)){
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
      return INVALID_SOCKET;
    rc=getaddrinfo(host, port, &hints, &res);
  }
#endif
  if (unlikely(rc!=0)){
    debug(D_WARNING, "failed to resolve %s", host);
    return INVALID_SOCKET;
  }
  sock=connect_res(res);
  freeaddrinfo(res);
  if (likely(sock!=INVALID_SOCKET)){
    int sock_opt=1;
#if defined(SO_KEEPALIVE) && defined(SOL_SOCKET)
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&sock_opt, sizeof(sock_opt));
#endif
#if defined(TCP_KEEPALIVE) && defined(IPPROTO_TCP)
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, (char*)&sock_opt, sizeof(sock_opt));
#endif
#if defined(SOL_TCP)
#if defined(TCP_KEEPCNT)
    sock_opt=3;
    setsockopt(sock, SOL_TCP, TCP_KEEPCNT, (char*)&sock_opt, sizeof(sock_opt));
#endif
#if defined(TCP_KEEPIDLE)
    sock_opt=60;
    setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (char*)&sock_opt, sizeof(sock_opt));
#endif
#if defined(TCP_KEEPINTVL)
    sock_opt=20;
    setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (char*)&sock_opt, sizeof(sock_opt));
#endif
#endif
  }
  else
    debug(D_WARNING, "failed to connect to %s:%s", host, port);
  return sock;
}

static int wait_sock_ready_for_ssl(psync_socket_t sock){
  fd_set fds, *rfds, *wfds;
  struct timeval tv;
  int res;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);
  if (psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ){
    rfds=&fds;
    wfds=NULL;
    tv.tv_sec=PSYNC_SOCK_READ_TIMEOUT;
  }
  else if (psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE){
    rfds=NULL;
    wfds=&fds;
    tv.tv_sec=PSYNC_SOCK_WRITE_TIMEOUT;
  }
  else{
    debug(D_BUG, "this functions should only be called when SSL returns WANT_READ/WANT_WRITE");
    psync_sock_set_err(P_INVAL);
    return SOCKET_ERROR;
  }
  tv.tv_usec=0;
  res=select(sock+1, rfds, wfds, NULL, &tv);
  if (res==1)
    return 0;
  if (res==0)
    psync_sock_set_err(P_TIMEDOUT);
  return SOCKET_ERROR;
}

psync_socket *psync_socket_connect(const char *host, int unsigned port, int ssl){
  psync_socket *ret;
  void *sslc;
  psync_socket_t sock;
  char sport[24];
  sprintf(sport, "%d", port);
  sock=connect_socket(host, sport);
  if (unlikely_log(sock==INVALID_SOCKET))
    return NULL;
  if (ssl){
    ssl=psync_ssl_connect(sock, &sslc, host);
    while (ssl==PSYNC_SSL_NEED_FINISH){
      if (wait_sock_ready_for_ssl(sock)){
        psync_ssl_free(sslc);
        break;
      }
      ssl=psync_ssl_connect_finish(sslc, host);
    }
    if (unlikely_log(ssl!=PSYNC_SSL_SUCCESS)){
      psync_close_socket(sock);
      return NULL;
    }
  }
  else
    sslc=NULL;
  ret=psync_new(psync_socket);
  ret->ssl=sslc;
  ret->sock=sock;
  ret->pending=0;
  return ret;
}

void psync_socket_close(psync_socket *sock){
  if (sock->ssl)
    while (psync_ssl_shutdown(sock->ssl)==PSYNC_SSL_NEED_FINISH)
      if (wait_sock_ready_for_ssl(sock->sock)){
        psync_ssl_free(sock->ssl);
        break;
      }
  psync_close_socket(sock->sock);
  psync_free(sock);
}

void psync_socket_close_bad(psync_socket *sock){
  if (sock->ssl)
    psync_ssl_free(sock->ssl);
  psync_close_socket(sock->sock);
  psync_free(sock);
}

int psync_socket_set_recvbuf(psync_socket *sock, uint32_t bufsize){
#if defined(SO_RCVBUF) && defined(SOL_SOCKET)
  return setsockopt(sock->sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
#else
  return -1;
#endif
}

int psync_socket_set_sendbuf(psync_socket *sock, uint32_t bufsize){
#if defined(SO_SNDBUF) && defined(SOL_SOCKET)
  return setsockopt(sock->sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, sizeof(bufsize));
#else
  return -1;
#endif
}

int psync_socket_isssl(psync_socket *sock){
  if (sock->ssl)
    return 1;
  else
    return 0;
}

int psync_socket_pendingdata(psync_socket *sock){
  if (sock->pending)
    return 1;
  if (sock->ssl)
    return psync_ssl_pendingdata(sock->ssl);
  else
    return 0;
}

int psync_socket_pendingdata_buf(psync_socket *sock){
  int ret;
#if defined(P_OS_POSIX) && defined(FIONREAD)
  if (ioctl(sock->sock, FIONREAD, &ret))
    return -1;
#elif defined(P_OS_WINDOWS)
  u_long l;
  if (ioctlsocket(sock->sock, FIONREAD, &l))
    return -1;
  else
    ret=l;
#else
  return -1;
#endif
  if (sock->ssl)
    ret+=psync_ssl_pendingdata(sock->ssl);
  return ret;
}

int psync_socket_readable(psync_socket *sock){
  if (sock->ssl && psync_ssl_pendingdata(sock->ssl))
    return 1;
  else if (psync_wait_socket_readable(sock->sock, 0))
    return 0;
  else{
    sock->pending=1;
    return 1;
  }
}

int psync_socket_writable(psync_socket *sock){
  return !psync_wait_socket_writable(sock->sock, 0);
}

static int psync_socket_read_ssl(psync_socket *sock, void *buff, int num){
  int r;
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending && psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending=0;
  while (1){
    r=psync_ssl_read(sock->ssl, buff, num);
    if (r==PSYNC_SSL_FAIL){
      if (likely_log(psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ || psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE)){
        if (wait_sock_ready_for_ssl(sock->sock))
          return -1;
        else
          continue;
      }
      else{
        psync_sock_set_err(P_CONNRESET);
        return -1;
      }
    }
    else
      return r;
  }
}

static int psync_socket_read_plain(psync_socket *sock, void *buff, int num){
  int r;
  while (1){
    if (sock->pending)
      sock->pending=0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    r=psync_read_socket(sock->sock, buff, num);
    if (r==SOCKET_ERROR){
      if (likely_log(psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN))
        continue;
      else
        return -1;
    }
    else
      return r;
  }
}

int psync_socket_read(psync_socket *sock, void *buff, int num){
  if (sock->ssl)
    return psync_socket_read_ssl(sock, buff, num);
  else
    return psync_socket_read_plain(sock, buff, num);
}


int psync_socket_write(psync_socket *sock, const void *buff, int num){
  int r;
  if (psync_wait_socket_write_timeout(sock->sock))
    return -1;
  if (sock->ssl){
    r=psync_ssl_write(sock->ssl, buff, num);
    if (r==PSYNC_SSL_FAIL){
      if (likely_log(psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ || psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE))
        return 0;
      else
        return -1;
    }
  }
  else{
    r=psync_write_socket(sock->sock, buff, num);
    if (r==SOCKET_ERROR){
      if (likely_log(psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN))
        return 0;
      else
        return -1;
    }
  }
  return r;
}

static int psync_socket_readall_ssl(psync_socket *sock, void *buff, int num){
  int br, r;
  br=0;
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending && psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending=0;
  while (br<num){
    r=psync_ssl_read(sock->ssl, (char *)buff+br, num-br);
    if (r==PSYNC_SSL_FAIL){
      if (likely_log(psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ || psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE)){
        if (wait_sock_ready_for_ssl(sock->sock))
          return -1;
        else
          continue;
      }
      else{
        psync_sock_set_err(P_CONNRESET);
        return -1;
      }
    }
    if (r==0)
      return br;
    br+=r;
  }
  return br;
}

static int psync_socket_readall_plain(psync_socket *sock, void *buff, int num){
  int br, r;
  br=0;
  while (br<num){
    if (sock->pending)
      sock->pending=0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    r=psync_read_socket(sock->sock, (char *)buff+br, num-br);
    if (r==SOCKET_ERROR){
      if (likely_log(psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN))
        continue;
      else
        return -1;
    }
    if (r==0)
      return br;
    br+=r;
  }
  return br;
}

int psync_socket_readall(psync_socket *sock, void *buff, int num){
  if (sock->ssl)
    return psync_socket_readall_ssl(sock, buff, num);
  else
    return psync_socket_readall_plain(sock, buff, num);
}


static int psync_socket_writeall_ssl(psync_socket *sock, const void *buff, int num){
  int br, r;
  br=0;
  while (br<num){
    r=psync_ssl_write(sock->ssl, (char *)buff+br, num-br);
    if (r==PSYNC_SSL_FAIL){
      if (psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ || psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE){
        if (wait_sock_ready_for_ssl(sock->sock))
          return -1;
        else
          continue;
      }
      else{
        psync_sock_set_err(P_CONNRESET);
        return -1;
      }
    }
    if (r==0)
      return br;
    br+=r;
  }
  return br;
}

static int psync_socket_writeall_plain(psync_socket_t sock, const void *buff, int num){
  int br, r;
  br=0;
  while (br<num){
    r=psync_write_socket(sock, (const char *)buff+br, num-br);
    if (r==SOCKET_ERROR){
      if (psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN){
        if (psync_wait_socket_write_timeout(sock))
          return -1;
        else
          continue;
      }
      else
        return -1;
    }
    br+=r;
  }
  return br;
}

int psync_socket_writeall(psync_socket *sock, const void *buff, int num){
  if (sock->ssl)
    return psync_socket_writeall_ssl(sock, buff, num);
  else
    return psync_socket_writeall_plain(sock->sock, buff, num);
}

psync_interface_list_t *psync_list_ip_adapters(){
  psync_interface_list_t *ret;
  size_t cnt;
#if defined(P_OS_POSIX)
  struct ifaddrs *addrs, *addr;
  sa_family_t family;
  size_t sz;
  if (unlikely_log(getifaddrs(&addrs)))
    goto empty;
  cnt=0;
  addr=addrs;
  while (addr){
    family=addr->ifa_addr->sa_family;
    if ((family==AF_INET || family==AF_INET6) && (addr->ifa_flags&IFF_BROADCAST))
      cnt++;
    addr=addr->ifa_next;
  }
  ret=psync_malloc(offsetof(psync_interface_list_t, interfaces)+sizeof(psync_interface_t)*cnt);
  ret->interfacecnt=cnt;
  addr=addrs;
  cnt=0;
  while (addr){
    family=addr->ifa_addr->sa_family;
    if ((family==AF_INET || family==AF_INET6) && (addr->ifa_flags&IFF_BROADCAST)){
      if (family==AF_INET)
        sz=sizeof(struct sockaddr_in);
      else
        sz=sizeof(struct sockaddr_in6);
      memcpy(&ret->interfaces[cnt].address, &addr->ifa_addr, sz);
      memcpy(&ret->interfaces[cnt].broadcast, &addr->ifa_broadaddr, sz);
      memcpy(&ret->interfaces[cnt].netmask, &addr->ifa_netmask, sz);
      ret->interfaces[cnt].addrsize=sz;
      cnt++;
    }
    addr=addr->ifa_next;
  }
  freeifaddrs(addrs);
  return ret;
#elif defined(P_OS_WINDOWS)
  {
  IP_ADAPTER_ADDRESSES *adapters, *adapter;
  IP_ADAPTER_UNICAST_ADDRESS *addr;
  ULONG sz, rt, fl;
  int isz;
  sz=16*1024;
  adapters=(IP_ADAPTER_ADDRESSES *)psync_malloc(sz);
  fl=GAA_FLAG_SKIP_DNS_SERVER|GAA_FLAG_SKIP_FRIENDLY_NAME|GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST;
  rt=GetAdaptersAddresses(AF_UNSPEC, fl, NULL, adapters, &sz);
  if (rt==ERROR_BUFFER_OVERFLOW){
    adapters=(IP_ADAPTER_ADDRESSES *)psync_realloc(adapters, sz);
    rt=GetAdaptersAddresses(AF_UNSPEC, fl, NULL, adapters, &sz);
  }
  if (rt!=ERROR_SUCCESS){
    psync_free(adapters);
    goto empty;
  }
  adapter=adapters;
  cnt=0;
  while (adapter){
    addr=adapter->FirstUnicastAddress;
    while (addr){
      if (!(addr->Flags&IP_ADAPTER_ADDRESS_TRANSIENT) && (addr->Address.lpSockaddr->sa_family==AF_INET || addr->Address.lpSockaddr->sa_family==AF_INET6))
        cnt++;
      addr=addr->Next;
    }
    adapter=adapter->Next;
  }
  ret=psync_malloc(offsetof(psync_interface_list_t, interfaces)+sizeof(psync_interface_t)*cnt);
  memset(&ret->interfaces, 0, sizeof(psync_interface_t)*cnt);
  ret->interfacecnt=cnt;
  adapter=adapters;
  cnt=0;
  while (adapter){
    addr=adapter->FirstUnicastAddress;
    while (addr){
      if (!(addr->Flags&IP_ADAPTER_ADDRESS_TRANSIENT) && (addr->Address.lpSockaddr->sa_family==AF_INET || addr->Address.lpSockaddr->sa_family==AF_INET6)){
        isz=addr->Address.iSockaddrLength;
        memcpy(&ret->interfaces[cnt].address, addr->Address.lpSockaddr, isz);
        if (addr->Address.lpSockaddr->sa_family==AF_INET){
          ret->interfaces[cnt].broadcast.ss_family=AF_INET;
          memset(&(((struct sockaddr_in *)(&ret->interfaces[cnt].broadcast))->sin_addr), 0xff, sizeof(((struct sockaddr_in *)NULL)->sin_addr));
        }
        else{
          ret->interfaces[cnt].broadcast.ss_family=AF_INET6;
          memset(&(((struct sockaddr_in6 *)(&ret->interfaces[cnt].broadcast))->sin6_addr), 0xff, sizeof(((struct sockaddr_in6 *)NULL)->sin6_addr));
        }
        ret->interfaces[cnt].addrsize=isz;
        cnt++;
      }
      addr=addr->Next;
    }
    adapter=adapter->Next;
  }
  return ret;
  }
#endif
empty:
  ret=psync_malloc(offsetof(psync_interface_list_t, interfaces));
  ret->interfacecnt=0;
  return ret;
}

int psync_pipe(psync_socket_t pipefd[2]){
#if defined(P_OS_POSIX)
  return pipe(pipefd);
#else
  psync_socket_t sock;
  struct sockaddr_in addr;
  socklen_t addrlen;
  sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock==INVALID_SOCKET){
#if defined(P_OS_WINDOWS)
    if (psync_sock_err()==WSANOTINITIALISED){
      WSADATA wsaData;
      if (WSAStartup(MAKEWORD(2, 2), &wsaData) || (sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))==INVALID_SOCKET)
        goto err0;
    }
    else
#endif
      goto err0;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  addrlen=sizeof(addr);
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))==SOCKET_ERROR ||
      listen(sock, 1)==SOCKET_ERROR ||
      getsockname(sock, (struct sockaddr *)&addr, &addrlen)==SOCKET_ERROR ||
      (pipefd[0]=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))==INVALID_SOCKET)
    goto err1;
  if (connect(pipefd[0], (struct sockaddr *)&addr, addrlen)==SOCKET_ERROR ||
      (pipefd[1]=accept(sock, NULL, NULL))==INVALID_SOCKET)
    goto err2;
  psync_close_socket(sock);
  return 0;
err2:
  psync_close_socket(pipefd[0]);
err1:
  psync_close_socket(sock);
err0:
  return SOCKET_ERROR;
#endif
}

int psync_pipe_close(psync_socket_t pfd){
  return psync_close_socket(pfd);
}

int psync_pipe_read(psync_socket_t pfd, void *buff, int num){
#if defined(P_OS_POSIX)
  return read(pfd, buff, num);
#elif defined(P_OS_WINDOWS)
  return recv(pfd, (char *)buff, num, 0);
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_pipe_write(psync_socket_t pfd, const void *buff, int num){
#if defined(P_OS_POSIX)
  return write(pfd, buff, num);
#elif defined(P_OS_WINDOWS)
  return send(pfd, (const char *)buff, num, 0);
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_select_in(psync_socket_t *sockets, int cnt, int64_t timeoutmilisec){
  fd_set rfds;
  struct timeval tv, *ptv;
  psync_socket_t max;
  int i;
  if (timeoutmilisec<0)
    ptv=NULL;
  else{
    tv.tv_sec=timeoutmilisec/1000;
    tv.tv_usec=(timeoutmilisec%1000)*1000;
    ptv=&tv;
  }
  FD_ZERO(&rfds);
  max=0;
  for (i=0; i<cnt; i++){
    FD_SET(sockets[i], &rfds);
    if (sockets[i]>=max)
      max=sockets[i]+1;
  }
  i=select(max, &rfds, NULL, NULL, ptv);
  if (i>0){
    for (i=0; i<cnt; i++)
      if (FD_ISSET(sockets[i], &rfds))
        return i;
  }
  else if (i==0)
    psync_sock_set_err(P_TIMEDOUT);
  return SOCKET_ERROR;
}

#if defined(P_OS_WINDOWS)
#if !defined(gmtime_r)
struct tm *gmtime_r(const time_t *timep, struct tm *result){
  struct tm *res=gmtime(timep);
  *result=*res;
  return result;
}
#endif

static wchar_t *utf8_to_wchar(const char *str){
  int len;
  wchar_t *ret;
  len=MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  ret=psync_new_cnt(wchar_t, len);
  MultiByteToWideChar(CP_UTF8, 0, str, -1, ret, len);
  return ret;
}

static char *wchar_to_utf8(const wchar_t *str){
  int len;
  char *ret;
  len=WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
  ret=psync_new_cnt(char, len);
  WideCharToMultiByte(CP_UTF8, 0, str, -1, ret, len, NULL, NULL);
  return ret;
}

int psync_stat(const char *path, psync_stat_t *st){
  wchar_t *wpath;
  HANDLE fd;
  BOOL ret;
  int flag = FILE_ATTRIBUTE_NORMAL;
  wpath=utf8_to_wchar(path);
  if (GetFileAttributesW(wpath)&FILE_ATTRIBUTE_DIRECTORY)
    flag = FILE_FLAG_BACKUP_SEMANTICS;
  fd=CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, flag, NULL);
  psync_free(wpath);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE))
    return -1;
  ret=GetFileInformationByHandle(fd, st);
  CloseHandle(fd);
  return psync_bool_to_zero(ret);
}

#endif

int psync_list_dir(const char *path, psync_list_dir_callback callback, void *ptr){
#if defined(P_OS_POSIX)
  psync_pstat pst;
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry, *de;
  dh=opendir(path);
  if (unlikely_log(!dh))
    goto err1;
  pl=strlen(path);
  namelen=pathconf(path, _PC_NAME_MAX);
  if (namelen==-1)
    namelen=255;
  entrylen=offsetof(struct dirent, d_name)+namelen+1;
  cpath=(char *)psync_malloc(pl+namelen+2);
  entry=(struct dirent *)psync_malloc(entrylen);
  memcpy(cpath, path, pl);
  if (!pl || cpath[pl-1]!=PSYNC_DIRECTORY_SEPARATORC)
    cpath[pl++]=PSYNC_DIRECTORY_SEPARATORC;
  pst.path=cpath;
  while (!readdir_r(dh, entry, &de) && de)
    if (de->d_name[0]!='.' || (de->d_name[1]!=0 && (de->d_name[1]!='.' || de->d_name[2]!=0))){
      strcpy(cpath+pl, de->d_name);
      if (likely_log(!lstat(cpath, &pst.stat)) && (S_ISREG(pst.stat.st_mode) || S_ISDIR(pst.stat.st_mode))){
        pst.name=de->d_name;
        callback(ptr, &pst);
      }
    }
  psync_free(entry);
  psync_free(cpath);
  closedir(dh);
  return 0;
err1:
  psync_error=PERROR_LOCAL_FOLDER_NOT_FOUND;
  return -1;
#elif defined(P_OS_WINDOWS)
  psync_pstat pst;
  char *spath, *name;
  wchar_t *wpath;
  WIN32_FIND_DATAW st;
  HANDLE dh;
  spath=psync_strcat(path, PSYNC_DIRECTORY_SEPARATOR "*", NULL);
  wpath=utf8_to_wchar(spath);
  psync_free(spath);
  dh=FindFirstFileW(wpath, &st);
  psync_free(wpath);
  if (dh==INVALID_HANDLE_VALUE){
    if (GetLastError()==ERROR_FILE_NOT_FOUND)
      return 0;
    else{
      psync_error=PERROR_LOCAL_FOLDER_NOT_FOUND;
      return -1;
    }
  }
  do {
    if (st.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && (!wcscmp(st.cFileName, L".") || !wcscmp(st.cFileName, L"..")))
        continue;
    name=wchar_to_utf8(st.cFileName);
    spath=psync_strcat(path, PSYNC_DIRECTORY_SEPARATOR, name, NULL);
    pst.name=name;
    pst.path=spath;
    if (likely_log(!psync_stat(spath, &pst.stat)))
      callback(ptr, &pst);
    psync_free(name);
    psync_free(spath);
  } while (FindNextFileW(dh, &st));
  FindClose(dh);
  return 0;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_list_dir_fast(const char *path, psync_list_dir_callback_fast callback, void *ptr){
#if defined(P_OS_POSIX)
  psync_pstat_fast pst;
  struct stat st;
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry, *de;
  dh=opendir(path);
  if (unlikely_log(!dh))
    goto err1;
  pl=strlen(path);
  namelen=pathconf(path, _PC_NAME_MAX);
  if (namelen==-1)
    namelen=255;
  entrylen=offsetof(struct dirent, d_name)+namelen+1;
  cpath=(char *)psync_malloc(pl+namelen+2);
  entry=(struct dirent *)psync_malloc(entrylen);
  memcpy(cpath, path, pl);
  if (!pl || cpath[pl-1]!=PSYNC_DIRECTORY_SEPARATORC)
    cpath[pl++]=PSYNC_DIRECTORY_SEPARATORC;
  while (!readdir_r(dh, entry, &de) && de)
    if (de->d_name[0]!='.' || (de->d_name[1]!=0 && (de->d_name[1]!='.' || de->d_name[2]!=0))){
#if defined(DT_UNKNOWN) && defined(DT_DIR) && defined(DT_REG)
      pst.name=de->d_name;
      if (de->d_type==DT_UNKNOWN){
        strcpy(cpath+pl, de->d_name);
        if (unlikely_log(lstat(cpath, &st)))
          continue;
        pst.isfolder=S_ISDIR(st.st_mode);
      }
      else if (de->d_type==DT_DIR)
        pst.isfolder=1;
      else if (de->d_type==DT_REG)
        pst.isfolder=0;
      else
        continue;
      callback(ptr, &pst);
#else
      strcpy(cpath+pl, de->d_name);
      if (likely_log(!lstat(cpath, &st))){
        pst.name=de->d_name;
        pst.isfolder=S_ISDIR(st.st_mode);
        callback(ptr, &pst);
      }
#endif
    }
  psync_free(entry);
  psync_free(cpath);
  closedir(dh);
  return 0;
err1:
  psync_error=PERROR_LOCAL_FOLDER_NOT_FOUND;
  return -1;
#elif defined(P_OS_WINDOWS)
  psync_pstat_fast pst;
  char *spath, *name;
  wchar_t *wpath;
  WIN32_FIND_DATAW st;
  HANDLE dh;
  spath=psync_strcat(path, PSYNC_DIRECTORY_SEPARATOR "*", NULL);
  wpath=utf8_to_wchar(spath);
  psync_free(spath);
  dh=FindFirstFileW(wpath, &st);
  psync_free(wpath);
  if (dh==INVALID_HANDLE_VALUE){
    if (GetLastError()==ERROR_FILE_NOT_FOUND)
      return 0;
    else{
      psync_error=PERROR_LOCAL_FOLDER_NOT_FOUND;
      return -1;
    }
  }
  do {
    name=wchar_to_utf8(st.cFileName);
    pst.name=name;
    pst.isfolder=(st.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)>0;
    callback(ptr, &pst);
    psync_free(name);
  } while (FindNextFileW(dh, &st));
  FindClose(dh);
  return 0;
#else
#error "Function not implemented for your operating system"
#endif
}

int64_t psync_get_free_space_by_path(const char *path){
#if defined(P_OS_POSIX)
  struct statvfs buf;
  if (unlikely_log(statvfs(path, &buf)))
    return -1;
  else
    return (int64_t)buf.f_bavail*(int64_t)buf.f_bsize;
#elif defined(P_OS_WINDOWS)
  ULARGE_INTEGER free;
  wchar_t *wpath;
  BOOL ret;
  wpath=utf8_to_wchar(path);
  ret=GetDiskFreeSpaceExW(wpath, &free, NULL, NULL);
  psync_free(wpath);
  if (likely_log(ret))
    return free.QuadPart;
  else
    return -1;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_mkdir(const char *path){
#if defined(P_OS_POSIX)
  return mkdir(path, PSYNC_DEFAULT_POSIX_FOLDER_MODE);
#elif defined(P_OS_WINDOWS)
  wchar_t *wpath;
  int ret;
  wpath=utf8_to_wchar(path);
  ret=psync_bool_to_zero(CreateDirectoryW(wpath, NULL));
  psync_free(wpath);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_rmdir(const char *path){
#if defined(P_OS_POSIX)
  return rmdir(path);
#elif defined(P_OS_WINDOWS)
  wchar_t *wpath;
  int ret;
  wpath=utf8_to_wchar(path);
  ret=psync_bool_to_zero(RemoveDirectoryW(wpath));
  psync_free(wpath);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_rename(const char *oldpath, const char *newpath){
#if defined(P_OS_POSIX)
  return rename(oldpath, newpath);
#elif defined(P_OS_WINDOWS) // should we just use rename() here?
  wchar_t *oldwpath, *newwpath;
  int ret;
  oldwpath=utf8_to_wchar(oldpath);
  newwpath=utf8_to_wchar(newpath);
  ret=psync_bool_to_zero(MoveFileW(oldwpath, newwpath));
  psync_free(oldwpath);
  psync_free(newwpath);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_rename_overwrite(const char *oldpath, const char *newpath){
  if (!psync_filename_cmp(oldpath, newpath))
    return 0;
#if defined(P_OS_POSIX)
  return rename(oldpath, newpath);
#elif defined(P_OS_WINDOWS) // should we just use rename() here?
  {
    wchar_t *oldwpath, *newwpath;
    int ret;
    oldwpath=utf8_to_wchar(oldpath);
    newwpath=utf8_to_wchar(newpath);
    DeleteFileW(newwpath);
    ret=psync_bool_to_zero(MoveFileW(oldwpath, newwpath));
    psync_free(oldwpath);
    psync_free(newwpath);
    return ret;
  }
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_delete(const char *path){
#if defined(P_OS_POSIX)
  return unlink(path);
#elif defined(P_OS_WINDOWS)
  wchar_t *wpath;
  int ret;
  wpath=utf8_to_wchar(path);
  ret=psync_bool_to_zero(DeleteFileW(wpath));
  psync_free(wpath);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

psync_file_t psync_file_open(const char *path, int access, int flags){
#if defined(P_OS_POSIX)
#if defined(O_CLOEXEC)
  flags|=O_CLOEXEC;
#endif
#if defined(O_NOATIME)
  flags|=O_NOATIME;
#endif
  return open(path, access|flags, PSYNC_DEFAULT_POSIX_FILE_MODE);
#elif defined(P_OS_WINDOWS)
  DWORD cdis;
  wchar_t *wpath;
  HANDLE ret;
  if (flags&P_O_EXCL)
    cdis=CREATE_NEW;
  else if (flags&(P_O_CREAT|P_O_TRUNC))
    cdis=CREATE_ALWAYS;
  else if (flags&P_O_CREAT)
    cdis=OPEN_ALWAYS;
  else if (flags&P_O_TRUNC)
    cdis=TRUNCATE_EXISTING;
  else
    cdis=OPEN_EXISTING;
  wpath=utf8_to_wchar(path);
  ret=CreateFileW(wpath, access, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, cdis, FILE_ATTRIBUTE_NORMAL, NULL);
  psync_free(wpath);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_close(psync_file_t fd){
#if defined(P_OS_POSIX)
  return close(fd);
#elif defined(P_OS_WINDOWS)
  return psync_bool_to_zero(CloseHandle(fd));
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_sync(psync_file_t fd){
#if defined(P_OS_POSIX)
  return fsync(fd);
#elif defined(P_OS_WINDOWS)
  return psync_bool_to_zero(FlushFileBuffers(fd));
#else
#error "Function not implemented for your operating system"
#endif
}

ssize_t psync_file_read(psync_file_t fd, void *buf, size_t count){
#if defined(P_OS_POSIX)
  return read(fd, buf, count);
#elif defined(P_OS_WINDOWS)
  DWORD ret;
  if (ReadFile(fd, buf, count, &ret, NULL))
    return ret;
  else
    return -1;
#else
#error "Function not implemented for your operating system"
#endif
}

ssize_t psync_file_write(psync_file_t fd, const void *buf, size_t count){
#if defined(P_OS_POSIX)
  return write(fd, buf, count);
#elif defined(P_OS_WINDOWS)
  DWORD ret;
  if (WriteFile(fd, buf, count, &ret, NULL))
    return ret;
  else
    return -1;
#else
#error "Function not implemented for your operating system"
#endif
}

int64_t psync_file_seek(psync_file_t fd, uint64_t offset, int whence){
#if defined(P_OS_POSIX)
  return lseek(fd, offset, whence);
#elif defined(P_OS_WINDOWS)
   LARGE_INTEGER li;
   li.QuadPart=offset;
   li.LowPart=SetFilePointer(fd, li.LowPart, &li.HighPart, whence);
   if (li.LowPart==INVALID_SET_FILE_POINTER && GetLastError()!=NO_ERROR)
     return -1;
   else
     return li.QuadPart;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_truncate(psync_file_t fd){
#if defined(P_OS_POSIX)
  off_t off;
  off=lseek(fd, 0, SEEK_CUR);
  if (likely_log(off!=(off_t)-1))
    return ftruncate(fd, off);
  else
    return -1;
#elif defined(P_OS_WINDOWS)
   return psync_bool_to_zero(SetEndOfFile(fd));
#else
#error "Function not implemented for your operating system"
#endif
}

int64_t psync_file_size(psync_file_t fd){
#if defined(P_OS_POSIX)
  struct stat st;
  if (unlikely_log(fstat(fd, &st)))
    return -1;
  else
    return st.st_size;
#elif defined(P_OS_WINDOWS)
   ULARGE_INTEGER li;
   li.LowPart=GetFileSize(fd, &li.HighPart);
   if (unlikely_log(li.LowPart==INVALID_FILE_SIZE && GetLastError()!=NO_ERROR))
     return -1;
   else
     return li.QuadPart;
#else
#error "Function not implemented for your operating system"
#endif
}
