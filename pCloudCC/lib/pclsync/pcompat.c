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
#include "ptimer.h"

#if defined(P_OS_LINUX)
#include <sys/sysinfo.h>
#endif

#if defined(P_OS_MACOSX)
#include <sys/sysctl.h>
#include <sys/attr.h>
#include <SystemConfiguration/SystemConfiguration.h>
#endif

#if defined(P_OS_POSIX)

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <utime.h>
#include <limits.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

extern char **environ;

#if defined(MAP_ANONYMOUS)
#define PSYNC_MAP_ANONYMOUS MAP_ANONYMOUS
#elif defined(MAP_ANON)
#define PSYNC_MAP_ANONYMOUS MAP_ANON
#endif

#elif defined(P_OS_WINDOWS)

#include <process.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <shlobj.h>

#pragma comment(lib, "winhttp.lib")

#endif

#define PROXY_NONE    0
#define PROXY_CONNECT 1

typedef struct {
  psync_thread_start0 run;
  const char *name;
} psync_run_data0;

typedef struct {
  psync_thread_start1 run;
  void *ptr;
  const char *name;
} psync_run_data1;

#if defined(P_OS_POSIX)
static uid_t psync_uid;
static gid_t psync_gid;
static gid_t *psync_gids;
static int psync_gids_cnt;
#endif

static int proxy_type=PROXY_NONE;
static int proxy_detected=0;
static char proxy_host[256];
static char proxy_port[8];

static int psync_page_size;

static const char *psync_software_name=PSYNC_LIB_VERSION;
static const char *psync_os_name=NULL;

PSYNC_THREAD const char *psync_thread_name="no name";
static pthread_mutex_t socket_mutex=PTHREAD_MUTEX_INITIALIZER;

const unsigned char psync_invalid_filename_chars[256]={
#if defined(P_OS_WINDOWS)
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#elif defined(P_OS_LINUX)
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#elif defined(P_OS_MACOSX)
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#else
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#endif
};

int psync_user_is_admin(){
#if defined(P_OS_MACOSX)
  struct group *ag;
  int i;
  if (psync_uid==0)
    return 1;
  else if (psync_gids_cnt==0)
    return 0;
  ag=getgrnam("admin");
  if (!ag)
    return 0;
  for (i=0; i<psync_gids_cnt; i++)
    if (ag->gr_gid==psync_gids[i])
      return 1;
  return 0;
#else
  return 0;
#endif
}

#if defined(P_OS_WINDOWS)
#if !defined(gmtime_r)
struct tm *gmtime_r(const time_t *timep, struct tm *result){
  struct tm *res=gmtime(timep);
  *result=*res;
  return result;
}
#endif

/*static wchar_t *utf8_to_wchar(const char *str){
  int len;
  wchar_t *ret;
  len=MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  ret=psync_new_cnt(wchar_t, len);
  MultiByteToWideChar(CP_UTF8, 0, str, -1, ret, len);
  return ret;
}*/

static wchar_t *utf8_to_wchar_path(const char *str){
  int len;
  wchar_t *ret;
  len=MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  /* MAX_PATH seems not to be apporopriate here as it is defined as 260, and CreateDirectory() description says:
   * There is a default string size limit for paths of 248 characters. This limit is related to how the CreateDirectory function parses paths.
   */
//  if (len>=248){
    ret=psync_new_cnt(wchar_t, len+4);
    memcpy(ret, L"\\\\?\\", 4*sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, str, -1, ret+4, len);
//  }
//  else{
//    ret=psync_new_cnt(wchar_t, len);
//    MultiByteToWideChar(CP_UTF8, 0, str, -1, ret, len);
//  }
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
  DWORD flag, attr;
  wpath=utf8_to_wchar_path(path);
retry:
  attr=GetFileAttributesW(wpath);
  if (attr==INVALID_FILE_ATTRIBUTES){
    psync_free(wpath);
    return -1;
  }
  if (attr&FILE_ATTRIBUTE_DIRECTORY)
    flag=FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_POSIX_SEMANTICS;
  else
    flag=FILE_ATTRIBUTE_NORMAL|FILE_FLAG_POSIX_SEMANTICS;

  fd=CreateFileW(wpath, 0, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, flag, NULL);
  if (unlikely_log(fd==INVALID_HANDLE_VALUE)){
    if (GetLastError()==ERROR_SHARING_VIOLATION){
      debug(D_WARNING, "file %s is locked by another process, will retry after sleep", path);
      psync_milisleep(PSYNC_SLEEP_ON_OS_LOCK);
      goto retry;
    }
    else
      debug(D_NOTICE, "could not open file %s, error %d", path, (int)GetLastError());
    psync_free(wpath);
    return -1;
  }
  psync_free(wpath);
  ret=GetFileInformationByHandle(fd, st);
  CloseHandle(fd);
  return psync_bool_to_zero(ret);
}
#endif

void psync_compat_init(){
#if defined(P_OS_POSIX)
  struct rlimit limit;
  limit.rlim_cur=limit.rlim_max=2048;
  if (setrlimit(RLIMIT_NOFILE, &limit))
    debug(D_ERROR, "setrlimit failed errno=%d", errno);
#if IS_DEBUG
  if (getrlimit(RLIMIT_CORE, &limit))
    debug(D_ERROR, "getrlimit failed errno=%d", errno);
  else{
    limit.rlim_cur=limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit))
      debug(D_ERROR, "setrlimit failed errno=%d", errno);
  }
#endif
  signal(SIGPIPE, SIG_IGN);
  psync_uid=getuid();
  psync_gid=getgid();
  psync_gids_cnt=getgroups(0, NULL);
  psync_gids=psync_new_cnt(gid_t, psync_gids_cnt);
  if (unlikely_log(getgroups(psync_gids_cnt, psync_gids)!=psync_gids_cnt))
    psync_gids_cnt=0;
#if defined(PAGESIZE)
  psync_page_size=PAGESIZE;
#else
  psync_page_size=sysconf(_SC_PAGESIZE);
#endif
#elif defined(P_OS_WINDOWS)
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  psync_page_size=si.dwPageSize;
#else
  psync_page_size=-1;
#endif
  debug(D_NOTICE, "detected page size %d", psync_page_size);
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

char *psync_get_default_database_path_old(){
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

static char *psync_get_pcloud_path_nc(){
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
  return psync_strcat(dir, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_POSIX_DIR, NULL);
#elif defined(P_OS_WINDOWS)
  wchar_t path[MAX_PATH], *wdir;
  char *dir, *ret;
  if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path)==S_OK)
    wdir=path;
  else{
    wdir=_wgetenv(L"LOCALAPPDATA");
    if (!wdir){
      wdir=_wgetenv(L"APPDATA");
      if (unlikely_log(!wdir))
        return NULL;
    }
  }
  dir=wchar_to_utf8(wdir);
  ret=psync_strcat(dir, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_WINDOWS_DIR, NULL);
  psync_free(dir);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

char *psync_get_pcloud_path(){
  char *path;
  psync_stat_t st;
  path=psync_get_pcloud_path_nc();
  if (unlikely_log(!path))
    return NULL;
  if (psync_stat(path, &st) && unlikely_log(psync_mkdir(path))){
    psync_free(path);
    return NULL;
  }
  return path;
}

char *psync_get_private_dir(char *name){
  char *path, *rpath;
  psync_stat_t st;
  path=psync_get_pcloud_path();
  if (!path)
    return NULL;
  rpath=psync_strcat(path, PSYNC_DIRECTORY_SEPARATOR, name, NULL);
  free(path);
  if (psync_stat(rpath, &st) && psync_mkdir(rpath)){
    psync_free(rpath);
    return NULL;
  }
  return rpath;
}

char *psync_get_private_tmp_dir(){
  return psync_get_private_dir(PSYNC_DEFAULT_TMP_DIR);
}

char *psync_get_default_database_path(){
  char *dirpath, *path;
  psync_stat_t st;
  dirpath=psync_get_pcloud_path();
  if (!dirpath)
    return NULL;
  path=psync_strcat(dirpath, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_DB_NAME, NULL);
  psync_free(dirpath);
  if (psync_stat(path, &st) && (dirpath=psync_get_default_database_path_old())){
    if (!psync_stat(dirpath, &st)){
      if (psync_sql_reopen(dirpath)){
        psync_free(path);
        return dirpath;
      }
      else
        psync_file_rename(dirpath, path);
    }
    psync_free(dirpath);
  }
  return path;
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
  //debug(D_NOTICE, "thread started"); //This repeats too many times because of the overlays
}

static void thread_exited(){
 // debug(D_NOTICE, "thread exited"); //This repeats too many times because of the overlays
}

static void *thread_entry0(void *data){
  psync_thread_start0 run;
  run=((psync_run_data0 *)data)->run;
  psync_thread_name=((psync_run_data0 *)data)->name;
  psync_free(data);
  thread_started();
  run();
  thread_exited();
  return NULL;
}

void psync_run_thread(const char *name, psync_thread_start0 run){
  psync_run_data0 *data;
  pthread_t thread;
  pthread_attr_t attr;
  data=psync_new(psync_run_data0);
  data->run=run;
  data->name=name;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry0, data);
  pthread_attr_destroy(&attr);
}

static void *thread_entry1(void *data){
  psync_thread_start1 run;
  void *ptr;
  run=((psync_run_data1 *)data)->run;
  ptr=((psync_run_data1 *)data)->ptr;
  psync_thread_name=((psync_run_data1 *)data)->name;
  psync_free(data);
  thread_started();
  run(ptr);
  thread_exited();
  return NULL;
}

void psync_run_thread1(const char *name, psync_thread_start1 run, void *ptr){
  psync_run_data1 *data;
  pthread_t thread;
  pthread_attr_t attr;
  data=psync_new(psync_run_data1);
  data->run=run;
  data->ptr=ptr;
  data->name=name;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry1, data);
  pthread_attr_destroy(&attr);
}

static void psync_check_no_sql_lock(uint64_t millisec){
#if IS_DEBUG
  if (psync_sql_islocked()){
    debug(D_CRITICAL, "trying to sleep while holding sql lock, aborting");
    psync_sql_dump_locks();
    abort();
  }
#endif
}

void psync_milisleep_nosqlcheck(uint64_t millisec){
#if defined(P_OS_POSIX)
  struct timespec tm;
  tm.tv_sec=millisec/1000;
  tm.tv_nsec=(millisec%1000)*1000000;
  nanosleep(&tm, NULL);
#elif defined(P_OS_WINDOWS)
  Sleep(millisec);
#else
#error "Function not implemented for your operating system"
#endif
}

void psync_milisleep(uint64_t millisec){
  psync_check_no_sql_lock(millisec);
  psync_milisleep_nosqlcheck(millisec);
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

uint64_t psync_millitime(){
  struct timespec tm;
  psync_nanotime(&tm);
  return tm.tv_sec*1000+tm.tv_nsec/1000000;
}

#if defined(P_OS_POSIX)
static void psync_add_file_to_seed(const char *fn, psync_lhash_ctx *hctx, size_t max){
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
      psync_lhash_update(hctx, buff, rd);
    close(fd);
  }
}
#endif

#if defined(P_OS_LINUX)
static void psync_get_random_seed_linux(psync_lhash_ctx *hctx){
  struct sysinfo si;
  if (likely_log(!sysinfo(&si)))
    psync_lhash_update(hctx, &si, sizeof(si));
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

static void psync_get_random_seed_from_query(psync_lhash_ctx *hctx, psync_sql_res *res){
  psync_variant_row row;
  struct timespec tm;
  int i;
  while ((row=psync_sql_fetch_row(res))){
    for (i=0; i<res->column_count; i++)
      if (row[i].type==PSYNC_TSTRING)
        psync_lhash_update(hctx, row[i].str, row[i].length);
    psync_lhash_update(hctx, row, sizeof(psync_variant)*res->column_count);
  }
  psync_sql_free_result(res);
  psync_nanotime(&tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
}

static void psync_get_random_seed_from_db(psync_lhash_ctx *hctx){
  psync_sql_res *res;
  struct timespec tm;
  unsigned char rnd[PSYNC_LHASH_DIGEST_LEN];
  psync_nanotime(&tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
  res=psync_sql_query_rdlock("SELECT * FROM setting ORDER BY RANDOM()");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query_rdlock("SELECT * FROM resolver ORDER BY RANDOM() LIMIT 50");
  psync_get_random_seed_from_query(hctx, res);
/*  res=psync_sql_query_rdlock("SELECT * FROM filerevision ORDER BY RANDOM() LIMIT 50");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query_rdlock("SELECT * FROM file ORDER BY RANDOM() LIMIT 50");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query_rdlock("SELECT * FROM localfile ORDER BY RANDOM() LIMIT 50");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query_rdlock("SELECT * FROM folder ORDER BY RANDOM() LIMIT 25");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query_rdlock("SELECT * FROM localfolder ORDER BY RANDOM() LIMIT 25");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query_rdlock("SELECT * FROM hashchecksum ORDER BY RANDOM() LIMIT 25");
  psync_get_random_seed_from_query(hctx, res);
  res=psync_sql_query_rdlock("SELECT * FROM pagecache WHERE type=1 AND rowid>(ABS(RANDOM())%(SELECT MAX(rowid)+1 FROM pagecache)) ORDER BY rowid LIMIT 50");
  psync_get_random_seed_from_query(hctx, res); */
  psync_sql_statement("REPLACE INTO setting (id, value) VALUES ('random', RANDOM())");
  psync_nanotime(&tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
  psync_sql_sync();
  psync_nanotime(&tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
  sqlite3_randomness(sizeof(rnd), rnd);
  psync_lhash_update(hctx, rnd, sizeof(rnd));
}

static void psync_rehash_cnt(unsigned char *hashbin, psync_uint_t cnt){
  psync_lhash_ctx hctx;
  psync_uint_t i;
  struct timespec tm;
  for (i=0; i<cnt; i++){
    psync_lhash_init(&hctx);
    if ((i&511)==0){
      psync_nanotime(&tm);
      psync_lhash_update(&hctx, &tm, sizeof(&tm));
    }
    else
      psync_lhash_update(&hctx, &i, sizeof(i));
    psync_lhash_update(&hctx, hashbin, PSYNC_LHASH_DIGEST_LEN);
    psync_lhash_final(hashbin, &hctx);
  }
}

static void psync_store_seed_in_db(const unsigned char *seed){
  psync_sql_res *res;
  unsigned char hashbin[PSYNC_LHASH_DIGEST_LEN];
  char hashhex[PSYNC_LHASH_DIGEST_HEXLEN], nm[16];
  memcpy(hashbin, seed, PSYNC_LHASH_DIGEST_LEN);
  psync_rehash_cnt(hashbin, 2000);
  psync_binhex(hashhex, hashbin, PSYNC_LHASH_DIGEST_LEN);
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES ('randomhash', ?)");
  psync_sql_bind_lstring(res, 1, hashhex, PSYNC_LHASH_DIGEST_HEXLEN);
  psync_sql_run_free(res);
  psync_rehash_cnt(hashbin, 2000);
  psync_binhex(hashhex, hashbin, PSYNC_LHASH_DIGEST_LEN);
  memcpy(nm, "randomhash", 10);
  nm[10]=hashhex[0];
  nm[11]=0;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_lstring(res, 1, nm, 11);
  psync_sql_bind_lstring(res, 2, hashhex, PSYNC_LHASH_DIGEST_HEXLEN);
  psync_sql_run_free(res);
}

void psync_get_random_seed(unsigned char *seed, const void *addent, size_t aelen, int fast){
  static unsigned char lastseed[PSYNC_LHASH_DIGEST_LEN];
  psync_lhash_ctx hctx;
  struct timespec tm;
  psync_stat_t st;
  char *home;
  void *ptr;
  psync_uint_t i, j;
  int64_t i64;
  pthread_t threadid;
  unsigned char lsc[64][PSYNC_LHASH_DIGEST_LEN];
#if defined(P_OS_POSIX)
  debug(D_NOTICE, "in");
  struct utsname un;
  struct statvfs stfs;
  char **env;
  pid_t pid;
  psync_nanotime(&tm);
  psync_lhash_init(&hctx);
  psync_lhash_update(&hctx, &tm, sizeof(tm));
  if (likely_log(!uname(&un)))
    psync_lhash_update(&hctx, &un, sizeof(un));
  pid=getpid();
  psync_lhash_update(&hctx, &pid, sizeof(pid));
  if (!statvfs("/", &stfs))
    psync_lhash_update(&hctx, &stfs, sizeof(stfs));
  for (env=environ; *env!=NULL; env++)
    psync_lhash_update(&hctx, *env, strlen(*env));
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
  if (likely_log(!clock_gettime(CLOCK_MONOTONIC, &tm)))
    psync_lhash_update(&hctx, &tm, sizeof(tm));
#endif
#if defined(P_OS_LINUX)
  psync_add_file_to_seed("/dev/urandom", &hctx, PSYNC_HASH_DIGEST_LEN);
#else
  psync_add_file_to_seed("/dev/random", &hctx, PSYNC_HASH_DIGEST_LEN);
#endif
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
  debug(D_NOTICE, "in");
  psync_nanotime(&tm);
  psync_lhash_init(&hctx);
  psync_lhash_update(&hctx, &tm, sizeof(tm));
  if (CryptAcquireContext(&cprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)){
    if (CryptGenRandom(cprov, PSYNC_HASH_DIGEST_LEN, lsc[0]))
      psync_lhash_update(&hctx, lsc[0], PSYNC_HASH_DIGEST_LEN);
    CryptReleaseContext(cprov, 0);
  }
  if ((pr=CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0))!=INVALID_HANDLE_VALUE){
    pe.dwSize=sizeof(pe);
    if (Process32First(pr, &pe))
      do {
        psync_lhash_update(&hctx, &pe, sizeof(pe));
      } while(Process32Next(pr, &pe));
    te.dwSize=sizeof(te);
    if (Thread32First(pr, &te))
      do {
        psync_lhash_update(&hctx, &te, sizeof(te));
      } while(Thread32Next(pr, &te));
    me.dwSize=sizeof(me);
    if (Module32First(pr, &me))
      do {
        psync_lhash_update(&hctx, &me, sizeof(me));
      } while(Module32Next(pr, &me));
    CloseHandle(pr);
  }
  ms.dwLength=sizeof(ms);
  if (GlobalMemoryStatusEx(&ms))
    psync_lhash_update(&hctx, &ms, sizeof(ms));
  ci.cbSize=sizeof(ci);
  if (GetCursorInfo(&ci))
    psync_lhash_update(&hctx, &ci, sizeof(ci));
  GetSystemInfo(&si);
  psync_lhash_update(&hctx, &si, sizeof(si));
  ibc=ARRAY_SIZE(ib);
  if (GetComputerName(ib, &ibc))
    psync_lhash_update(&hctx, ib, sizeof(TCHAR)*ibc);
  ibc=ARRAY_SIZE(ib);
  if (GetUserName(ib, &ibc))
    psync_lhash_update(&hctx, ib, sizeof(TCHAR)*ibc);
  memset(&osvi, 0, sizeof(OSVERSIONINFO));
  osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFO);
  if (GetVersionEx(&osvi))
    psync_lhash_update(&hctx, &osvi, sizeof(osvi));
  ibc=GetCurrentProcessId();
  psync_lhash_update(&hctx, &ibc, sizeof(ibc));
  ibc=GetTickCount();
  psync_lhash_update(&hctx, &ibc, sizeof(ibc));
  if (QueryPerformanceCounter(&li))
    psync_lhash_update(&hctx, &li, sizeof(li));
#endif
#if defined(P_OS_LINUX)
  psync_get_random_seed_linux(&hctx);
#endif
  threadid=pthread_self();
  psync_lhash_update(&hctx, &threadid, sizeof(threadid));
  ptr=(void *)&ptr;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr=(void *)psync_get_random_seed;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr=(void *)pthread_self;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr=(void *)malloc;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr=(void *)&lastseed;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  home=psync_get_home_dir();
  if (home){
    i64=psync_get_free_space_by_path(home);
    psync_lhash_update(&hctx, &i64, sizeof(i64));
    psync_lhash_update(&hctx, home, strlen(home));
    if (likely_log(!psync_stat(home, &st)))
      psync_lhash_update(&hctx, &st, sizeof(st));
    psync_free(home);
  }
  if (!fast){
    debug(D_NOTICE, "db in");
    psync_get_random_seed_from_db(&hctx);
    debug(D_NOTICE, "db out");
  }
  if (aelen)
    psync_lhash_update(&hctx, addent, aelen);
  debug(D_NOTICE, "adding bulk data");
  for (i=0; i<ARRAY_SIZE(lsc); i++){
    memcpy(&lsc[i], lastseed, PSYNC_LHASH_DIGEST_LEN);
    for (j=0; j<PSYNC_LHASH_DIGEST_LEN; j++)
      lsc[i][j]^=(unsigned char)i;
  }
  for (j=fast?3:0; j<5; j++){
    for (i=0; i<100; i++){
      psync_lhash_update(&hctx, &i, sizeof(i));
      psync_lhash_update(&hctx, &j, sizeof(j));
      psync_lhash_update(&hctx, lsc, sizeof(lsc));
    }
    psync_nanotime(&tm);
    psync_lhash_update(&hctx, &tm, sizeof(&tm));
  }
  psync_lhash_final(seed, &hctx);
  memcpy(lastseed, seed, PSYNC_LHASH_DIGEST_LEN);
  debug(D_NOTICE, "storing in db");
  psync_store_seed_in_db(seed);
  debug(D_NOTICE, "out");
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

int psync_wait_socket_write_timeout(psync_socket_t sock){
  return psync_wait_socket_writable(sock, PSYNC_SOCK_WRITE_TIMEOUT);
}

static int psync_wait_socket_readable_microsec(psync_socket_t sock, long sec, long usec){
  fd_set rfds;
  struct timeval tv;
#if IS_DEBUG
  struct timespec start, end;
  unsigned long msec;
#endif
  int res;
  tv.tv_sec=sec;
  tv.tv_usec=usec;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
#if IS_DEBUG
  psync_nanotime(&start);
#endif
  res=select(sock+1, &rfds, NULL, NULL, &tv);

  if (res==1){
#if IS_DEBUG
    psync_nanotime(&end);
    msec=(end.tv_sec-start.tv_sec)*1000+end.tv_nsec/1000000-start.tv_nsec/1000000;
    if (msec>=30000)
      debug(D_WARNING, "got response from socket after %lu milliseconds", msec);
    else if (msec>=5000)
      debug(D_NOTICE, "got response from socket after %lu milliseconds", msec);
#endif
    return 0;
  }
  if (res==0){
    if (sec)
      debug(D_WARNING, "socket read timeouted on %ld seconds", sec);
    psync_sock_set_err(P_TIMEDOUT);
  }
  else
    debug(D_WARNING, "select returned %d", res);

  return SOCKET_ERROR;
}

#define psync_wait_socket_readable(sock, sec) psync_wait_socket_readable_microsec(sock, sec, 0)

int psync_wait_socket_read_timeout(psync_socket_t sock){
  return psync_wait_socket_readable(sock, PSYNC_SOCK_READ_TIMEOUT);
}

static psync_socket_t connect_res(struct addrinfo *res){
  psync_socket_t sock;
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
#if defined(P_OS_WINDOWS)
    if (unlikely(sock==INVALID_SOCKET && WSAGetLastError()==WSANOTINITIALISED)){
      WSADATA wsaData;
      if (!WSAStartup(MAKEWORD(2, 2), &wsaData))
        sock=socket(res->ai_family, res->ai_socktype|PSOCK_TYPE_OR, res->ai_protocol);
    }
#endif
    if (likely_log(sock!=INVALID_SOCKET)){
#if defined(PSOCK_NEED_NOBLOCK)
#if defined(P_OS_WINDOWS)
      static const unsigned long mode=1;
      static int need_snd_buf=0;
      ioctlsocket(sock, FIONBIO, &mode);
      if (need_snd_buf==0){
        unsigned ver=GetVersion();
        ver=LOBYTE(LOWORD(ver))*10+HIBYTE(LOWORD(ver));
        if (ver<=61){
          need_snd_buf=1;
          debug(D_NOTICE, "detected windows %u, setting socket buffers", ver);
        }
        else{
          need_snd_buf=-1;
          debug(D_NOTICE, "detected windows %u, not setting socket buffers", ver);
        }
      }
      if (need_snd_buf==1){
        int bufsize=PSYNC_SOCK_WIN_SNDBUF;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize));
      }
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
  psync_socket_t ret;
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

static void addr_save_to_db(const char *host, const char *port, struct addrinfo *addr){
  psync_sql_res *res;
  uint64_t id;
  if (psync_sql_isrdlocked()){
    if (psync_sql_tryupgradelock())
      return;
    else
      debug(D_NOTICE, "upgraded read to write lock to save data to DB");
  }
  psync_sql_start_transaction();
  res=psync_sql_prep_statement("DELETE FROM resolver WHERE hostname=? AND port=?");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  psync_sql_run_free(res);
  res=psync_sql_prep_statement("INSERT INTO resolver (hostname, port, prio, created, family, socktype, protocol, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  psync_sql_bind_uint(res, 4, psync_timer_time());
  id=0;
  do {
    psync_sql_bind_uint(res, 3, id++);
    psync_sql_bind_int(res, 5, addr->ai_family);
    psync_sql_bind_int(res, 6, addr->ai_socktype);
    psync_sql_bind_int(res, 7, addr->ai_protocol);
    psync_sql_bind_blob(res, 8, (char *)addr->ai_addr, addr->ai_addrlen);
    psync_sql_run(res);
    addr=addr->ai_next;
  } while (addr);
  psync_sql_free_result(res);
  psync_sql_commit_transaction();
}

static struct addrinfo *addr_load_from_db(const char *host, const char *port){
  psync_sql_res *res;
  psync_uint_row row;
  psync_variant_row vrow;
  struct addrinfo *ret;
  char *data;
  const char *str;
  uint64_t i;
  size_t len;
  psync_sql_rdlock();
  res=psync_sql_query_nolock("SELECT COUNT(*), SUM(LENGTH(data)) FROM resolver WHERE hostname=? AND port=?");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  if (!(row=psync_sql_fetch_rowint(res)) || row[0]==0){
    psync_sql_free_result(res);
    psync_sql_rdunlock();
    return NULL;
  }
  ret=(struct addrinfo *)psync_malloc(sizeof(struct addrinfo)*row[0]+row[1]);
  data=(char *)(ret+row[0]);
  for (i=0; i<row[0]-1; i++)
    ret[i].ai_next=&ret[i+1];
  ret[i].ai_next=NULL;
  psync_sql_free_result(res);
  res=psync_sql_query_nolock("SELECT family, socktype, protocol, data FROM resolver WHERE hostname=? AND port=? ORDER BY prio");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  i=0;
  while ((vrow=psync_sql_fetch_row(res))){
    ret[i].ai_family=psync_get_snumber(vrow[0]);
    ret[i].ai_socktype=psync_get_snumber(vrow[1]);
    ret[i].ai_protocol=psync_get_snumber(vrow[2]);
    str=psync_get_lstring(vrow[3], &len);
    ret[i].ai_addr=(struct sockaddr *)data;
    ret[i].ai_addrlen=len;
    i++;
    memcpy(data, str, len);
    data+=len;
  }
  psync_sql_free_result(res);
  psync_sql_rdunlock();
  return ret;
}

static int addr_still_valid(struct addrinfo *olda, struct addrinfo *newa){
  struct addrinfo *a;
  do {
    a=newa;
    while (1){
      if (a->ai_addrlen==olda->ai_addrlen && !memcmp(a->ai_addr, olda->ai_addr, a->ai_addrlen))
        break;
      a=a->ai_next;
      if (!a)
        return 0;
    }
    olda=olda->ai_next;
  } while (olda);
  return 1;
}

typedef struct {
  const char *host;
  const char *port;
} resolve_host_port;

static void connect_res_callback(void *h, void *ptr){
  struct addrinfo *res;
  psync_socket_t sock;
  int r;
  res=(struct addrinfo *)ptr;
  sock=connect_res(res);
  r=psync_task_complete(h, (void *)(uintptr_t)sock);
  psync_free(res);
  if (r && sock!=INVALID_SOCKET)
    psync_close_socket(sock);
}

static void resolve_callback(void *h, void *ptr){
  resolve_host_port *hp;
  struct addrinfo *res;
  struct addrinfo hints;
  int rc;
  hp=(resolve_host_port *)ptr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family=AF_UNSPEC;
  hints.ai_socktype=SOCK_STREAM;
  res=NULL;
  rc=getaddrinfo(hp->host, hp->port, &hints, &res);
#if defined(P_OS_WINDOWS)
  if (unlikely(rc==WSANOTINITIALISED)){
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)){
      psync_task_complete(h, NULL);
      return;
    }
    rc=getaddrinfo(hp->host, hp->port, &hints, &res);
  }
#endif
  if (unlikely(rc!=0))
    res=NULL;
  psync_task_complete(h, res);
}

#if defined(P_OS_WINDOWS)
static void gfree_ptr(HGLOBAL ptr){
  if (ptr!=NULL)
    GlobalFree(ptr);
}

static int try_set_proxy(LPWSTR pstr){
  char *str, *c;
  size_t hl, pl;
  if (!pstr)
    return 0;
  str=wchar_to_utf8(pstr);
  c=strchr(str, ':');
  if (!c)
    goto err;
  hl=c-str;
  c++;
  pl=strlen(c);
  if (pl && hl && hl<sizeof(proxy_host) && pl<sizeof(proxy_port)) {
    proxy_host[hl]=0;
    memcpy(proxy_host, str, hl);
    proxy_port[pl]=0;
    memcpy(proxy_port, c, pl);
    psync_free(str);
    proxy_type=PROXY_CONNECT;
    debug(D_NOTICE, "auto detected proxy %s:%s", proxy_host, proxy_port);
    return 1;
  }
err:
  psync_free(str);
  return 0;
}

#define PSYNC_HAS_PROXY_CODE

#endif

#if defined(P_OS_MACOSX) && 0

#define PSYNC_HAS_PROXY_CODE

const void *get_value_cstr(CFDictionaryRef dict, const char *key) {
  CFStringRef str;
  const void *ret;
  str=CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
  ret=CFDictionaryGetValue(dict, str);
  CFRelease(str);
  return ret;
}

#endif

#if defined(PSYNC_HAS_PROXY_CODE)
static int recent_detect(){
  static time_t lastdetect=0;
  if (psync_timer_time()<lastdetect+60)
    return 1;
  else{
    lastdetect=psync_timer_time();
    return 0;
  }
}
#endif

static void detect_proxy(){
#if defined(P_OS_WINDOWS)
  WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieconf;
  WINHTTP_AUTOPROXY_OPTIONS aopt;
  WINHTTP_PROXY_INFO pinfo;
  HINTERNET hi;
  if (recent_detect())
    return;
  proxy_type=PROXY_NONE;
  hi=NULL;
  pinfo.lpszProxy=NULL;
  pinfo.lpszProxyBypass=NULL;
  if (!WinHttpGetIEProxyConfigForCurrentUser(&ieconf))
    return;
  if (ieconf.fAutoDetect){
    hi=WinHttpOpen(L"pCloud", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hi){
      debug(D_NOTICE, "WinHttpOpen failed");
      goto manual;
    }
    memset(&aopt, 0, sizeof(aopt));
    aopt.dwFlags=WINHTTP_AUTOPROXY_AUTO_DETECT;
    aopt.dwAutoDetectFlags=WINHTTP_AUTO_DETECT_TYPE_DHCP|WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    if (ieconf.lpszAutoConfigUrl){
      aopt.dwFlags|=WINHTTP_AUTOPROXY_CONFIG_URL;
      aopt.lpszAutoConfigUrl=ieconf.lpszAutoConfigUrl;
    }
    aopt.fAutoLogonIfChallenged=TRUE;
    if (WinHttpGetProxyForUrl(hi, L"https://api.pcloud.com/", &aopt, &pinfo)  && pinfo.dwAccessType==WINHTTP_ACCESS_TYPE_NAMED_PROXY &&
        try_set_proxy(pinfo.lpszProxy))
      goto ex;
  }
manual:
  try_set_proxy(pinfo.lpszProxy);
ex:
  if (hi)
    WinHttpCloseHandle(hi);
  gfree_ptr(pinfo.lpszProxy);
  gfree_ptr(pinfo.lpszProxyBypass);
  gfree_ptr(ieconf.lpszProxy);
  gfree_ptr(ieconf.lpszProxyBypass);
  gfree_ptr(ieconf.lpszAutoConfigUrl);
#elif defined(P_OS_MACOSX)
/*  CFDictionaryRef proxies;
  CFStringRef hostr, portr;
  CFNumberRef enabledr;
  UInt32 enabled;
  if (recent_detect())
    return;
  proxies=SCDynamicStoreCopyProxies(NULL);
  enabledr=(CFNumberRef)get_value_cstr(proxies, "HTTPSEnable");
  if (enabledr!=NULL){
    if (CFNumberGetValue(enabledr, kCFNumberIntType, &enabled) && enabled){
      hostr=(CFStringRef)get_value_cstr(proxies, "HTTPSProxy");
      portr=(CFStringRef)get_value_cstr(proxies, "HTTPSPort");
      if (hostr!=NULL && portr!=NULL){

      }
    }
  }
  CFRelease(proxies);*/
#endif
}

static psync_socket_t connect_socket_direct(const char *host, const char *port){
  struct addrinfo *res, *dbres;
  struct addrinfo hints;
  psync_socket_t sock;
  int rc;
  debug(D_NOTICE, "connecting to %s:%s", host, port);
  dbres=addr_load_from_db(host, port);
  if (dbres){
    resolve_host_port resolv;
    void *params[2];
    psync_task_callback_t callbacks[2];
    psync_task_manager_t tasks;
    resolv.host=host;
    resolv.port=port;
    params[0]=dbres;
    params[1]=&resolv;
    callbacks[0]=connect_res_callback;
    callbacks[1]=resolve_callback;
    tasks=psync_task_run_tasks(callbacks, params, 2);
    res=(struct addrinfo *)psync_task_get_result(tasks, 1);
    if (unlikely(!res)){
      psync_task_free(tasks);
      detect_proxy();
      debug(D_WARNING, "failed to resolve %s", host);
      return INVALID_SOCKET;
    }
    addr_save_to_db(host, port, res);
    if (addr_still_valid(dbres, res)){
      debug(D_NOTICE, "successfully reused cached IP for %s:%s", host, port);
      sock=(psync_socket_t)(uintptr_t)psync_task_get_result(tasks, 0);
    }
    else{
      debug(D_NOTICE, "cached IP not valid for %s:%s", host, port);
      sock=connect_res(res);
    }
    freeaddrinfo(res);
    psync_task_free(tasks);
  }
  else{
    memset(&hints, 0, sizeof(hints));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    res=NULL;
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
      detect_proxy();
      return INVALID_SOCKET;
    }
    addr_save_to_db(host, port, res);
    sock=connect_res(res);
    freeaddrinfo(res);
  }
  if (likely(sock!=INVALID_SOCKET)){
    int sock_opt=1;
#if defined(P_OS_LINUX)
    setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&sock_opt, sizeof(sock_opt));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&sock_opt, sizeof(sock_opt));
#elif defined(P_OS_WINDOWS)
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&sock_opt, sizeof(sock_opt));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&sock_opt, sizeof(sock_opt));
#elif defined(P_OS_MACOSX) || defined(P_OS_BSD)
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char  *)&sock_opt, sizeof(sock_opt));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, (char*)&sock_opt, sizeof(sock_opt));
#endif
#if defined(SOL_TCP)
#if defined(TCP_KEEPCNT)
    sock_opt=3;
    setsockopt(sock, SOL_TCP, TCP_KEEPCNT, (char *)&sock_opt, sizeof(sock_opt));
#endif
#if defined(TCP_KEEPIDLE)
    sock_opt=60;
    setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (char *)&sock_opt, sizeof(sock_opt));
#endif
#if defined(TCP_KEEPINTVL)
    sock_opt=20;
    setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (char *)&sock_opt, sizeof(sock_opt));
#endif
#endif
  }
  else{
    detect_proxy();
    debug(D_WARNING, "failed to connect to %s:%s", host, port);
  }
  return sock;
}

static int check_http_resp(char *str) {
  if (memcmp(str, "HTTP", 4)){
    debug(D_WARNING, "bad proxy response %s", str);
    return 0;
  }
  while (*str && !isspace(*str))
    str++;
  while (*str && isspace(*str))
    str++;
  if (!isdigit(*str)){
    debug(D_WARNING, "bad proxy response %s", str);
    return 0;
  }
  if (atoi(str)!=200) {
    debug(D_NOTICE, "proxy returned HTTP code %d", atoi(str));
    return 0;
  }
  return 1;
}

static psync_socket_t connect_socket_connect_proxy(const char *host, const char *port){
  char buff[2048], *str;
  psync_socket_t sock;
  int ln, wr, r, rc;
  sock=connect_socket_direct(proxy_host, proxy_port);
  if (unlikely(sock==INVALID_SOCKET)){
    debug(D_NOTICE, "connection to proxy %s:%s failed", proxy_host, proxy_port);
    goto err0;
  }
  ln=psync_slprintf(buff, sizeof(buff), "CONNECT %s:%s HTTP/1.0\015\012User-Agent: %s\015\012\015\012", host, port, psync_software_name);
  wr=0;
  while (wr<ln){
    r=psync_write_socket(sock, buff+wr, ln-wr);
    if (unlikely(r==SOCKET_ERROR)){
      if (likely_log((psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN || psync_sock_err()==P_INTR) && !psync_wait_socket_write_timeout(sock)))
        continue;
      else
        goto err1;
    }
    wr+=r;
  }
  wr=0;
  rc=0;
  while (1){
    if (unlikely(psync_wait_socket_read_timeout(sock))){
      debug(D_WARNING, "connection to %s:%s via %s:%s timeouted", host, port, proxy_host, proxy_port);
      goto err1;
    }
    r=psync_read_socket(sock, buff+wr, sizeof(buff)-1-wr);
    if (unlikely(r==0 || r==SOCKET_ERROR)){
      if (r==0){
        debug(D_NOTICE, "proxy server %s:%s closed connection", proxy_host, proxy_port);
        goto err1;
      }
      if (likely_log(psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN || psync_sock_err()==P_INTR))
        continue;
      else
        goto err1;
    }
    wr+=r;
    buff[wr]=0;
    str=strstr(buff, "\015\012\015\012");
    if (str){
      if (rc || check_http_resp(buff)){
        debug(D_NOTICE, "connected to %s:%s via %s:%s", host, port, proxy_host, proxy_port);
        return sock;
      }else
        goto err1;
    }
    if (wr==sizeof(buff)-1){
      rc=check_http_resp(buff);
      if (!rc)
        goto err1;
      memcpy(buff, buff+sizeof(buff)-8, 8);
      wr=7; // yes, 7
    }
  }
err1:
  psync_close_socket(sock);
err0:
  detect_proxy();
  if (proxy_type!=PROXY_CONNECT)
    return connect_socket_direct(host, port);
  else
    return INVALID_SOCKET;
}

static psync_socket_t connect_socket(const char *host, const char *port){
  if (unlikely(!proxy_detected)){
    proxy_detected=1;
    detect_proxy();
  }
  if (likely(proxy_type!=PROXY_CONNECT))
    return connect_socket_direct(host, port);
  else
    return connect_socket_connect_proxy(host, port);
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
  if (res==0){
    debug(D_WARNING, "socket timeouted");
    psync_sock_set_err(P_TIMEDOUT);
  }
  return PRINT_RETURN_CONST(SOCKET_ERROR);
}

psync_socket *psync_socket_connect(const char *host, int unsigned port, int ssl){
  psync_socket *ret;
  void *sslc;
  psync_socket_t sock;
  char sport[8];
  psync_slprintf(sport, sizeof(sport), "%d", port);
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
  ret->buffer=NULL;
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
  psync_socket_clear_write_buffered(sock);
  psync_close_socket(sock->sock);
  psync_free(sock);
}

void psync_socket_close_bad(psync_socket *sock){
  if (sock->ssl)
    psync_ssl_free(sock->ssl);
  psync_socket_clear_write_buffered(sock);
  psync_close_socket(sock->sock);
  psync_free(sock);
}

void psync_socket_set_write_buffered(psync_socket *sock){
  psync_socket_buffer *sb;
  if (sock->buffer)
    return;
  sb=(psync_socket_buffer *)psync_malloc(offsetof(psync_socket_buffer, buff)+PSYNC_FIRST_SOCK_WRITE_BUFF_SIZE);
  sb->next=NULL;
  sb->size=PSYNC_FIRST_SOCK_WRITE_BUFF_SIZE;
  sb->woffset=0;
  sb->roffset=0;
  sock->buffer=sb;
}

void psync_socket_set_write_buffered_thread(psync_socket *sock){
  pthread_mutex_lock(&socket_mutex);
  psync_socket_set_write_buffered(sock);
  pthread_mutex_unlock(&socket_mutex);
}

void psync_socket_clear_write_buffered(psync_socket *sock){
  psync_socket_buffer *nb;
  while (sock->buffer){
    nb=sock->buffer->next;
    free(sock->buffer);
    sock->buffer=nb;
  }
}

void psync_socket_clear_write_buffered_thread(psync_socket *sock){
  pthread_mutex_lock(&socket_mutex);
  psync_socket_clear_write_buffered(sock);
  pthread_mutex_unlock(&socket_mutex);
}

int psync_socket_set_recvbuf(psync_socket *sock, int bufsize){
#if defined(SO_RCVBUF) && defined(SOL_SOCKET)
  return setsockopt(sock->sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
#else
  return -1;
#endif
}

int psync_socket_set_sendbuf(psync_socket *sock, int bufsize){
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

int psync_socket_pendingdata_buf_thread(psync_socket *sock){
  int ret;
  pthread_mutex_lock(&socket_mutex);
  ret=psync_socket_pendingdata_buf(sock);
  pthread_mutex_unlock(&socket_mutex);
  return ret;
}

int psync_socket_try_write_buffer(psync_socket *sock){
  if (sock->buffer){
    psync_socket_buffer *b;
    int wrt, cw;
    wrt=0;
    while ((b=sock->buffer)){
      if (b->roffset==b->woffset){
        sock->buffer=b->next;
        psync_free(b);
        continue;
      }
      if (sock->ssl){
        cw=psync_ssl_write(sock->ssl, b->buff+b->roffset, b->woffset-b->roffset);
        if (cw==PSYNC_SSL_FAIL){
          if (likely_log(psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ || psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE))
            break;
          else{
            if (!wrt)
              wrt=-1;
            break;
          }
        }
      }
      else{
        cw=psync_write_socket(sock->sock, b->buff+b->roffset, b->woffset-b->roffset);
        if (cw==SOCKET_ERROR){
          if (likely_log(psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN || psync_sock_err()==P_INTR))
            break;
          else{
            if (!wrt)
              wrt=-1;
            break;
          }
        }
      }
      wrt+=cw;
      b->roffset+=cw;
      if (b->roffset!=b->woffset)
        break;
    }
    if (wrt>0)
      debug(D_NOTICE, "wrote %d bytes to socket from buffers", wrt);
    return wrt;
  }
  else
    return 0;
}

int psync_socket_try_write_buffer_thread(psync_socket *sock){
  int ret;
  pthread_mutex_lock(&socket_mutex);
  ret=psync_socket_try_write_buffer(sock);
  pthread_mutex_unlock(&socket_mutex);
  return ret;
}

int psync_socket_readable(psync_socket *sock){
  psync_socket_try_write_buffer(sock);
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
  if (sock->buffer)
    return 1;
  return !psync_wait_socket_writable(sock->sock, 0);
}

static int psync_socket_read_ssl(psync_socket *sock, void *buff, int num){
  int r;
  psync_socket_try_write_buffer(sock);
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending && psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending=0;
  while (1){
    psync_socket_try_write_buffer(sock);
    r=psync_ssl_read(sock->ssl, buff, num);
    if (r==PSYNC_SSL_FAIL){
      if (likely_log(psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ || psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE)){
        if (wait_sock_ready_for_ssl(sock->sock)){
          if (sock->buffer)
            debug(D_WARNING, "timeouted on socket with pending buffers");
          return -1;
        }
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
    psync_socket_try_write_buffer(sock);
    if (sock->pending)
      sock->pending=0;
    else if (psync_wait_socket_read_timeout(sock->sock)){
      debug(D_WARNING, "timeouted on socket with pending buffers");
      return -1;
    }
    else
        psync_socket_try_write_buffer(sock);
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

static int psync_socket_read_noblock_ssl(psync_socket *sock, void *buff, int num){
  int r;
  r=psync_ssl_read(sock->ssl, buff, num);
  if (r==PSYNC_SSL_FAIL){
    sock->pending=0;
    if (likely_log(psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ || psync_ssl_errno==PSYNC_SSL_ERR_WANT_WRITE))
      return PSYNC_SOCKET_WOULDBLOCK;
    else{
      psync_sock_set_err(P_CONNRESET);
      return -1;
    }
  }
  else
    return r;
}

static int psync_socket_read_noblock_plain(psync_socket *sock, void *buff, int num){
  int r;
  r=psync_read_socket(sock->sock, buff, num);
  if (r==SOCKET_ERROR){
    sock->pending=0;
    if (likely_log(psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN))
      return PSYNC_SOCKET_WOULDBLOCK;
    else
      return -1;
  }
  else
    return r;
}

int psync_socket_read_noblock(psync_socket *sock, void *buff, int num){
  psync_socket_try_write_buffer(sock);
  if (sock->ssl)
    return psync_socket_read_noblock_ssl(sock, buff, num);
  else
    return psync_socket_read_noblock_plain(sock, buff, num);
}

static int psync_socket_read_ssl_thread(psync_socket *sock, void *buff, int num){
  int r;
  pthread_mutex_lock(&socket_mutex);
  psync_socket_try_write_buffer(sock);
  pthread_mutex_unlock(&socket_mutex);
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending && psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending=0;
  while (1){
    pthread_mutex_lock(&socket_mutex);
    psync_socket_try_write_buffer(sock);
    r=psync_ssl_read(sock->ssl, buff, num);
    pthread_mutex_unlock(&socket_mutex);
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

static int psync_socket_read_plain_thread(psync_socket *sock, void *buff, int num){
  int r;
  pthread_mutex_lock(&socket_mutex);
  psync_socket_try_write_buffer(sock);
  pthread_mutex_unlock(&socket_mutex);
  while (1){
    if (sock->pending)
      sock->pending=0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    pthread_mutex_lock(&socket_mutex);
    psync_socket_try_write_buffer(sock);
    r=psync_read_socket(sock->sock, buff, num);
    pthread_mutex_unlock(&socket_mutex);
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

int psync_socket_read_thread(psync_socket *sock, void *buff, int num){
  if (sock->ssl)
    return psync_socket_read_ssl_thread(sock, buff, num);
  else
    return psync_socket_read_plain_thread(sock, buff, num);
}

static int psync_socket_write_to_buf(psync_socket *sock, const void *buff, int num){
  psync_socket_buffer *b;
  assert(sock->buffer);
  b=sock->buffer;
  while (b->next)
    b=b->next;
  if (likely(b->size-b->woffset>=num)){
    memcpy(b->buff+b->woffset, buff, num);
    b->woffset+=num;
    return num;
  }
  else{
    uint32_t rnum, wr;
    rnum=num;
    do {
      wr=b->size-b->woffset;
      if (!wr){
        b->next=(psync_socket_buffer *)psync_malloc(offsetof(psync_socket_buffer, buff)+PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE);
        b=b->next;
        b->next=NULL;
        b->size=PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE;
        b->woffset=0;
        b->roffset=0;
        wr=PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE;
      }
      if (wr>rnum)
        wr=rnum;
      memcpy(b->buff+b->woffset, buff, wr);
      b->woffset+=wr;
      buff=(const char *)buff+wr;
      rnum-=wr;
    } while (rnum);
    return num;
  }
}

int psync_socket_write(psync_socket *sock, const void *buff, int num){
  int r;
  if (sock->buffer)
    return psync_socket_write_to_buf(sock, buff, num);
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
      if (likely_log(psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN || psync_sock_err()==P_INTR))
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

  psync_socket_try_write_buffer(sock);

  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending && psync_wait_socket_read_timeout(sock->sock)) {
    return -1;
  }

  sock->pending=0;

  while (br<num){
    psync_socket_try_write_buffer(sock);

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
    psync_socket_try_write_buffer(sock);
    if (sock->pending)
      sock->pending=0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    else
        psync_socket_try_write_buffer(sock);
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

int psync_socket_readall(psync_socket* sock, void* buff, int num) {
  if (sock->ssl) {
    return psync_socket_readall_ssl(sock, buff, num);
  }
  else {
    return psync_socket_readall_plain(sock, buff, num);
  }
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
  if (sock->buffer)
    return psync_socket_write_to_buf(sock, buff, num);
  if (sock->ssl)
    return psync_socket_writeall_ssl(sock, buff, num);
  else
    return psync_socket_writeall_plain(sock->sock, buff, num);
}

static int psync_socket_readall_ssl_thread(psync_socket *sock, void *buff, int num){
  int br, r;
  br=0;
  pthread_mutex_lock(&socket_mutex);
  psync_socket_try_write_buffer(sock);
  r=psync_ssl_pendingdata(sock->ssl);
  pthread_mutex_unlock(&socket_mutex);
  if (!r && !sock->pending && psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending=0;
  while (br<num){
    pthread_mutex_lock(&socket_mutex);
    psync_socket_try_write_buffer(sock);
    r=psync_ssl_read(sock->ssl, (char *)buff+br, num-br);
    pthread_mutex_unlock(&socket_mutex);
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

static int psync_socket_readall_plain_thread(psync_socket *sock, void *buff, int num){
  int br, r;
  br=0;
  pthread_mutex_lock(&socket_mutex);
  psync_socket_try_write_buffer(sock);
  pthread_mutex_unlock(&socket_mutex);
  while (br<num){
    if (sock->pending)
      sock->pending=0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    pthread_mutex_lock(&socket_mutex);
    psync_socket_try_write_buffer(sock);
    r=psync_read_socket(sock->sock, (char *)buff+br, num-br);
    pthread_mutex_unlock(&socket_mutex);
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

int psync_socket_readall_thread(psync_socket *sock, void *buff, int num){
  if (sock->ssl)
    return psync_socket_readall_ssl_thread(sock, buff, num);
  else
    return psync_socket_readall_plain_thread(sock, buff, num);
}


static int psync_socket_writeall_ssl_thread(psync_socket *sock, const void *buff, int num){
  int br, r;
  br=0;
  while (br<num){
    pthread_mutex_lock(&socket_mutex);
    if (sock->buffer)
      r=psync_socket_write_to_buf(sock, buff, num);
    else
      r=psync_ssl_write(sock->ssl, (char *)buff+br, num-br);
    pthread_mutex_unlock(&socket_mutex);
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

static int psync_socket_writeall_plain_thread(psync_socket *sock, const void *buff, int num){
  int br, r;
  br=0;
  while (br<num){
    pthread_mutex_lock(&socket_mutex);
    if (sock->buffer)
      r=psync_socket_write_to_buf(sock, buff, num);
    else
      r=psync_write_socket(sock->sock, (const char *)buff+br, num-br);
    pthread_mutex_unlock(&socket_mutex);
    if (r==SOCKET_ERROR){
      if (psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN){
        if (psync_wait_socket_write_timeout(sock->sock))
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

int psync_socket_writeall_thread(psync_socket *sock, const void *buff, int num){
  if (sock->ssl)
    return psync_socket_writeall_ssl_thread(sock, buff, num);
  else
    return psync_socket_writeall_plain_thread(sock, buff, num);
}

static void copy_address(struct sockaddr_storage *dst, const struct sockaddr *src) {
  dst->ss_family=src->sa_family;
  if (src->sa_family==AF_INET)
    memcpy(&((struct sockaddr_in *)dst)->sin_addr, &((const struct sockaddr_in *)src)->sin_addr, sizeof(((struct sockaddr_in *)dst)->sin_addr));
  else
    memcpy(&((struct sockaddr_in6 *)dst)->sin6_addr, &((const struct sockaddr_in6 *)src)->sin6_addr, sizeof(((struct sockaddr_in6 *)dst)->sin6_addr));
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
    if (addr->ifa_addr){
      family=addr->ifa_addr->sa_family;
      if ((family==AF_INET || family==AF_INET6) && addr->ifa_broadaddr && addr->ifa_netmask)
        cnt++;
    }
    addr=addr->ifa_next;
  }
  ret=psync_malloc(offsetof(psync_interface_list_t, interfaces)+sizeof(psync_interface_t)*cnt);
  memset(ret, 0, offsetof(psync_interface_list_t, interfaces)+sizeof(psync_interface_t)*cnt);
  ret->interfacecnt=cnt;
  addr=addrs;
  cnt=0;
  while (addr){
    if (addr->ifa_addr){
      family=addr->ifa_addr->sa_family;
      if ((family==AF_INET || family==AF_INET6) && addr->ifa_broadaddr && addr->ifa_netmask){
        if (family==AF_INET)
          sz=sizeof(struct sockaddr_in);
        else
          sz=sizeof(struct sockaddr_in6);
        copy_address(&ret->interfaces[cnt].address, addr->ifa_addr);
        copy_address(&ret->interfaces[cnt].broadcast, addr->ifa_broadaddr);
        copy_address(&ret->interfaces[cnt].netmask, addr->ifa_netmask);
        ret->interfaces[cnt].addrsize=sz;
        cnt++;
      }
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
  fl=GAA_FLAG_SKIP_DNS_SERVER|GAA_FLAG_SKIP_FRIENDLY_NAME|GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|0x0800;//GAA_FLAG_SKIP_DNS_INFO;
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
  memset(ret, 0, offsetof(psync_interface_list_t, interfaces)+sizeof(psync_interface_t)*cnt);
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
  psync_free(adapters);
  return ret;
  }
#endif
empty:
  ret=psync_malloc(offsetof(psync_interface_list_t, interfaces));
  ret->interfacecnt=0;
  return ret;
}

#if !defined(P_OS_POSIX)
static int psync_compat_socketpair(psync_socket_t sockfd[2]){
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
      (sockfd[0]=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))==INVALID_SOCKET)
    goto err1;
  if (connect(sockfd[0], (struct sockaddr *)&addr, addrlen)==SOCKET_ERROR ||
      (sockfd[1]=accept(sock, NULL, NULL))==INVALID_SOCKET)
    goto err2;
  psync_close_socket(sock);
  return 0;
err2:
  psync_close_socket(sockfd[0]);
err1:
  psync_close_socket(sock);
err0:
  return SOCKET_ERROR;
}
#endif

int psync_pipe(psync_socket_t pipefd[2]){
#if defined(P_OS_POSIX)
  return pipe(pipefd);
#else
  return psync_compat_socketpair(pipefd);
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

int psync_socket_pair(psync_socket_t sfd[2]){
#if defined(P_OS_POSIX)
  return socketpair(AF_UNIX, SOCK_STREAM, 0, sfd);
#else
  return psync_compat_socketpair(sfd);
#endif
}

int psync_socket_is_broken(psync_socket_t sock){
  fd_set rfds;
  struct timeval tv;
  memset(&tv, 0, sizeof(tv));
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  return select(sock+1, NULL, NULL, &rfds, &tv)==1;
}

int psync_select_in(psync_socket_t *sockets, int cnt, int64_t timeoutmillisec){
  fd_set rfds;
  struct timeval tv, *ptv;
  psync_socket_t max;
  int i;
  if (timeoutmillisec<0)
    ptv=NULL;
  else{
    tv.tv_sec=timeoutmillisec/1000;
    tv.tv_usec=(timeoutmillisec%1000)*1000;
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

int psync_list_dir(const char *path, psync_list_dir_callback callback, void *ptr){
#if defined(P_OS_POSIX)
  psync_pstat pst;
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry, *de;
  dh=opendir(path);
  if (unlikely(!dh)){
    debug(D_WARNING, "could not open directory %s", path);
    goto err1;
  }
  pl=strlen(path);
  namelen=pathconf(path, _PC_NAME_MAX);
  if (unlikely_log(namelen==-1))
    namelen=255;
  if (namelen<sizeof(de->d_name)-1)
    namelen=sizeof(de->d_name)-1;
  entrylen=offsetof(struct dirent, d_name)+namelen+1;
  cpath=(char *)psync_malloc(pl+namelen+2);
  entry=(struct dirent *)psync_malloc(entrylen);
  memcpy(cpath, path, pl);
  if (!pl || cpath[pl-1]!=PSYNC_DIRECTORY_SEPARATORC)
    cpath[pl++]=PSYNC_DIRECTORY_SEPARATORC;
  pst.path=cpath;
  while (!readdir_r(dh, entry, &de) && de)
    if (de->d_name[0]!='.' || (de->d_name[1]!=0 && (de->d_name[1]!='.' || de->d_name[2]!=0))){
      psync_strlcpy(cpath+pl, de->d_name, namelen+1);
      if (likely_log(!lstat(cpath, &pst.stat)) && (S_ISREG(pst.stat.st_mode) || S_ISDIR(pst.stat.st_mode))){
#if defined(P_OS_MACOSX)
        if (pst.stat.st_flags&(UF_HIDDEN|UF_IMMUTABLE|SF_IMMUTABLE))
          continue;
#endif
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
  wpath=utf8_to_wchar_path(spath);
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
    if (st.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY && (!wcscmp(st.cFileName, L".") || !wcscmp(st.cFileName, L"..")))
      continue;
    if (st.dwFileAttributes&(FILE_ATTRIBUTE_SYSTEM|/*FILE_ATTRIBUTE_TEMPORARY|*/FILE_ATTRIBUTE_DEVICE|FILE_ATTRIBUTE_HIDDEN)){
      if (st.dwFileAttributes&FILE_ATTRIBUTE_SYSTEM)
        debug(D_NOTICE, "Ignoring file %ls with FILE_ATTRIBUTE_SYSTEM attribute", st.cFileName);
      if (st.dwFileAttributes&FILE_ATTRIBUTE_TEMPORARY)
        debug(D_NOTICE, "Ignoring file %ls with FILE_ATTRIBUTE_TEMPORARY attribute", st.cFileName);
      if (st.dwFileAttributes&FILE_ATTRIBUTE_DEVICE)
        debug(D_NOTICE, "Ignoring file %ls with FILE_ATTRIBUTE_DEVICE attribute", st.cFileName);
      if (st.dwFileAttributes&FILE_ATTRIBUTE_HIDDEN)
        debug(D_NOTICE, "Ignoring file %ls with FILE_ATTRIBUTE_HIDDEN attribute", st.cFileName);
      continue;
    }
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
#if defined(P_OS_MACOSX)
  return psync_list_dir(path, callback, ptr);
#elif defined(P_OS_POSIX)
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
  if (namelen<sizeof(de->d_name)-1)
    namelen=sizeof(de->d_name)-1;
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
        psync_strlcpy(cpath+pl, de->d_name, namelen+1);
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
      psync_strlcpy(cpath+pl, de->d_name, namelen+1);
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
  wpath=utf8_to_wchar_path(spath);
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
    return (int64_t)buf.f_bavail*(int64_t)buf.f_frsize;
#elif defined(P_OS_WINDOWS)
  ULARGE_INTEGER free;
  wchar_t *wpath;
  BOOL ret;
  wpath=utf8_to_wchar_path(path);
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
  wpath=utf8_to_wchar_path(path);
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
  wpath=utf8_to_wchar_path(path);
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
  oldwpath=utf8_to_wchar_path(oldpath);
  newwpath=utf8_to_wchar_path(newpath);
retry:
  ret=psync_bool_to_zero(MoveFileW(oldwpath, newwpath));
  if (ret && GetLastError()==ERROR_SHARING_VIOLATION){
    debug(D_WARNING, "file %s is locked by another process, will retry after sleep", oldpath);
    psync_milisleep(PSYNC_SLEEP_ON_OS_LOCK);
    goto retry;
  }
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
  else{
    wchar_t *oldwpath, *newwpath;
    int ret;
    oldwpath=utf8_to_wchar_path(oldpath);
    newwpath=utf8_to_wchar_path(newpath);
retry:
    ret=psync_bool_to_zero(MoveFileExW(oldwpath, newwpath, MOVEFILE_COPY_ALLOWED|MOVEFILE_REPLACE_EXISTING));
    if (ret && GetLastError()==ERROR_SHARING_VIOLATION){
      debug(D_WARNING, "file %s is locked by another process, will retry after sleep", oldpath);
      psync_milisleep(PSYNC_SLEEP_ON_OS_LOCK);
      goto retry;
    }
    else if (ret)
      debug(D_WARNING, "rename from %s to %s failed with error %d", oldpath, newpath, (int)GetLastError());
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
  wpath=utf8_to_wchar_path(path);
  ret=psync_bool_to_zero(DeleteFileW(wpath));
  psync_free(wpath);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

psync_file_t psync_file_open(const char *path, int access, int flags){
#if defined(P_OS_POSIX)
  int fd;
#if defined(O_CLOEXEC)
  flags|=O_CLOEXEC;
#endif
#if defined(O_NOATIME)
  flags|=O_NOATIME;
#endif
  fd=open(path, access|flags, PSYNC_DEFAULT_POSIX_FILE_MODE);
  if (unlikely(fd==-1)){
    while (errno==EINTR){
      debug(D_NOTICE, "got EINTR while opening file");
      fd=open(path, access|flags, PSYNC_DEFAULT_POSIX_FILE_MODE);
      if (fd!=-1)
        return fd;
    }
  }
  return fd;
#elif defined(P_OS_WINDOWS)
  DWORD cdis;
  wchar_t *wpath;
  HANDLE ret;
  if (flags&P_O_EXCL)
    cdis=CREATE_NEW;
  else if ((flags&(P_O_CREAT|P_O_TRUNC))==(P_O_CREAT|P_O_TRUNC))
    cdis=CREATE_ALWAYS;
  else if (flags&P_O_CREAT)
    cdis=OPEN_ALWAYS;
  else if (flags&P_O_TRUNC)
    cdis=TRUNCATE_EXISTING;
  else
    cdis=OPEN_EXISTING;
  wpath=utf8_to_wchar_path(path);
  ret=CreateFileW(wpath, access, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, cdis, FILE_FLAG_POSIX_SEMANTICS|FILE_ATTRIBUTE_NORMAL, NULL);
  if (IS_DEBUG && ret==INVALID_HANDLE_VALUE && GetLastError()!=ERROR_FILE_NOT_FOUND)
    debug(D_WARNING, "could not open file %s, error %d", path, (int)GetLastError());
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
#if defined(F_FULLFSYNC) && defined(P_OS_POSIX)
  if (unlikely(fcntl(fd, F_FULLFSYNC))){
    while (errno==EINTR){
      debug(D_NOTICE, "got EINTR while fsyncing file");
      if (!fcntl(fd, F_FULLFSYNC))
        return 0;
    }
    debug(D_NOTICE, "got error %d, when doing fcntl(F_FULLFSYNC), trying fsync()", (int)errno);
    if (fsync(fd)){
      debug(D_NOTICE, "fsync also failed, error %d", (int)errno);
      return -1;
    }
    else{
      debug(D_NOTICE, "fsync succeded");
      return 0;
    }
  }
  else
    return 0;
#elif defined(P_OS_POSIX)
#if _POSIX_SYNCHRONIZED_IO>0
  if (unlikely(fdatasync(fd))){
#else
  if (unlikely(fsync(fd))){
#endif
    while (errno==EINTR){
      debug(D_NOTICE, "got EINTR while fsyncing file");
      if (!fsync(fd))
        return 0;
    }
    debug(D_NOTICE, "got error %d", (int)errno);
    return -1;
  }
  else
    return 0;
#elif defined(P_OS_WINDOWS)
  return psync_bool_to_zero(FlushFileBuffers(fd));
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_schedulesync(psync_file_t fd){
#if defined(P_OS_LINUX) && defined(SYNC_FILE_RANGE_WRITE)
  return sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE);
#elif defined(P_OS_POSIX) && _POSIX_MAPPED_FILES>0 && _POSIX_SYNCHRONIZED_IO>0
  struct stat st;
  void *fmap;
  int ret;
  if (unlikely(fstat(fd, &st))){
    debug(D_NOTICE, "fstat failed, errno=%d", (int)errno);
    return -1;
  }
  fmap=mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (unlikely(fmap==MAP_FAILED)){
    debug(D_NOTICE, "mmap failed, errno=%d", (int)errno);
    return -1;
  }
  ret=msync(fmap, st.st_size, MS_ASYNC);
  if (unlikely(ret))
    debug(D_NOTICE, "msync failed, errno=%d", (int)errno);
  munmap(fmap, st.st_size);
  return ret;
#elif defined(P_OS_WINDOWS)
  HANDLE mapping;
  void *fmap;
  int ret;
  ret=-1;
  mapping=CreateFileMapping(fd, NULL, PAGE_READWRITE, 0, 0, NULL);
  if (mapping!=NULL){
    fmap=MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0);
    if (fmap!=NULL){
      if (FlushViewOfFile(fmap, 0))
        ret=0;
      else
        debug(D_NOTICE, "FlushViewOfFile failed, error %u", (unsigned)GetLastError());
      UnmapViewOfFile(fmap);
    }
    else
      debug(D_NOTICE, "MapViewOfFile failed, error %u", (unsigned)GetLastError());
    CloseHandle(mapping);
  }
  else
    debug(D_NOTICE, "CreateFileMapping failed, error %u", (unsigned)GetLastError());
  return ret;
#else
  return 0;
#endif
}

int psync_folder_sync(const char *path){
#if defined(P_OS_POSIX)
  int fd, ret;
  fd=open(path, O_RDONLY);
  if (fd==-1){
    debug(D_NOTICE, "could not open folder %s, error %d", path, (int)errno);
    return -1;
  }
  if (unlikely(psync_file_sync(fd))){
    debug(D_NOTICE, "could not fsync folder %s, error %d", path, (int)errno);
    ret=-1;
  }
  else
    ret=0;
  close(fd);
  return ret;
#elif defined(P_OS_WINDOWS)
  wchar_t *wpath;
  HANDLE fd;
  int ret;
  wpath=utf8_to_wchar_path(path);
  fd=CreateFileW(wpath, 0, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_POSIX_SEMANTICS, NULL);
  psync_free(wpath);
  if (fd==INVALID_HANDLE_VALUE){
    debug(D_NOTICE, "could not open folder %s", path);
    return -1;
  }
  if (FlushFileBuffers(fd))
    ret=0;
  else{
    debug(D_NOTICE, "could not flush folder %s err=%u", path, GetLastError());
    ret=-1;
  }
  CloseHandle(fd);
  return ret;
#else
#error "Function not implemented for your operating system"
#endif
}

psync_file_t psync_file_dup(psync_file_t fd){
#if defined(P_OS_POSIX)
  return dup(fd);
#elif defined(P_OS_WINDOWS)
  HANDLE process, fddup;
  process=GetCurrentProcess();
  if (!DuplicateHandle(process, fd, process, &fddup, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return INVALID_HANDLE_VALUE;
  else
    return fddup;
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_file_set_creation(psync_file_t fd, time_t ctime){
#if defined(P_OS_WINDOWS)
  FILETIME fctime;
  uint64_t lctime;
  lctime=Int32x32To64(ctime, 10000000)+116444736000000000;
  fctime.dwLowDateTime=(DWORD)lctime;
  fctime.dwHighDateTime=lctime>>32;
  return psync_bool_to_zero(SetFileTime(fd, &fctime, NULL, NULL));
#elif defined(P_OS_MACOSX)
  struct attrlist attr;
  struct timespec crtime;
  memset(&attr, 0, sizeof(attr));
  attr.bitmapcount=ATTR_BIT_MAP_COUNT;
  attr.commonattr=ATTR_CMN_CRTIME;
  crtime.tv_sec=ctime;
  crtime.tv_nsec=0;
  return fsetattrlist(fd, &attr, &crtime, sizeof(struct timespec), FSOPT_NOFOLLOW);
#else
  return -1;
#endif
}

int psync_set_crtime_mtime(const char *path, time_t crtime, time_t mtime){
#if defined(P_OS_WINDOWS)
  wchar_t *wpath;
  FILETIME fctime, fmtime, *pfctime, *pfmtime;
  uint64_t tm64;
  HANDLE fd;
  int ret;
  wpath=utf8_to_wchar_path(path);
  fd=CreateFileW(wpath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                 FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_POSIX_SEMANTICS, NULL);
  psync_free(wpath);
  if (fd==INVALID_HANDLE_VALUE){
    debug(D_NOTICE, "could not open file/folder %s", path);
    return -1;
  }
  if (crtime){
    tm64=Int32x32To64(crtime, 10000000)+116444736000000000;
    fctime.dwLowDateTime=(DWORD)tm64;
    fctime.dwHighDateTime=tm64>>32;
    pfctime=&fctime;
  }
  else
    pfctime=NULL;
  if (mtime){
    tm64=Int32x32To64(mtime, 10000000)+116444736000000000;
    fmtime.dwLowDateTime=(DWORD)tm64;
    fmtime.dwHighDateTime=tm64>>32;
    pfmtime=&fmtime;
  }
  else
    pfmtime=NULL;
  ret=psync_bool_to_zero(SetFileTime(fd, pfctime, NULL, pfmtime));
  CloseHandle(fd);
  return ret;
#elif defined(P_OS_MACOSX)
  if (crtime){
    struct attrlist attr;
    struct timespec crtimes;
    memset(&attr, 0, sizeof(attr));
    attr.bitmapcount=ATTR_BIT_MAP_COUNT;
    attr.commonattr=ATTR_CMN_CRTIME;
    crtimes.tv_sec=crtime;
    crtimes.tv_nsec=0;
    if (setattrlist(path, &attr, &crtimes, sizeof(struct timespec), FSOPT_NOFOLLOW))
      return -1;
  }
  if (mtime){
    struct timeval tm[2];
    tm[0].tv_sec=mtime;
    tm[0].tv_usec=0;
    tm[1].tv_sec=mtime;
    tm[1].tv_usec=0;
    return utimes(path, tm);
  }
  return 0;
#elif defined(P_OS_POSIX)
  if (mtime){
    struct timeval tm[2];
    tm[0].tv_sec=mtime;
    tm[0].tv_usec=0;
    tm[1].tv_sec=mtime;
    tm[1].tv_usec=0;
    if (unlikely(utimes(path, tm))){
      debug(D_NOTICE, "got errno %d while setting modification time of %s to %lu: %s", errno, path, (unsigned long)mtime, strerror(errno));
      return -1;
    }
    else
      return 0;
  }
  else
    return 0;
#else
  return -1;
#endif
}

int psync_set_crtime_mtime_by_fd(psync_file_t fd, const char *path, time_t crtime, time_t mtime){
#if defined(P_OS_WINDOWS)
  FILETIME fctime, fmtime, *pfctime, *pfmtime;
  uint64_t tm64;
  int ret;
  if (crtime){
    tm64=Int32x32To64(crtime, 10000000)+116444736000000000;
    fctime.dwLowDateTime=(DWORD)tm64;
    fctime.dwHighDateTime=tm64>>32;
    pfctime=&fctime;
  }
  else
    pfctime=NULL;
  if (mtime){
    tm64=Int32x32To64(mtime, 10000000)+116444736000000000;
    fmtime.dwLowDateTime=(DWORD)tm64;
    fmtime.dwHighDateTime=tm64>>32;
    pfmtime=&fmtime;
  }
  else
    pfmtime=NULL;
  ret=psync_bool_to_zero(SetFileTime(fd, pfctime, NULL, pfmtime));
  return ret;
#elif defined(P_OS_MACOSX)
  if (crtime){
    struct attrlist attr;
    struct timespec crtimes;
    memset(&attr, 0, sizeof(attr));
    attr.bitmapcount=ATTR_BIT_MAP_COUNT;
    attr.commonattr=ATTR_CMN_CRTIME;
    crtimes.tv_sec=crtime;
    crtimes.tv_nsec=0;
    if (fsetattrlist(fd, &attr, &crtimes, sizeof(struct timespec), FSOPT_NOFOLLOW))
      return -1;
  }
  if (mtime){
    struct timeval tm[2];
    tm[0].tv_sec=mtime;
    tm[0].tv_usec=0;
    tm[1].tv_sec=mtime;
    tm[1].tv_usec=0;
    return futimes(fd, tm);
  }
  return 0;
#elif defined(_BSD_SOURCE) || defined(P_OS_BSD)
  if (mtime){
    struct timeval tm[2];
    tm[0].tv_sec=mtime;
    tm[0].tv_usec=0;
    tm[1].tv_sec=mtime;
    tm[1].tv_usec=0;
    if (unlikely(futimes(fd, tm))){
      debug(D_NOTICE, "got errno %d while setting modification time of %s to %lu: %s", errno, path, (unsigned long)mtime, strerror(errno));
      return -1;
    }
    else
      return 0;
  }
  else
    return 0;
#else
  return psync_set_crtime_mtime(path, crtime, mtime);
#endif
}

typedef struct {
  uint64_t offset;
  size_t count;
  psync_file_t fd;
} psync_file_preread_t;

static void psync_file_preread_thread(void *ptr){
  char buff[16*1024];
  psync_file_preread_t *pr;
  ssize_t rd;
  pr=(psync_file_preread_t *)ptr;
  while (pr->count){
    rd=psync_file_pread(pr->fd, buff, pr->count>sizeof(buff)?sizeof(buff):pr->count, pr->offset);
    if (rd<=0)
      break;
    pr->offset+=rd;
    pr->count-=rd;
  }
  psync_file_close(pr->fd);
  psync_free(pr);
}

int psync_file_preread(psync_file_t fd, uint64_t offset, size_t count){
  psync_file_preread_t *pr;
  psync_file_t cfd;
  cfd=psync_file_dup(fd);
  if (cfd==INVALID_HANDLE_VALUE)
    return -1;
  pr=psync_new(psync_file_preread_t);
  pr->offset=offset;
  pr->count=count;
  pr->fd=cfd;
  psync_run_thread1("pre-read (readahead) thread", psync_file_preread_thread, pr);
  return 0;
}

int psync_file_readahead(psync_file_t fd, uint64_t offset, size_t count){
#if defined(P_OS_POSIX) && defined(POSIX_FADV_WILLNEED)
  return posix_fadvise(fd, offset, count, POSIX_FADV_WILLNEED);
#elif defined(P_OS_POSIX) && defined(F_RDADVISE)
  struct radvisory ra;
  ra.ra_offset=offset;
  ra.ra_count=count;
  return fcntl(fd, F_RDADVISE, &ra);
#else
  return psync_file_preread(fd, offset, count);
#endif
}

ssize_t psync_file_read(psync_file_t fd, void *buf, size_t count){
#if defined(P_OS_POSIX)
  ssize_t ret;
  ret=read(fd, buf, count);
  if (unlikely(ret==-1)){
    while (errno==EINTR){
      debug(D_NOTICE, "got EINTR while reading from file");
      ret=read(fd, buf, count);
      if (ret!=-1)
        return ret;
    }
    debug(D_NOTICE, "got error %d", (int)errno);
  }
  return ret;
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

ssize_t psync_file_pread(psync_file_t fd, void *buf, size_t count, uint64_t offset){
#if defined(P_OS_POSIX)
  ssize_t ret;
  ret=pread(fd, buf, count, offset);
  if (unlikely(ret==-1)){
    while (errno==EINTR){
      debug(D_NOTICE, "got EINTR while writing to file");
      ret=pread(fd, buf, count, offset);
      if (ret!=-1)
        return ret;
    }
    debug(D_NOTICE, "got error %d", (int)errno);
  }
  return ret;
#elif defined(P_OS_WINDOWS)
  OVERLAPPED ov;
  LARGE_INTEGER li;
  DWORD ret;
  li.QuadPart=offset;
  memset(&ov, 0, sizeof(ov));
  ov.Offset=li.LowPart;
  ov.OffsetHigh=li.HighPart;
  if (ReadFile(fd, buf, count, &ret, &ov))
    return ret;
  else{
    if (GetLastError()==ERROR_HANDLE_EOF)
      return 0;
    else
      return -1;
  }
#else
#error "Function not implemented for your operating system"
#endif
}

ssize_t psync_file_write(psync_file_t fd, const void *buf, size_t count){
#if defined(P_OS_POSIX)
  ssize_t ret;
  ret=write(fd, buf, count);
  if (unlikely(ret==-1)){
    while (errno==EINTR){
      debug(D_NOTICE, "got EINTR while writing to file");
      ret=write(fd, buf, count);
      if (ret!=-1)
        return ret;

    }
    debug(D_NOTICE, "got error %d", (int)errno);
  }
  return ret;
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

ssize_t psync_file_pwrite(psync_file_t fd, const void *buf, size_t count, uint64_t offset){
#if defined(P_OS_POSIX)
  ssize_t ret;
  ret=pwrite(fd, buf, count, offset);
  if (unlikely(ret==-1)){
    while (errno==EINTR){
      debug(D_NOTICE, "got EINTR while writing to file");
      ret=pwrite(fd, buf, count, offset);
      if (ret!=-1)
        return ret;
    }
    debug(D_NOTICE, "got error %d", (int)errno);
  }
  return ret;
#elif defined(P_OS_WINDOWS)
  OVERLAPPED ov;
  LARGE_INTEGER li;
  DWORD ret;
  li.QuadPart=offset;
  memset(&ov, 0, sizeof(ov));
  ov.Offset=li.LowPart;
  ov.OffsetHigh=li.HighPart;
  if (WriteFile(fd, buf, count, &ret, &ov))
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
   if (li.LowPart==INVALID_SET_FILE_POINTER && GetLastError()!=NO_ERROR){
     debug(D_WARNING, "got error %d from SetFilePointer", (int)GetLastError());
     return -1;
   }
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
  if (likely_log(off!=(off_t)-1)){
    if (unlikely(ftruncate(fd, off))){
      while (errno==EINTR){
        debug(D_NOTICE, "got EINTR while truncating file");
        if (!ftruncate(fd, off))
          return 0;
      }
      debug(D_NOTICE, "got error %d", (int)errno);
      return -1;
    }
    else
      return 0;
  }
  else
    return -1;
#elif defined(P_OS_WINDOWS)
#if IS_DEBUG
  if (SetEndOfFile(fd))
    return 0;
  else{
    debug(D_WARNING, "got error %d from SetEndOfFile", (int)GetLastError());
    return -1;
  }
#else
  return psync_bool_to_zero(SetEndOfFile(fd));
#endif
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

void psync_set_software_name(const char *snm){
  psync_software_name=snm;
}

void psync_set_os_name(const char *osnm){
  psync_os_name=osnm;
}

char *psync_deviceos(){
  return psync_os_name?psync_strdup(psync_os_name):psync_deviceid();
}

char *psync_device_string(){
#if defined(P_OS_LINUX)
	char *osname=psync_deviceos();
	char *ret = psync_strcat(osname, ", ", psync_software_name, NULL);
	free(osname);
	return ret;

#endif
  return psync_strcat(psync_deviceid(), ", ", psync_software_name, NULL);
}

const char *psync_appname(){
  return psync_software_name;
}

char *psync_deviceid(){
  char *device;
#if defined(P_OS_WINDOWS)
  SYSTEM_POWER_STATUS bat;
  const char *hardware, *ver;
  char versbuff[32];
  DWORD vers, vmajor, vminor;
  if (GetSystemMetrics(SM_TABLETPC))
    hardware="Tablet";
  else if (GetSystemPowerStatus(&bat) || (bat.BatteryFlag&128))
    hardware="Desktop";
  else
    hardware="Laptop";
  vers=GetVersion();
  vmajor=(DWORD)(LOBYTE(LOWORD(vers)));
  vminor=(DWORD)(HIBYTE(LOWORD(vers)));
  if (vmajor==6){
    switch (vminor){
      case 3: ver="8.1"; break;
      case 2: ver="8.0"; break;
      case 1: ver="7.0"; break;
      case 0: ver="Vista"; break;
      default: psync_slprintf(versbuff, sizeof(versbuff), "6.%u", (unsigned int)vminor); ver=versbuff;
    }
  }
  else if (vmajor==5){
    switch (vminor){
      case 2: ver="XP 64bit"; break;
      case 1: ver="XP"; break;
      case 0: ver="2000"; break;
      default: psync_slprintf(versbuff, sizeof(versbuff), "5.%u", (unsigned int)vminor); ver=versbuff;
    }
  }
  else if (vmajor==10){
    switch (vminor){
      case 0: ver="10.0"; break;
      default: psync_slprintf(versbuff, sizeof(versbuff), "10.%u", (unsigned int)vminor); ver=versbuff;
    }
  }
  else{
    psync_slprintf(versbuff, sizeof(versbuff), "%u.%u", (unsigned int)vmajor, (unsigned int)vminor);
    ver=versbuff;
  }
  device=psync_strcat(hardware, ", Windows ", ver, NULL);
#elif defined(P_OS_MACOSX)
  struct utsname un;
  const char *ver;
  size_t len;
  char versbuff[64], modelname[256];
  int v;
  if (uname(&un))
    ver="Mac OS X";
  else{
    v=atoi(un.release);
    switch (v){
      case 16: ver="macOS 10.12 Sierra"; break;
      case 15: ver="OS X 10.11 El Capitan"; break;
      case 14: ver="OS X 10.10 Yosemite"; break;
      case 13: ver="OS X 10.9 Mavericks"; break;
      case 12: ver="OS X 10.8 Mountain Lion"; break;
      case 11: ver="OS X 10.7 Lion"; break;
      case 10: ver="OS X 10.6 Snow Leopard"; break;
      default: psync_slprintf(versbuff, sizeof(versbuff), "Mac/Darwin %s", un.release); ver=versbuff;
    }
  }
  len=sizeof(modelname);
  if (sysctlbyname("hw.model", modelname, &len, NULL, 0))
    psync_strlcpy(modelname, "Mac", sizeof(modelname));
  versbuff[sizeof(versbuff)-1]=0;
  device=psync_strcat(modelname, ", ", ver, NULL);
#elif defined(P_OS_LINUX)
  DIR *dh;
  struct dirent entry, *de;
  const char *hardware;
  char *path, buf[8];
  int fd;
  hardware="Desktop";
  dh=opendir("/sys/class/power_supply");
  if (dh){
    while (!readdir_r(dh, &entry, &de) && de)
      if (de->d_name[0]!='.' || (de->d_name[1]!=0 && (de->d_name[1]!='.' || de->d_name[2]!=0))){
        path=psync_strcat("/sys/class/power_supply/", de->d_name, "/type", NULL);
        fd=open(path, O_RDONLY);
        psync_free(path);
        if (fd==-1)
          continue;
        if (read(fd, buf, 7)==7 && !memcmp(buf, "Battery", 7)){
          close(fd);
          hardware="Laptop";
          break;
        }
        close(fd);
      }
    closedir(dh);
  }
  device=psync_strcat(hardware, ", Linux", NULL);
#else
  device=psync_strcat("Desktop", NULL);
#endif
  debug(D_NOTICE, "detected device: %s", device);
  return device;
}

int psync_run_update_file(const char *path){
#if defined(P_OS_LINUX) || defined(P_OS_MACOSX)
#if defined(P_OS_LINUX)
#if defined(P_OS_DEBIAN)
#define PSYNC_RUN_CMD "/usr/lib/psyncgui/debinstall.sh"
#else
#define PSYNC_RUN_CMD "qapt-deb-installer"
#endif
#else
#define PSYNC_RUN_CMD "open"
#endif
  pid_t pid;
  debug(D_NOTICE, "running %s with "PSYNC_RUN_CMD, path);
  pid=fork();
  if (unlikely(pid==-1)){
    debug(D_ERROR, "fork failed");
    return -1;
  }
  else if (pid){
    int status;
    psync_milisleep(100);
    if (waitpid(pid, &status, WNOHANG)==0)
      return 0;
    else
      return -1;
  }
  else{
    char *ex;
    int fd;
    fd=open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    setsid();
    ex=psync_strcat(PSYNC_RUN_CMD" \"", path, "\"", NULL);
    execl("/bin/sh", "/bin/sh", "-c", ex, NULL);
    debug(D_ERROR, "exec of %s failed", ex);
    psync_free(ex);
    exit(1);
  }
#elif defined(P_OS_WINDOWS)
  if ((int)ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWDEFAULT)>32)
    return 0;
  else
    return -1;
#else
  return -1;
#endif
}

int psync_invalidate_os_cache_needed(){
#if defined(P_OS_WINDOWS)
  return 1;
#elif defined(P_OS_MACOSX)
  return 0;
#else
  return 0;
#endif
}

#define REBUILD_ICON_BUFFER_SIZE 1024

extern int overlays_running;

#if defined(P_OS_WINDOWS)
void psync_rebuild_icons(){
  TCHAR buf[REBUILD_ICON_BUFFER_SIZE] = { 0 };
  HKEY hRegKey = 0;
  DWORD dwRegValue;
  DWORD dwRegValueTemp;
  DWORD dwSize;
  DWORD_PTR dwResult;
  LONG lRegResult;
  int result = 0;

  // we're going to change the Shell Icon Size value
  const TCHAR* sRegValueName = L"Shell Icon Size";

  if (!overlays_running)
	  return;

  lRegResult = RegOpenKeyEx(HKEY_CURRENT_USER, L"Control Panel\\Desktop\\WindowMetrics",
    0, KEY_READ | KEY_WRITE, &hRegKey);
  if (lRegResult != ERROR_SUCCESS)
    goto Cleanup;

  // Read registry value
  dwSize = REBUILD_ICON_BUFFER_SIZE;
  lRegResult = RegQueryValueEx(hRegKey, sRegValueName, NULL, NULL,
    (LPBYTE)buf, &dwSize);
  if (lRegResult != ERROR_FILE_NOT_FOUND)
  {
    // If registry key doesn't exist create it using system current setting
    int iDefaultIconSize = GetSystemMetrics(SM_CXICON);
    if (0 == iDefaultIconSize)
      iDefaultIconSize = 32;
    _snprintf(buf, REBUILD_ICON_BUFFER_SIZE, L"%d", iDefaultIconSize);
  }
  else if (lRegResult != ERROR_SUCCESS)
    goto Cleanup;

  // Change registry value
  dwRegValue = _wtoi(buf);
  dwRegValueTemp = dwRegValue - 1;

  dwSize = _snprintf(buf, REBUILD_ICON_BUFFER_SIZE, L"%lu", dwRegValueTemp) + sizeof(TCHAR);
  lRegResult = RegSetValueEx(hRegKey, sRegValueName, 0, REG_SZ,
    (LPBYTE)buf, dwSize);
  if (lRegResult != ERROR_SUCCESS)
    goto Cleanup;


  // Update all windows
  SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, SPI_SETNONCLIENTMETRICS,
    0, SMTO_ABORTIFHUNG, 5000, &dwResult);

  // Reset registry value
  dwSize = _snprintf(buf, REBUILD_ICON_BUFFER_SIZE, L"%lu", dwRegValue) + sizeof(TCHAR);
  lRegResult = RegSetValueEx(hRegKey, sRegValueName, 0, REG_SZ,
    (LPBYTE)buf, dwSize);
  if (lRegResult != ERROR_SUCCESS)
    goto Cleanup;

  // Update all windows
  SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, SPI_SETNONCLIENTMETRICS,
    0, SMTO_ABORTIFHUNG, 5000, &dwResult);

  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

  result = 1;

Cleanup:
  if (hRegKey != 0)
  {
    RegCloseKey(hRegKey);
  }
  return;
}
#elif defined(P_OS_MACOSX)
void psync_rebuild_icons(){
  int ret = 0;

  if (!overlays_running)
    return;

  debug(D_NOTICE, "Stopping finder plugin to refresh all icons.");
  ret = system("/bin/sh -c \"pluginkit -e ignore -i com.pcloud.pcloud.macos.pCloudFinderExt;sleep 0.5;pluginkit -e use -i com.pcloud.pcloud.macos.pCloudFinderExt;\"");
  debug(D_ERROR, "Reseting Finder Ext");
}
#else
void psync_rebuild_icons(){
  if (!overlays_running)
    return;
  return;
}
#endif

int psync_invalidate_os_cache(const char *path){
#if defined(P_OS_WINDOWS)
  wchar_t *wpath;
  debug(D_NOTICE, "got invalidate for path %s", path);
  wpath=utf8_to_wchar_path(path);
  SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATH, wpath, NULL);
  psync_free(wpath);
  return 0;
#elif defined(P_OS_MACOSX)
  int pfds[2];
  pid_t pid;
  debug(D_NOTICE, "running osascript to refresh finder");
  if (unlikely(pipe(pfds))){
    debug(D_ERROR, "pipe failed");
    return -1;
  }
  pid=fork();
  if (unlikely(pid==-1)){
    close(pfds[0]);
    close(pfds[1]);
    debug(D_ERROR, "fork failed");
    return -1;
  }
  else if (pid){
    const char *cmd="tell application \"Finder\"\n\
  repeat with i from 1 to count of Finder windows\n\
    tell window i\n\
      try\n\
        update every item in every folder with necessity\n\
      end try\n\
    end tell\n\
  end repeat\n\
end tell\n";
    int status;
    close(pfds[0]);
    status=strlen(cmd);
    if (write(pfds[1], cmd, status)!=status || close(pfds[1])!=0){
      debug(D_ERROR, "write to pipe failed");
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      return -1;
    }
    if (waitpid(pid, &status, 0)==0 && WIFEXITED(status) && WEXITSTATUS(status)==0){
      debug(D_NOTICE, "execution of osascript succeded");
      return 0;
    }
    else{
      debug(D_ERROR, "execution of osascript failed");
      return -1;
    }
  }
  else{
    int fd;
    close(pfds[1]);
    dup2(pfds[0], STDIN_FILENO);
    close(pfds[0]);
    fd=open("/dev/null", O_RDWR);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    execl("/bin/sh", "/bin/sh", "-c", "osascript", NULL);
    debug(D_ERROR, "exec of \"/bin/sh -c osascript\" failed");
    exit(1);
  }
#else
  return 0;
#endif
}

void *psync_mmap_anon(size_t size){
#if defined(PSYNC_MAP_ANONYMOUS)
  return mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|PSYNC_MAP_ANONYMOUS, -1, 0);
#elif defined(P_OS_WINDOWS)
  return VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
#else
  return malloc(size);
#endif
}

PSYNC_NOINLINE static void *psync_mmap_anon_emergency(size_t size){
  void *ret;
  debug(D_WARNING, "could not allocate %lu bytes", (unsigned long)size);
  psync_try_free_memory();
  ret=psync_mmap_anon(size);
  if (likely(ret))
    return ret;
  else{
    debug(D_CRITICAL, "could not allocate %lu bytes even after freeing some memory, aborting", (unsigned long)size);
    abort();
    return NULL;
  }
}

void *psync_mmap_anon_safe(size_t size){
  void *ret;
  ret=psync_mmap_anon(size);
  if (likely(ret))
    return ret;
  else
    return psync_mmap_anon_emergency(size);
}

int psync_munmap_anon(void *ptr, size_t size){
#if defined(PSYNC_MAP_ANONYMOUS)
  return munmap(ptr, size);
#elif defined(P_OS_WINDOWS)
  return psync_bool_to_zero(VirtualFree(ptr, 0, MEM_RELEASE));
#else
  free(ptr);
  return 0;
#endif
}

void psync_anon_reset(void *ptr, size_t size){
#if defined(PSYNC_MAP_ANONYMOUS) && defined(MADV_DONTNEED)
  madvise(ptr, size, MADV_DONTNEED);
#elif defined(P_OS_WINDOWS)
  VirtualAlloc(ptr, size, MEM_RESET, PAGE_READWRITE);
#endif
}

int psync_mlock(void *ptr, size_t size){
#if defined(_POSIX_MEMLOCK_RANGE)
  return mlock(ptr, size);
#elif defined(P_OS_WINDOWS)
  return psync_bool_to_zero(VirtualLock(ptr, size));
#else
  return -1;
#endif
}

int psync_munlock(void *ptr, size_t size){
#if defined(_POSIX_MEMLOCK_RANGE)
  return munlock(ptr, size);
#elif defined(P_OS_WINDOWS)
  return psync_bool_to_zero(VirtualUnlock(ptr, size));
#else
  return -1;
#endif
}

int psync_get_page_size(){
  return psync_page_size;
}
