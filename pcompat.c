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
#include <time.h>
#include "pcompat.h"
#include "psynclib.h"
#include "plibs.h"
#include "psettings.h"
#include "pssl.h"

#if defined(P_OS_POSIX)

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>

#define psync_close_socket close

#elif defined(P_OS_WINDOWS)

#include <process.h>
#include <windows.h>

#define psync_close_socket closesocket

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
  psync_uid=getuid();
  psync_gid=getgid();
  psync_gids_cnt=getgroups(0, NULL);
  psync_gids=(gid_t *)psync_malloc(sizeof(gid_t)*psync_gids_cnt);
  if (getgroups(psync_gids_cnt, psync_gids)!=psync_gids_cnt)
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
  if (!dir || stat(dir, &st) || !psync_stat_mode_ok(&st, 7)){
    struct passwd pwd;
    struct passwd *result;
    char buff[4096];
    if (getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result) || stat(result->pw_dir, &st) || !psync_stat_mode_ok(&st, 7))
      return NULL;
    dir=result->pw_dir;
  }
  return psync_strcat(dir, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_POSIX_DBNAME, NULL);
#elif defined(P_OS_WINDOWS)
#warning "should we create pCloud directory in user's home directory and put the file there on Windows?"
  const char *dir;
  dir=getenv("UserProfile");
  if (!dir)
    return NULL;
  return psync_strcat(dir, PSYNC_DIRECTORY_SEPARATOR, PSYNC_DEFAULT_WINDOWS_DBNAME, NULL);
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
  data=(psync_run_data1 *)psync_malloc(sizeof(psync_run_data1));
  data->run=run;
  data->ptr=ptr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry1, data);
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
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
#define PSOCK_TYPE_OR (SOCK_NONBLOCK|SOCK_CLOEXEC)
#else
#define PSOCK_TYPE_OR 0
#define PSOCK_NEED_NOBLOCK
#endif
  while (res){
    sock=socket(res->ai_family, res->ai_socktype|PSOCK_TYPE_OR, res->ai_protocol);
    if (sock!=INVALID_SOCKET){
#if defined(PSOCK_NEED_NOBLOCK)
#if defined(P_OS_WINDOWS)
      ioctlsocket(sock, FIONBIO, &non_blocking_mode);
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
      close(sock);
    }
    res=res->ai_next;
  }
  return INVALID_SOCKET;
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
  if (rc==WSANOTINITIALISED){
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) 
      return INVALID_SOCKET;
    rc=getaddrinfo(host, port, &hints, &res);
  }
#endif
  if (rc!=0){
    debug(D_WARNING, "failed to resolve %s", host);
    return INVALID_SOCKET;
  }
  sock=connect_res(res);
  freeaddrinfo(res);
  if (sock!=INVALID_SOCKET){
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
  else if (psync_ssl_errno==PSYNC_SSL_ERR_WANT_READ){
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
  if (sock==INVALID_SOCKET)
    return NULL;
  if (ssl){
    ssl=psync_ssl_connect(sock, &sslc);
    while (ssl==PSYNC_SSL_NEED_FINISH){
      if (wait_sock_ready_for_ssl(sock)){
        psync_ssl_free(sslc);
        break;
      }
      ssl=psync_ssl_connect_finish(sslc);
    }
    if (ssl!=PSYNC_SSL_SUCCESS){
      psync_close_socket(sock);
      return NULL;
    }
  }
  else
    sslc=NULL;
  ret=(psync_socket *)psync_malloc(sizeof(psync_socket));
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

int psync_socket_pendingdata(psync_socket *sock){
  if (sock->pending)
    return 1;
  if (sock->ssl)
    return psync_ssl_pendingdata(sock->ssl);
  else
    return 0;
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

static int psync_socket_readall_plain(psync_socket *sock, void *buff, int num){
  int br, r;
  br=0;
  if (!sock->pending && psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending=0;
  while (br<num){
    r=recv(sock->sock, (char *)buff+br, num-br, 0);
    if (r==SOCKET_ERROR){
      if ((psync_sock_err()==P_WOULDBLOCK || psync_sock_err()==P_AGAIN) && !psync_wait_socket_read_timeout(sock->sock))
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
    r=send(sock, (const char *)buff+br, num-br, 0);
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
  return recv(pfd, buff, num, 0);
#else
#error "Function not implemented for your operating system"
#endif
}

int psync_pipe_write(psync_socket_t pfd, const void *buff, int num){
#if defined(P_OS_POSIX)
  return write(pfd, buff, num);
#elif defined(P_OS_WINDOWS)
  return send(pfd, buff, num, 0);
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
struct tm *gmtime_r(const time_t *timep, struct tm *result){
  struct tm *res=gmtime(timep);
  *result=*res;
  return result;
}

static time_t filetime_to_timet(const FILETIME *ft){
  return (ft->dwHighDateTime*(MAXDWORD+1ULL)+ft->dwLowDateTime)/10000000ULL-11644473600ULL;
}
#endif

int psync_list_dir(const char *path, psync_list_dir_callback callback, void *ptr){
#if defined(P_OS_POSIX)
  struct stat st;
  psync_pstat pst;
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry, *de;
  if (stat(path, &st))
    goto err1;
  pst.canmodifyparent=psync_stat_mode_ok(&st, 2);
  dh=opendir(path);
  if (!dh)
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
      strcpy(cpath+pl, de->d_name);
      if (!stat(cpath, &st)){
        pst.name=de->d_name;
        pst.size=st.st_size;
        pst.lastmod=st.st_mtime;
        pst.isfolder=S_ISDIR(st.st_mode);
        pst.canread=psync_stat_mode_ok(&st, 4);
        pst.canwrite=psync_stat_mode_ok(&st, 2);
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
  char *spath;
  WIN32_FIND_DATA st;
  HANDLE dh;
  spath=psync_strcat(path, PSYNC_DIRECTORY_SEPARATOR "*", NULL);
  dh=FindFirstFile(spath, &st);
  psync_free(spath);
  if (dh==INVALID_HANDLE_VALUE){
    if (GetLastError()==ERROR_FILE_NOT_FOUND)
      return 0;
    else{
      psync_error=PERROR_LOCAL_FOLDER_NOT_FOUND;
      return -1;
    }
  }
  pst.name=st.cFileName;
  pst.canread=1;
  pst.canwrite=1;
  pst.canmodifyparent=1;
  do {
    pst.size=st.nFileSizeHigh*(MAXDWORD+1ULL)+st.nFileSizeLow;
    pst.lastmod=filetime_to_timet(&st.ftLastWriteTime);
    pst.isfolder=(st.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==FILE_ATTRIBUTE_DIRECTORY;
    callback(ptr, &pst);
  } while (FindNextFile(dh, &st));
  FindClose(dh);
  return 0;
#else
#error "Function not implemented for your operating system"
#endif
}
