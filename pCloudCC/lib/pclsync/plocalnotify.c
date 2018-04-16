/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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

#include "pcompat.h"
#include "plocalnotify.h"
#include "plocalscan.h"
#include "psettings.h"
#include "plist.h"
#include "plibs.h"

#define NOTIFY_MSG_ADD 0
#define NOTIFY_MSG_DEL 1

typedef struct{
  uint32_t type;
  psync_syncid_t syncid;
} localnotify_msg;

#if defined(P_OS_LINUX)

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

static int pipe_read, pipe_write, epoll_fd;
static psync_list dirs=PSYNC_LIST_STATIC_INIT(dirs);

#define WATCH_HASH 512

typedef struct _localnotify_watch{
  struct _localnotify_watch *next;
  int watchid;
  uint32_t pathlen;
  uint32_t namelen;
  char path[];
} localnotify_watch;

typedef struct{
  psync_list list;
  psync_syncid_t syncid;
  int inotifyfd;
  localnotify_watch *watches[WATCH_HASH];
  char path[];
} localnotify_dir;

static void add_dir_scan(localnotify_dir *dir, const char *path){
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry, *de;
  localnotify_watch *wch;
  struct stat st;
  int wid;
  pl=strlen(path);
  if (unlikely((wid=inotify_add_watch(dir->inotifyfd, path, IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE_SELF))==-1)){
    debug(D_ERROR, "inotify_add_watch failed");
    return;
  }
  namelen=pathconf(path, _PC_NAME_MAX);
  if (namelen==-1)
    namelen=255;
  if (namelen<sizeof(de->d_name)-1)
    namelen=sizeof(de->d_name)-1;
  wch=(localnotify_watch *)psync_malloc(offsetof(localnotify_watch, path)+pl+1+namelen+1);
  wch->next=dir->watches[wid%WATCH_HASH];
  dir->watches[wid%WATCH_HASH]=wch;
  wch->watchid=wid;
  wch->pathlen=pl;
  wch->namelen=namelen;
  memcpy(wch->path, path, pl+1);
  if (likely_log(dh=opendir(path))){
    entrylen=offsetof(struct dirent, d_name)+namelen+1;
    cpath=(char *)psync_malloc(pl+namelen+2);
    entry=(struct dirent *)psync_malloc(entrylen);
    memcpy(cpath, path, pl);
    if (!pl || cpath[pl-1]!=PSYNC_DIRECTORY_SEPARATORC)
      cpath[pl++]=PSYNC_DIRECTORY_SEPARATORC;
    while (!readdir_r(dh, entry, &de) && de)
      if (de->d_name[0]!='.' || (de->d_name[1]!=0 && (de->d_name[1]!='.' || de->d_name[2]!=0))){
        psync_strlcpy(cpath+pl, de->d_name, namelen+1);
        if (!lstat(cpath, &st) && S_ISDIR(st.st_mode))
          add_dir_scan(dir, cpath);
      }
    psync_free(entry);
    psync_free(cpath);
    closedir(dh);
  }
}

static void add_syncid(psync_syncid_t syncid){
  psync_sql_res *res;
  psync_variant_row row;
  localnotify_dir *dir;
  const char *str;
  size_t len;
  struct epoll_event e;
  res=psync_sql_query("SELECT localpath FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  if (likely(row=psync_sql_fetch_row(res))){
    str=psync_get_lstring(row[0], &len);
    len++;
    dir=(localnotify_dir *)psync_malloc(offsetof(localnotify_dir, path)+len);
    memcpy(dir->path, str, len);
    psync_sql_free_result(res);
  }
  else{
    psync_sql_free_result(res);
    debug(D_ERROR, "could not find syncfolder with id %u", (unsigned int)syncid);
    return;
  }
  dir->syncid=syncid;
  dir->inotifyfd=inotify_init();
  if (unlikely_log(dir->inotifyfd==-1))
    goto err;
  memset(dir->watches, 0, sizeof(dir->watches));
  add_dir_scan(dir, dir->path);
  e.events=EPOLLIN;
  e.data.ptr=dir;
  if (unlikely_log(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, dir->inotifyfd, &e)))
    goto err2;
  psync_list_add_tail(&dirs, &dir->list);
  return;
err2:
  close(dir->inotifyfd);
err:
  psync_free(dir);
}

static void del_syncid(psync_syncid_t syncid){
  localnotify_dir *dir;
  localnotify_watch *wch, *next;
  psync_uint_t i;
  psync_list_for_each_element(dir, &dirs, localnotify_dir, list)
    if (dir->syncid==syncid){
      psync_list_del(&dir->list);
      for (i=0; i<WATCH_HASH; i++){
        wch=dir->watches[i];
        while (wch){
          next=wch->next;
          inotify_rm_watch(dir->inotifyfd, wch->watchid);
          psync_free(wch);
          wch=next;
        }
      }
      epoll_ctl(epoll_fd, EPOLL_CTL_DEL, dir->inotifyfd, NULL);
      close(dir->inotifyfd);
      psync_free(dir);
      return;
    }
}

static void process_pipe(){
  localnotify_msg msg;
  if (read(pipe_read, &msg, sizeof(msg))!=sizeof(msg)){
    debug(D_ERROR, "read from pipe failed");
    return;
  }
  if (msg.type==NOTIFY_MSG_ADD)
    add_syncid(msg.syncid);
  else if (msg.type==NOTIFY_MSG_DEL)
    del_syncid(msg.syncid);
  else
    debug(D_ERROR, "invalid message type %u", (unsigned int)msg.type);
}

static uint32_t process_notification(localnotify_dir *dir){
  ssize_t rd, off;
  struct inotify_event ev;
  localnotify_watch *wch, **pwch;
  struct stat st;
  char buff[8*1024];
  rd=read(dir->inotifyfd, buff, sizeof(buff));
  off=0;
  while (off<rd){
    memcpy(&ev, buff+off, offsetof(struct inotify_event, name));
    if (ev.mask&(IN_CREATE|IN_MOVED_TO)){
      wch=dir->watches[ev.wd%WATCH_HASH];
      while (wch){
        if (wch->watchid==ev.wd){
          wch->path[wch->pathlen]='/';
          psync_strlcpy(wch->path+wch->pathlen+1, buff+off+offsetof(struct inotify_event, name), wch->namelen+1);
          if (!lstat(wch->path, &st) && S_ISDIR(st.st_mode))
            add_dir_scan(dir, wch->path);
          wch->path[wch->pathlen]=0;
          break;
        }
        else
          wch=wch->next;
      }
    }
    else if (ev.mask&IN_DELETE_SELF){
      wch=dir->watches[ev.wd%WATCH_HASH];
      pwch=&dir->watches[ev.wd%WATCH_HASH];
      while (wch){
        if (wch->watchid==ev.wd){
          *pwch=wch->next;
          inotify_rm_watch(dir->inotifyfd, wch->watchid);
          psync_free(wch);
          break;
        }
        else{
          pwch=&wch->next;
          wch=wch->next;
        }
      }
    }
    off+=offsetof(struct inotify_event, name)+ev.len;
  }
  if (rd>0)
    return 1;
  else
    return 0;
}

static void psync_localnotify_thread(){
  struct epoll_event ev;
  uint32_t ncnt;
  int cnt;
  ncnt=0;
  while (psync_do_run){
    if ((cnt=epoll_wait(epoll_fd, &ev, 1, 1000))!=1){
      if (cnt==-1) {
        if (errno!=EINTR)
          debug(D_WARNING, "epoll_wait failed errno %d", errno);
      }
      else if (cnt==0 && ncnt) {
        ncnt=0;
        psync_wake_localscan();
      }
    }
    else {
      if (ev.data.ptr)
        ncnt+=process_notification((localnotify_dir *)ev.data.ptr);
      else
        process_pipe();
    }
  }
}

int psync_localnotify_init(){
  struct epoll_event e;
  int pfd[2];
  if (unlikely_log(pipe(pfd)))
    goto err0;
  pipe_read=pfd[0];
  pipe_write=pfd[1];
  epoll_fd=epoll_create(1);
  if (unlikely_log(epoll_fd==-1))
    goto err1;
  e.events=EPOLLIN;
  e.data.ptr=NULL;
  if (unlikely_log(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_read, &e)))
    goto err2;
  psync_run_thread("localnotify", psync_localnotify_thread);
  return 0;
err2:
  close(epoll_fd);
err1:
  close(pfd[0]);
  close(pfd[1]);
err0:
  pipe_read=pipe_write=-1;
  return -1;
}

void psync_localnotify_add_sync(psync_syncid_t syncid){
  localnotify_msg msg;
  msg.type=NOTIFY_MSG_ADD;
  msg.syncid=syncid;
  if (write(pipe_write, &msg, sizeof(msg))!=sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
}

void psync_localnotify_del_sync(psync_syncid_t syncid){
  localnotify_msg msg;
  msg.type=NOTIFY_MSG_DEL;
  msg.syncid=syncid;
  if (write(pipe_write, &msg, sizeof(msg))!=sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
}

#elif defined(P_OS_WINDOWS)

static HANDLE pipe_read, pipe_write, *handles;
static psync_syncid_t *syncids=NULL;
static DWORD handlecnt;

static wchar_t *utf8_to_wchar(const char *str){
  int len;
  wchar_t *ret;
  len=MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  ret=psync_new_cnt(wchar_t, len);
  MultiByteToWideChar(CP_UTF8, 0, str, -1, ret, len);
  return ret;
}

static void process_notification(DWORD handleid){
  if (!FindNextChangeNotification(handles[handleid])){
    debug(D_ERROR, "FindNextChangeNotification failed");
    psync_milisleep(PSYNC_LOCALSCAN_RESCAN_INTERVAL*1000);
  }
  psync_wake_localscan();
}

static void add_syncid(psync_syncid_t syncid){
  psync_sql_res *res;
  psync_variant_row row;
  wchar_t *path;
  DWORD idx;
  HANDLE h;
  res=psync_sql_query("SELECT localpath FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  if (likely(row=psync_sql_fetch_row(res))){
    path=utf8_to_wchar(psync_get_string(row[0]));
    psync_sql_free_result(res);
  }
  else{
    psync_sql_free_result(res);
    debug(D_ERROR, "could not find syncfolder with id %u", (unsigned int)syncid);
    return;
  }
  h=FindFirstChangeNotificationW(path, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME|
                                             FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE|FILE_NOTIFY_CHANGE_ATTRIBUTES);
  psync_free(path);
  if (unlikely(h==INVALID_HANDLE_VALUE)){
    debug(D_ERROR, "FindFirstChangeNotificationW failed");
    return;
  }
  idx=handlecnt++;
  handles=(HANDLE *)psync_realloc(handles, sizeof(HANDLE)*handlecnt);
  syncids=(psync_syncid_t *)psync_realloc(syncids, sizeof(psync_syncid_t)*handlecnt);
  handles[idx]=h;
  syncids[idx]=syncid;
}

static void del_syncid(psync_syncid_t syncid){
  DWORD i;
  for (i=1; i<handlecnt; i++)
    if (syncids[i]==syncid){
      FindCloseChangeNotification(handles[i]);
      handlecnt--;
      handles[i]=handles[handlecnt];
      syncids[i]=syncids[handlecnt];
      break;
    }
}

static void process_pipe(){
  localnotify_msg msg;
  DWORD br;

  if (PeekNamedPipe(pipe_read, &msg, sizeof(msg), &br, NULL, NULL) && br != sizeof(msg)){
    ResetEvent(handles[0]);
    return;
  }
  if (!ReadFile(pipe_read, &msg, sizeof(msg), &br, NULL) || br!=sizeof(msg)){
    debug(D_ERROR, "reading from pipe failed %d", GetLastError());
    return;
  }
  if (msg.type==NOTIFY_MSG_ADD)
    add_syncid(msg.syncid);
  else if (msg.type==NOTIFY_MSG_DEL)
    del_syncid(msg.syncid);
  else
    debug(D_ERROR, "invalid message type %u", (unsigned int)msg.type);
}

static void psync_localnotify_thread(){
  DWORD ret;
  while (psync_do_run){
    ret=WaitForMultipleObjects(handlecnt, handles, FALSE, INFINITE);
    if (ret>=WAIT_OBJECT_0 && ret<WAIT_OBJECT_0+handlecnt){
      ret-=WAIT_OBJECT_0;
      if (ret)
        process_notification(ret);
      else
        process_pipe();
    }
  }
}

int psync_localnotify_init(){
  DWORD state = PIPE_NOWAIT;

  if (!CreatePipe(&pipe_read, &pipe_write, NULL, 0))
    return -1;

  handles=psync_new(HANDLE);
  handlecnt = 1;
  handles[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
  psync_run_thread("localnotify", psync_localnotify_thread);
  return 0;
}

void psync_localnotify_add_sync(psync_syncid_t syncid){
  localnotify_msg msg;
  DWORD bw;
  msg.type=NOTIFY_MSG_ADD;
  msg.syncid=syncid;
  if (!WriteFile(pipe_write, &msg, sizeof(msg), &bw, NULL) || bw!=sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
  SetEvent(handles[0]);
}

void psync_localnotify_del_sync(psync_syncid_t syncid){
  localnotify_msg msg;
  DWORD bw;
  msg.type=NOTIFY_MSG_DEL;
  msg.syncid=syncid;
  if (!WriteFile(pipe_write, &msg, sizeof(msg), &bw, NULL) || bw!=sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
  SetEvent(handles[0]);
}

#elif defined(P_OS_MACOSX)

#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

static CFRunLoopRef runloop=NULL;
static FSEventStreamEventId lastevent;

static void stream_callback(ConstFSEventStreamRef streamRef,
                            void *clientCallBackInfo,
                            size_t numEvents,
                            void *eventPaths,
                            const FSEventStreamEventFlags eventFlags[],
                            const FSEventStreamEventId eventIds[]){
  size_t i;
  for (i=0; i<numEvents; i++)
    if (eventIds[i]>lastevent)
      lastevent=eventIds[i];
  psync_wake_localscan();
}

static void timer_callback(CFRunLoopTimerRef timer, void *info){
}

static CFRunLoopTimerRef get_timer(){
  CFRunLoopTimerRef timer;
  CFRunLoopTimerContext context={0, NULL, NULL, NULL, NULL};
  timer=CFRunLoopTimerCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent(), 3600, 0, 0, timer_callback, &context);
  return timer;
}

static void psync_localnotify_thread(){
  psync_sql_res *res;
  psync_str_row row;
  CFMutableArrayRef dirs;
  CFStringRef dir;
  FSEventStreamRef stream;
  CFAbsoluteTime latency;
  CFRunLoopTimerRef timer;
  struct stat st;
  psync_uint_t cnt;
  latency=0.2;
  lastevent=kFSEventStreamEventIdSinceNow;
  runloop=CFRunLoopGetCurrent();
  /* the timer is needed only for cases with no directories to monitor, because loops do not like to run empty */
  timer=get_timer();
  CFRunLoopAddTimer(runloop, timer, kCFRunLoopCommonModes);
  while (psync_do_run){
    dirs=CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    cnt=0;
    res=psync_sql_query("SELECT localpath FROM syncfolder WHERE synctype&"NTO_STR(PSYNC_UPLOAD_ONLY)"="NTO_STR(PSYNC_UPLOAD_ONLY));
    while ((row=psync_sql_fetch_rowstr(res))){
      if (stat(row[0], &st) || !S_ISDIR(st.st_mode))
        continue;
      dir=CFStringCreateWithBytes(kCFAllocatorDefault, (const unsigned char *)row[0], strlen(row[0]), kCFStringEncodingUTF8, false);
      CFArrayAppendValue(dirs, dir);
      CFRelease(dir);
      cnt++;
    }
    psync_sql_free_result(res);
    if (likely(cnt)){
      stream=FSEventStreamCreate(kCFAllocatorDefault, stream_callback, NULL, dirs, lastevent, latency, kFSEventStreamCreateFlagNone);
      FSEventStreamScheduleWithRunLoop(stream, runloop, kCFRunLoopDefaultMode);
      FSEventStreamStart(stream);
    }
    CFRelease(dirs);
    CFRunLoopRun();
    if (likely(cnt)){
      FSEventStreamStop(stream);
      FSEventStreamInvalidate(stream);
      FSEventStreamRelease(stream);
    }
  }
}

int psync_localnotify_init(){
  psync_run_thread("localnotify", psync_localnotify_thread);
  return 0;
}

static void wake_loop(){
  if (unlikely(!runloop)){
    unsigned int tries=0;
    while (!runloop && tries++<1000)
      psync_milisleep(2);
    if (!runloop)
      return;
  }
  CFRunLoopStop(runloop);
}

void psync_localnotify_add_sync(psync_syncid_t syncid){
  wake_loop();
}

void psync_localnotify_del_sync(psync_syncid_t syncid){
  wake_loop();
}

#elif defined(P_OS_BSD)

/* this implementation only monitors folder changes - it does not catch
 * file changes (however it does catch deleted and created files).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

typedef struct{
  psync_list nextfolder;
  psync_list subfolders;
  psync_syncid_t syncid;
  int fd;
  uint32_t nameoff; /* can also be uint16_t */
  char path[];
} localnotify_dir;

typedef struct{
  psync_list list;
  uint32_t nameoff;
  char path[];
} localnotify_tmpdir;

static int pipe_read, pipe_write, kevent_fd;
static psync_list dirs=PSYNC_LIST_STATIC_INIT(dirs);

static int sort_dir_by_name(const psync_list *l1, const psync_list *l2){
  const localnotify_dir *d1=psync_list_element(l1, localnotify_dir, nextfolder);
  const localnotify_dir *d2=psync_list_element(l2, localnotify_dir, nextfolder);
  return strcmp(d1->path+d1->nameoff, d2->path+d2->nameoff);
}

static int sort_tdir_by_name(const psync_list *l1, const psync_list *l2){
  const localnotify_tmpdir *d1=psync_list_element(l1, localnotify_tmpdir, list);
  const localnotify_tmpdir *d2=psync_list_element(l2, localnotify_tmpdir, list);
  return strcmp(d1->path+d1->nameoff, d2->path+d2->nameoff);
}

static localnotify_dir *get_dir_scan(const char *path, psync_syncid_t syncid){
  struct kevent ke;
  struct timespec ts;
  localnotify_dir *dir, *child;
  char *str, *cpath;
  DIR *dh;
  struct dirent *de, *entry;
  size_t len, entrylen;
  long namelen;
  struct stat st;
  len=strlen(path)+1;
  dir=(localnotify_dir *)psync_malloc(offsetof(localnotify_dir, path)+len);
  psync_list_init(&dir->subfolders);
  memcpy(dir->path, path, len);
  str=strrchr(dir->path, '/');
  if (str)
    dir->nameoff=str-dir->path+1;
  else
    dir->nameoff=0;
  dir->syncid=syncid;
  dir->fd=open(dir->path,
#ifdef O_EVTONLY
  O_EVTONLY
#else
  O_RDONLY
#endif
  );
  if (unlikely_log(dir->fd==-1))
    goto err;
  EV_SET(&ke, dir->fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB, 0, dir);
  memset(&ts, 0, sizeof(ts));
  if (unlikely_log(kevent(kevent_fd, &ke, 1, NULL, 0, &ts)==-1))
    goto err2;
  namelen=pathconf(path, _PC_NAME_MAX);
  if (namelen==-1)
    namelen=255;
  if (namelen<sizeof(de->d_name)-1)
    namelen=sizeof(de->d_name)-1;
  if (likely_log(dh=opendir(path))){
    entrylen=offsetof(struct dirent, d_name)+namelen+1;
    cpath=(char *)psync_malloc(len+namelen+1);
    entry=(struct dirent *)psync_malloc(entrylen);
    len--;
    memcpy(cpath, path, len);
    if (!len || cpath[len-1]!=PSYNC_DIRECTORY_SEPARATORC)
      cpath[len++]=PSYNC_DIRECTORY_SEPARATORC;
    while (!readdir_r(dh, entry, &de) && de)
      if (de->d_name[0]!='.' || (de->d_name[1]!=0 && (de->d_name[1]!='.' || de->d_name[2]!=0))){
        psync_strlcpy(cpath+len, de->d_name, namelen+1);
        if (!lstat(cpath, &st) && S_ISDIR(st.st_mode)){
          child=get_dir_scan(cpath, syncid);
          if (child)
            psync_list_add_tail(&dir->subfolders, &child->nextfolder);
        }
      }
    psync_free(entry);
    psync_free(cpath);
    closedir(dh);
  }
  psync_list_sort(&dir->subfolders, sort_dir_by_name);
  return dir;
err2:
  close(dir->fd);
err:
  psync_free(dir);
  return NULL;
}

static void add_syncid(psync_syncid_t syncid){
  psync_sql_res *res;
  psync_str_row row;
  char *str;
  localnotify_dir *dir;
  res=psync_sql_query("SELECT localpath FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  if (likely(row=psync_sql_fetch_rowstr(res))){
    str=psync_strdup(row[0]);
    psync_sql_free_result(res);
  }
  else{
    psync_sql_free_result(res);
    debug(D_ERROR, "could not find syncfolder with id %u", (unsigned int)syncid);
    return;
  }
  dir=get_dir_scan(str, syncid);
  if (!dir)
    debug(D_ERROR, "could not scan folder %s", str);
  psync_free(str);
  if (dir)
    psync_list_add_tail(&dirs, &dir->nextfolder);
}

static void free_dir(localnotify_dir *dir){
  psync_list *e, *b;
  psync_list_for_each_safe(e, b, &dir->subfolders)
    free_dir(psync_list_element(e, localnotify_dir, nextfolder));
  close(dir->fd);
  psync_free(dir);
}

static void del_syncid(psync_syncid_t syncid){
  psync_list *e;
  localnotify_dir *dir;
  psync_list_for_each(e, &dirs){
    dir=psync_list_element(e, localnotify_dir, nextfolder);
    if (dir->syncid==syncid){
      psync_list_del(e);
      free_dir(dir);
      return;
    }
  }
}

static void process_pipe(){
  localnotify_msg msg;
  if (read(pipe_read, &msg, sizeof(msg))!=sizeof(msg)){
    debug(D_ERROR, "read from pipe failed");
    return;
  }
  if (msg.type==NOTIFY_MSG_ADD)
    add_syncid(msg.syncid);
  else if (msg.type==NOTIFY_MSG_DEL)
    del_syncid(msg.syncid);
  else
    debug(D_ERROR, "invalid message type %u", (unsigned int)msg.type);
}

static void process_notification(localnotify_dir *dir){
  DIR *dh;
  char *cpath;
  struct dirent *de, *entry;
  localnotify_tmpdir *tdir;
  localnotify_dir *cdir;
  psync_list tlist;
  psync_list *l1, *l2;
  size_t len, len2, entrylen;
  long namelen;
  struct stat st;
  int cmp;
  debug(D_NOTICE, "got notification for folder %s", dir->path);
  dh=opendir(dir->path);
  if (unlikely_log(!dh)){
    psync_list_del(&dir->nextfolder);
    free_dir(dir);
    return;
  }
  len=strlen(dir->path);
  namelen=pathconf(dir->path, _PC_NAME_MAX);
  if (namelen==-1)
    namelen=255;
  entrylen=offsetof(struct dirent, d_name)+namelen+1;
  cpath=(char *)psync_malloc(len+namelen+2);
  entry=(struct dirent *)psync_malloc(entrylen);
  memcpy(cpath, dir->path, len);
  if (!len || cpath[len-1]!=PSYNC_DIRECTORY_SEPARATORC)
    cpath[len++]=PSYNC_DIRECTORY_SEPARATORC;
  psync_list_init(&tlist);
  while (!readdir_r(dh, entry, &de) && de)
    if (de->d_name[0]!='.' || (de->d_name[1]!=0 && (de->d_name[1]!='.' || de->d_name[2]!=0))){
      len2=strlen(de->d_name);
      memcpy(cpath+len, de->d_name, len2+1);
      if (!lstat(cpath, &st) && S_ISDIR(st.st_mode)){
        tdir=(localnotify_tmpdir *)psync_malloc(offsetof(localnotify_tmpdir, path)+len+len2+1);
        tdir->nameoff=len;
        memcpy(tdir->path, cpath, len+len2+1);
        psync_list_add_tail(&tlist, &tdir->list);
      }
    }
  psync_free(entry);
  psync_free(cpath);
  closedir(dh);
  psync_list_sort(&tlist, sort_tdir_by_name);
  l1=dir->subfolders.next;
  l2=tlist.next;
  while (l1!=&dir->subfolders && l2!=&tlist){
    cdir=psync_list_element(l1, localnotify_dir, nextfolder);
    tdir=psync_list_element(l2, localnotify_tmpdir, list);
    cmp=strcmp(cdir->path+cdir->nameoff, tdir->path+tdir->nameoff);
    if (cmp==0){
      l1=l1->next;
      l2=l2->next;
    }
    else if (cmp<0){ /* deleted folder */
      l1=l1->next;
      psync_list_del(&cdir->nextfolder);
      free_dir(cdir);
    }
    else{
      l2=l2->next;
      cdir=get_dir_scan(tdir->path, dir->syncid);
      if (cdir)
        psync_list_add_between(l1->prev, l1, &cdir->nextfolder);
    }
  }
  psync_list_for_each_element_call(&tlist, localnotify_tmpdir, list, psync_free);
  psync_wake_localscan();
}

static void psync_localnotify_thread(){
  struct kevent ke;
  while (psync_do_run){
    if (unlikely_log(kevent(kevent_fd, NULL, 0, &ke, 1, NULL)!=1))
      continue;
    if (ke.udata)
      process_notification((localnotify_dir *)ke.udata);
    else
      process_pipe();
  }
}

int psync_localnotify_init(){
  struct kevent ke;
  struct timespec ts;
  int pfd[2];
  if (unlikely_log(pipe(pfd)))
    goto err0;
  pipe_read=pfd[0];
  pipe_write=pfd[1];
  kevent_fd=kqueue();
  if (unlikely_log(kevent_fd==-1))
    goto err1;
  EV_SET(&ke, pipe_read, EVFILT_READ, EV_ADD|EV_CLEAR, 0, 0, 0);
  memset(&ts, 0, sizeof(ts));
  if (unlikely_log(kevent(kevent_fd, &ke, 1, NULL, 0, &ts)==-1))
    goto err2;
  psync_run_thread("localnotify", psync_localnotify_thread);
  /* return -1 so we still run frequent rescans */
  return -1;
err2:
  close(kevent_fd);
err1:
  close(pfd[0]);
  close(pfd[1]);
err0:
  pipe_read=pipe_write=-1;
  return -1;
}

void psync_localnotify_add_sync(psync_syncid_t syncid){
  localnotify_msg msg;
  msg.type=NOTIFY_MSG_ADD;
  msg.syncid=syncid;
  if (write(pipe_write, &msg, sizeof(msg))!=sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
}

void psync_localnotify_del_sync(psync_syncid_t syncid){
  localnotify_msg msg;
  msg.type=NOTIFY_MSG_DEL;
  msg.syncid=syncid;
  if (write(pipe_write, &msg, sizeof(msg))!=sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
}

#else

int psync_localnotify_init(){
  return -1;
}

void psync_localnotify_add_sync(psync_syncid_t syncid){
}

void psync_localnotify_del_sync(psync_syncid_t syncid){
}

#endif
