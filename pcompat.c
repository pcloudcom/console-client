#include <pthread.h>
#include "pcompat.h"
#include "psynclib.h"
#include "plibs.h"

#if defined(LINUX)
#define POSIX
#elif defined(MACOSX)
#define POSIX
#endif

#ifdef POSIX
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#endif

#define STACK_SIZE 64*1024

#define DEFAULT_POSIX_DBNAME ".pcloudsyncdb"

typedef struct {
 psync_thread_start1 run;
  void *ptr;
} psync_run_data1;

char *psync_get_default_database_path(){
#if defined(POSIX)
  struct passwd pwd;
  struct passwd *result;
  struct stat st;
  const char *dir;
  char buff[4096];
  dir=getenv("HOME");
  if (!dir || stat(dir, &st) || !S_ISDIR(st.st_mode)){
    if (getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result)!=0)
      return NULL;
    dir=result->pw_dir;
  }
  if (stat(dir, &st) || !S_ISDIR(st.st_mode))
    return NULL;
  return psync_strcat(dir, "/", DEFAULT_POSIX_DBNAME, NULL);
#elif defined(WINDOWS)
#error "Need Windows implementation"
#else
#error "Function not implemented for your operating system"
#endif
}

static void thread_started(){
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
  pthread_attr_setstacksize(&attr, STACK_SIZE);
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
  pthread_attr_setstacksize(&attr, STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry1, data);
}

void psync_milisleep(uint64_t milisec){
#if defined(POSIX)
  struct timespec tm;
  tm.tv_sec=milisec/1000;
  tm.tv_nsec=(milisec%1000)*1000000;
  nanosleep(&tm, NULL);
#elif defined(WINDOWS)
  Sleep(milisec);
#else
#error "Function not implemented for your operating system"
#endif
}

#if defined(WINDOWS)
struct tm *gmtime_r(const time_t *timep, struct tm *result){
  struct tm *res=gmtime(timep);
  *result=*res;
  return result;
}
#endif
