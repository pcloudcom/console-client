#ifndef _PSYNC_COMPAT_H
#define _PSYNC_COMPAT_H

#include <stdint.h>

#if (defined(LINUX) || defined(MACOSX)) && !defined(POSIX)
#define POSIX
#endif

#if defined(POSIX)

#include <sys/socket.h>

typedef int psync_socket_t;

#elif defined(WINDOWS)

#include <winsock2.h>
#include <Ws2tcpip.h>

typedef SOCKET psync_socket_t;

#else
#error "Need to define types for your operating system"
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

#if defined(WINDOWS)
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif

#endif
