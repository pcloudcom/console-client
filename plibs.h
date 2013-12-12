#ifndef _PSYNC_LIBS_H
#define _PSYNC_LIBS_H

#ifdef __GNUC__
#define PSYNC_MALLOC __attribute__((malloc))
#define PSYNC_SENTINEL __attribute__ ((sentinel))
#else
#define PSYNC_MALLOC
#define PSYNC_SENTINEL
#endif

char *psync_strdup(const char *str) PSYNC_MALLOC;
char *psync_strcat(const char *str, ...) PSYNC_MALLOC PSYNC_SENTINEL;


#endif
