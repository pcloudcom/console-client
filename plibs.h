#ifndef _PSYNC_LIBS_H
#define _PSYNC_LIBS_H

#include "pcompat.h"
#include "psynclib.h"

#define D_NONE     0
#define D_BUG      10
#define D_CRITICAL 20
#define D_ERROR    30
#define D_WARNING  40
#define D_NOTICE   50

#define DEBUG_LEVELS {\
 {D_BUG, "BUG"},\
 {D_CRITICAL, "CRITICAL ERROR"},\
 {D_ERROR, "ERROR"},\
 {D_WARNING, "WARNING"},\
 {D_NOTICE, "NOTICE"}\
}

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL D_ERROR
#endif

#define DEBUG_FILE "/tmp/psync_err.log"

#define debug(level, ...) do {if (level<=DEBUG_LEVEL) psync_debug(__FILE__, __FUNCTION__, __LINE__, level, __VA_ARGS__);} while (0)
#define assert(cond, ...) do {if (!(cond)) debug(D_ERROR, __VA_ARGS__);} while (0)

extern int psync_do_run;
extern pstatus_t psync_status;

char *psync_strdup(const char *str) PSYNC_MALLOC;
char *psync_strcat(const char *str, ...) PSYNC_MALLOC PSYNC_SENTINEL;

int psync_sql_connect(const char *db);
int psync_sql_statement(const char *sql);
char *psync_sql_cellstr(const char *sql);
int64_t psync_sql_cellint(const char *sql, int64_t dflt);

void psync_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...)
#if defined(__GNUC__)
  __attribute__ ((cold))
  __attribute__ ((format (printf, 5, 6)))
#endif
;

#endif
