#ifndef _DEBUG_H
#define _DEBUG_H

#define REGISTRY_KEY_PCLOUD    "SOFTWARE\\PCloud\\pCloud"

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

#define DEBUG_FILE "/tmp/overlay_client.log"

#define debug(level, ...) do {if (level<=DEBUG_LEVEL) pc_debug(__FILE__, __FUNCTION__, __LINE__, level, __VA_ARGS__);} while (0)
#define debug_execute(level, expr) do {if (level<=DEBUG_LEVEL) (expr);} while (0)
#define assert(cond, ...) do {if (!(cond)) debug(D_ERROR, __VA_ARGS__);} while (0)

void pc_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...)
#if defined(__GNUC__)
  __attribute__ ((cold))
  __attribute__ ((format (printf, 5, 6)))
#endif
;

#endif /*_DEBUG_H*/
