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
#include <pwd.h>
#endif

#define DEFAULT_POSIX_DBNAME ".pcloudsyncdb"

char *psync_get_default_database_path(){
#if defined(POSIX)
  struct passwd pwd;
  struct passwd *result;
  struct stat st;
  char buff[4096];
  if (getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result)!=0)
    return NULL;
  if (stat(result->pw_dir, &st) || !S_ISDIR(st.st_mode))
    return NULL;
  return psync_strcat(result->pw_dir, "/", DEFAULT_POSIX_DBNAME, NULL);
#elif defined(WINDOWS)
#error "Need Windows implementation"
#else
#error "Function not implemented for your operating system"
#endif
}