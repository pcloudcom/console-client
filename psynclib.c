#include <string.h>
#include <sqlite3.h>
#include "psynclib.h"
#include "pcompat.h"
#include "plibs.h"
#include "pdatabase.h"

psync_malloc_t psync_malloc=malloc;
psync_realloc_t psync_realloc=realloc;
psync_free_t psync_free=free;

const char *psync_database=NULL;

pstatus_t psync_status;

#define return_error(err) do {psync_error=err; return -1;} while (0)

PSYNC_THREAD uint32_t psync_error=0;

sqlite3 *psync_db;

uint32_t psync_get_last_error(){
  return psync_error;
}

void psync_database_path(const char *databasepath){
  psync_database=psync_strdup(databasepath);
}

void psync_set_alloc(psync_malloc_t malloc_call, psync_realloc_t realloc_call, psync_free_t free_call){
  psync_malloc=malloc_call;
  psync_realloc=realloc_call;
  psync_free=free_call;
}

int psync_init(pstatus_change_callback_t status_callback, pevent_callback_t event_callback){
  if (!psync_database){
    psync_database=psync_get_default_database_path();
    if (!psync_database)
      return_error(PERROR_NO_HOMEDIR);
  }
  if (sqlite3_open(psync_database, &psync_db)!=SQLITE_OK || sqlite3_exec(psync_db, PSYNC_DATABASE_STRUCTURE, NULL, NULL, NULL)!=SQLITE_OK)
    return_error(PERROR_DATABASE_OPEN);
  memset(&psync_status, 0, sizeof(psync_status));
  return 0;
}
