#include "psynclib.h"
#include "pcompat.h"

psync_malloc_t psync_malloc=malloc;
psync_realloc_t psync_realloc=realloc;
psync_free_t psync_free=free;

const char *psync_database=NULL;

void psync_database_path(const char *databasepath){
  psync_database=databasepath;
}

void psync_set_alloc(psync_malloc_t malloc_call, psync_realloc_t realloc_call, psync_free_t free_call){
  psync_malloc=malloc_call;
  psync_realloc=realloc_call;
  psync_free=free_call;
}

int psync_init(pstatus_change_callback_t status_callback, pevent_callback_t event_callback){
  if (!psync_database)
    psync_database=psync_get_default_database_path();
  return 0;
}