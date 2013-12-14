#include <string.h>
#include "psynclib.h"
#include "pcompat.h"
#include "plibs.h"
#include "pcallbacks.h"
#include "pdatabase.h"
#include "pstatus.h"
#include "pdiff.h"

psync_malloc_t psync_malloc=malloc;
psync_realloc_t psync_realloc=realloc;
psync_free_t psync_free=free;

const char *psync_database=NULL;

PSYNC_THREAD uint32_t psync_error=0;

#define return_error(err) do {psync_error=err; return -1;} while (0)

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
  if (psync_sql_connect(psync_database) || psync_sql_statement(PSYNC_DATABASE_STRUCTURE))
    return_error(PERROR_DATABASE_OPEN);
  psync_status_init();
  psync_run_thread(psync_diff_thread);
  if (status_callback)
    psync_set_status_callback(status_callback);
  if (event_callback)
    psync_set_event_callback(event_callback);
  return 0;
}

void psync_destroy(){
  psync_do_run=0;
  psync_send_status_update();
  psync_milisleep(20);
  psync_sql_lock();
  psync_sql_close();
}
