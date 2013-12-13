#include <string.h>
#include "pstatus.h"
#include "plibs.h"

#define RUN_STATUS_RUN   1
#define RUN_STATUS_PAUSE 2
#define RUN_STATUS_STOP  3

static int run_status;

void psync_status_init(){
  memset(&psync_status, 0, sizeof(psync_status));
  run_status=psync_sql_cellint("SELECT value FROM settings WHERE id='runstatus'", 0);
  if (run_status<RUN_STATUS_RUN || run_status>RUN_STATUS_STOP){
    run_status=RUN_STATUS_RUN;
    psync_sql_statement("REPLACE INTO settings (id, value) VALUES ('runstatus', " #RUN_STATUS_RUN ")");
  }
}

int psync_is_stopped(){
  return run_status==RUN_STATUS_STOP;
}

int psync_is_paused(){
  return run_status==RUN_STATUS_STOP || run_status==RUN_STATUS_PAUSE;
}

