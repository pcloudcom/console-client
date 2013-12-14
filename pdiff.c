#include "pdiff.h"
#include "pcompat.h"
#include "pstatus.h"

void psync_diff_thread(){
  psync_set_status(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  psync_milisleep(2);
  psync_wait_status(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN|PSTATUS_RUN_PAUSE);
}