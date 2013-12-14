#ifndef _PSYNC_STATUS_H
#define _PSYNC_STATUS_H

#include <stdint.h>

#define PSTATUS_NUM_STATUSES 2

#define PSTATUS_TYPE_RUN    0
#define PSTATUS_TYPE_ONLINE 1

#define PSTATUS_RUN_RUN   1
#define PSTATUS_RUN_PAUSE 2
#define PSTATUS_RUN_STOP  4

#define PSTATUS_ONLINE_CONNECTING 1
#define PSTATUS_ONLINE_SCANNING   2
#define PSTATUS_ONLINE_ONLINE     4
#define PSTATUS_ONLINE_OFFLINE    8

void psync_status_init();
void psync_set_status(uint32_t statusid, uint32_t status);
void psync_wait_status(uint32_t statusid, uint32_t status);


#endif