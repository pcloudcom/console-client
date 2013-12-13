#ifndef _PSYNC_CALLBACKS_H
#define _PSYNC_CALLBACKS_H

#include "psynclib.h"

void psync_set_status_callback(pstatus_change_callback_t callback);
void psync_send_status_update();
void psync_set_event_callback(pevent_callback_t callback);

#endif