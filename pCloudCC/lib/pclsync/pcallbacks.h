/* Copyright (c) 2013-2014 Anton Titov.
 * Copyright (c) 2013-2014 pCloud Ltd.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of pCloud Ltd nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL pCloud Ltd BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _PSYNC_CALLBACKS_H
#define _PSYNC_CALLBACKS_H

#include "psynclib.h"

#if defined(P_OS_LINUX) || defined(P_OS_BSD)
typedef void(/*_cdecl*/ *data_event_callback)(int eventId, char* str1, char* str2, uint64_t uint1, uint64_t uint2);
#else
typedef void(/*_cdecl*/__stdcall *data_event_callback)(int eventId, char* str1, char* str2, uint64_t uint1, uint64_t uint2);
#endif

typedef struct {
  int eventid;
  const char *str1;
  const char* str2;
  uint64_t   uint1;
  uint64_t   uint2;
} event_data_struct;


void psync_callbacks_get_status(pstatus_t *status);
void psync_set_status_callback(pstatus_change_callback_t callback);
void psync_send_status_update();
void psync_set_event_callback(pevent_callback_t callback);
void psync_send_event_by_id(psync_eventtype_t eventid, psync_syncid_t syncid, const char *localpath, psync_fileorfolderid_t remoteid);
void psync_send_event_by_path(psync_eventtype_t eventid, psync_syncid_t syncid, const char *localpath, psync_fileorfolderid_t remoteid, const char *remotepath);
void psync_send_eventid(psync_eventtype_t eventid);
void psync_send_eventdata(psync_eventtype_t eventid, void *eventdata);

#define PEVENT_SYNC_RENAME_F 1

void psync_init_data_event(void* ptr);

void psync_send_data_event(event_data_struct *data);

void psync_data_event_test(int eventid, char* str1, char* str2, uint64_t uint1, uint64_t uint2);
#endif
