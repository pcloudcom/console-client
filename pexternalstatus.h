/* Copyright (c) 2013 pCloud Ltd.
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

#ifndef _PSYNC_EXTERNAL_STATUS_H
#define _PSYNC_EXTERNAL_STATUS_H

#include "plist.h"
#include "pfsfolder.h"
#include "psynclib.h"

typedef struct {
  psync_list list;
  char * str;
} string_list_t;

static inline const char* print_external_status(external_status stat)
{
  switch (stat)
  {
    case INSYNC: return "INSYNC";
    case INPROG: return "INPROG";
    case NOSYNC: return "NOSYNC";
    default: return "NOSYNC";
  }
}

external_status do_psync_external_status(char *path);
external_status do_psync_external_status_file(const char *path);
external_status do_psync_external_status_folder(const char *path);

external_status psync_sync_status_folder(const char *path, int syncid);
string_list_t*  sync_get_sync_folders();

external_status psync_external_status_folderid(psync_fsfolderid_t folder_id);
external_status psync_sync_status_file(const char *name, psync_fsfolderid_t folderid, int syncid);
external_status psync_sync_status_folderid(psync_fsfolderid_t folderid, int syncid);

#endif //_PSYNC_EXTERNAL_STATUS_H
