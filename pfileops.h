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

#ifndef _PSYNC_FILEOPS_H
#define _PSYNC_FILEOPS_H

#include "pcompiler.h"
#include "papi.h"
#include "psettings.h"
#include "psynclib.h"

#define PSYNC_INVALID_FOLDERID ((psync_folderid_t)-1)
#define PSYNC_INVALID_PATH NULL

static inline uint64_t psync_get_permissions(const binresult *meta){
  const binresult *canmanage=psync_check_result(meta, "canmanage", PARAM_BOOL);
  return
    (psync_find_result(meta, "canread", PARAM_BOOL)->num?PSYNC_PERM_READ:0)+
    (psync_find_result(meta, "canmodify", PARAM_BOOL)->num?PSYNC_PERM_MODIFY:0)+
    (psync_find_result(meta, "candelete", PARAM_BOOL)->num?PSYNC_PERM_DELETE:0)+
    (psync_find_result(meta, "cancreate", PARAM_BOOL)->num?PSYNC_PERM_CREATE:0)+
    (canmanage && canmanage->num?PSYNC_PERM_MANAGE:0);
}

void psync_ops_create_folder_in_db(const binresult *meta);
void psync_ops_update_folder_in_db(const binresult *meta);
void psync_ops_delete_folder_from_db(const binresult *meta);
void psync_ops_create_file_in_db(const binresult *meta);
void psync_ops_update_file_in_db(const binresult *meta);
void psync_ops_delete_file_from_db(const binresult *meta);

#endif
