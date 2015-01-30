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

#ifndef _PSYNC_FOLDER_H
#define _PSYNC_FOLDER_H

#include "pcompiler.h"
#include "psynclib.h"

#define PSYNC_INVALID_FOLDERID ((psync_folderid_t)-1)
#define PSYNC_INVALID_PATH NULL

#define PSYNC_FOLDER_FLAG_ENCRYPTED 1
#define PSYNC_FOLDER_FLAG_INVISIBLE 2

psync_folderid_t psync_get_folderid_by_path(const char *path) PSYNC_NONNULL(1) PSYNC_PURE;
psync_folderid_t psync_get_folderid_by_path_or_create(const char *path) PSYNC_NONNULL(1);
char *psync_get_path_by_folderid(psync_folderid_t folderid, size_t *retlen);
char *psync_get_path_by_folderid_sep(psync_folderid_t folderid, const char *sep, size_t *retlen);
char *psync_get_path_by_fileid(psync_fileid_t fileid, size_t *retlen);
char *psync_local_path_for_local_folder(psync_folderid_t localfolderid, psync_syncid_t syncid, size_t *retlen);
char *psync_local_path_for_local_file(psync_fileid_t localfileid, size_t *retlen);
//char *psync_local_path_for_remote_folder(psync_folderid_t folderid, psync_syncid_t syncid, size_t *retlen);
//char *psync_local_path_for_remote_file(psync_fileid_t fileid, psync_syncid_t syncid, size_t *retlen);
//char *psync_local_path_for_remote_file_or_folder_by_name(psync_folderid_t parentfolderid, const char *filename, psync_syncid_t syncid, size_t *retlen);
pfolder_list_t *psync_list_remote_folder(psync_folderid_t folderid, psync_listtype_t listtype);
pfolder_list_t *psync_list_local_folder(const char *path, psync_listtype_t listtype) PSYNC_NONNULL(1);
pentry_t *psync_folder_stat_path(const char *remotepath);

psync_folder_list_t *psync_list_get_list();

#endif
