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

#ifndef _PSYNC_TASKS_H
#define _PSYNC_TASKS_H

#include "pcompiler.h"
#include "psynclib.h"

#define PSYNC_TASK_DOWNLOAD 0
#define PSYNC_TASK_UPLOAD   1
#define PSYNC_TASK_DWLUPL_MASK 1

#define PSYNC_TASK_FOLDER   0
#define PSYNC_TASK_FILE     2

#define PSYNC_TASK_TYPE_OFF 2

#define PSYNC_TASK_TYPE_CREATE 0
#define PSYNC_TASK_TYPE_DELETE 1
#define PSYNC_TASK_TYPE_DELREC 2
#define PSYNC_TASK_TYPE_RENAME 3
#define PSYNC_TASK_TYPE_COPY   4

#define PSYNC_CREATE_LOCAL_FOLDER  ((PSYNC_TASK_TYPE_CREATE<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_DOWNLOAD)
#define PSYNC_DELETE_LOCAL_FOLDER  ((PSYNC_TASK_TYPE_DELETE<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_DOWNLOAD)
#define PSYNC_DELREC_LOCAL_FOLDER  ((PSYNC_TASK_TYPE_DELREC<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_DOWNLOAD)
#define PSYNC_RENAME_LOCAL_FOLDER  ((PSYNC_TASK_TYPE_RENAME<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_DOWNLOAD)
#define PSYNC_COPY_LOCAL_FOLDER    ((PSYNC_TASK_TYPE_COPY  <<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_DOWNLOAD)
#define PSYNC_DOWNLOAD_FILE        ((PSYNC_TASK_TYPE_CREATE<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FILE+PSYNC_TASK_DOWNLOAD)
#define PSYNC_RENAME_LOCAL_FILE    ((PSYNC_TASK_TYPE_RENAME<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FILE+PSYNC_TASK_DOWNLOAD)
#define PSYNC_DELETE_LOCAL_FILE    ((PSYNC_TASK_TYPE_DELETE<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FILE+PSYNC_TASK_DOWNLOAD)

#define PSYNC_CREATE_REMOTE_FOLDER ((PSYNC_TASK_TYPE_CREATE<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_UPLOAD)
#define PSYNC_RENAME_REMOTE_FOLDER ((PSYNC_TASK_TYPE_RENAME<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_UPLOAD)
#define PSYNC_UPLOAD_FILE          ((PSYNC_TASK_TYPE_CREATE<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FILE+PSYNC_TASK_UPLOAD)
#define PSYNC_RENAME_REMOTE_FILE   ((PSYNC_TASK_TYPE_RENAME<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FILE+PSYNC_TASK_UPLOAD)
#define PSYNC_DELETE_REMOTE_FILE   ((PSYNC_TASK_TYPE_DELETE<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FILE+PSYNC_TASK_UPLOAD)
#define PSYNC_DELREC_REMOTE_FOLDER ((PSYNC_TASK_TYPE_DELREC<<PSYNC_TASK_TYPE_OFF)+PSYNC_TASK_FOLDER+PSYNC_TASK_UPLOAD)


void psync_task_create_local_folder(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid);
void psync_task_delete_local_folder(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid, const char *remotepath);
void psync_task_delete_local_folder_recursive(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid);
void psync_task_rename_local_folder(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid,
                                    psync_folderid_t newlocalparentfolderid, const char *newname);
void psync_task_download_file(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name);
void psync_task_download_file_silent(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name);
void psync_task_rename_local_file(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t fileid, psync_folderid_t oldlocalfolderid,
                                  psync_folderid_t newlocalfolderid, const char *newname);
void psync_task_delete_local_file(psync_fileid_t fileid, const char *remotepath);
void psync_task_delete_local_file_syncid(psync_syncid_t syncid, psync_fileid_t fileid, const char *remotepath);


void psync_task_create_remote_folder(psync_syncid_t syncid, psync_folderid_t localfolderid, const char *name);
void psync_task_upload_file(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name);
void psync_task_upload_file_silent(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name);

/* newname should be passed here instead of reading it from localfile in time of renaming as there might be many pending
 * renames and filename conflict is possible
 */
void psync_task_rename_remote_file(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid,
                                   psync_folderid_t newlocalparentfolderid, const char *newname);
void psync_task_rename_remote_folder(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid,
                                   psync_folderid_t newlocalparentfolderid, const char *newname);
void psync_task_delete_remote_file(psync_syncid_t syncid, psync_fileid_t fileid);
void psync_task_delete_remote_folder(psync_syncid_t syncid, psync_folderid_t folderid);

#endif
