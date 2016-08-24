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

#include "ptasks.h"
#include "plibs.h"
#include "pdownload.h"
#include "pupload.h"
#include "pstatus.h"
#include "pcallbacks.h"
#include "ppathstatus.h"

static void create_task1(psync_uint_t type, psync_syncid_t syncid, uint64_t entryid, uint64_t localentryid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, localitemid) VALUES (?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, type);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, entryid);
  psync_sql_bind_uint(res, 4, localentryid);
  psync_sql_run_free(res);
}

static void create_task2(psync_uint_t type, psync_syncid_t syncid, uint64_t entryid, uint64_t localentryid, uint64_t newitemid, const char *name){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, localitemid, newitemid, name) VALUES (?, ?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, type);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, entryid);
  psync_sql_bind_uint(res, 4, localentryid);
  psync_sql_bind_uint(res, 5, newitemid);
  psync_sql_bind_string(res, 6, name);
  psync_sql_run_free(res);
}

static void create_task3(psync_uint_t type, psync_syncid_t syncid, uint64_t entryid, uint64_t localentryid, const char *name){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, localitemid, name) VALUES (?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, type);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, entryid);
  psync_sql_bind_uint(res, 4, localentryid);
  psync_sql_bind_string(res, 5, name);
  psync_sql_run_free(res);
}

static void create_task4(psync_uint_t type, uint64_t entryid, const char *name){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, itemid, localitemid, name) VALUES (?, ?, 0, ?)");
  psync_sql_bind_uint(res, 1, type);
  psync_sql_bind_uint(res, 2, entryid);
  psync_sql_bind_string(res, 3, name);
  psync_sql_run_free(res);
}

static void create_task5(psync_uint_t type, psync_syncid_t syncid, uint64_t entryid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, localitemid) VALUES (?, ?, ?, 0)");
  psync_sql_bind_uint(res, 1, type);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, entryid);
  psync_sql_run_free(res);
}

static void create_task6(psync_uint_t type, psync_syncid_t syncid, uint64_t entryid, const char *name){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, localitemid, name) VALUES (?, ?, ?, 0, ?)");
  psync_sql_bind_uint(res, 1, type);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, entryid);
  psync_sql_bind_string(res, 4, name);
  psync_sql_run_free(res);
}

void psync_task_create_local_folder(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid){
  create_task1(PSYNC_CREATE_LOCAL_FOLDER, syncid, folderid, localfolderid);
}

void psync_task_delete_local_folder(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid, const char *remotepath){
  create_task3(PSYNC_DELETE_LOCAL_FOLDER, syncid, folderid, localfolderid, remotepath);
}

void psync_task_delete_local_folder_recursive(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid){
  create_task1(PSYNC_DELREC_LOCAL_FOLDER, syncid, folderid, localfolderid);
}

void psync_task_rename_local_folder(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid,
                                    psync_folderid_t newlocalparentfolderid, const char *newname){
  create_task2(PSYNC_RENAME_LOCAL_FOLDER, syncid, folderid, localfolderid, newlocalparentfolderid, newname);
}

void psync_task_download_file_silent(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, localitemid, name) VALUES (?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, fileid);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_bind_string(res, 5, name);
  psync_path_status_sync_folder_task_added_locked(syncid, localfolderid);
  psync_sql_run_free(res);
}

void psync_task_download_file(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name){
  psync_task_download_file_silent(syncid, fileid, localfolderid, name);
  psync_wake_download();
  psync_status_recalc_to_download();
  psync_send_status_update();
}

void psync_task_rename_local_file(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t fileid, psync_folderid_t oldlocalfolderid,
                                  psync_folderid_t newlocalfolderid, const char *newname){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, newsyncid, itemid, localitemid, newitemid, name) VALUES (?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_RENAME_LOCAL_FILE);
  psync_sql_bind_uint(res, 2, oldsyncid);
  psync_sql_bind_uint(res, 3, newsyncid);
  psync_sql_bind_uint(res, 4, fileid);
  psync_sql_bind_uint(res, 5, oldlocalfolderid);
  psync_sql_bind_uint(res, 6, newlocalfolderid);
  psync_sql_bind_string(res, 7, newname);
  psync_sql_run_free(res);
}

void psync_task_delete_local_file(psync_fileid_t fileid, const char *remotepath){
  create_task4(PSYNC_DELETE_LOCAL_FILE, fileid, remotepath);
}

void psync_task_delete_local_file_syncid(psync_syncid_t syncid, psync_fileid_t fileid, const char *remotepath){
  create_task6(PSYNC_DELETE_LOCAL_FILE, syncid, fileid, remotepath);
}

void psync_task_create_remote_folder(psync_syncid_t syncid, psync_folderid_t localfolderid, const char *name){
  create_task3(PSYNC_CREATE_REMOTE_FOLDER, syncid, 0, localfolderid, name);
}

void psync_task_upload_file_silent(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name){
  create_task3(PSYNC_UPLOAD_FILE, syncid, 0, localfileid, name);
}

void psync_task_upload_file(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name){
  create_task3(PSYNC_UPLOAD_FILE, syncid, 0, localfileid, name);
  psync_wake_upload();
  psync_status_recalc_to_upload_async();
}

void psync_task_rename_remote_file(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid,
                                   psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, newsyncid, localitemid, newitemid, name, itemid) VALUES (?, ?, ?, ?, ?, ?, 0)");
  psync_sql_bind_uint(res, 1, PSYNC_RENAME_REMOTE_FILE);
  psync_sql_bind_uint(res, 2, oldsyncid);
  psync_sql_bind_uint(res, 3, newsyncid);
  psync_sql_bind_uint(res, 4, localfileid);
  psync_sql_bind_uint(res, 5, newlocalparentfolderid);
  psync_sql_bind_string(res, 6, newname);
  psync_sql_run_free(res);
}

void psync_task_rename_remote_folder(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid,
                                   psync_folderid_t newlocalparentfolderid, const char *newname){
  psync_sql_res *res;
  res=psync_sql_prep_statement("INSERT INTO task (type, syncid, newsyncid, localitemid, newitemid, name, itemid) VALUES (?, ?, ?, ?, ?, ?, 0)");
  psync_sql_bind_uint(res, 1, PSYNC_RENAME_REMOTE_FOLDER);
  psync_sql_bind_uint(res, 2, oldsyncid);
  psync_sql_bind_uint(res, 3, newsyncid);
  psync_sql_bind_uint(res, 4, localfileid);
  psync_sql_bind_uint(res, 5, newlocalparentfolderid);
  psync_sql_bind_string(res, 6, newname);
  psync_sql_run_free(res);
}

void psync_task_delete_remote_file(psync_syncid_t syncid, psync_fileid_t fileid){
  create_task5(PSYNC_DELETE_REMOTE_FILE, syncid, fileid);
}

void psync_task_delete_remote_folder(psync_syncid_t syncid, psync_folderid_t folderid){
  create_task5(PSYNC_DELREC_REMOTE_FOLDER, syncid, folderid);
}
