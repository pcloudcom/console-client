/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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

#include "pfileops.h"
#include "plibs.h"
#include "pdiff.h"
#include "pfolder.h"

void psync_ops_create_folder_in_db(const binresult *meta){
  psync_sql_res *res;
  const binresult *name;
  uint64_t userid, perms, flags;
  flags=0;
  if ((name=psync_check_result(meta, "encrypted", PARAM_BOOL)) && name->num)
    flags|=PSYNC_FOLDER_FLAG_ENCRYPTED;
  res=psync_sql_prep_statement("INSERT OR IGNORE INTO folder (id, parentfolderid, userid, permissions, name, ctime, mtime, flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  if (psync_find_result(meta, "ismine", PARAM_BOOL)->num){
    userid=psync_my_userid;
    perms=PSYNC_PERM_ALL;
  }
  else{
    userid=psync_find_result(meta, "userid", PARAM_NUM)->num;
    perms=psync_get_permissions(meta);
  }
  name=psync_find_result(meta, "name", PARAM_STR);
  psync_sql_bind_uint(res, 1, psync_find_result(meta, "folderid", PARAM_NUM)->num);
  psync_sql_bind_uint(res, 2, psync_find_result(meta, "parentfolderid", PARAM_NUM)->num);
  psync_sql_bind_uint(res, 3, userid);
  psync_sql_bind_uint(res, 4, perms);
  psync_sql_bind_lstring(res, 5, name->str, name->length);
  psync_sql_bind_uint(res, 6, psync_find_result(meta, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(res, 7, psync_find_result(meta, "modified", PARAM_NUM)->num);
  psync_sql_bind_uint(res, 8, flags);
  psync_sql_run_free(res);
}

void psync_ops_update_folder_in_db(const binresult *meta){
  psync_diff_update_folder(meta);
}

void psync_ops_delete_folder_from_db(const binresult *meta){
  psync_diff_delete_folder(meta);
}

void psync_ops_create_file_in_db(const binresult *meta){
  psync_diff_create_file(meta);
}

void psync_ops_update_file_in_db(const binresult *meta){
  psync_diff_update_file(meta);
}

void psync_ops_delete_file_from_db(const binresult *meta){
  psync_diff_delete_file(meta);
}
