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

#include "psynclib.h"

int psync_fs_remount(){
  return 0;
}

int psync_fs_isstarted(){
  return 0;
}

int psync_fs_start(){
  return -1;
}

void psync_fs_stop(){
}

char *psync_fs_getmountpoint(){
  return NULL;
}

char *psync_fs_get_path_by_folderid(psync_folderid_t folderid){
  return NULL;
}

void psync_fs_refresh(){
}

void psync_fs_file_deleted(psync_fileid_t fileid){
}

void psync_fs_folder_deleted(psync_folderid_t folderid){
}

void psync_fs_task_deleted(uint64_t taskid){
}

int psync_fs_need_per_folder_refresh_f(){
  return 0;
}

void psync_fs_refresh_folder(psync_folderid_t folderid){
}

void psync_pagecache_resize_cache(){
}

int psync_cloud_crypto_setup(const char *password){
  return PSYNC_CRYPTO_SETUP_NOT_SUPPORTED;
}

void psync_pagecache_clean_cache(){
}

void psync_fs_pause_until_login(){
}

void psync_fs_clean_tasks(){
}
