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

#ifndef _PSYNC_PAGECACHE_H
#define _PSYNC_PAGECACHE_H

#include "pfs.h"

typedef struct {
  uint64_t offset;
  uint64_t size;
  char *buf;
} psync_pagecache_read_range;

void psync_pagecache_init();
int psync_pagecache_flush();
int psync_pagecache_read_modified_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset);
int psync_pagecache_read_unmodified_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset);
int psync_pagecache_read_unmodified_encrypted_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset);
int psync_pagecache_readv_locked(psync_openfile_t *of, psync_pagecache_read_range *ranges, int cnt);
void psync_pagecache_creat_to_pagecache(uint64_t taskid, uint64_t hash, int onthisthread);
void psync_pagecache_modify_to_pagecache(uint64_t taskid, uint64_t hash, uint64_t oldhash);
int psync_pagecache_have_all_pages_in_cache(uint64_t hash, uint64_t size);
int psync_pagecache_copy_all_pages_from_cache_to_file_locked(psync_openfile_t *of, uint64_t hash, uint64_t size);
int psync_pagecache_lock_pages_in_cache();
void psync_pagecache_unlock_pages_from_cache();
void psync_pagecache_resize_cache();
uint64_t psync_pagecache_free_from_read_cache(uint64_t size);
void psync_pagecache_clean_cache();
void psync_pagecache_reopen_read_cache();
void psync_pagecache_clean_read_cache();
int psync_pagecache_move_cache(const char *path);

#endif
