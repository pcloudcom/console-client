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

#ifndef _PSYNC_FS_H
#define _PSYNC_FS_H

#include "psynclib.h"
#include "ptree.h"
#include "pintervaltree.h"
#include "papi.h"
#include "psettings.h"
#include "pfsfolder.h"
#include "pfstasks.h"
#include "pcompat.h"
#include "pcrypto.h"
#include "pcrc32c.h"
#include "ptimer.h"
#include "plibs.h"
#include <pthread.h>


#if defined(P_OS_POSIX)
#define psync_fs_need_per_folder_refresh() psync_fs_need_per_folder_refresh_f()
#define psync_fs_need_per_folder_refresh_const() 1
#else
#define psync_fs_need_per_folder_refresh() (psync_invalidate_os_cache_needed() && psync_fs_need_per_folder_refresh_f())
#define psync_fs_need_per_folder_refresh_const() 1
#endif

extern char *psync_fake_prefix;
extern size_t psync_fake_prefix_len;

typedef struct {
  uint64_t frompage;
  uint64_t topage;
  uint64_t length;
  uint64_t requestedto;
  uint64_t id;
  time_t lastuse;
} psync_file_stream_t;

typedef struct {
  pthread_cond_t cond;
  uint64_t extendto;
  uint64_t extendedto;
  uint32_t waiters;
  int error;
  unsigned char ready;
  unsigned char kill;
} psync_enc_file_extender_t;

typedef struct {
  psync_tree tree;
  psync_file_stream_t streams[PSYNC_FS_FILESTREAMS_CNT];
  pthread_mutex_t mutex;
  psync_interval_tree_t *writeintervals;
  psync_fstask_folder_t *currentfolder;
  char *currentname;
  psync_fsfileid_t fileid;
  psync_fsfileid_t remotefileid;
  union {
    uint64_t hash;
    const char *staticdata;
  };
  uint64_t initialsize;
  uint64_t currentsize;
  uint64_t laststreamid;
  uint64_t indexoff;
  union {
    uint64_t writeid;
    time_t staticctime;
  };
  psync_timer_t writetimer;
  time_t currentsec;
  time_t origctime;
  psync_file_t datafile;
  psync_file_t indexfile;
  uint32_t refcnt;
  uint32_t runningreads;
  uint32_t currentspeed;
  uint32_t bytesthissec;
  unsigned char modified;
  unsigned char newfile;
  unsigned char releasedforupload;
  unsigned char deleted;
  unsigned char encrypted;
  unsigned char throttle;
  unsigned char staticfile;
#if IS_DEBUG
  const char *lockfile;
  const char *lockthread;
  unsigned long lockline;
#endif
  /*
   * for non-encrypted files only offsetof(psync_openfile_t, encoder) bytes are allocated
   * keep all fields for encryption after encoder
   */
  psync_crypto_aes256_sector_encoder_decoder_t encoder;
  psync_tree *sectorsinlog;
  psync_interval_tree_t *authenticatedints;
  psync_fast_hash256_ctx loghashctx;
  psync_enc_file_extender_t *extender;
  psync_file_t logfile;
  uint32_t logoffset;
} psync_openfile_t;

typedef struct {
  uint64_t offset;
  uint64_t length;
} psync_fs_index_record;

typedef struct {
  int dummy[0];
} psync_fs_index_header;

#if IS_DEBUG && (defined(P_OS_LINUX) || defined(P_OS_WINDOWS))
#define psync_fs_lock_file(of) psync_fs_do_lock_file(of, __FILE__, __LINE__)

static inline void psync_fs_do_lock_file(psync_openfile_t *of, const char *file, unsigned long line){
  if (unlikely(pthread_mutex_trylock(&of->mutex))){
    struct timespec tm;
    psync_nanotime(&tm);
    tm.tv_sec+=60;
    if (pthread_mutex_timedlock(&of->mutex, &tm)) {
      debug(D_BUG, "could not lock mutex of file %s taken in %s:%lu by thread %s, aborting", of->currentname, of->lockfile, of->lockline, of->lockthread);
      abort();
    }
  }
  of->lockfile=file;
  of->lockthread=psync_thread_name;
  of->lockline=line;
}
#else
static inline void psync_fs_lock_file(psync_openfile_t *of){
  pthread_mutex_lock(&of->mutex);
}
#endif

int psync_fs_crypto_err_to_errno(int cryptoerr);
int psync_fs_update_openfile(uint64_t taskid, uint64_t writeid, psync_fileid_t newfileid, uint64_t hash, uint64_t size, time_t ctime);
//void psync_fs_uploading_openfile(uint64_t taskid);
int psync_fs_rename_openfile_locked(psync_fsfileid_t fileid, psync_fsfolderid_t folderid, const char *name);
void psync_fs_mark_openfile_deleted(uint64_t taskid);
int64_t psync_fs_get_file_writeid(uint64_t taskid);
int64_t psync_fs_load_interval_tree(psync_file_t fd, uint64_t size, psync_interval_tree_t **tree);
int psync_fs_remount();
void psync_fs_inc_of_refcnt_locked(psync_openfile_t *of);
void psync_fs_inc_of_refcnt(psync_openfile_t *of);
void psync_fs_dec_of_refcnt(psync_openfile_t *of);
void psync_fs_inc_of_refcnt_and_readers(psync_openfile_t *of);
void psync_fs_dec_of_refcnt_and_readers(psync_openfile_t *of);

void psync_fs_refresh();
int psync_fs_need_per_folder_refresh_f();
void psync_fs_refresh_folder(psync_folderid_t folderid);

void psync_fs_pause_until_login();
void psync_fs_clean_tasks();

#endif
