/* Copyright (c) 2013 Anton Titov.
 * Copyright (c) 2013 pCloud Ltd.
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

#ifndef _PSYNC_SETTINGS_H
#define _PSYNC_SETTINGS_H

#include <stdint.h>
#include "pcompiler.h"
#include "pcompat.h"

#define PSYNC_LIB_VERSION "1.5.0"

/*
#define PSYNC_API_HOST     "api74.pcloud.com"
#define PSYNC_API_PORT     8398
#define PSYNC_API_PORT_SSL 8399
*/

#define PSYNC_API_HOST     "binapi.pcloud.com"
#define PSYNC_API_PORT     80
#define PSYNC_API_PORT_SSL 443

#define PSYNC_API_AHOST     "api.pcloud.com"
#define PSYNC_API_APORT     8398
#define PSYNC_API_APORT_SSL 8399

// #define PSYNC_API_HOST     "binapi69.pcloud.com"
// #define PSYNC_API_PORT     80
// #define PSYNC_API_PORT_SSL 443
//
// #define PSYNC_API_AHOST     "api69.pcloud.com"
// #define PSYNC_API_APORT     8398
// #define PSYNC_API_APORT_SSL 8399

#define PSYNC_P2P_PORT 42420

#define PSYNC_P2P_HEXHASH_BYTES 3

#define PSYNC_P2P_RSA_SIZE 2048

#define PSYNC_DIFF_LIMIT   500000

#define PSYNC_RETRY_REQUEST 5

#define PSYNC_SOCK_CONNECT_TIMEOUT 20
#define PSYNC_SOCK_READ_TIMEOUT    180
#define PSYNC_SOCK_WRITE_TIMEOUT   120

#define PSYNC_SOCK_TIMEOUT_ON_EXCEPTION 6

#define PSYNC_SOCK_WIN_SNDBUF (4*1024*1024)

#define PSYNC_STACK_SIZE (128*1024)

#define PSYNC_DEBUG_LOG_ALLOC_OVER (8*1024*1024)
#define PSYNC_DEBUG_LOCK_TIMEOUT 45

#define PSYNC_QUERY_CACHE_SEC 600
#define PSYNC_QUERY_MAX_CNT 8

#define PSYNC_DIFF_CHECK_ADAPTER_CHANGE_SEC 5

#define PSYNC_MAX_PARALLEL_DOWNLOADS 1024
#define PSYNC_MAX_PARALLEL_UPLOADS 32
#define PSYNC_FSUPLOAD_NUM_TASKS_PER_RUN 128
#define PSYNC_START_NEW_DOWNLOADS_TRESHOLD (4*1024*1024)
#define PSYNC_START_NEW_UPLOADS_TRESHOLD (512*1024)
#define PSYNC_MIN_SIZE_FOR_CHECKSUMS (64*1024)
#define PSYNC_MIN_SIZE_FOR_EXISTS_CHECK (8*1024)
#define PSYNC_MIN_SIZE_FOR_P2P (32*1024)
#define PSYNC_MAX_SIZE_FOR_ASYNC_DOWNLOAD (256*1024)
#define PSYNC_MAX_CHECKSUMS_SIZE (64*1024*1024)
#define PSYNC_MAX_COPY_FROM_REQ  (32*1024*1024)
#define PSYNC_MAX_PENDING_UPLOAD_REQS 16

#define PSYNC_COPY_BUFFER_SIZE (256*1024)
#define PSYNC_RECV_BUFFER_SHAPED (128*1024)
#define PSYNC_MAX_SPEED_RECV_BUFFER (1024*1024)

#define PSYNC_FIRST_SOCK_WRITE_BUFF_SIZE (2700) // safe bet for two packets minus ssl overhead
#define PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE (64*1024) // better not be small

#define PSYNC_UPLOAD_OLDER_THAN_SEC 5

#define PSYNC_SPEED_CALC_AVERAGE_SEC 8

#define PSYNC_SCANNER_PERCENT     80
#define PSYNC_SCANNER_MIN_FILES   25
#define PSYNC_SCANNER_MIN_DISPLAY 10
#define PSYNC_SCANNER_MAX_SUGGESTIONS 6

/* in seconds */
#define PSYNC_LOCALSCAN_SLEEPSEC_PER_SCAN       10
#define PSYNC_LOCALSCAN_RESCAN_INTERVAL         10
#define PSYNC_LOCALSCAN_RESCAN_NOTIFY_SUPPORTED 3600
#define PSYNC_LOCALSCAN_MIN_INTERVAL            60
#define PSYNC_MIN_INTERVAL_RECALC_DOWNLOAD      2
#define PSYNC_MIN_INTERVAL_RECALC_UPLOAD        5
#define PSYNC_UPLOAD_NOWRITE_TIMER              30

#define PSYNC_APIPOOL_MAXIDLE    24
#define PSYNC_APIPOOL_MAXACTIVE  36
#define PSYNC_APIPOOL_MAXIDLESEC 600

#define PSYNC_MAX_IDLE_HTTP_CONNS 16
#define PSYNC_MAX_SSL_SESSIONS_PER_DOMAIN 16

#define PSYNC_SSL_SESSION_CACHE_TIMEOUT (24*3600)

#define PSYNC_DEFAULT_POSIX_DBNAME ".pclouddb"
#define PSYNC_DEFAULT_WINDOWS_DBNAME "pcloud.db"

#define PSYNC_DEFAULT_DB_NAME "data.db"
#define PSYNC_DEFAULT_POSIX_DIR ".pcloud"
#define PSYNC_DEFAULT_WINDOWS_DIR "pCloud"

#define PSYNC_DEFAULT_TMP_DIR "temp"
#define PSYNC_DEFAULT_NTF_THUMB_DIR "ntfthumbs"

#define PSYNC_DB_CHECKPOINT_AT_PAGES 2000

#define PSYNC_DEFAULT_CACHE_FOLDER "Cache"
#define PSYNC_DEFAULT_READ_CACHE_FILE "cached"

#define PSYNC_DEFAULT_FS_FOLDER "pCloudDrive"

#define PSYNC_DEFAULT_POSIX_FOLDER_MODE 0755
#define PSYNC_DEFAULT_POSIX_FILE_MODE 0644

#define PSYNC_APPEND_PARTIAL_FILES ".part"

#define PSYNC_REPLACE_INV_CH_IN_FILENAMES '_'

/* in milliseconds */
#define PSYNC_SLEEP_BEFORE_RECONNECT   5000
#define PSYNC_SLEEP_ON_DISK_FULL       10000
#define PSYNC_SLEEP_ON_FAILED_DOWNLOAD 2000
#define PSYNC_SLEEP_ON_FAILED_UPLOAD   2000
#define PSYNC_SLEEP_AUTO_SHAPER        100
#define PSYNC_SLEEP_ON_LOCKED_FILE     2000
#define PSYNC_SLEEP_ON_OS_LOCK         5000
#define PSYNC_SLEEP_FILE_CHANGE        2000

#define PSYNC_P2P_INITIAL_TIMEOUT      600
#define PSYNC_P2P_SLEEP_WAIT_DOWNLOAD  20000

#define PSYNC_ASYNC_THREAD_TIMEOUT     (15*60*1000)
#define PSYNC_ASYNC_GROUP_REQUESTS_FOR 60

#define PSYNC_ASYNC_MAX_GROUPED_REQUESTS 128

#define PSYNC_CRYPTO_DEFAULT_STOP_ON_SLEEP 0

#define PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS 20000
#define PSYNC_CRYPTO_PBKDF2_SALT_LEN     64
#define PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN 128
#define PSYNC_CRYPTO_RSA_SIZE          4096

#define PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT 0
#define PSYNC_CRYPTO_PUB_TYPE_RSA4096                0
#define PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC         0

#define PSYNC_CRYPTO_CACHE_DIR_SYM_KEY      600
#define PSYNC_CRYPTO_CACHE_DIR_ECODER_SEC   15
#define PSYNC_CRYPTO_CACHE_FILE_SYM_KEY     300
#define PSYNC_CRYPTO_CACHE_FILE_ECODER_SEC  15

#define PSYNC_CRYPTO_MAX_LOG_SIZE          (64*1024*1024)
#define PSYNC_CRYPTO_RUN_EXTEND_IN_THREAD_OVER (1024*1024)
#define PSYNC_CRYPTO_EXTENDER_STEP         (512*1024)

#define PSYNC_HTTP_RESP_BUFFER 4000

#define PSYNC_CHECKSUM "sha1"

#define PSYNC_HASH_BLOCK_SIZE    PSYNC_SHA1_BLOCK_LEN
#define PSYNC_HASH_DIGEST_LEN    PSYNC_SHA1_DIGEST_LEN
#define PSYNC_HASH_DIGEST_HEXLEN PSYNC_SHA1_DIGEST_HEXLEN
#define psync_hash_ctx           psync_sha1_ctx
#define psync_hash               psync_sha1
#define psync_hash_init          psync_sha1_init
#define psync_hash_update        psync_sha1_update
#define psync_hash_final         psync_sha1_final

#define PSYNC_LHASH_BLOCK_SIZE    PSYNC_SHA512_BLOCK_LEN
#define PSYNC_LHASH_DIGEST_LEN    PSYNC_SHA512_DIGEST_LEN
#define PSYNC_LHASH_DIGEST_HEXLEN PSYNC_SHA512_DIGEST_HEXLEN
#define psync_lhash_ctx           psync_sha512_ctx
#define psync_lhash               psync_sha512
#define psync_lhash_init          psync_sha512_init
#define psync_lhash_update        psync_sha512_update
#define psync_lhash_final         psync_sha512_final


#define PSYNC_UPL_AUTO_SHAPER_INITIAL (100*1024)
#define PSYNC_UPL_AUTO_SHAPER_MIN     (10*1024)
#define PSYNC_UPL_AUTO_SHAPER_INC_PER 105
#define PSYNC_UPL_AUTO_SHAPER_DEC_PER 95
#define PSYNC_UPL_AUTO_SHAPER_BUF_PER 400

#define PSYNC_DEFAULT_SEND_BUFF (4*1024*1024)

#define PSYNC_FS_PAGE_SIZE 4096
#define PSYNC_FS_MEMORY_CACHE (64*1024*1024)
#define PSYNC_FS_DISK_FLUSH_SEC 20
#define PSYNC_FS_FILESTREAMS_CNT 12
#define PSYNC_FS_MIN_READAHEAD_START (128*1024)
#define PSYNC_FS_MIN_READAHEAD_RAND (16*1024)
#define PSYNC_FS_MAX_READAHEAD (16*1024*1024)
#define PSYNC_FS_MAX_READAHEAD_IF_SEC (64*1024*1024)
#define PSYNC_FS_MAX_READAHEAD_SEC 16
#define PSYNC_FS_DEFAULT_CACHE_SIZE ((uint64_t)5*1024*1024*1024)
#define PSYNC_FS_DIRECT_UPLOAD_LIMIT (256*1024)
#define PSYNC_FS_FILESIZE_FOR_2CONN (4*1024*1024)
#define PSYNC_FS_FILE_LOC_HIST_SEC 30
#define PSYNC_FS_MAX_SIZE_CONVERT_NEWFILE (32*PSYNC_FS_PAGE_SIZE)
#define PSYNC_FS_MIN_INITIAL_WRITE_SHAPER (200*1024)
#define PSYNC_FS_MAX_SHAPER_SLEEP_SEC 8

/* defaults for database settings */
#define PSYNC_USE_SSL_DEFAULT 1
#define PSYNC_DWL_SHAPER_DEFAULT -1
#define PSYNC_UPL_SHAPER_DEFAULT -1
#define PSYNC_MIN_LOCAL_FREE_SPACE ((uint64_t)2048*1024*1024)
#define PSYNC_P2P_SYNC_DEFAULT 1
#define PSYNC_AUTOSTARTFS_DEFAULT 1
#define PSYNC_IGNORE_PATTERNS_DEFAULT ".DS_Store;\
.DS_Store?;\
.AppleDouble;\
._*;\
.Spotlight-V100;\
.DocumentRevisions-V100;\
.TemporaryItems;\
.Trashes;\
.fseventsd;\
.~lock.*;\
ehThumbs.db;\
Thumbs.db;\
hiberfil.sys;\
pagefile.sys;\
$RECYCLE.BIN;\
*.part;\
.pcloud"

#define _PS(s) PSYNC_SETTING_##s

#define PSYNC_SETTING_usessl            0
#define PSYNC_SETTING_saveauth          1
#define PSYNC_SETTING_maxdownloadspeed  2
#define PSYNC_SETTING_maxuploadspeed    3
#define PSYNC_SETTING_ignorepatterns    4
#define PSYNC_SETTING_minlocalfreespace 5
#define PSYNC_SETTING_p2psync           6
#define PSYNC_SETTING_fsroot            7
#define PSYNC_SETTING_autostartfs       8
#define PSYNC_SETTING_fscachesize       9
#define PSYNC_SETTING_fscachepath      10
#define PSYNC_SETTING_sleepstopcrypto  11
#define PSYNC_SETTING_trusted          12

typedef int psync_settingid_t;

#define PSYNC_INVALID_SETTINGID -1

void psync_settings_init();

void psync_settings_reset();

psync_settingid_t psync_setting_getid(const char *name) PSYNC_CONST PSYNC_NONNULL(1);

int psync_setting_get_bool(psync_settingid_t settingid) PSYNC_PURE;
int psync_setting_set_bool(psync_settingid_t settingid, int value);
int64_t psync_setting_get_int(psync_settingid_t settingid) PSYNC_PURE;
int psync_setting_set_int(psync_settingid_t settingid, int64_t value);
uint64_t psync_setting_get_uint(psync_settingid_t settingid) PSYNC_PURE;
int psync_setting_set_uint(psync_settingid_t settingid, uint64_t value);
const char *psync_setting_get_string(psync_settingid_t settingid) PSYNC_PURE;
int psync_setting_set_string(psync_settingid_t settingid, const char *value);

#endif
