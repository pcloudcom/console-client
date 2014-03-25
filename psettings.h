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

#define PSYNC_API_HOST     "binapi.pcloud.com"
#define PSYNC_API_PORT     80
#define PSYNC_API_PORT_SSL 443

#define PSYNC_API_AHOST     "api.pcloud.com"
#define PSYNC_API_APORT     8398
#define PSYNC_API_APORT_SSL 8399

#define PSYNC_P2P_PORT 42420

#define PSYNC_P2P_HEXHASH_BYTES 3

#define PSYNC_P2P_RSA_SIZE 4096

#define PSYNC_DIFF_LIMIT   25000

#define PSYNC_SOCK_CONNECT_TIMEOUT 20
#define PSYNC_SOCK_READ_TIMEOUT    60
#define PSYNC_SOCK_WRITE_TIMEOUT   120

#define PSYNC_SOCK_TIMEOUT_ON_EXCEPTION 6

#define PSYNC_STACK_SIZE 64*1024

#define PSYNC_MAX_PARALLEL_DOWNLOADS 32
#define PSYNC_MAX_PARALLEL_UPLOADS 32
#define PSYNC_START_NEW_DOWNLOADS_TRESHOLD (512*1024)
#define PSYNC_START_NEW_UPLOADS_TRESHOLD (256*1024)
#define PSYNC_MIN_SIZE_FOR_CHECKSUMS (64*1024)

#define PSYNC_COPY_BUFFER_SIZE 64*1024
#define PSYNC_RECV_BUFFER_SHAPED 128*1024
#define PSYNC_MAX_SPEED_RECV_BUFFER 1024*1024

#define PSYNC_SPEED_CALC_AVERAGE_SEC 10

#define PSYNC_DIR_HASH_SIZE 1024

#define PSYNC_SCANNER_PERCENT     80
#define PSYNC_SCANNER_MIN_FILES   25
#define PSYNC_SCANNER_MIN_DISPLAY 10
#define PSYNC_SCANNER_MAX_SUGGESTIONS 6

/* in seconds */
#define PSYNC_LOCALSCAN_SLEEPSEC_PER_SCAN       10
#define PSYNC_LOCALSCAN_RESCAN_INTERVAL         10
#define PSYNC_LOCALSCAN_RESCAN_NOTIFY_SUPPORTED 3600

#define PSYNC_APIPOOL_MAXIDLE    4
#define PSYNC_APIPOOL_MAXACTIVE  32
#define PSYNC_APIPOOL_MAXIDLESEC 120

#define PSYNC_DEFAULT_POSIX_DBNAME ".pclouddb"
#define PSYNC_DEFAULT_WINDOWS_DBNAME "pcloud.db"

#define PSYNC_DEFAULT_POSIX_FOLDER_MODE 0755
#define PSYNC_DEFAULT_POSIX_FILE_MODE 0644

#define PSYNC_APPEND_PARTIAL_FILES ".part"

/* in miliseconds */
#define PSYNC_SLEEP_BEFORE_RECONNECT   5000
#define PSYNC_SLEEP_ON_DISK_FULL       10000
#define PSYNC_SLEEP_ON_FAILED_DOWNLOAD 200
#define PSYNC_SLEEP_ON_FAILED_UPLOAD   200
#define PSYNC_SLEEP_AUTO_SHAPER        100
#define PSYNC_SLEEP_ON_LOCKED_FILE     10000
#define PSYNC_SLEEP_ON_OS_LOCK         5000

#define PSYNC_P2P_INITIAL_TIMEOUT      400
#define PSYNC_P2P_SLEEP_WAIT_DOWNLOAD  20000

#define PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS 20000
#define PSYNC_CRYPTO_PASS_TO_KEY_SALT       "cak]As1`;CXGTq,+9dh:C'xxTGTDgy*~dF|$,yD>3*uR-hHM?wsY\"Np>j.)Z/[|"

#define PSYNC_PERM_READ   1
#define PSYNC_PERM_CREATE 2
#define PSYNC_PERM_MODIFY 4
#define PSYNC_PERM_DELETE 8

#define PSYNC_PERM_ALL (PSYNC_PERM_READ|PSYNC_PERM_CREATE|PSYNC_PERM_MODIFY|PSYNC_PERM_DELETE)
#define PSYNC_PERM_WRITE (PSYNC_PERM_CREATE|PSYNC_PERM_MODIFY|PSYNC_PERM_DELETE)

#define PSYNC_HTTP_RESP_BUFFER 4000

#define PSYNC_CHECKSUM "sha1"

#define PSYNC_HASH_BLOCK_SIZE    64
#define PSYNC_HASH_DIGEST_LEN    PSYNC_SHA1_DIGEST_LEN
#define PSYNC_HASH_DIGEST_HEXLEN PSYNC_SHA1_DIGEST_HEXLEN
#define psync_hash_ctx           psync_sha1_ctx
#define psync_hash               psync_sha1
#define psync_hash_init          psync_sha1_init
#define psync_hash_update        psync_sha1_update
#define psync_hash_final         psync_sha1_final

#define PSYNC_UPL_AUTO_SHAPER_INITIAL (100*1024)
#define PSYNC_UPL_AUTO_SHAPER_MIN     (10*1024)
#define PSYNC_UPL_AUTO_SHAPER_INC_PER 105
#define PSYNC_UPL_AUTO_SHAPER_DEC_PER 95
#define PSYNC_UPL_AUTO_SHAPER_BUF_PER 400

#define PSYNC_DEFAULT_SEND_BUFF (512*1024)

/* defaults for database settings */
#define PSYNC_USE_SSL_DEFAULT 1
#define PSYNC_DWL_SHAPER_DEFAULT -1
#define PSYNC_UPL_SHAPER_DEFAULT -1
#define PSYNC_MIN_LOCAL_FREE_SPACE (512*1024*1024)
#define PSYNC_P2P_SYNC_DEFAULT 1
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
.pclouddb;\
pcloud.db"

#define _PS(s) PSYNC_SETTING_##s

#define PSYNC_SETTING_usessl            0
#define PSYNC_SETTING_saveauth          1
#define PSYNC_SETTING_maxdownloadspeed  2
#define PSYNC_SETTING_maxuploadspeed    3
#define PSYNC_SETTING_ignorepatterns    4
#define PSYNC_SETTING_minlocalfreespace 5
#define PSYNC_SETTING_p2psync           6

typedef int psync_settingid_t;

#define PSYNC_INVALID_SETTINGID -1

void psync_settings_init();

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
