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

#ifndef _PSYNC_DATABASE_H
#define _PSYNC_DATABASE_H

#include "pcompat.h"
#include <sqlite3.h>

#if defined(SQLITE_VERSION_NUMBER) && SQLITE_VERSION_NUMBER>=3008002
#define P_SQL_WOWROWID "WITHOUT ROWID"
#else
#define P_SQL_WOWROWID
#endif

#if PSYNC_FILENAMES_CASESENSITIVE
#define PSYNC_TEXT_COL "COLLATE BINARY"
#else
#define PSYNC_TEXT_COL "COLLATE NOCASE"
#endif

#define PSYNC_DATABASE_STRUCTURE \
"BEGIN;\
PRAGMA page_size=4096;\
CREATE TABLE IF NOT EXISTS setting (id VARCHAR(16) PRIMARY KEY, value TEXT) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS folder (id INTEGER PRIMARY KEY, parentfolderid INTEGER, userid INTEGER, permissions INTEGER, \
  name VARCHAR(1024), ctime INTEGER, mtime INTEGER);\
CREATE INDEX IF NOT EXISTS kfolderfolderid ON folder(parentfolderid);\
CREATE TABLE IF NOT EXISTS file (id INTEGER PRIMARY KEY, parentfolderid INTEGER, userid INTEGER, size INTEGER, hash INTEGER,\
  name VARCHAR(1024), ctime INTEGER, mtime INTEGER);\
CREATE INDEX IF NOT EXISTS kfilefolderid ON file(parentfolderid);\
CREATE TABLE IF NOT EXISTS syncfolder (id INTEGER PRIMARY KEY, folderid INTEGER REFERENCES folder(id) ON DELETE SET NULL,\
  localpath VARCHAR(4096), synctype INTEGER, flags INTEGER);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderfolderid ON syncfolder(folderid);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderlocalpath ON syncfolder(localpath);\
CREATE TABLE IF NOT EXISTS localfolder (id INTEGER PRIMARY KEY, localparentfolderid INTEGER REFERENCES localfolder(id) ON DELETE CASCADE, folderid INTEGER, \
  syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, inode INTEGER, mtime INTEGER, mtimenative INTEGER, flags INTEGER, taskcnt INTEGER, name VARCHAR(1024) "PSYNC_TEXT_COL");\
CREATE INDEX IF NOT EXISTS klocalfolderlpfid ON localfolder(localparentfolderid);\
CREATE UNIQUE INDEX IF NOT EXISTS klocalfolderpsn ON localfolder(syncid, localparentfolderid, name);\
CREATE INDEX IF NOT EXISTS klocalfolderfolderid ON localfolder(folderid);\
CREATE INDEX IF NOT EXISTS klocalfoldersyncid ON localfolder(syncid);\
CREATE TABLE IF NOT EXISTS localfile (id INTEGER PRIMARY KEY, localparentfolderid INTEGER REFERENCES localfolder(id) ON DELETE CASCADE, fileid INTEGER, \
  syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, size INTEGER, inode INTEGER, mtime INTEGER, mtimenative INTEGER, name VARCHAR(1024) "PSYNC_TEXT_COL", checksum TEXT);\
CREATE INDEX IF NOT EXISTS klocalfilelpfid ON localfile(localparentfolderid);\
CREATE INDEX IF NOT EXISTS klocalfilefileid ON localfile(fileid);\
CREATE UNIQUE INDEX IF NOT EXISTS klocalfilerpsn ON localfile(syncid, localparentfolderid, name);\
CREATE TABLE IF NOT EXISTS syncedfolder (syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, folderid INTEGER, localfolderid INTEGER, synctype INTEGER);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderdownsyncidfolderid ON syncedfolder(folderid, syncid);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderdownsyncidlocalfolderid ON syncedfolder(localfolderid, syncid);\
CREATE INDEX IF NOT EXISTS ksyncedfoldersyncid ON syncedfolder(syncid);\
CREATE TABLE IF NOT EXISTS task (id INTEGER PRIMARY KEY, type INTEGER, syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, \
  itemid INTEGER, localitemid INTEGER, newitemid INTEGER, name VARCHAR(4096));\
CREATE TABLE IF NOT EXISTS hashchecksum (hash INTEGER, size INTEGER, checksum TEXT, PRIMARY KEY (hash, size)) " P_SQL_WOWROWID ";\
INSERT OR IGNORE INTO localfolder (id) VALUES (0);\
INSERT OR IGNORE INTO setting (id, value) VALUES ('dbversion', 1);\
COMMIT;\
"

#endif
