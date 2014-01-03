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

#ifndef _PSYNC_DATABASE_H
#define _PSYNC_DATABASE_H

#include <sqlite3.h>

#if defined(SQLITE_VERSION_NUMBER) && SQLITE_VERSION_NUMBER>=3008002
#define P_SQL_WOWROWID "WITHOUT ROWID"
#else
#define P_SQL_WOWROWID
#endif

#define PSYNC_DATABASE_STRUCTURE \
"BEGIN;\
PRAGMA page_size=4096;\
CREATE TABLE IF NOT EXISTS setting (id VARCHAR(16) PRIMARY KEY, value TEXT) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS folder (id INTEGER PRIMARY KEY, parentfolderid INTEGER, userid INTEGER, permissons INTEGER, \
name VARCHAR(1024), ctime INTEGER, mtime INTEGER);\
CREATE INDEX IF NOT EXISTS kfolderfolderid ON folder(parentfolderid);\
CREATE TABLE IF NOT EXISTS file (id INTEGER PRIMARY KEY, parentfolderid INTEGER, userid INTEGER, size INTEGER, hash INTEGER,\
name VARCHAR(1024), ctime INTEGER, mtime INTEGER);\
CREATE INDEX IF NOT EXISTS kfilefolderid ON file(parentfolderid);\
CREATE TABLE IF NOT EXISTS syncfolder (id INTEGER PRIMARY KEY, folderid INTEGER REFERENCES folder(id) ON DELETE CASCADE,\
localpath VARCHAR(4096), synctype INTEGER, flags INTEGER);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderfolderid ON syncfolder(folderid);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderlocalpath ON syncfolder(localpath);\
CREATE TABLE IF NOT EXISTS syncfolderdown (syncid INTEGER, folderid INTEGER);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderdownsyncidfolderid ON syncfolderdown(syncid, folderid);\
CREATE INDEX IF NOT EXISTS ksyncfolderdownfolderid ON syncfolderdown(folderid);\
CREATE TABLE IF NOT EXISTS task (id INTEGER PRIMARY KEY, type INTEGER, syncid INTEGER, itemid INTEGER, localpath VARCHAR(4096));\
CREATE TABLE IF NOT EXISTS hashchecksum (hash INTEGER, size INTEGER, checksum TEXT, PRIMARY KEY (hash, size)) " P_SQL_WOWROWID ";\
COMMIT;\
"

#define PSYNC_DATABASE_DELETE \
"DROP INDEX kfolderfolderid;\
DROP INDEX kfilefolderid;\
DROP INDEX ksyncfolderfolderid;\
DROP INDEX ksyncfolderlocalpath;\
DROP INDEX ksyncfolderdownsyncidfolderid;\
DROP INDEX ksyncfolderdownfolderid;\
DROP TABLE setting;\
DROP TABLE folder;\
DROP TABLE file;\
DROP TABLE syncfolder;\
DROP TABLE syncfolderdown;\
DROP TABLE task;\
DROP TABLE hashchecksum;\
VACUUM;\
" PSYNC_DATABASE_STRUCTURE


#endif
