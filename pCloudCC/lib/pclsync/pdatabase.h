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

#define PSYNC_DATABASE_VERSION 18

#define PSYNC_DATABASE_CONFIG \
"\
PRAGMA page_size=4096;\
PRAGMA journal_mode=WAL;\
PRAGMA synchronous=1;\
PRAGMA locking_mode=EXCLUSIVE;\
PRAGMA cache_size=8000;\
PRAGMA foreign_keys=ON;\
"

#define PSYNC_DATABASE_STRUCTURE \
"\
PRAGMA page_size=4096;\
PRAGMA cache_size=8000;\
BEGIN;\
CREATE TABLE IF NOT EXISTS setting (id VARCHAR(16) PRIMARY KEY, value TEXT) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS folder (id INTEGER PRIMARY KEY, parentfolderid INTEGER, userid INTEGER, permissions INTEGER, \
  name VARCHAR(1024) "PSYNC_TEXT_COL", ctime INTEGER, mtime INTEGER, flags INTEGER DEFAULT 0, subdircnt INTEGER DEFAULT 0);\
CREATE INDEX IF NOT EXISTS kfolderfolderid ON folder(parentfolderid);\
CREATE TABLE IF NOT EXISTS file (id INTEGER PRIMARY KEY, parentfolderid INTEGER, userid INTEGER, size INTEGER, hash INTEGER, flags INTEGER DEFAULT 0,\
  name VARCHAR(1024) "PSYNC_TEXT_COL", ctime INTEGER, mtime INTEGER, category INTEGER, thumb INTEGER, icon VARCHAR(32),\
  artist TEXT, album TEXT, title TEXT, genre TEXT, trackno INTEGER, width INTEGER, height INTEGER, duration REAL,\
  fps REAL, videocodec TEXT, audiocodec TEXT, videobitrate INTEGER, audiobitrate INTEGER, audiosamplerate INTEGER, rotate INTEGER);\
CREATE INDEX IF NOT EXISTS kfilefolderid ON file(parentfolderid);\
CREATE INDEX IF NOT EXISTS kfilecategory ON file(category);\
CREATE INDEX IF NOT EXISTS kfileartist ON file(artist, album);\
CREATE TABLE IF NOT EXISTS filerevision (fileid INTEGER REFERENCES file(id) ON DELETE CASCADE, hash INTEGER, ctime INTEGER, size INTEGER,\
  PRIMARY KEY (fileid, hash)) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS syncfolderdelayed (id INTEGER PRIMARY KEY, localpath VARCHAR(4096), remotepath VARCHAR(4096), synctype INTEGER); \
CREATE TABLE IF NOT EXISTS syncfolder (id INTEGER PRIMARY KEY, folderid INTEGER REFERENCES folder(id) ON DELETE SET NULL,\
  localpath VARCHAR(4096), synctype INTEGER, flags INTEGER, inode INTEGER, deviceid INTEGER);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncfolderfolderidlocalpath ON syncfolder(folderid, localpath);\
CREATE TABLE IF NOT EXISTS localfolder (id INTEGER PRIMARY KEY AUTOINCREMENT, localparentfolderid INTEGER REFERENCES localfolder(id) ON DELETE CASCADE, folderid INTEGER, \
  syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, inode INTEGER, deviceid INTEGER, mtime INTEGER, mtimenative INTEGER, flags INTEGER, taskcnt INTEGER, name VARCHAR(1024) "PSYNC_TEXT_COL");\
CREATE INDEX IF NOT EXISTS klocalfolderlpfid ON localfolder(localparentfolderid);\
CREATE UNIQUE INDEX IF NOT EXISTS klocalfolderpsn ON localfolder(syncid, localparentfolderid, name);\
CREATE INDEX IF NOT EXISTS klocalfolderfolderid ON localfolder(folderid);\
CREATE INDEX IF NOT EXISTS klocalfoldersyncid ON localfolder(syncid);\
CREATE TABLE IF NOT EXISTS localfile (id INTEGER PRIMARY KEY AUTOINCREMENT, localparentfolderid INTEGER REFERENCES localfolder(id) ON DELETE CASCADE, fileid INTEGER, hash INTEGER, \
  syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, size INTEGER, inode INTEGER, mtime INTEGER, mtimenative INTEGER, name VARCHAR(1024) "PSYNC_TEXT_COL", checksum TEXT);\
CREATE INDEX IF NOT EXISTS klocalfilelpfid ON localfile(localparentfolderid);\
CREATE INDEX IF NOT EXISTS klocalfilefileid ON localfile(fileid);\
CREATE INDEX IF NOT EXISTS klocalfilechecksum ON localfile(checksum);\
CREATE UNIQUE INDEX IF NOT EXISTS klocalfilerpsn ON localfile(syncid, localparentfolderid, name);\
CREATE TABLE IF NOT EXISTS localfileupload (localfileid INTEGER REFERENCES localfile(id) ON DELETE CASCADE, uploadid INTEGER, PRIMARY KEY (localfileid, uploadid)) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS syncedfolder (syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, folderid INTEGER, localfolderid INTEGER, synctype INTEGER,\
  PRIMARY KEY (syncid, folderid));\
CREATE INDEX IF NOT EXISTS ksyncedfolderdownfolderid ON syncedfolder(folderid);\
CREATE UNIQUE INDEX IF NOT EXISTS ksyncedfolderdownsyncidlocalfolderid ON syncedfolder(localfolderid, syncid);\
CREATE TABLE IF NOT EXISTS task (id INTEGER PRIMARY KEY, type INTEGER, syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, \
  newsyncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, itemid INTEGER, localitemid INTEGER, newitemid INTEGER, \
  inprogress INTEGER NOT NULL DEFAULT 0,\
  name VARCHAR(4096));\
CREATE INDEX IF NOT EXISTS ktaskitemid ON task(itemid);\
CREATE INDEX IF NOT EXISTS ktasklocalitemid ON task(localitemid);\
CREATE TABLE IF NOT EXISTS hashchecksum (hash INTEGER, size INTEGER, checksum TEXT, PRIMARY KEY (hash, size)) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS sharerequest (id INTEGER PRIMARY KEY, isincoming INTEGER, folderid INTEGER, ctime INTEGER, etime INTEGER, permissions INTEGER,\
  userid INTEGER, mail TEXT, name VARCHAR(1024), message TEXT, isba INTEGER);\
CREATE TABLE IF NOT EXISTS sharedfolder (id INTEGER PRIMARY KEY, isincoming INTEGER, folderid INTEGER, ctime INTEGER, permissions INTEGER,\
  userid INTEGER, mail TEXT, name VARCHAR(1024), bsharedfolderid INTEGER);\
CREATE TABLE IF NOT EXISTS pagecache (id INTEGER PRIMARY KEY, hash INTEGER, pageid INTEGER, type INTEGER, flags INTEGER,\
  lastuse INTEGER, usecnt INTEGER, size INTEGER, crc INTEGER);\
CREATE UNIQUE INDEX IF NOT EXISTS kpagecachehashpageid ON pagecache(hash, pageid);\
CREATE INDEX IF NOT EXISTS kpagecachetype ON pagecache(type);\
CREATE TABLE IF NOT EXISTS fstask (id INTEGER PRIMARY KEY, type INTEGER, status INTEGER, folderid INTEGER, sfolderid INTEGER, fileid INTEGER,\
  text1 TEXT, text2 TEXT, int1 INTEGER, int2 INTEGER);\
CREATE INDEX IF NOT EXISTS kfstaskfolderid ON fstask(folderid);\
CREATE INDEX IF NOT EXISTS kfstasksfolderid ON fstask(sfolderid);\
CREATE INDEX IF NOT EXISTS kfstaskfileid ON fstask(fileid);\
CREATE TABLE IF NOT EXISTS fstaskdepend (fstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE, dependfstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE,\
PRIMARY KEY (fstaskid, dependfstaskid)) " P_SQL_WOWROWID ";\
CREATE INDEX IF NOT EXISTS kfstaskdependdependfstaskid ON fstaskdepend(dependfstaskid);\
CREATE TABLE IF NOT EXISTS pagecachetask(id INTEGER PRIMARY KEY, type INTEGER, taskid INTEGER, hash INTEGER, oldhash INTEGER);\
CREATE TABLE IF NOT EXISTS fstaskupload (fstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE, uploadid INTEGER, PRIMARY KEY (fstaskid, uploadid)) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS fstaskfileid (fstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE, fileid INTEGER, PRIMARY KEY (fstaskid, fileid)) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS resolver (hostname TEXT, port TEXT, prio INTEGER, created INTEGER, family INTEGER, socktype INTEGER, protocol INTEGER,\
  data TEXT, PRIMARY KEY (hostname, port, prio)) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS fsxattr (objectid INTEGER, name TEXT, value BLOB, PRIMARY KEY (objectid, name)) " P_SQL_WOWROWID ";\
CREATE TABLE IF NOT EXISTS cryptofolderkey (folderid INTEGER PRIMARY KEY REFERENCES folder(id) ON DELETE CASCADE, enckey BLOB NOT NULL);\
CREATE TABLE IF NOT EXISTS cryptofilekey (fileid INTEGER PRIMARY KEY REFERENCES file(id) ON DELETE CASCADE, hash INTEGER NOT NULL, enckey BLOB NOT NULL);\
CREATE TABLE IF NOT EXISTS bsharedfolder (id INTEGER PRIMARY KEY, isincoming INTEGER, folderid INTEGER, \
  ctime INTEGER, permissions INTEGER, message TEXT, name VARCHAR(1024), isuser INTEGER, \
  touserid INTEGER, isteam INTEGER, toteamid INTEGER, fromuserid INTEGER, folderownerid INTEGER); \
CREATE TABLE IF NOT EXISTS baccountemail (id INTEGER PRIMARY KEY, mail TEXT, firstname TEXT, lastname TEXT); \
CREATE TABLE IF NOT EXISTS baccountteam (id INTEGER PRIMARY KEY, name TEXT); \
CREATE TABLE IF NOT EXISTS links ( \
id INTEGER PRIMARY KEY, code VARCHAR(2048), comment TEXT, traffic INTEGER, maxspace INTEGER, \
downloads INTEGER, created INTEGER, modified INTEGER, name VARCHAR(2048),  isfolder INTEGER, folderid INTEGER, fileid INTEGER, isincomming INTEGER, icon INTEGER); \
CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, mail varchar(2048), name TEXT); \
INSERT OR IGNORE INTO folder (id, name) VALUES (0, '');\
INSERT OR IGNORE INTO localfolder (id) VALUES (0);\
INSERT OR IGNORE INTO setting (id, value) VALUES ('dbversion', " NTO_STR(PSYNC_DATABASE_VERSION) ");\
CREATE TABLE IF NOT EXISTS myteams (id INTEGER PRIMARY KEY, name TEXT); \
CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, last_path VARCHAR(1024), type INTEGER, vendor VARCHAR(2048), product VARCHAR(2048), device_id VARCHAR(4096),\
  connected INTEGER, enabled INTEGER); \
COMMIT;\
"

/*
 * fstask.status:
 *   0 - normal task for execution
 *   1 - file is still open, will switch to 0 on close
 *   2 - large upload task
 *   3 - upload task that is finished but still not added to cache
 *   10- rename tasks are inserted as two rows, first one, the "rename from" is with status 10
 *   11- cancelled task
 *   12- file that is new, still open and marked deleted
 * 
 */

static const char *psync_db_upgrade[PSYNC_DATABASE_VERSION]={
  "",
  "BEGIN;\
ALTER TABLE filerevision ADD size INTEGER;\
DROP TABLE IF EXISTS fstask;\
CREATE TABLE IF NOT EXISTS fstask (id INTEGER PRIMARY KEY, type INTEGER, status INTEGER, folderid INTEGER, sfolderid INTEGER, fileid INTEGER,\
  text1 TEXT, text2 TEXT, int1 INTEGER, int2 INTEGER);\
CREATE INDEX IF NOT EXISTS kfstaskfolderid ON fstask(folderid);\
CREATE INDEX IF NOT EXISTS kfstasksfolderid ON fstask(sfolderid);\
CREATE INDEX IF NOT EXISTS kfstaskfileid ON fstask(fileid);\
CREATE TABLE IF NOT EXISTS resolver (hostname TEXT, port TEXT, prio INTEGER, created INTEGER, family INTEGER, socktype INTEGER, protocol INTEGER,\
  data TEXT, PRIMARY KEY (hostname, port, prio)) " P_SQL_WOWROWID ";\
UPDATE filerevision SET size=(SELECT size FROM file WHERE file.id=filerevision.fileid AND file.hash=filerevision.hash);\
UPDATE setting SET value=2 WHERE id='dbversion';\
COMMIT;\
",
  "BEGIN;\
CREATE TABLE IF NOT EXISTS fsxattr (objectid INTEGER, name TEXT, value BLOB, PRIMARY KEY (objectid, name)) " P_SQL_WOWROWID ";\
UPDATE setting SET value=3 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
CREATE TABLE IF NOT EXISTS pagecachetask(id INTEGER PRIMARY KEY, type INTEGER, taskid INTEGER, hash INTEGER);\
ALTER TABLE pagecachetask ADD oldhash INTEGER;\
UPDATE setting SET value=4 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
DROP TABLE IF EXISTS localfileupload;\
CREATE TABLE IF NOT EXISTS localfileupload (localfileid INTEGER REFERENCES localfile(id) ON DELETE CASCADE, uploadid INTEGER, PRIMARY KEY (localfileid, uploadid)) " P_SQL_WOWROWID ";\
UPDATE setting SET value=5 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
CREATE TABLE IF NOT EXISTS fstaskfileid (fstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE, fileid INTEGER, PRIMARY KEY (fstaskid, fileid)) " P_SQL_WOWROWID ";\
UPDATE setting SET value=6 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
CREATE TABLE IF NOT EXISTS cryptofolderkey (folderid INTEGER PRIMARY KEY REFERENCES folder(id) ON DELETE CASCADE, enckey BLOB NOT NULL);\
CREATE TABLE IF NOT EXISTS cryptofilekey (fileid INTEGER PRIMARY KEY REFERENCES file(id) ON DELETE CASCADE, enckey BLOB NOT NULL);\
CREATE TABLE IF NOT EXISTS pagecache (id INTEGER PRIMARY KEY, hash INTEGER, pageid INTEGER, type INTEGER, flags INTEGER,\
  lastuse INTEGER, usecnt INTEGER, size INTEGER);\
CREATE UNIQUE INDEX IF NOT EXISTS kpagecachehashpageid ON pagecache(hash, pageid);\
CREATE INDEX IF NOT EXISTS kpagecachetype ON pagecache(type);\
CREATE TABLE IF NOT EXISTS fstask (id INTEGER PRIMARY KEY, type INTEGER, status INTEGER, folderid INTEGER, sfolderid INTEGER, fileid INTEGER,\
  text1 TEXT, text2 TEXT, int1 INTEGER, int2 INTEGER);\
CREATE INDEX IF NOT EXISTS kfstaskfolderid ON fstask(folderid);\
CREATE INDEX IF NOT EXISTS kfstasksfolderid ON fstask(sfolderid);\
CREATE INDEX IF NOT EXISTS kfstaskfileid ON fstask(fileid);\
CREATE TABLE IF NOT EXISTS fstaskdepend (fstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE, dependfstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE,\
PRIMARY KEY (fstaskid, dependfstaskid)) " P_SQL_WOWROWID ";\
CREATE INDEX IF NOT EXISTS kfstaskdependdependfstaskid ON fstaskdepend(dependfstaskid);\
CREATE TABLE IF NOT EXISTS fstaskupload (fstaskid INTEGER REFERENCES fstask(id) ON DELETE CASCADE, uploadid INTEGER, PRIMARY KEY (fstaskid, uploadid)) " P_SQL_WOWROWID ";\
UPDATE setting SET value=7 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
INSERT OR IGNORE INTO folder (id, name) VALUES (0, '');\
INSERT OR IGNORE INTO localfolder (id) VALUES (0);\
UPDATE setting SET value=8 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
ALTER TABLE pagecache ADD crc INTEGER;\
UPDATE setting SET value=9 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
DROP TABLE cryptofilekey;\
CREATE TABLE IF NOT EXISTS cryptofilekey (fileid INTEGER PRIMARY KEY REFERENCES file(id) ON DELETE CASCADE, hash INTEGER NOT NULL, enckey BLOB NOT NULL);\
UPDATE setting SET value=10 WHERE id='dbversion';\
COMMIT;",
  "PRAGMA foreign_keys=OFF;\
BEGIN;\
CREATE TABLE localfolder_new (id INTEGER PRIMARY KEY AUTOINCREMENT, localparentfolderid INTEGER REFERENCES localfolder(id) ON DELETE CASCADE, folderid INTEGER, \
  syncid INTEGER REFERENCES syncfolder(id) ON DELETE CASCADE, inode INTEGER, deviceid INTEGER, mtime INTEGER, mtimenative INTEGER, flags INTEGER, taskcnt INTEGER, name VARCHAR(1024) "PSYNC_TEXT_COL");\
INSERT INTO localfolder_new SELECT * FROM localfolder;\
DROP TABLE localfolder;\
ALTER TABLE localfolder_new RENAME TO localfolder;\
CREATE INDEX IF NOT EXISTS klocalfolderlpfid ON localfolder(localparentfolderid);\
CREATE UNIQUE INDEX IF NOT EXISTS klocalfolderpsn ON localfolder(syncid, localparentfolderid, name);\
CREATE INDEX IF NOT EXISTS klocalfolderfolderid ON localfolder(folderid);\
CREATE INDEX IF NOT EXISTS klocalfoldersyncid ON localfolder(syncid);\
UPDATE setting SET value=11 WHERE id='dbversion';\
COMMIT;\
PRAGMA foreign_keys=ON;",
  "BEGIN;\
ALTER TABLE sharedfolder ADD bsharedfolderid INTEGER;\
CREATE TABLE IF NOT EXISTS bsharedfolder (id INTEGER PRIMARY KEY, isincoming INTEGER, folderid INTEGER, \
ctime INTEGER, permissions INTEGER, message TEXT, name VARCHAR(1024), isuser INTEGER, \
touserid INTEGER, isteam INTEGER, toteamid INTEGER, fromuserid INTEGER, folderownerid INTEGER); \
UPDATE setting SET value=12 WHERE id='dbversion';\
COMMIT;",
  "BEGIN;\
CREATE TABLE IF NOT EXISTS baccountemail (id INTEGER PRIMARY KEY, mail TEXT, firstname TEXT, lastname TEXT); \
CREATE TABLE IF NOT EXISTS baccountteam (id INTEGER PRIMARY KEY, name TEXT); \
CREATE TABLE IF NOT EXISTS links ( \
id INTEGER PRIMARY KEY, code VARCHAR(2048), comment TEXT, traffic INTEGER, maxspace INTEGER, \
downloads INTEGER, created INTEGER, modified INTEGER, name VARCHAR(2048),  isfolder INTEGER, folderid INTEGER, fileid INTEGER, isincomming INTEGER); \
CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, mail varchar(2048), name TEXT); \
UPDATE setting SET value=13 WHERE id='dbversion'; \
COMMIT;",
"BEGIN;\
ALTER TABLE links ADD icon INTEGER; \
UPDATE setting SET value=14 WHERE id='dbversion'; \
COMMIT;",
"BEGIN;\
ALTER TABLE sharerequest ADD isba INTEGER; \
UPDATE setting SET value=15 WHERE id='dbversion'; \
COMMIT;",
"BEGIN;\
CREATE TABLE IF NOT EXISTS myteams (id INTEGER PRIMARY KEY, name TEXT);\
UPDATE setting SET value=16 WHERE id='dbversion'; \
UPDATE setting SET value=0 WHERE id='diffid'; \
COMMIT;",
"BEGIN;\
UPDATE setting SET value=17 WHERE id='dbversion'; \
UPDATE setting SET value=0 WHERE id='diffid'; \
COMMIT;",
"BEGIN;\
CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, last_path VARCHAR(1024), type INTEGER, vendor VARCHAR(2048), product VARCHAR(2048), device_id VARCHAR(4096),\
  connected INTEGER, enabled INTEGER); \
COMMIT;"
};

#endif
