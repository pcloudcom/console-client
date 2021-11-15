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

#include "psettings.h"
#include "plibs.h"
#include "ptimer.h"
#include "pcache.h"
#include "ptree.h"
#include "pdatabase.h"
#include "plocks.h"
#include "pnetlibs.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>

#define return_error(err) do {psync_error=err; return -1;} while (0)

#define SQL_NO_LOCK    0
#define SQL_READ_LOCK  1
#define SQL_WRITE_LOCK 2

struct run_after_ptr {
  struct run_after_ptr *next;
  psync_run_after_t run;
  void *ptr;
};

typedef struct {
  psync_list list;
  psync_transaction_callback_t commit_callback;
  psync_transaction_callback_t rollback_callback;
  void *ptr;
} tran_callback_t;

static const uint8_t __hex_lookupl[513]={
  "000102030405060708090a0b0c0d0e0f"
  "101112131415161718191a1b1c1d1e1f"
  "202122232425262728292a2b2c2d2e2f"
  "303132333435363738393a3b3c3d3e3f"
  "404142434445464748494a4b4c4d4e4f"
  "505152535455565758595a5b5c5d5e5f"
  "606162636465666768696a6b6c6d6e6f"
  "707172737475767778797a7b7c7d7e7f"
  "808182838485868788898a8b8c8d8e8f"
  "909192939495969798999a9b9c9d9e9f"
  "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
  "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
  "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
  "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
  "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
};

const char base64_table[]={
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

static const char base64_reverse_table[256]={
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, 62, -2, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -1, -2, -2,
        -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, 63,
        -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

uint16_t const *__hex_lookup=(uint16_t *)__hex_lookupl;
static char normalize_table[256];

const static char *psync_typenames[]={"[invalid type]", "[number]", "[string]", "[float]", "[null]", "[bool]"};

char psync_my_auth[64]="", psync_my_2fa_code[32], *psync_my_user=NULL, *psync_my_pass=NULL, *psync_my_2fa_token=NULL, *psync_my_verify_token=NULL;
int psync_my_2fa_code_type=0, psync_my_2fa_trust=0, psync_my_2fa_has_devices=0, psync_my_2fa_type=1;
uint64_t psync_my_userid=0;
pthread_mutex_t psync_my_auth_mutex=PTHREAD_MUTEX_INITIALIZER;

psync_rwlock_t psync_db_lock;
sqlite3 *psync_db;
pstatus_t psync_status;
int psync_do_run=1;
int psync_recache_contacts=1;
PSYNC_THREAD uint32_t psync_error=0;

static pthread_mutex_t psync_db_checkpoint_mutex;

static int in_transaction=0;
static int transaction_failed=0;
static psync_list tran_callbacks;

char *psync_strdup(const char *str){
  size_t len;
  len=strlen(str)+1;
  return (char *)memcpy(psync_new_cnt(char, len), str, len);
}

char *psync_strnormalize_filename(const char *str){
  size_t len, i;
  char *ptr;
  len=strlen(str)+1;
  ptr=psync_new_cnt(char, len);
  for (i=0; i<len; i++)
    ptr[i]=normalize_table[(unsigned char)str[i]];
  return ptr;
}

char *psync_strndup(const char *str, size_t len){
  char *ptr;
  ptr=(char *)memcpy(psync_new_cnt(char, len+1), str, len);
  ptr[len]=0;
  return ptr;
}

char *psync_strcat(const char *str, ...){
  size_t i, size, len;
  const char *strs[64];
  size_t lengths[64];
  const char *ptr;
  char *ptr2, *ptr3;
  va_list ap;
  va_start(ap, str);
  strs[0]=str;
  len=strlen(str);
  lengths[0]=len;
  size=len+1;
  i=1;
  while ((ptr=va_arg(ap, const char *))){
    assert(i<ARRAY_SIZE(strs));
    len=strlen(ptr);
    lengths[i]=len;
    strs[i++]=ptr;
    size+=len;
  }
  va_end(ap);
  ptr2=ptr3=(char *)psync_malloc(size);
  for (size=0; size<i; size++){
    memcpy(ptr2, strs[size], lengths[size]);
    ptr2+=lengths[size];
  }
  *ptr2=0;
  return ptr3;
}

int psync_slprintf(char *str, size_t size, const char *format, ...){
  va_list ap;
  int ret;
  va_start(ap, format);
  ret=vsnprintf(str, size, format, ap);
  va_end(ap);
  if (unlikely_log(ret>=size))
    str[size-1]=0;
  return ret;
}

unsigned char *psync_base32_encode(const unsigned char *str, size_t length, size_t *ret_length){
  static const unsigned char *table=(const unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  unsigned char *result;
  unsigned char *p;
  uint32_t bits, buff;

  result=(unsigned char *)psync_malloc(((length+4)/5)*8+1);
  p=result;

  bits=0;
  buff=0; // don't really have to initialize this one, but a compiler that will detect that this is safe is yet to be born

  while (length){
    if (bits<5){
      buff=(buff<<8)|(*str++);
      length--;
      bits+=8;
    }
    bits-=5;
    *p++=table[0x1f&(buff>>bits)];
  }

  while (bits){
    if (bits<5){
      buff<<=(5-bits);
      bits=5;
    }
    bits-=5;
    *p++=table[0x1f&(buff>>bits)];
  }

  *ret_length=p-result;
  *p=0;
  return result;
}

unsigned char *psync_base32_decode(const unsigned char *str, size_t length, size_t *ret_length){
  unsigned char *result, *p;
  uint32_t bits, buff;
  unsigned char ch;
  result=(unsigned char *)psync_malloc((length+7)/8*5+1);
  p=result;
  bits=0;
  buff=0;
  while (length){
    ch=*str++;
    length--;
    if (ch>='A' && ch<='Z')
      ch=(ch&0x1f)-1;
    else if (ch>='2'&&ch<='7')
      ch-='2'-26;
    else{
      psync_free(result);
      return NULL;
    }
    buff=(buff<<5)+ch;
    bits+=5;
    if (bits>=8){
      bits-=8;
      *p++=buff>>bits;
    }
  }
  *p=0;
  *ret_length=p-result;
  return result;
}

unsigned char *psync_base64_encode(const unsigned char *str, size_t length, size_t *ret_length){
  const unsigned char *current = str;
  unsigned char *p;
  unsigned char *result;

  result=(unsigned char *)psync_malloc(((length+2)/3)*4+1);
  p=result;

  while(length>2){
    *p++=base64_table[current[0] >> 2];
    *p++=base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
    *p++=base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
    *p++=base64_table[current[2] & 0x3f];
    current+=3;
    length-=3;
  }

  if (length!=0){
    *p++=base64_table[current[0] >> 2];
    if (length>1){
      *p++=base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
      *p++=base64_table[(current[1] & 0x0f) << 2];
    }
    else
      *p++=base64_table[(current[0] & 0x03) << 4];
  }

  *ret_length=p-result;
  *p=0;
  return result;
}

unsigned char *psync_base64_decode(const unsigned char *str, size_t length, size_t *ret_length){
  const unsigned char *current = str;
  unsigned char *result;
  size_t i=0, j=0;
  ssize_t ch;

  result=(unsigned char *)psync_malloc((length+3)/4*3+1);

  while (length-- > 0){
    ch=base64_reverse_table[*current++];
    if (ch==-1)
     continue;
    else if (ch==-2) {
       psync_free(result);
      return NULL;
    }
    switch(i%4) {
      case 0:
        result[j]=ch<<2;
        break;
      case 1:
        result[j++]|=ch>>4;
        result[j]=(ch&0x0f)<<4;
        break;
      case 2:
        result[j++]|=ch>>2;
        result[j]=(ch&0x03)<<6;
        break;
      case 3:
        result[j++]|=ch;
        break;
    }
    i++;
  }
  *ret_length=j;
  result[j]=0;
  return result;
}

int psync_is_valid_utf8(const char *str){
  static const int8_t trailing[]={
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, -1, -1, -1, -1, -1, -1, -1, -1
  };
  int8_t t;
  while (*str) {
    t=trailing[(unsigned char)*str++];
    if (unlikely(t)){
      if (t<0)
        return 0;
      while (t--)
        if ((((unsigned char)*str++)&0xc0)!=0x80)
          return 0;
    }
  }
  return 1;
}

void psync_sql_err_callback(void *ptr, int code, const char *msg){
  debug(D_WARNING, "database warning %d: %s", code, msg);
}

static void psync_sql_wal_checkpoint(){
  int code;
  psync_sql_lock();
  psync_sql_unlock();
  if (pthread_mutex_trylock(&psync_db_checkpoint_mutex)){
    debug(D_NOTICE, "checkpoint already in progress");
    return;
  }
  debug(D_NOTICE, "checkpointing database");
  code=sqlite3_wal_checkpoint(psync_db, NULL);
  while (code==SQLITE_LOCKED){
    psync_milisleep(2);
    code=sqlite3_wal_checkpoint(psync_db, NULL);
  }
  pthread_mutex_unlock(&psync_db_checkpoint_mutex);
  if (unlikely(code!=SQLITE_OK))
    debug(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
  else
    debug(D_NOTICE, "checkpoint finished");
}

static int psync_sql_wal_hook(void *ptr, sqlite3 *db, const char *name, int numpages){
  if (numpages>=PSYNC_DB_CHECKPOINT_AT_PAGES)
    psync_run_thread("checkpoint charlie", psync_sql_wal_checkpoint);
  return SQLITE_OK;
}

int psync_sql_connect(const char *db){
  static int initmutex=1;
  pthread_mutexattr_t mattr;
  psync_stat_t st;
  uint64_t dbver;
  int initdbneeded=0;
  int code;

  assert(sqlite3_libversion_number()==SQLITE_VERSION_NUMBER);
  assert(!strcmp(sqlite3_sourceid(), SQLITE_SOURCE_ID));
  assert(!strcmp(sqlite3_libversion(), SQLITE_VERSION));
  debug(D_NOTICE, "Using sqlite version %s source %s", sqlite3_libversion(), sqlite3_sourceid());
  if (!sqlite3_threadsafe()){
    debug(D_CRITICAL, "sqlite is compiled without thread support");
    return -1;
  }
  if (psync_stat(db, &st)!=0)
    initdbneeded=1;

  code=sqlite3_open(db, &psync_db);
  if (likely(code==SQLITE_OK)){
    if (initmutex){
      psync_rwlock_init(&psync_db_lock);
      pthread_mutexattr_init(&mattr);
      pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
      pthread_mutex_init(&psync_db_checkpoint_mutex, &mattr);
      pthread_mutexattr_destroy(&mattr);
      initmutex=0;
    }
    if (IS_DEBUG)
      sqlite3_config(SQLITE_CONFIG_LOG, psync_sql_err_callback, NULL);
    sqlite3_wal_hook(psync_db, psync_sql_wal_hook, NULL);
    psync_sql_statement(PSYNC_DATABASE_CONFIG);
    if (initdbneeded==1)
      return psync_sql_statement(PSYNC_DATABASE_STRUCTURE);
    else if (psync_sql_statement("DELETE FROM setting WHERE id='justcheckingiflocked'")){
      debug(D_ERROR, "database is locked");
      sqlite3_close(psync_db);
      psync_rwlock_destroy(&psync_db_lock);
      return -1;
    }

    dbver=psync_sql_cellint("SELECT value FROM setting WHERE id='dbversion'", 0);
    if (dbver<PSYNC_DATABASE_VERSION){
      uint64_t i;
      debug(D_NOTICE, "database version %d detected, upgrading to %d", (int)dbver, (int)PSYNC_DATABASE_VERSION);
      for (i=dbver; i<PSYNC_DATABASE_VERSION; i++)
        if (psync_sql_statement(psync_db_upgrade[i])){
          debug(D_ERROR, "error running statement %s on sqlite %s", psync_db_upgrade[i], sqlite3_libversion());
          if (IS_DEBUG)
            return_error(PERROR_DATABASE_OPEN);
        }
    }

    return 0;
  }
  else{
    debug(D_CRITICAL, "could not open sqlite database %s: %d", db, code);
    return -1;
  }
}

int psync_sql_close(){
  int code, tries;
  tries=0;
  while (1){
    code=sqlite3_close(psync_db);
    if (code==SQLITE_BUSY){
      psync_cache_clean_all();
      tries++;
      if (tries>100){
        psync_milisleep_nosqlcheck(tries-90);
        if (tries>200){
          debug(D_ERROR, "failed to close database");
          break;
        }
      }
    }
    else
      break;
  }
  psync_db=NULL;
  if (unlikely(code!=SQLITE_OK)){
    debug(D_CRITICAL, "error when closing database: %d", code);
    code=sqlite3_close_v2(psync_db);
    if (unlikely(code!=SQLITE_OK)){
      debug(D_CRITICAL, "error when closing database even with sqlite3_close_v2: %d", code);
      return -1;
    }
  }
  return 0;
}

int psync_sql_reopen(const char *path){
  sqlite3 *db;
  int code;
  debug(D_NOTICE, "reopening database %s", path);
  code=sqlite3_open(path, &db);
  if (likely(code==SQLITE_OK)){
    code=sqlite3_wal_checkpoint(db, NULL);
    if (unlikely(code!=SQLITE_OK)){
      debug(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
      sqlite3_close(db);
      return -1;
    }
    code=sqlite3_close(db);
    if (unlikely(code!=SQLITE_OK)){
      debug(D_CRITICAL, "sqlite3_close returned error %d", code);
      return -1;
    }
    return 0;
  }
  else{
    debug(D_CRITICAL, "could not open sqlite dabase %s: %d", path, code);
    return -1;
  }
}

void psync_sql_checkpoint_lock(){
  pthread_mutex_lock(&psync_db_checkpoint_mutex);
}

void psync_sql_checkpoint_unlock(){
  pthread_mutex_unlock(&psync_db_checkpoint_mutex);
}

#if IS_DEBUG
typedef struct {
  psync_list list;
  const char *file;
  const char *thread;
  struct timespec tm;
  unsigned line;
} rd_lock_data;

static PSYNC_THREAD rd_lock_data *rdlock=NULL;
static PSYNC_THREAD unsigned long sqlrdlockcnt=0;
static PSYNC_THREAD struct timespec sqlrdlockstart;
unsigned long sqllockcnt=0;
static struct timespec sqllockstart;
static const char *wrlockfile="none";
static const char *wrlockthread="";
static unsigned wrlockline=0;
static unsigned wrlocked=0;
static pthread_t wrlocker;
static psync_list rdlocks=PSYNC_LIST_STATIC_INIT(rdlocks);
static pthread_mutex_t rdmutex=PTHREAD_MUTEX_INITIALIZER;

static void record_wrlock(const char *file, unsigned line){
  if (unlikely(rdlock)){
    debug(D_BUG, "trying to get write lock at %s:%u, but read lock is already taken at %s:%u, aborting", file, line, rdlock->file, rdlock->line);
    senddebug("trying to get write lock at %s:%u, but read lock is already taken at %s:%u, aborting", file, line, rdlock->file, rdlock->line);
    abort();
  }
  sendassert(!wrlocked);
  assert(!wrlocked);
  wrlockfile=file;
  wrlockline=line;
  wrlockthread=psync_thread_name;
  wrlocked=1;
  wrlocker=pthread_self();
}

static void record_wrunlock(){
  sendassert(pthread_equal(pthread_self(), wrlocker));
  sendassert(wrlocked);
  assert(pthread_equal(pthread_self(), wrlocker));
  assert(wrlocked);
  wrlocked=0;
}

static void record_rdlock(const char *file, unsigned line, struct timespec *tm){
  rd_lock_data *lock;
  lock=psync_new(rd_lock_data);
  lock->file=file;
  lock->thread=psync_thread_name;
  lock->line=line;
  memcpy(&lock->tm, tm, sizeof(struct timespec));
  pthread_mutex_lock(&rdmutex);
  psync_list_add_tail(&rdlocks, &lock->list);
  pthread_mutex_unlock(&rdmutex);
  rdlock=lock;
}

static rd_lock_data *record_rdunlock(){
  rd_lock_data *lock;
  assert(rdlock);
  lock=rdlock;
  rdlock=NULL;
  pthread_mutex_lock(&rdmutex);
  psync_list_del(&lock->list);
  pthread_mutex_unlock(&rdmutex);
  return lock;
}

static void time_format(time_t tm, unsigned long ns, char *result);

void psync_sql_dump_locks(){
  rd_lock_data *lock;
  char dttime[36];
  if (wrlocked){
    time_format(sqllockstart.tv_sec, sqllockstart.tv_nsec, dttime);
    debug(D_ERROR, "write lock taken by thread %s from %s:%u at %s", wrlockthread, wrlockfile, wrlockline, dttime);
    senddebug("write lock taken by thread %s from %s:%u at %s", wrlockthread, wrlockfile, wrlockline, dttime);
  }
  pthread_mutex_lock(&rdmutex);
  psync_list_for_each_element(lock, &rdlocks, rd_lock_data, list){
    time_format(lock->tm.tv_sec, lock->tm.tv_nsec, dttime);
    debug(D_ERROR, "read lock taken by thread %s from %s:%u at %s", lock->thread, lock->file, lock->line, dttime);
    senddebug("read lock taken by thread %s from %s:%u at %s", lock->thread, lock->file, lock->line, dttime);
  }
  pthread_mutex_unlock(&rdmutex);
}

#endif

#if IS_DEBUG
int psync_sql_do_trylock(const char *file, unsigned line){
  if (psync_rwlock_trywrlock(&psync_db_lock))
    return -1;
  if (++sqllockcnt==1){
    psync_nanotime(&sqllockstart);
    record_wrlock(file, line);
  }
  return 0;
}
#else
int psync_sql_trylock(){
  return psync_rwlock_trywrlock(&psync_db_lock);
}
#endif

#if IS_DEBUG
void psync_sql_do_lock(const char *file, unsigned line){
  if (psync_rwlock_trywrlock(&psync_db_lock)){
    struct timespec start, end;
    unsigned long msec;
    psync_nanotime(&start);
    memcpy(&end, &start, sizeof(end));
    end.tv_sec+=PSYNC_DEBUG_LOCK_TIMEOUT;
    if (psync_rwlock_timedwrlock(&psync_db_lock, &end)){
      debug(D_BUG, "sql write lock timed out called from %s:%u", file, line);
      senddebug("sql write lock timed out called from %s:%u", file, line);
      psync_sql_dump_locks();
      abort();
    }
    psync_nanotime(&end);
    msec=(end.tv_sec-start.tv_sec)*1000+end.tv_nsec/1000000-start.tv_nsec/1000000;
    if (msec>=5)
      debug(D_WARNING, "waited %lu milliseconds for database write lock", msec);
    assert(sqllockcnt==0);
    sqllockcnt++;
    memcpy(&sqllockstart, &end, sizeof(struct timespec));
    record_wrlock(file, line);
  }
  else if (++sqllockcnt==1){
    psync_nanotime(&sqllockstart);
    record_wrlock(file, line);
  }
}
#else
void psync_sql_lock(){
  psync_rwlock_wrlock(&psync_db_lock);
}
#endif

void psync_sql_unlock(){
#if IS_DEBUG
  assert(sqllockcnt>0);
  if (--sqllockcnt==0){
    struct timespec end;
    unsigned long msec;
    psync_nanotime(&end);
    msec=(end.tv_sec-sqllockstart.tv_sec)*1000+end.tv_nsec/1000000-sqllockstart.tv_nsec/1000000;
    if (msec>=10)
      debug(D_WARNING, "held database write lock for %lu milliseconds taken from %s:%u", msec, wrlockfile, wrlockline);
    record_wrunlock();
    psync_rwlock_unlock(&psync_db_lock);
  }
  else
    psync_rwlock_unlock(&psync_db_lock);
#else
  psync_rwlock_unlock(&psync_db_lock);
#endif
}

#if IS_DEBUG
void psync_sql_do_rdlock(const char *file, unsigned line){
  if (psync_rwlock_tryrdlock(&psync_db_lock)){
    struct timespec start, end;
    unsigned long msec;
    psync_nanotime(&start);
    memcpy(&end, &start, sizeof(end));
    end.tv_sec+=PSYNC_DEBUG_LOCK_TIMEOUT;
    if (psync_rwlock_timedrdlock(&psync_db_lock, &end)){
      debug(D_BUG, "sql read lock timed out, called from %s:%u", file, line);
      senddebug("sql read lock timed out, called from %s:%u", file, line);
      psync_sql_dump_locks();
      abort();
    }
    psync_nanotime(&end);
    msec=(end.tv_sec-start.tv_sec)*1000+end.tv_nsec/1000000-start.tv_nsec/1000000;
    if (msec>=5)
      debug(D_WARNING, "waited %lu milliseconds for database read lock", msec);
    sqlrdlockcnt++;
    memcpy(&sqlrdlockstart, &end, sizeof(struct timespec));
    record_rdlock(file, line, &sqlrdlockstart);
  }
  else if (++sqlrdlockcnt==1){
    psync_nanotime(&sqlrdlockstart);
    record_rdlock(file, line, &sqlrdlockstart);
  }
}
#else
void psync_sql_rdlock(){
  psync_rwlock_rdlock(&psync_db_lock);
}
#endif

void psync_sql_rdunlock(){
#if IS_DEBUG
  if (unlikely(sqlrdlockcnt==0)){
    psync_sql_unlock();
    return;
  }
  if (--sqlrdlockcnt==0){
    struct timespec end;
    unsigned long msec;
    rd_lock_data *lock;
    psync_rwlock_unlock(&psync_db_lock);
    psync_nanotime(&end);
    lock=record_rdunlock();
    msec=(end.tv_sec-sqlrdlockstart.tv_sec)*1000+end.tv_nsec/1000000-sqlrdlockstart.tv_nsec/1000000;
    if (msec>=20)
      debug(D_WARNING, "held database read lock for %lu milliseconds taken at %s:%u", msec, lock->file, lock->line);
    psync_free(lock);
  }
  else
    psync_rwlock_unlock(&psync_db_lock);
#else
  psync_rwlock_unlock(&psync_db_lock);
#endif
}

int psync_sql_has_waiters(){
  return psync_rwlock_num_waiters(&psync_db_lock)>0;
}

int psync_sql_isrdlocked(){
  return psync_rwlock_holding_rdlock(&psync_db_lock);
}

int psync_sql_islocked(){
  return psync_rwlock_holding_lock(&psync_db_lock);
}

int psync_sql_tryupgradelock(){
#if IS_DEBUG
  if (psync_rwlock_holding_wrlock(&psync_db_lock))
    return 0;
  assert(psync_rwlock_holding_rdlock(&psync_db_lock));
  if (psync_rwlock_towrlock(&psync_db_lock))
    return -1;
  else{
    rd_lock_data *lock=record_rdunlock();
    sqllockcnt=sqlrdlockcnt;
    sqlrdlockcnt=0;
    assert(sqllockcnt==1);
    sqllockstart=sqlrdlockstart;
    record_wrlock(lock->file, lock->line);
    psync_free(lock);
    return 0;
  }
#else
  return psync_rwlock_towrlock(&psync_db_lock);
#endif
}

int psync_sql_sync(){
  int code;
  pthread_mutex_lock(&psync_db_checkpoint_mutex);
  code=sqlite3_wal_checkpoint(psync_db, NULL);
  if (unlikely(code==SQLITE_BUSY || code==SQLITE_LOCKED)){
    psync_sql_lock();
    code=sqlite3_wal_checkpoint(psync_db, NULL);
    psync_sql_unlock();
  }
  pthread_mutex_unlock(&psync_db_checkpoint_mutex);
  if (unlikely(code!=SQLITE_OK)){
    debug(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
    return -1;
  }
  else
    return 0;
}

#if IS_DEBUG
int psync_sql_do_statement(const char *sql, const char *file, unsigned line){
  char *errmsg;
  int code;
  psync_sql_do_lock(file, line);
#else
int psync_sql_statement(const char *sql){
  char *errmsg;
  int code;
  psync_sql_lock();
#endif
  code=sqlite3_exec(psync_db, sql, NULL, NULL, &errmsg);
  psync_sql_unlock();
  if (likely(code==SQLITE_OK))
    return 0;
  else{
#if IS_DEBUG
    debug(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql, errmsg, file, line);
#else
    debug(D_ERROR, "error running sql statement: %s: %s", sql, errmsg);
#endif
    sqlite3_free(errmsg);
    return -1;
  }
}

#if IS_DEBUG
int psync_sql_do_start_transaction(const char *file, unsigned line){
  psync_sql_res *res;
  psync_sql_do_lock(file, line);
  res=psync_sql_do_prep_statement("BEGIN", file, line);
#else
int psync_sql_start_transaction(){
  psync_sql_res *res;
  psync_sql_lock();
  res=psync_sql_prep_statement("BEGIN");
#endif
  assert(!in_transaction);
  if (unlikely(!res || psync_sql_run_free(res)))
    return -1;
  in_transaction=1;
  transaction_failed=0;
  psync_list_init(&tran_callbacks);
  return 0;
}

static void run_commit_callbacks(int success){
  tran_callback_t *cb;
  psync_list *l1, *l2;
  psync_list_for_each_safe(l1, l2, &tran_callbacks) {
    cb=psync_list_element(l1, tran_callback_t, list);
    if (success)
      cb->commit_callback(cb->ptr);
    else
      cb->rollback_callback(cb->ptr);
    psync_free(cb);
  }
}

int psync_sql_commit_transaction(){
  assert(in_transaction);
  if (likely(!transaction_failed)){
    psync_sql_res *res=psync_sql_prep_statement("COMMIT");
    if (likely(!psync_sql_run_free(res))){
      run_commit_callbacks(1);
      in_transaction=0;
      psync_sql_unlock();
      return 0;
    }
  }
  else
    debug(D_ERROR, "rolling back transaction as some statements failed");
  psync_sql_rollback_transaction();
  return -1;
}

int psync_sql_rollback_transaction(){
  psync_sql_res *res=psync_sql_prep_statement("ROLLBACK");
  assert(in_transaction);
  psync_sql_run_free(res);
  run_commit_callbacks(0);
  in_transaction=0;
  psync_sql_unlock();
  return 0;
}

void psync_sql_transation_add_callbacks(psync_transaction_callback_t commit_callback, psync_transaction_callback_t rollback_callback, void *ptr){
  tran_callback_t *cb;
  assert(in_transaction);
  cb=psync_new(tran_callback_t);
  cb->commit_callback=commit_callback;
  cb->rollback_callback=rollback_callback;
  cb->ptr=ptr;
  psync_list_add_tail(&tran_callbacks, &cb->list);
}

#if IS_DEBUG && 0

typedef struct {
  psync_tree tree;
  const char *sql;
} psync_sql_tree_t;

static psync_tree *sql_tree=PSYNC_TREE_EMPTY;

static void psync_sql_do_check_query_plan(const char *sql){
  sqlite3_stmt *stmt;
  char *exsql;
  const char *detail;
  int code;
  exsql=psync_strcat("EXPLAIN QUERY PLAN ", sql, NULL);
  code=sqlite3_prepare_v2(psync_db, exsql, -1, &stmt, 0);
  psync_free(exsql);
  if (code!=SQLITE_OK){
    debug(D_ERROR, "EXPLAIN QUERY PLAN %s returned error: %d", sql, code);
    return;
  }
  while (sqlite3_step(stmt)==SQLITE_ROW){
    detail=(const char *)sqlite3_column_text(stmt, 3);
    if (!strncmp(detail, "SCAN TABLE", strlen("SCAN TABLE")))
      debug(D_WARNING, "doing %s on sql %s", detail, sql);
  }
  sqlite3_finalize(stmt);
}

static psync_tree *psync_sql_new_tree_node(const char *sql){
  psync_sql_tree_t *node;
  node=psync_new(psync_sql_tree_t);
  node->sql=sql;
  return &node->tree;
}

static void psync_sql_check_query_plan_locked(const char *sql){
  psync_tree *node;
  int cmp;
  if (!sql_tree){
    psync_tree_add_after(&sql_tree, NULL, psync_sql_new_tree_node(sql));
    return;
  }
  node=sql_tree;
  while (1){
    cmp=strcmp(sql, psync_tree_element(node, psync_sql_tree_t, tree)->sql);
    if (cmp<0){
      if (node->left)
        node=node->left;
      else{
        psync_tree_add_before(&sql_tree, node, psync_sql_new_tree_node(sql));
        break;
      }
    }
    else if (cmp>0){
      if (node->right)
        node=node->right;
      else{
        psync_tree_add_after(&sql_tree, node, psync_sql_new_tree_node(sql));
        break;
      }
    }
    else
      return;
  }
  psync_sql_do_check_query_plan(sql);
}

static void psync_sql_check_query_plan(const char *sql){
  psync_sql_lock();
  psync_sql_check_query_plan_locked(sql);
  psync_sql_unlock();
}

#else

#define psync_sql_check_query_plan(s) ((void)0)

#endif

char *psync_sql_cellstr(const char *sql){
  sqlite3_stmt *stmt;
  int code;
  psync_sql_check_query_plan(sql);
  psync_sql_rdlock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_rdunlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    sendtdebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  code=sqlite3_step(stmt);
  if (code==SQLITE_ROW){
    char *ret;
    ret=(char *)sqlite3_column_text(stmt, 0);
    if (ret)
      ret=psync_strdup(ret);
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    return ret;
  }
  else {
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    if (unlikely(code!=SQLITE_DONE)){
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
      sendtdebug("sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

int64_t psync_sql_cellint(const char *sql, int64_t dflt){
  sqlite3_stmt *stmt;
  int code;
  psync_sql_check_query_plan(sql);
  psync_sql_rdlock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    sendtdebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
  }
  else{
    code=sqlite3_step(stmt);
    if (code==SQLITE_ROW)
      dflt=sqlite3_column_int64(stmt, 0);
    else if (unlikely(code!=SQLITE_DONE)){
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
      sendtdebug("sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    }
    sqlite3_finalize(stmt);
  }
  psync_sql_rdunlock();
  return dflt;
}

char **psync_sql_rowstr(const char *sql){
  sqlite3_stmt *stmt;
  int code, cnt;
  psync_sql_check_query_plan(sql);
  psync_sql_rdlock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_rdunlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    sendtdebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt=sqlite3_column_count(stmt);
  code=sqlite3_step(stmt);
  if (code==SQLITE_ROW){
    char **arr, *nstr, *str;
    size_t l, ln;
    psync_def_var_arr(lens, size_t, cnt);
    int i;
    ln=0;
    for (i=0; i<cnt; i++){
      l=sqlite3_column_bytes(stmt, i);
      ln+=l;
      lens[i]=l;
    }
    ln+=(sizeof(char *)+1)*cnt;
    arr=(char **)psync_malloc(ln);
    nstr=((char *)arr)+sizeof(char *)*cnt;
    for (i=0; i<cnt; i++){
      str=(char *)sqlite3_column_blob(stmt, i);
      if (str){
        ln=lens[i];
        memcpy(nstr, str, ln);
        nstr[ln]=0;
        arr[i]=nstr;
        nstr+=ln+1;
      }
      else
        arr[i]=NULL;
    }
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    return arr;
  }
  else {
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    if (unlikely(code!=SQLITE_DONE)){
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
      sendtdebug("sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

psync_variant *psync_sql_row(const char *sql){
  sqlite3_stmt *stmt;
  int code, cnt;
  psync_sql_check_query_plan(sql);
  psync_sql_rdlock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_rdunlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    sendtdebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt=sqlite3_column_count(stmt);
  code=sqlite3_step(stmt);
  if (code==SQLITE_ROW){
    psync_variant *arr;
    char *nstr, *str;
    size_t l, ln;
    psync_def_var_arr(lens, size_t, cnt);
    int i, t;
    psync_def_var_arr(types, int, cnt);
    ln=sizeof(psync_variant)*cnt;
    for (i=0; i<cnt; i++){
      t=sqlite3_column_type(stmt, i);
      types[i]=t;
      if (t==SQLITE_TEXT || t==SQLITE_BLOB){
        l=sqlite3_column_bytes(stmt, i);
        ln+=l+1;
        lens[i]=l;
      }
    }
    arr=(psync_variant *)psync_malloc(ln);
    nstr=((char *)arr)+sizeof(psync_variant)*cnt;
    for (i=0; i<cnt; i++){
      t=types[i];
      if (t==SQLITE_INTEGER){
        arr[i].type=PSYNC_TNUMBER;
        arr[i].snum=sqlite3_column_int64(stmt, i);
      }
      else if (t==SQLITE_TEXT || t==SQLITE_BLOB){
        str=(char *)sqlite3_column_blob(stmt, i);
        ln=lens[i];
        memcpy(nstr, str, ln);
        nstr[ln]=0;
        arr[i].type=PSYNC_TSTRING;
        arr[i].str=nstr;
        nstr+=ln+1;
      }
      else if (t==SQLITE_FLOAT){
        arr[i].type=PSYNC_TREAL;
        arr[i].real=sqlite3_column_double(stmt, i);
      }
      else {
        arr[i].type=PSYNC_TNULL;
      }
    }
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    return arr;
  }
  else {
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    if (unlikely(code!=SQLITE_DONE)){
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
      sendtdebug("sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_nocache(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_query_nocache(const char *sql){
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  psync_sql_check_query_plan(sql);
#if IS_DEBUG
  psync_sql_do_lock(file, line);
#else
  psync_sql_lock();
#endif
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
#if IS_DEBUG
    debug(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql, sqlite3_errmsg(psync_db), file, line);
    senddebug("error running sql statement: %s: %s called from %s:%u", sql, sqlite3_errmsg(psync_db), file, line);
#else
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    senddebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
#endif
    return NULL;
  }
  cnt=sqlite3_column_count(stmt);
  res=(psync_sql_res *)psync_malloc(sizeof(psync_sql_res)+cnt*sizeof(psync_variant));
  res->stmt=stmt;
  res->sql=sql;
  res->column_count=cnt;
  res->locked=SQL_WRITE_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_query(const char *sql){
#endif
  psync_sql_res *ret;
  ret=(psync_sql_res *)psync_cache_get(sql);
  if (ret){
//    debug(D_NOTICE, "got query %s from cache", sql);
    ret->locked=SQL_WRITE_LOCK;
    ret->sql=sql;
#if IS_DEBUG
    psync_sql_do_lock(file, line);
#else
    psync_sql_lock();
#endif
    return ret;
  }
  else
#if IS_DEBUG
    return psync_sql_do_query_nocache(sql, file, line);
#else
    return psync_sql_query_nocache(sql);
#endif
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_rdlock_nocache(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_query_rdlock_nocache(const char *sql){
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  psync_sql_check_query_plan(sql);
#if IS_DEBUG
  psync_sql_do_rdlock(file, line);
#else
  psync_sql_rdlock();
#endif
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_rdunlock();
#if IS_DEBUG
    debug(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql, sqlite3_errmsg(psync_db), file, line);
    senddebug("error running sql statement: %s: %s called from %s:%u", sql, sqlite3_errmsg(psync_db), file, line);
#else
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    senddebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
#endif
    return NULL;
  }
  cnt=sqlite3_column_count(stmt);
  res=(psync_sql_res *)psync_malloc(sizeof(psync_sql_res)+cnt*sizeof(psync_variant));
  res->stmt=stmt;
  res->sql=sql;
  res->column_count=cnt;
  res->locked=SQL_READ_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_rdlock(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_query_rdlock(const char *sql){
#endif
  psync_sql_res *ret;
  ret=(psync_sql_res *)psync_cache_get(sql);
  if (ret){
//    debug(D_NOTICE, "got query %s from cache", sql);
    ret->locked=SQL_READ_LOCK;
    ret->sql=sql;
#if IS_DEBUG
    psync_sql_do_rdlock(file, line);
#else
    psync_sql_rdlock();
#endif
    return ret;
  }
  else
#if IS_DEBUG
    return psync_sql_do_query_rdlock_nocache(sql, file, line);
#else
    return psync_sql_query_rdlock_nocache(sql);
#endif
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_nolock_nocache(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_query_nolock_nocache(const char *sql){
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
#if IS_DEBUG
  if (!psync_sql_islocked()){
    debug(D_BUG, "illegal use of psync_sql_query_nolock, can only be used while holding lock, invoked from %s:%u, sql: %s", file, line, sql);
    senddebug("illegal use of psync_sql_query_nolock, can only be used while holding lock, invoked from %s:%u, sql: %s", file, line, sql);
    abort();
  }
#endif
  psync_sql_check_query_plan(sql);
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    senddebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt=sqlite3_column_count(stmt);
  res=(psync_sql_res *)psync_malloc(sizeof(psync_sql_res)+cnt*sizeof(psync_variant));
  res->stmt=stmt;
  res->sql=sql;
  res->column_count=cnt;
  res->locked=SQL_NO_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_nolock(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_query_nolock(const char *sql){
#endif
  psync_sql_res *ret;
#if IS_DEBUG
  if (!psync_sql_islocked()){
    debug(D_BUG, "illegal use of psync_sql_query_nolock, can only be used while holding lock, invoked from %s:%u, sql: %s", file, line, sql);
    senddebug("illegal use of psync_sql_query_nolock, can only be used while holding lock, invoked from %s:%u, sql: %s", file, line, sql);
    abort();
  }
#endif
  ret=(psync_sql_res *)psync_cache_get(sql);
  if (ret){
//    debug(D_NOTICE, "got query %s from cache", sql);
    ret->locked=SQL_NO_LOCK;
    ret->sql=sql;
    return ret;
  }
  else
#if IS_DEBUG
    return psync_sql_do_query_nolock_nocache(sql, file, line);
#else
    return psync_sql_query_nolock_nocache(sql);
#endif
}

static void psync_sql_free_cache(void *ptr){
  psync_sql_res *res=(psync_sql_res *)ptr;
  sqlite3_finalize(res->stmt);
#if IS_DEBUG
  memset(res, 0xff, sizeof(psync_sql_res));
#endif
  psync_free(res);
}

static void psync_sql_res_unlock(psync_sql_res *res){
  switch (res->locked){
    case SQL_NO_LOCK:
      break;
    case SQL_READ_LOCK:
      psync_sql_rdunlock();
      break;
    case SQL_WRITE_LOCK:
      psync_sql_unlock();
      break;
#if IS_DEBUG
    default:
      debug(D_ERROR, "unknown value for locked %d", res->locked);
      abort();
#endif
  }
}

void psync_sql_free_result(psync_sql_res *res){
  int code=sqlite3_reset(res->stmt);
  psync_sql_res_unlock(res);
#if IS_DEBUG
  memset(res->row, 0xff, res->column_count*sizeof(psync_variant));
#endif
  if (code==SQLITE_OK)
    psync_cache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache, PSYNC_QUERY_MAX_CNT);
  else
    psync_sql_free_cache(res);
}

void psync_sql_free_result_nocache(psync_sql_res *res){
  sqlite3_finalize(res->stmt);
  psync_sql_res_unlock(res);
#if IS_DEBUG
  memset(res, 0xff, sizeof(psync_sql_res));
#endif
  psync_free(res);
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_prep_statement_nocache(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_prep_statement_nocache(const char *sql){
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code;
  psync_sql_check_query_plan(sql);
#if IS_DEBUG
  psync_sql_do_lock(file, line);
#else
  psync_sql_lock();
#endif
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
#if IS_DEBUG
    debug(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql, sqlite3_errmsg(psync_db), file, line);
    senddebug("error running sql statement: %s: %s called from %s:%u", sql, sqlite3_errmsg(psync_db), file, line);
#else
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    senddebug("error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
#endif
    return NULL;
  }
  res=psync_new(psync_sql_res);
  res->stmt=stmt;
  res->sql=sql;
#if IS_DEBUG
  res->column_count=0;
#endif
  res->locked=SQL_WRITE_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_prep_statement(const char *sql, const char *file, unsigned line){
#else
psync_sql_res *psync_sql_prep_statement(const char *sql){
#endif
  psync_sql_res *ret;
  ret=psync_cache_get(sql);
  if (ret){
//    debug(D_NOTICE, "got statement %s from cache", sql);
    ret->locked=SQL_WRITE_LOCK;
#if IS_DEBUG
    psync_sql_do_lock(file, line);
#else
    psync_sql_lock();
#endif
    return ret;
  }
  else
#if IS_DEBUG
    return psync_sql_do_prep_statement_nocache(sql, file, line);
#else
    return psync_sql_prep_statement_nocache(sql);
#endif
}

int psync_sql_reset(psync_sql_res *res){
  int code=sqlite3_reset(res->stmt);
  if (unlikely(code!=SQLITE_OK)){
    debug(D_ERROR, "sqlite3_reset returned error: %s", sqlite3_errmsg(psync_db));
    return -1;
  }
  else
    return 0;
}

int psync_sql_run(psync_sql_res *res){
  int code=sqlite3_step(res->stmt);
  if (unlikely(code!=SQLITE_DONE)){
    debug(D_ERROR, "sqlite3_step returned error: %s: %s", sqlite3_errmsg(psync_db), res->sql);
    sendtdebug("sqlite3_step returned error (in_transaction=%d): %s: %s", in_transaction, sqlite3_errmsg(psync_db), res->sql);
    transaction_failed=1;
    if (in_transaction)
      debug(D_BUG, "transaction query failed, this may lead to restarting transaction over and over");
    return -1;
  }
  code=sqlite3_reset(res->stmt);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "sqlite3_reset returned error: %s", sqlite3_errmsg(psync_db));
  return 0;
}

int psync_sql_run_free_nocache(psync_sql_res *res){
  int code=sqlite3_step(res->stmt);
  if (unlikely(code!=SQLITE_DONE)){
    debug(D_ERROR, "sqlite3_step returned error: %s: %s", sqlite3_errmsg(psync_db), res->sql);
    sendtdebug("sqlite3_step returned error (in_transaction=%d): %s: %s", in_transaction, sqlite3_errmsg(psync_db), res->sql);
    code=-1;
    transaction_failed=1;
    if (in_transaction)
      debug(D_BUG, "transaction query failed, this may lead to restarting transaction over and over");
  }
  else
    code=0;
  sqlite3_finalize(res->stmt);
  psync_sql_res_unlock(res);
  psync_free(res);
  return code;
}

int psync_sql_run_free(psync_sql_res *res){
  int code=sqlite3_step(res->stmt);
  if (unlikely(code!=SQLITE_DONE || (code=sqlite3_reset(res->stmt))!=SQLITE_OK)){
    debug(D_ERROR, "sqlite3_step returned error: %s: %s", sqlite3_errmsg(psync_db), res->sql);
    sendtdebug("sqlite3_step returned error (in_transaction=%d): %s: %s", in_transaction, sqlite3_errmsg(psync_db), res->sql);
    sqlite3_finalize(res->stmt);
    transaction_failed=1;
    if (in_transaction)
      debug(D_BUG, "transaction query failed, this may lead to restarting transaction over and over");
    psync_sql_res_unlock(res);
    psync_free(res);
    return -1;
  }
  else{
    psync_sql_res_unlock(res);
    psync_cache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache, PSYNC_QUERY_MAX_CNT);
    return 0;
  }
}

void psync_sql_bind_int(psync_sql_res *res, int n, int64_t val){
  int code=sqlite3_bind_int64(res->stmt, n, val);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_uint(psync_sql_res *res, int n, uint64_t val){
  int code=sqlite3_bind_int64(res->stmt, n, val);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_double(psync_sql_res *res, int n, double val){
  int code=sqlite3_bind_double(res->stmt, n, val);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_string(psync_sql_res *res, int n, const char *str){
  int code=sqlite3_bind_text(res->stmt, n, str, -1, SQLITE_STATIC);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));}

void psync_sql_bind_lstring(psync_sql_res *res, int n, const char *str, size_t len){
  int code=sqlite3_bind_text(res->stmt, n, str, len, SQLITE_STATIC);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_blob(psync_sql_res *res, int n, const char *str, size_t len){
  int code=sqlite3_bind_blob(res->stmt, n, str, len, SQLITE_STATIC);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_null(psync_sql_res *res, int n){
  int code=sqlite3_bind_null(res->stmt, n);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

psync_variant_row psync_sql_fetch_row(psync_sql_res *res){
  int code, i;
  code=sqlite3_step(res->stmt);
  if (code==SQLITE_ROW){
    for (i=0; i<res->column_count; i++){
      code=sqlite3_column_type(res->stmt, i);
      if (code==SQLITE_INTEGER){
        res->row[i].type=PSYNC_TNUMBER;
        res->row[i].snum=sqlite3_column_int64(res->stmt, i);
      }
      else if (code==SQLITE_TEXT || code==SQLITE_BLOB){
        res->row[i].type=PSYNC_TSTRING;
        res->row[i].length=sqlite3_column_bytes(res->stmt, i);
        res->row[i].str=(char *)sqlite3_column_text(res->stmt, i);
      }
      else if (code==SQLITE_FLOAT){
        res->row[i].type=PSYNC_TREAL;
        res->row[i].real=sqlite3_column_double(res->stmt, i);
      }
      else
        res->row[i].type=PSYNC_TNULL;
    }
    return res->row;
  }
  else {
    if (unlikely(code!=SQLITE_DONE))
      debug(D_ERROR, "sqlite3_step returned error: %s", sqlite3_errmsg(psync_db));
    return NULL;
  }
}

psync_str_row psync_sql_fetch_rowstr(psync_sql_res *res){
  int code, i;
  const char **strs;
  code=sqlite3_step(res->stmt);
  if (code==SQLITE_ROW){
    strs=(const char **)res->row;
    for (i=0; i<res->column_count; i++)
      strs[i]=(const char *)sqlite3_column_text(res->stmt, i);
    return strs;
  }
  else {
    if (unlikely(code!=SQLITE_DONE))
      debug(D_ERROR, "sqlite3_step returned error: %s", sqlite3_errmsg(psync_db));
    return NULL;
  }
}

const uint64_t *psync_sql_fetch_rowint(psync_sql_res *res){
  int code, i;
  uint64_t *ret;
  code=sqlite3_step(res->stmt);
  if (code==SQLITE_ROW){
    ret=(uint64_t *)res->row;
    for (i=0; i<res->column_count; i++)
      ret[i]=sqlite3_column_int64(res->stmt, i);
    return ret;
  }
  else {
    if (unlikely(code!=SQLITE_DONE))
      debug(D_ERROR, "sqlite3_step returned error: %s", sqlite3_errmsg(psync_db));
    return NULL;
  }
}

psync_full_result_int *psync_sql_fetchall_int(psync_sql_res *res){
  uint64_t *data;
  psync_full_result_int *ret;
  psync_uint_t rows, cols, off, i, all;
  int code;
  cols=res->column_count;
  rows=0;
  off=0;
  all=0;
  data=NULL;
  while ((code=sqlite3_step(res->stmt))==SQLITE_ROW){
    if (rows>=all){
      all=10+all*2;
      data=(uint64_t *)psync_realloc(data, sizeof(uint64_t)*cols*all);
    }
    for (i=0; i<cols; i++)
      data[off+i]=sqlite3_column_int64(res->stmt, i);
    off+=cols;
    rows++;
  }
  if (unlikely(code!=SQLITE_DONE))
    debug(D_ERROR, "sqlite3_step returned error: %s", sqlite3_errmsg(psync_db));
  psync_sql_free_result(res);
  ret=(psync_full_result_int *)psync_malloc(offsetof(psync_full_result_int, data)+sizeof(uint64_t)*off);
  ret->rows=rows;
  ret->cols=cols;
  memcpy(ret->data, data, sizeof(uint64_t)*off);
  psync_free(data);
  return ret;
}

uint32_t psync_sql_affected_rows(){
  return sqlite3_changes(psync_db);
}

uint64_t psync_sql_insertid(){
  return sqlite3_last_insert_rowid(psync_db);
}

int psync_rename_conflicted_file(const char *path){
  char *npath;
  size_t plen, dotidx;
  psync_stat_t st;
  psync_int_t num, l;
  plen=strlen(path);
  dotidx=plen;
  while (dotidx && path[dotidx]!='.')
    dotidx--;
  if (!dotidx)
    dotidx=plen;
  npath=(char *)psync_malloc(plen+32);
  memcpy(npath, path, dotidx);
  num=0;
  while (1){
    if (num)
      l=psync_slprintf(npath+dotidx, 32, " (conflicted %"P_PRI_I")", num);
    else{
      l=13;
      memcpy(npath+dotidx, " (conflicted)", l);
    }
    memcpy(npath+dotidx+l, path+dotidx, plen-dotidx+1);
    if (psync_stat(npath, &st)){
      debug(D_NOTICE, "renaming conflict %s to %s", path, npath);
      l=psync_file_rename(path, npath);
      psync_free(npath);
      return l;
    }
    num++;
  }
}

void psync_libs_init(){
  psync_uint_t i;
  for (i=0; i<256; i++)
    normalize_table[i]=i;
  normalize_table[':']='_';
  normalize_table['/']='_';
  normalize_table['\\']='_';
}

static void run_after_sec(psync_timer_t timer, void *ptr){
  struct run_after_ptr *fp=(struct run_after_ptr *)ptr;
  psync_timer_stop(timer);
  fp->run(fp->ptr);
  psync_free(fp);
}

void psync_run_after_sec(psync_run_after_t run, void *ptr, uint32_t seconds){
  struct run_after_ptr *fp;
  fp=psync_new(struct run_after_ptr);
  fp->run=run;
  fp->ptr=ptr;
  psync_timer_register(run_after_sec, seconds, fp);
}

static void free_after_sec(psync_timer_t timer, void *ptr){
  psync_timer_stop(timer);
  psync_free(ptr);
}

void psync_free_after_sec(void *ptr, uint32_t seconds){
  psync_timer_register(free_after_sec, seconds, ptr);
}

int psync_match_pattern(const char *name, const char *pattern, size_t plen){
  size_t i;
  for (i=0; i<plen; i++){
    if (pattern[i]=='*'){
      name+=i;
      while (1){
        if (++i==plen)
          return 1;
        switch (pattern[i]){
          case '?':
            if (!*name++)
              return 0;
          case '*':
            break;
          default:
            name=strchr(name, pattern[i]);
            pattern+=i+1;
            plen-=i+1;
            while (name){
              name++;
              if (psync_match_pattern(name, pattern, plen))
                return 1;
              name=strchr(name, *(pattern-1));
            }
            return 0;
        }
      }
    }
    else if (!name[i] || (pattern[i]!=name[i] && pattern[i]!='?'))
      return 0;
  }
  return name[i]==0;
}

uint64_t psync_ato64(const char *str){
  uint64_t n=0;
  while (*str>='0' && *str<='9')
    n=n*10+(*str++)-'0';
  return n;
}

uint32_t psync_ato32(const char *str){
  uint32_t n=0;
  while (*str>='0' && *str<='9')
    n=n*10+(*str++)-'0';
  return n;
}

typedef struct {
  psync_list list;
  psync_uint_t used;
  char elements[];
} psync_list_element_list;

typedef struct {
  psync_list list;
  char *next;
  char *end;
} psync_list_string_list;

typedef struct {
  psync_list list;
  psync_uint_t used;
  uint32_t numbers[1000];
} psync_list_num_list;

struct psync_list_builder_t_{
  size_t element_size;
  size_t elements_offset;
  size_t elements_per_list;
  size_t stringalloc;
  uint64_t cnt;
  psync_list element_list;
  psync_list_element_list *last_elements;
  psync_list string_list;
  psync_list_string_list *last_strings;
  psync_list number_list;
  psync_list_num_list *last_numbers;
  psync_uint_t popoff;
  char *current_element;
  uint32_t *cstrcnt;
};

psync_list_builder_t *psync_list_builder_create(size_t element_size, size_t offset){
  psync_list_builder_t *builder;
  builder=psync_new(psync_list_builder_t);
  builder->element_size=element_size;
  builder->elements_offset=offset;
  if (element_size<=200)
    builder->elements_per_list=40;
  else
    builder->elements_per_list=12;
  builder->cnt=0;
  builder->stringalloc=0;
  psync_list_init(&builder->element_list);
  builder->last_elements=NULL;
  psync_list_init(&builder->string_list);
  builder->last_strings=NULL;
  psync_list_init(&builder->number_list);
  builder->last_numbers=NULL;
  return builder;
}

static uint32_t *psync_list_bulder_push_num(psync_list_builder_t *builder){
  if (!builder->last_numbers || builder->last_numbers->used>=sizeof(builder->last_numbers->numbers)/sizeof(uint32_t)){
    psync_list_num_list *l=psync_new(psync_list_num_list);
    l->used=0;
    builder->last_numbers=l;
    psync_list_add_tail(&builder->number_list, &l->list);
  }
  return &builder->last_numbers->numbers[builder->last_numbers->used++];
}

static uint32_t psync_list_bulder_pop_num(psync_list_builder_t *builder){
  uint32_t ret;
  ret=builder->last_numbers->numbers[builder->popoff++];
  if (builder->popoff>=builder->last_numbers->used){
    builder->last_numbers=psync_list_element(builder->last_numbers->list.next, psync_list_num_list, list);
    builder->popoff=0;
  }
  return ret;
}

void psync_list_bulder_add_sql(psync_list_builder_t *builder, psync_sql_res *res, psync_list_builder_sql_callback callback){
  psync_variant_row row;
  while ((row=psync_sql_fetch_row(res))){
    if (!builder->last_elements || builder->last_elements->used>=builder->elements_per_list){
      builder->last_elements=(psync_list_element_list *)psync_malloc(offsetof(psync_list_element_list, elements)+builder->element_size*builder->elements_per_list);
      psync_list_add_tail(&builder->element_list, &builder->last_elements->list);
      builder->last_elements->used=0;
    }
    builder->current_element=builder->last_elements->elements+builder->last_elements->used*builder->element_size;
    builder->cstrcnt=psync_list_bulder_push_num(builder);
    *builder->cstrcnt=0;
    while (callback(builder, builder->current_element, row)){
      row=psync_sql_fetch_row(res);
      if (!row)
        break;
      *builder->cstrcnt=0;
    }
    builder->last_elements->used++;
    builder->cnt++;
  }
  psync_sql_free_result(res);
}

void *psync_list_bulder_add_element(psync_list_builder_t *builder){
  if (!builder->last_elements || builder->last_elements->used>=builder->elements_per_list){
    builder->last_elements=(psync_list_element_list *)psync_malloc(offsetof(psync_list_element_list, elements)+builder->element_size*builder->elements_per_list);
    psync_list_add_tail(&builder->element_list, &builder->last_elements->list);
    builder->last_elements->used=0;
  }
  builder->current_element=builder->last_elements->elements+builder->last_elements->used*builder->element_size;
  builder->cstrcnt=psync_list_bulder_push_num(builder);
  *builder->cstrcnt=0;
  builder->last_elements->used++;
  builder->cnt++;
  return builder->current_element;
}

void psync_list_add_lstring_offset(psync_list_builder_t *builder, size_t offset, size_t length){
  char **str, *s;
  psync_list_string_list *l;
  length++;
  str=(char **)(builder->current_element+offset);
  builder->stringalloc+=length;
  if (unlikely(length>2000)){
    l=(psync_list_string_list *)psync_malloc(sizeof(psync_list_string_list)+length);
    s=(char *)(l+1);
    psync_list_add_tail(&builder->string_list, &l->list);
  }
  else if (!builder->last_strings || builder->last_strings->next+length>builder->last_strings->end){
    l=(psync_list_string_list *)psync_malloc(sizeof(psync_list_string_list)+4000);
    s=(char *)(l+1);
    l->next=s+length;
    l->end=s+4000;
    psync_list_add_tail(&builder->string_list, &l->list);
    builder->last_strings=l;
  }
  else {
    s=builder->last_strings->next;
    builder->last_strings->next+=length;
  }
  memcpy(s, *str, length);
  *str=s;
  *(psync_list_bulder_push_num(builder))=offset;
  *(psync_list_bulder_push_num(builder))=length;
  (*builder->cstrcnt)++;
}

void psync_list_add_string_offset(psync_list_builder_t *builder, size_t offset){
  psync_list_add_lstring_offset(builder, offset, strlen(*((char **)(builder->current_element+offset))));
}

void *psync_list_builder_finalize(psync_list_builder_t *builder){
  char *ret, *elem, *str;
  char **pstr;
  psync_list_element_list *el;
  psync_uint_t i;
  uint32_t j, scnt, offset, length;
  size_t sz;
  sz=builder->elements_offset+builder->element_size*builder->cnt+builder->stringalloc;
  debug(D_NOTICE, "allocating %lu bytes, %lu of which for strings", (unsigned long)sz, (unsigned long)builder->stringalloc);
  ret=psync_new_cnt(char, sz);
  if (builder->elements_offset<=sizeof(builder->cnt))
    memcpy(ret, &builder->cnt, builder->elements_offset);
  else
    memcpy(ret, &builder->cnt, sizeof(builder->cnt));
  elem=ret+builder->elements_offset;
  str=elem+builder->element_size*builder->cnt;

  builder->last_numbers=psync_list_element(builder->number_list.next, psync_list_num_list, list);
  builder->popoff=0;

  psync_list_for_each_element(el, &builder->element_list, psync_list_element_list, list){
    for (i=0; i<el->used; i++){
      memcpy(elem, el->elements+(i*builder->element_size), builder->element_size);
      scnt=psync_list_bulder_pop_num(builder);
      for (j=0; j<scnt; j++){
        offset=psync_list_bulder_pop_num(builder);
        length=psync_list_bulder_pop_num(builder);
        pstr=(char **)(elem+offset);
        memcpy(str, *pstr, length);
        *pstr=str;
        str+=length;
      }
      elem+=builder->element_size;
    }
  }

  psync_list_for_each_element_call(&builder->element_list, psync_list_element_list, list, psync_free);
  psync_list_for_each_element_call(&builder->string_list, psync_list_string_list, list, psync_free);
  psync_list_for_each_element_call(&builder->number_list, psync_list_num_list, list, psync_free);
  psync_free(builder);
  return ret;
}

#define PSYNC_TASK_STATUS_RUNNING  0
#define PSYNC_TASK_STATUS_READY    1
#define PSYNC_TASK_STATUS_DONE     2
#define PSYNC_TASK_STATUS_RETURNED 3

struct psync_task_t_{
  psync_task_callback_t callback;
  void *param;
  pthread_cond_t cond;
  int id;
  int status;
};

#define PSYNC_WAIT_ANYBODY -1
#define PSYNC_WAIT_NOBODY  -2
#define PSYNC_WAIT_FREED   -3

struct psync_task_manager_t_{
  pthread_mutex_t mutex;
  int taskcnt;
  int refcnt;
  int waitfor;
  struct psync_task_t_ tasks[];
};

static void psync_task_destroy(psync_task_manager_t tm){
  int i;
  for (i=0; i<tm->taskcnt; i++)
    pthread_cond_destroy(&tm->tasks[i].cond);
  pthread_mutex_destroy(&tm->mutex);
  psync_free(tm);
}

static void psync_task_dec_refcnt(psync_task_manager_t tm){
  int refcnt;
  pthread_mutex_lock(&tm->mutex);
  refcnt=--tm->refcnt;
  pthread_mutex_unlock(&tm->mutex);
  if (!refcnt)
    psync_task_destroy(tm);
}

static psync_task_manager_t psync_get_manager_of_task(struct psync_task_t_ *t){
  return (psync_task_manager_t)(((char *)(t-t->id))-offsetof(struct psync_task_manager_t_, tasks));
}

static void psync_task_entry(void *ptr){
  struct psync_task_t_ *t;
  t=(struct psync_task_t_*)ptr;
  t->callback(ptr, t->param);
  psync_task_dec_refcnt(psync_get_manager_of_task(t));
}

psync_task_manager_t psync_task_run_tasks(psync_task_callback_t const *callbacks, void *const *params, int cnt){
  psync_task_manager_t ret;
  struct psync_task_t_ *t;
  int i;
  ret=(psync_task_manager_t)psync_malloc(offsetof(struct psync_task_manager_t_, tasks)+sizeof(struct psync_task_t_)*cnt);
  pthread_mutex_init(&ret->mutex, NULL);
  ret->taskcnt=cnt;
  ret->refcnt=cnt+1;
  ret->waitfor=PSYNC_WAIT_NOBODY;
  for (i=0; i<cnt; i++){
    t=&ret->tasks[i];
    t->callback=callbacks[i];
    t->param=params[i];
    pthread_cond_init(&t->cond, NULL);
    t->id=i;
    t->status=PSYNC_TASK_STATUS_RUNNING;
    psync_run_thread1("task", psync_task_entry, t);
  }
  return ret;
}

void *psync_task_get_result(psync_task_manager_t tm, int id){
  void *ret;
  pthread_mutex_lock(&tm->mutex);
  if (tm->tasks[id].status==PSYNC_TASK_STATUS_RUNNING){
    do {
      tm->waitfor=id;
      pthread_cond_wait(&tm->tasks[id].cond, &tm->mutex);
      tm->waitfor=PSYNC_WAIT_NOBODY;
    } while (tm->tasks[id].status==PSYNC_TASK_STATUS_RUNNING);
    ret=tm->tasks[id].param;
    tm->tasks[id].status=PSYNC_TASK_STATUS_DONE;
  }
  else if (tm->tasks[id].status==PSYNC_TASK_STATUS_READY){
    ret=tm->tasks[id].param;
    tm->tasks[id].status=PSYNC_TASK_STATUS_DONE;
    pthread_cond_signal(&tm->tasks[id].cond);
  }
  else{
    debug(D_BUG, "invalid status %d of task id %d", (int)tm->tasks[id].status, id);
    ret=NULL;
  }
  pthread_mutex_unlock(&tm->mutex);
  return ret;
}

void psync_task_free(psync_task_manager_t tm){
  if (tm->refcnt==1)
    psync_task_destroy(tm);
  else{
    int refcnt, i;
    pthread_mutex_lock(&tm->mutex);
    tm->waitfor=PSYNC_WAIT_FREED;
    for (i=0; i<tm->taskcnt; i++)
      if (tm->tasks[i].status==PSYNC_TASK_STATUS_READY){
        tm->tasks[i].status=PSYNC_TASK_STATUS_RETURNED;
        pthread_cond_signal(&tm->tasks[i].cond);
      }
    refcnt=--tm->refcnt;
    pthread_mutex_unlock(&tm->mutex);
    if (!refcnt)
      psync_task_destroy(tm);
  }
}

int psync_task_complete(void *h, void *data){
  psync_task_manager_t tm;
  struct psync_task_t_ *t;
  int ret;
  t=(struct psync_task_t_ *)h;
  tm=psync_get_manager_of_task(t);
  pthread_mutex_lock(&tm->mutex);
  if (tm->waitfor==t->id){
    t->param=data;
    t->status=PSYNC_TASK_STATUS_READY;
    pthread_cond_signal(&t->cond);
    ret=0;
  }
  else if (tm->waitfor==PSYNC_WAIT_NOBODY || tm->waitfor>=0){
    t->param=data;
    t->status=PSYNC_TASK_STATUS_READY;
    do {
      pthread_cond_wait(&t->cond, &tm->mutex);
    } while (t->status==PSYNC_TASK_STATUS_READY);
    if (t->status==PSYNC_TASK_STATUS_RETURNED)
      ret=-1;
    else
      ret=0;
  }
  else if (tm->waitfor==PSYNC_WAIT_FREED)
    ret=-1;
  else{
    debug(D_BUG, "invalid waitfor value %d", tm->waitfor);
    ret=-1;
  }
  pthread_mutex_unlock(&tm->mutex);
  return ret;
}


#define rot(x,k) (((x)<<(k))|((x)>>(32-(k))))
static uint32_t pq_rnd() {
  static uint32_t a=0x95ae3d25, b=0xe225d755, c=0xc63a2ae7, d=0xe4556265;
  uint32_t e=a-rot(b, 27);
  a=b^rot(c, 17);
  b=c+d;
  c=d+e;
  d=e+a;
  return d;
}

#define QSORT_TRESH  8
#define QSORT_MTR   64
#define QSORT_REC_M (16*1024)

static inline void sw2(unsigned char **a, unsigned char **b) {
  unsigned char *tmp=*a;
  *a=*b;
  *b=tmp;
}

static unsigned char *med5(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *d, unsigned char *e,
                           int (*compar)(const void *, const void *)) {
  if (compar(b, a)<0)
    sw2(&a, &b);
  if (compar(d, c)<0)
    sw2(&c, &d);
  if (compar(a, c)<0) {
    a=e;
    if (compar(b, a)<0)
      sw2(&a, &b);
  } else {
    c=e;
    if (compar(d, c)<0)
      sw2(&c, &d);
  }
  if (compar(a, c)<0)
    a=b;
  else
    c=d;
  if (compar(a, c)<0)
    return a;
  else
    return c;
}

unsigned char *pq_choose_part(unsigned char *base, size_t cnt, size_t size, int (*compar)(const void *, const void *)) {
  if (cnt>=QSORT_REC_M) {
    cnt/=5;
    return med5(pq_choose_part(base, cnt, size, compar),
                pq_choose_part(base+cnt*size, cnt, size, compar),
                pq_choose_part(base+cnt*size*2, cnt, size, compar),
                pq_choose_part(base+cnt*size*3, cnt, size, compar),
                pq_choose_part(base+cnt*size*4, cnt, size, compar),
                compar);
  } else {
    return med5(base+(pq_rnd()%cnt)*size, base+(pq_rnd()%cnt)*size, base+(pq_rnd()%cnt)*size, base+(pq_rnd()%cnt)*size, base+(pq_rnd()%cnt)*size, compar);
  }
}

static inline void pqsswap(unsigned char *a, unsigned char *b, size_t size) {
  unsigned char tmp;
  do {
    tmp=*a;
    *a++=*b;
    *b++=tmp;
  } while (--size);
}

static inline void pqsswap32(unsigned char *a, unsigned char *b, size_t size) {
  uint32_t tmp;
  do {
    tmp=*(uint32_t *)a;
    *(uint32_t *)a=*(uint32_t *)b;
    *(uint32_t *)b=tmp;
    a+=sizeof(uint32_t);
    b+=sizeof(uint32_t);
  } while (--size);
}


typedef struct {
  unsigned char *lo;
  unsigned char *hi;
} psq_stack_t;

void psync_pqsort(void *base, size_t cnt, size_t sort_first, size_t size, int (*compar)(const void *, const void *)) {
  psq_stack_t stack[sizeof(size_t)*8];
  psq_stack_t *top;
  unsigned char *lo, *hi, *mid, *l, *r, *sf;
  size_t tresh, n, u32size;
  tresh=QSORT_TRESH*size;
  sf=(unsigned char *)base+sort_first*size;
  if (size%sizeof(uint32_t)==0 && (uintptr_t)base%sizeof(uint32_t)==0)
    u32size=size/sizeof(uint32_t);
  else
    u32size=0;
  if (cnt>QSORT_TRESH) {
    top=stack+1;
    lo=(unsigned char *)base;
    hi=lo+(cnt-1)*size;
    do {
      n=(hi-lo)/size;
      if (n<=QSORT_MTR) {
        mid=lo+(n>>1)*size;
        if (compar(mid, lo)<0)
          pqsswap(mid, lo, size);
        if (compar(hi, mid)<0) {
          pqsswap(mid, hi, size);
          if (compar(mid, lo)<0)
            pqsswap(mid, lo, size);
        }
        // we already sure *hi and *lo are good, so they will be skipped without checking
        l=lo;
        r=hi;
      } else {
        mid=pq_choose_part(lo, n, size, compar);
        l=lo-size;
        r=hi+size;
      }
      if (u32size) {
        do {
          do {
            l+=size;
          } while (compar(l, mid)<0);
          do {
            r-=size;
          } while (compar(mid, r)<0);
          if (l>=r)
            break;
          pqsswap32(l, r, u32size);
          if (mid==l) {
            mid=r;
            r+=size;
          } else if (mid==r) {
            mid=l;
            l-=size;
          }
        } while (1);
      } else {
        do {
          do {
            l+=size;
          } while (compar(l, mid)<0);
          do {
            r-=size;
          } while (compar(mid, r)<0);
          if (l>=r)
            break;
          pqsswap(l, r, size);
          if (mid==l) {
            mid=r;
            r+=size;
          } else if (mid==r) {
            mid=l;
            l-=size;
          }
        } while (1);
      }
      if (hi-mid<=tresh || mid>=sf) {
        if (mid-lo<=tresh) {
          top--;
          lo=top->lo;
          hi=top->hi;
        } else {
          hi=mid-size;
        }
      } else if (mid-lo<=tresh) {
        lo=mid+size;
      } else if (hi-mid<mid-lo) {
        top->lo=lo;
        top->hi=mid-size;
        top++;
        lo=mid+size;
      } else {
        top->lo=mid+size;
        top->hi=hi;
        top++;
        hi=mid-size;
      }
    } while (top!=stack);
  } else if (cnt<=1) {
    return;
  }
  lo=(unsigned char *)base;
  hi=lo+(cnt-1)*size;
  sf+=size*QSORT_TRESH;
  if (sf<hi)
    hi=sf;
  r=lo+QSORT_TRESH*size+4;
  if (r>hi)
    r=hi;
  for (l=lo+size; l<=r; l+=size)
    if (compar(l, lo)<0)
      lo=l;
  pqsswap((unsigned char *)base, lo, size);
  l=(unsigned char *)base+size;
  hi-=size;
  while (l<=hi) {
    lo=l;
    l+=size;
    while (compar(l, lo)<0)
      lo-=size;
    lo+=size;
    if (lo!=l) {
      unsigned char *t=l+size;
      if (u32size) {
        while ((t-=sizeof(uint32_t))>=l) {
          uint32_t tmp=*(uint32_t *)t;
          for (r=mid=t; (mid-=size)>=lo; r=mid)
            *(uint32_t *)r=*(uint32_t *)mid;
          *(uint32_t *)r=tmp;
        }
      } else {
        while (--t>=l) {
          unsigned char tmp=*t;
          for (r=mid=t; (mid-=size)>=lo; r=mid)
            *r=*mid;
          *r=tmp;
        }
      }
    }
  }
}

void psync_qpartition(void *base, size_t cnt, size_t sort_first, size_t size, int (*compar)(const void *, const void *)) {
  unsigned char *lo, *hi, *mid, *l, *r, *sf;
  size_t n, u32size;
  sf=(unsigned char *)base+sort_first*size;
  if (size%sizeof(uint32_t)==0 && (uintptr_t)base%sizeof(uint32_t)==0)
    u32size=size/sizeof(uint32_t);
  else
    u32size=0;
  if (cnt<=1) // otherwise cnt-1 will underflow
    return;
  lo=(unsigned char *)base;
  hi=lo+(cnt-1)*size;
  while (1) {
    n=(hi-lo)/size;
    if (n<=QSORT_MTR) {
      mid=lo+(n>>1)*size;
      if (compar(mid, lo)<0)
        pqsswap(mid, lo, size);
      if (compar(hi, mid)<0) {
        pqsswap(mid, hi, size);
        if (compar(mid, lo)<0)
          pqsswap(mid, lo, size);
      }
      // we already sure *hi and *lo are good, so they will be skipped without checking
      if (n<=2) // when n is 2, we have 3 elements
        return;
      l=lo;
      r=hi;
    } else {
      mid=pq_choose_part(lo, n, size, compar);
      l=lo-size;
      r=hi+size;
    }
    if (u32size) {
      do {
        do {
          l+=size;
        } while (compar(l, mid)<0);
        do {
          r-=size;
        } while (compar(mid, r)<0);
        if (l>=r)
          break;
        pqsswap32(l, r, u32size);
        if (mid==l) {
          mid=r;
          r+=size;
        } else if (mid==r) {
          mid=l;
          l-=size;
        }
      } while (1);
    } else {
      do {
        do {
          l+=size;
        } while (compar(l, mid)<0);
        do {
          r-=size;
        } while (compar(mid, r)<0);
        if (l>=r)
          break;
        pqsswap(l, r, size);
        if (mid==l) {
          mid=r;
          r+=size;
        } else if (mid==r) {
          mid=l;
          l-=size;
        }
      } while (1);
    }
    if (mid<sf)
      lo=mid+size;
    else if (mid>sf)
      hi=mid-size;
    else
      return;
  }
}

void psync_try_free_memory(){
  sqlite3_db_release_memory(psync_db);
  psync_cache_clean_all();
}

static void time_format(time_t tm, unsigned long ns, char *result){
  static const char month_names[12][4]={"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  static const char day_names[7][4] ={"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  struct tm dt;
  psync_uint_t y;
  ns/=1000000;
  gmtime_r(&tm, &dt);
  memcpy(result, day_names[dt.tm_wday], 3);
  result+=3;
  *result++=',';
  *result++=' ';
  *result++=dt.tm_mday/10+'0';
  *result++=dt.tm_mday%10+'0';
  *result++=' ';
  memcpy(result, month_names[dt.tm_mon], 3);
  result+=3;
  *result++=' ';
  y=dt.tm_year+1900;
  *result++='0'+y/1000;
  y=y%1000;
  *result++='0'+y/100;
  y=y%100;
  *result++='0'+y/10;
  y=y%10;
  *result++='0'+y;
  *result++=' ';
  *result++=dt.tm_hour/10+'0';
  *result++=dt.tm_hour%10+'0';
  *result++=':';
  *result++=dt.tm_min/10+'0';
  *result++=dt.tm_min%10+'0';
  *result++=':';
  *result++=dt.tm_sec/10+'0';
  *result++=dt.tm_sec%10+'0';
  *result++='.';
  *result++=ns/100+'0';
  *result++=(ns/10)%10+'0';
  *result++=ns%10+'0';
  memcpy(result, " +0000", 7); // copies the null byte
}

int psync_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...){
  static const struct {
    psync_uint_t level;
    const char *name;
  } debug_levels[]=DEBUG_LEVELS;
  static FILE *log=NULL;
  struct timespec ts;
  char dttime[36], format[512];
  va_list ap;
  const char *errname;
  psync_uint_t i;
  unsigned int u;
  pthread_t threadid;
#if defined(P_OS_WINDOWS)
  errname=strrchr(file, '\\');
  if (errname)
    file=errname+1;
#endif
  errname="BAD_ERROR_CODE";
  for (i=0; i<ARRAY_SIZE(debug_levels); i++)
    if (debug_levels[i].level==level){
      errname=debug_levels[i].name;
      break;
    }
  if (unlikely(!log)){
    log=fopen(DEBUG_FILE, "a+");
    if (!log)
      return 1;
  }
  psync_nanotime(&ts);
  time_format(ts.tv_sec, ts.tv_nsec, dttime);
  threadid=pthread_self();
  memcpy(&u, &threadid, sizeof(u));
  snprintf(format, sizeof(format), "%s %u %s %s: %s:%u (function %s): %s\n", dttime, u, psync_thread_name, errname, file, line, function, fmt);
  format[sizeof(format)-1]=0;
  va_start(ap, fmt);
  vfprintf(log, format, ap);
  va_end(ap);
  fflush(log);
  return 1;
}

static const char * PSYNC_CONST get_type_name(uint32_t t){
  if (unlikely(t>=ARRAY_SIZE(psync_typenames)))
    t=0;
  return psync_typenames[t];
}

uint64_t psync_err_number_expected(const char *file, const char *function, int unsigned line, const psync_variant *v){
  if (D_CRITICAL<=DEBUG_LEVEL)
    psync_debug(file, function, line, D_CRITICAL, "type error, wanted %s got %s", get_type_name(PSYNC_TNUMBER), get_type_name(v->type));
  return 0;
}

const char *psync_err_string_expected(const char *file, const char *function, int unsigned line, const psync_variant *v){
  if (D_CRITICAL<=DEBUG_LEVEL)
    psync_debug(file, function, line, D_CRITICAL, "type error, wanted %s got %s", get_type_name(PSYNC_TSTRING), get_type_name(v->type));
  return "";
}

const char *psync_lstring_expected(const char *file, const char *function, int unsigned line, const psync_variant *v, size_t *len){
  if (likely(v->type==PSYNC_TSTRING)){
    *len=v->length;
    return v->str;
  }
  else{
    if (D_CRITICAL<=DEBUG_LEVEL)
      psync_debug(file, function, line, D_CRITICAL, "type error, wanted %s got %s", get_type_name(PSYNC_TSTRING), get_type_name(v->type));
    *len=0;
    return "";
  }
}

double psync_err_real_expected(const char *file, const char *function, int unsigned line, const psync_variant *v){
  if (D_CRITICAL<=DEBUG_LEVEL)
    psync_debug(file, function, line, D_CRITICAL, "type error, wanted %s got %s", get_type_name(PSYNC_TREAL), get_type_name(v->type));
  return 0.0;
}
