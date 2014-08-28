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
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>

#define return_error(err) do {psync_error=err; return -1;} while (0)

struct run_after_ptr {
  struct run_after_ptr *next;
  psync_run_after_t run;
  void *ptr;
};

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

uint16_t const *__hex_lookup=(uint16_t *)__hex_lookupl;
static char normalize_table[256];

const static char *psync_typenames[]={"[invalid type]", "[number]", "[string]", "[float]", "[null]", "[bool]"};

char psync_my_auth[64]="", *psync_my_user=NULL, *psync_my_pass=NULL;
uint64_t psync_my_userid=0;
pthread_mutex_t psync_my_auth_mutex=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t psync_db_mutex;
sqlite3 *psync_db;
pstatus_t psync_status;
int psync_do_run=1;
PSYNC_THREAD uint32_t psync_error=0;

static pthread_mutex_t psync_db_checkpoint_mutex=PTHREAD_MUTEX_INITIALIZER;


char *psync_strdup(const char *str){
  size_t len;
  char *ptr;
  len=strlen(str)+1;
  ptr=psync_new_cnt(char, len);
  memcpy(ptr, str, len);
  return ptr;
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
  ptr=psync_new_cnt(char, len+1);
  memcpy(ptr, str, len);
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

void psync_sql_err_callback(void *ptr, int code, const char *msg){
  debug(D_WARNING, "database warning %d: %s", code, msg);
}

static void psync_sql_wal_checkpoint(){
  int code;
  if (pthread_mutex_trylock(&psync_db_checkpoint_mutex)){
    debug(D_NOTICE, "skipping checkpoint");
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
}

static int psync_sql_wal_hook(void *ptr, sqlite3 *db, const char *name, int numpages){
  if (numpages>=PSYNC_DB_CHECKPOINT_AT_PAGES)
    psync_run_thread("checkpoint charlie", psync_sql_wal_checkpoint);
  return SQLITE_OK;
}

int psync_sql_connect(const char *db){
  pthread_mutexattr_t mattr;
  psync_stat_t st;
  uint64_t dbver;
  int initdbneeded=0;

  int code;
  if (!sqlite3_threadsafe()){
    debug(D_CRITICAL, "sqlite is compiled without thread support");
    return -1;
  }
  if (psync_stat(db, &st)!=0)
    initdbneeded=1;

  code=sqlite3_open(db, &psync_db);
  if (likely(code==SQLITE_OK)){
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&psync_db_mutex, &mattr);
    pthread_mutexattr_destroy(&mattr);
    if (IS_DEBUG)
      sqlite3_config(SQLITE_CONFIG_LOG, psync_sql_err_callback, NULL);
    sqlite3_wal_hook(psync_db, psync_sql_wal_hook, NULL);
    psync_sql_statement(PSYNC_DATABASE_CONFIG);
    if (initdbneeded==1)
      return psync_sql_statement(PSYNC_DATABASE_STRUCTURE);
    else if (psync_sql_statement("DELETE FROM setting WHERE id='justcheckingiflocked'")){
      debug(D_ERROR, "database is locked");
      sqlite3_close(psync_db);
      pthread_mutex_destroy(&psync_db_mutex);
      return -1;
    }

    dbver=psync_sql_cellint("SELECT value FROM setting WHERE id='dbversion'", 0);
    if (dbver<PSYNC_DATABASE_VERSION){
      uint64_t i;
      debug(D_NOTICE, "database version %d detected, upgrading to %d", (int)dbver, (int)PSYNC_DATABASE_VERSION);
      for (i=dbver; i<PSYNC_DATABASE_VERSION; i++)
        if (psync_sql_statement(psync_db_upgrade[i])){
          debug(D_ERROR, "error running statement %s", psync_db_upgrade[i]);
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

void psync_sql_close(){
  int code, tries;
  tries=0;
  while (1){
    code=sqlite3_close(psync_db);
    if (code==SQLITE_BUSY){
      psync_cache_clean_all();
      tries++;
      if (tries>100){
        psync_milisleep(tries-90);
        if (tries>200){
          debug(D_ERROR, "failed to close database");
          break;
        }
      }
    }
    else
      break;
  }
  if (unlikely(code!=SQLITE_OK))
    debug(D_CRITICAL, "error when closing database: %d", code);
  psync_db=NULL;
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

#if IS_DEBUG
unsigned long sqllockcnt=0;
struct timespec sqllockstart;
#endif

int psync_sql_trylock(){
#if IS_DEBUG
  if (pthread_mutex_trylock(&psync_db_mutex))
    return -1;
  if (++sqllockcnt==1)
    psync_nanotime(&sqllockstart);
  return 0;
#else
  return pthread_mutex_trylock(&psync_db_mutex);
#endif
}

void psync_sql_lock(){
#if IS_DEBUG
  if (pthread_mutex_trylock(&psync_db_mutex)){
    struct timespec start, end;
    unsigned long msec;
    psync_nanotime(&start);
#if defined(P_OS_LINUX)
    memcpy(&end, &start, sizeof(end));
    end.tv_sec+=30;
    if (pthread_mutex_timedlock(&psync_db_mutex, &end)){
      debug(D_BUG, "sql mutex timed out");
      abort();
    }
#else
    pthread_mutex_lock(&psync_db_mutex);
#endif
    psync_nanotime(&end);
    msec=(end.tv_sec-start.tv_sec)*1000+end.tv_nsec/1000000-start.tv_nsec/1000000;
    if (msec>=5)
      debug(D_WARNING, "waited %lu milliseconds for database mutex", msec);
    sqllockcnt++;
    memcpy(&sqllockstart, &end, sizeof(struct timespec));
  }
  else if (++sqllockcnt==1)
    psync_nanotime(&sqllockstart);
#else
  pthread_mutex_lock(&psync_db_mutex);
#endif
}

void psync_sql_unlock(){
#if IS_DEBUG
  if (--sqllockcnt==0){
    struct timespec end;
    unsigned long msec;
    pthread_mutex_unlock(&psync_db_mutex);
    psync_nanotime(&end);
    msec=(end.tv_sec-sqllockstart.tv_sec)*1000+end.tv_nsec/1000000-sqllockstart.tv_nsec/1000000;
    if (msec>=10)
      debug(D_WARNING, "held database mutex for %lu milliseconds", msec);
  }
  else
    pthread_mutex_unlock(&psync_db_mutex);
#else
  pthread_mutex_unlock(&psync_db_mutex);
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

int psync_sql_statement(const char *sql){
  char *errmsg;
  int code;
  psync_sql_lock();
  code=sqlite3_exec(psync_db, sql, NULL, NULL, &errmsg);
  psync_sql_unlock();
  if (likely(code==SQLITE_OK))
    return 0;
  else{
    debug(D_ERROR, "error running sql statement: %s: %s", sql, errmsg);
    sqlite3_free(errmsg);
    return -1;
  }
}

int psync_sql_start_transaction(){
  psync_sql_lock();
  if (unlikely(psync_sql_statement("BEGIN"))){
    psync_sql_unlock();
    return -1;
  }
  else
    return 0;
}

int psync_sql_commit_transaction(){
  int code=psync_sql_statement("COMMIT");
  psync_sql_unlock();
  return code;
}

int psync_sql_rollback_transaction(){
  int code=psync_sql_statement("ROLLBACK");
  psync_sql_unlock();
  return code;
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
  psync_sql_lock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  code=sqlite3_step(stmt);
  if (code==SQLITE_ROW){
    char *ret;
    ret=(char *)sqlite3_column_text(stmt, 0);
    if (ret)
      ret=psync_strdup(ret);
    sqlite3_finalize(stmt);
    psync_sql_unlock();
    return ret;
  }
  else {
    sqlite3_finalize(stmt);
    psync_sql_unlock();
    if (unlikely(code!=SQLITE_DONE))
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
}

int64_t psync_sql_cellint(const char *sql, int64_t dflt){
  sqlite3_stmt *stmt;
  int code;
  psync_sql_check_query_plan(sql);
  psync_sql_lock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
  else{
    code=sqlite3_step(stmt);
    if (code==SQLITE_ROW)
      dflt=sqlite3_column_int64(stmt, 0);
    else if (unlikely(code!=SQLITE_DONE))
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    sqlite3_finalize(stmt);
  }
  psync_sql_unlock();
  return dflt;
}

char **psync_sql_rowstr(const char *sql){
  sqlite3_stmt *stmt;
  int code, cnt;
  psync_sql_check_query_plan(sql);
  psync_sql_lock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
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
    psync_sql_unlock();
    return arr;
  }
  else {
    sqlite3_finalize(stmt);
    psync_sql_unlock();
    if (unlikely(code!=SQLITE_DONE))
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
}

psync_variant *psync_sql_row(const char *sql){
  sqlite3_stmt *stmt;
  int code, cnt;
  psync_sql_check_query_plan(sql);
  psync_sql_lock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
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
    psync_sql_unlock();
    return arr;
  }
  else {
    sqlite3_finalize(stmt);
    psync_sql_unlock();
    if (unlikely(code!=SQLITE_DONE))
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
}

psync_sql_res *psync_sql_query_nocache(const char *sql){
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  psync_sql_check_query_plan(sql);
  psync_sql_lock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt=sqlite3_column_count(stmt);
  res=(psync_sql_res *)psync_malloc(sizeof(psync_sql_res)+cnt*sizeof(psync_variant));
  res->stmt=stmt;
  res->sql=sql;
  res->column_count=cnt;
  return res;
}

psync_sql_res *psync_sql_query(const char *sql){
  psync_sql_res *ret;
  ret=psync_cache_get(sql);
  if (ret){
//    debug(D_NOTICE, "got query %s from cache", sql);
    psync_sql_lock();
    return ret;
  }
  else
    return psync_sql_query_nocache(sql);
}

static void psync_sql_free_cache(void *ptr){
  psync_sql_res *res=(psync_sql_res *)ptr;
  sqlite3_finalize(res->stmt);
  psync_free(res);
}

void psync_sql_free_result(psync_sql_res *res){
  int code=sqlite3_reset(res->stmt);
  psync_sql_unlock();
  if (code==SQLITE_OK)
    psync_cache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache, PSYNC_QUERY_MAX_CNT);
  else
    psync_sql_free_cache(res);
}

void psync_sql_free_result_nocache(psync_sql_res *res){
  sqlite3_finalize(res->stmt);
  psync_sql_unlock();
  psync_free(res);
}

psync_sql_res *psync_sql_prep_statement_nocache(const char *sql){
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code;
  psync_sql_check_query_plan(sql);
  psync_sql_lock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  res=psync_new(psync_sql_res);
  res->stmt=stmt;
  res->sql=sql;
  return res;
}

psync_sql_res *psync_sql_prep_statement(const char *sql){
  psync_sql_res *ret;
  ret=psync_cache_get(sql);
  if (ret){
//    debug(D_NOTICE, "got statement %s from cache", sql);
    psync_sql_lock();
    return ret;
  }
  else
    return psync_sql_prep_statement_nocache(sql);
}

void psync_sql_reset(psync_sql_res *res){
  int code=sqlite3_reset(res->stmt);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "sqlite3_reset returned error: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_run(psync_sql_res *res){
  int code=sqlite3_step(res->stmt);
  if (unlikely(code!=SQLITE_DONE))
    debug(D_ERROR, "sqlite3_step returned error: %s: %s", sqlite3_errmsg(psync_db), res->sql);
  code=sqlite3_reset(res->stmt);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "sqlite3_reset returned error: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_run_free_nocache(psync_sql_res *res){
  int code=sqlite3_step(res->stmt);
  if (unlikely(code!=SQLITE_DONE))
    debug(D_ERROR, "sqlite3_step returned error: %s: %s", sqlite3_errmsg(psync_db), res->sql);
  sqlite3_finalize(res->stmt);
  psync_sql_unlock();
  psync_free(res);
}

void psync_sql_run_free(psync_sql_res *res){
  int code=sqlite3_step(res->stmt);
  if (unlikely(code!=SQLITE_DONE || (code=sqlite3_reset(res->stmt))!=SQLITE_OK)){
    debug(D_ERROR, "sqlite3_step returned error: %s: %s", sqlite3_errmsg(psync_db), res->sql);
    sqlite3_finalize(res->stmt);
    psync_sql_unlock();
    psync_free(res);
  }
  else{
    psync_sql_unlock();
    psync_cache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache, PSYNC_QUERY_MAX_CNT);
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
      l=sprintf(npath+dotidx, " (conflicted %"P_PRI_I")", num);
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
    if (pattern[i]=='?')
      continue;
    else if (pattern[i]=='*'){
      i++;
      plen-=i;
      if (!plen)
        return 1;
      pattern+=i;
      do {
        if (psync_match_pattern(name, pattern, plen))
          return 1;
      } while (*name++);
      return 0;
    }
    else if (pattern[i]!=name[i])
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
  memcpy(ret, &builder->cnt, builder->elements_offset);
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
