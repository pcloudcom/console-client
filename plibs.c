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

#include "plibs.h"
#include "ptimer.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>

struct run_after_ptr {
  struct run_after_ptr *next;
  psync_run_after_t run;
  void *ptr;
  time_t runat;
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

static pthread_mutex_t ptrs_to_run_mutex=PTHREAD_MUTEX_INITIALIZER;
static struct run_after_ptr *ptrs_to_run_next_min=NULL;
static struct run_after_ptr *ptrs_to_run_this_min=NULL;

const static char *psync_typenames[]={"[invalid type]", "[number]", "[string]", "[float]", "[null]", "[bool]"};

char psync_my_auth[64]="", *psync_my_user=NULL, *psync_my_pass=NULL;
uint64_t psync_my_userid=0;
pthread_mutex_t psync_my_auth_mutex=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t psync_db_mutex;
sqlite3 *psync_db;
pstatus_t psync_status;
int psync_do_run=1;
PSYNC_THREAD uint32_t psync_error=0;

char *psync_strdup(const char *str){
  size_t len;
  char *ptr;
  len=strlen(str)+1;
  ptr=psync_new_cnt(char, len);
  memcpy(ptr, str, len);
  return ptr;
}

char *psync_strndup(const char *str, size_t len){
  char *ptr;
  len++;
  ptr=psync_new_cnt(char, len);
  memcpy(ptr, str, len);
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

int psync_sql_connect(const char *db){
  pthread_mutexattr_t mattr;
  int code=sqlite3_open(db, &psync_db);
  if (likely(code==SQLITE_OK)){
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&psync_db_mutex, &mattr);
    pthread_mutexattr_destroy(&mattr);
    return 0;
  }
  else{
    debug(D_CRITICAL, "could not open sqlite dabase %s: %d", db, code);
    return -1;
  }
}

void psync_sql_close(){
  int code=sqlite3_close(psync_db);
  if (unlikely(code!=SQLITE_OK))
    debug(D_CRITICAL, "error when closing database: %d", code);
}

void psync_sql_lock(){
  if (IS_DEBUG){
    if (pthread_mutex_trylock(&psync_db_mutex)){
      debug(D_WARNING, "psync_db_mutex contended");
      pthread_mutex_lock(&psync_db_mutex);
      debug(D_WARNING, "got psync_db_mutex after contention");
    }
    else
      return;
  }
  else
    pthread_mutex_lock(&psync_db_mutex);
}

void psync_sql_unlock(){
  pthread_mutex_unlock(&psync_db_mutex);
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

char *psync_sql_cellstr(const char *sql){
  sqlite3_stmt *stmt;
  int code;
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

psync_sql_res *psync_sql_query(const char *sql){
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
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
#if D_ERROR<=DEBUG_LEVEL
  res->sql=sql;
#endif
  res->column_count=cnt;
  return res;
}

psync_sql_res *psync_sql_prep_statement(const char *sql){
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code;
  psync_sql_lock();
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code!=SQLITE_OK)){
    psync_sql_unlock();
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errmsg(psync_db));
    return NULL;
  }
  res=psync_new(psync_sql_res);
  res->stmt=stmt;
#if D_ERROR<=DEBUG_LEVEL
  res->sql=sql;
#endif
  return res;
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

void psync_sql_run_free(psync_sql_res *res){
  int code=sqlite3_step(res->stmt);
  if (unlikely(code!=SQLITE_DONE))
    debug(D_ERROR, "sqlite3_step returned error: %s: %s", sqlite3_errmsg(psync_db), res->sql);
  sqlite3_finalize(res->stmt);
  psync_sql_unlock();
  psync_free(res);
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

void psync_sql_bind_string(psync_sql_res *res, int n, const char *str){
  int code=sqlite3_bind_text(res->stmt, n, str, -1, SQLITE_STATIC);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));}

void psync_sql_bind_lstring(psync_sql_res *res, int n, const char *str, size_t len){
  int code=sqlite3_bind_blob(res->stmt, n, str, len, SQLITE_STATIC);
  if (unlikely(code!=SQLITE_OK))
    debug(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_free_result(psync_sql_res *res){
  sqlite3_finalize(res->stmt);
  psync_sql_unlock();
  psync_free(res);
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
      l=sprintf(npath+dotidx, "(conflicted %"P_PRI_I")", num);
    else{
      l=12;
      memcpy(npath+dotidx, "(conflicted)", l);
    }
    memcpy(npath+dotidx+l, path+dotidx, plen-dotidx+1);
    if (psync_stat(npath, &st)){
      l=psync_file_rename(path, npath);
      psync_free(npath);
      return l;
    }
    num++;
  }
}

static void psync_run_pointers_timer(void *ptr){
  struct run_after_ptr *fp, **pfp;
  if (psync_current_time%60==0 && ptrs_to_run_next_min){
    time_t nextmin=psync_current_time+60;
    pthread_mutex_lock(&ptrs_to_run_mutex);
    fp=ptrs_to_run_next_min;
    pfp=&ptrs_to_run_next_min;
    while (fp){
      if (fp->runat<nextmin){
        *pfp=fp->next;
        fp->next=ptrs_to_run_this_min;
        ptrs_to_run_this_min=fp;
        fp=*pfp;
      }
      else{
        pfp=&fp->next;
        fp=fp->next;
      }
    }
    pthread_mutex_unlock(&ptrs_to_run_mutex);
  }
  if (ptrs_to_run_this_min){
    pthread_mutex_lock(&ptrs_to_run_mutex);
    fp=ptrs_to_run_this_min;
    pfp=&ptrs_to_run_this_min;
    while (fp){
      if (fp->runat<=psync_current_time){
        *pfp=fp->next;
        /* it is ok to unlock the mutex while running the callback as this function is the only place that deletes elements from the list */
        pthread_mutex_unlock(&ptrs_to_run_mutex);
        fp->run(fp->ptr);
        psync_free(fp);
        pthread_mutex_lock(&ptrs_to_run_mutex);
        fp=*pfp;
      }
      else{
        pfp=&fp->next;
        fp=fp->next;
      }
    }
    pthread_mutex_unlock(&ptrs_to_run_mutex);
  }  
}

void psync_libs_init(){
  psync_timer_register(psync_run_pointers_timer, 1, NULL);
}

void psync_run_after_sec(psync_run_after_t run, void *ptr, uint32_t seconds){
  struct run_after_ptr *fp;
  fp=(struct run_after_ptr *)psync_malloc(sizeof(struct run_after_ptr));
  fp->run=run;
  fp->ptr=ptr;
  fp->runat=psync_current_time+seconds;
  pthread_mutex_lock(&ptrs_to_run_mutex);
  if (seconds<60){
    fp->next=ptrs_to_run_this_min;
    ptrs_to_run_this_min=fp;
  }
  else{
    fp->next=ptrs_to_run_next_min;
    ptrs_to_run_next_min=fp;
  }
  pthread_mutex_unlock(&ptrs_to_run_mutex);
}

void psync_free_after_sec(void *ptr, uint32_t seconds){
  psync_run_after_sec(psync_free, ptr, seconds);
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

static void time_format(time_t tm, char *result){
  static const char month_names[12][4]={"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  static const char day_names[7][4] ={"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  struct tm dt;
  psync_uint_t y;
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
  memcpy(result, " +0000", 7); // copies the null byte
}

int psync_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...){
  static const struct {
    psync_uint_t level;
    const char *name;
  } debug_levels[]=DEBUG_LEVELS;
  static FILE *log=NULL;
  char dttime[32], format[512];
  va_list ap;
  const char *errname;
  psync_uint_t i;
  time_t currenttime;
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
  currenttime=psync_timer_time();
  time_format(currenttime, dttime);
  snprintf(format, sizeof(format), "%s %s: %s:%u (function %s): %s\n", dttime, errname, file, line, function, fmt);
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
