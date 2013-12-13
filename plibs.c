#include <string.h>
#include <stdarg.h>
#include <sqlite3.h>
#include "plibs.h"

sqlite3 *psync_db;
pstatus_t psync_status;
int psync_do_run=1;

char *psync_strdup(const char *str){
  size_t len;
  char *ptr;
  len=strlen(str)+1;
  ptr=(char *)psync_malloc(len);
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
  int code=sqlite3_open(db, &psync_db);
  if (code==SQLITE_OK)
    return 0;
  else{
    debug(D_CRITICAL, "could not open sqlite dabase %s: %s", db, sqlite3_errstr(code));
    return -1;
  }
}

int psync_sql_statement(const char *sql){
  char *errmsg;
  int code;
  code=sqlite3_exec(psync_db, sql, NULL, NULL, &errmsg);
  if (code==SQLITE_OK)
    return 0;
  else{
    debug(D_ERROR, "error running sql statement: %s: %s", sql, errmsg);
    sqlite3_free(errmsg);
    return -1;
  }
}

char *psync_sql_cellstr(const char *sql){
  sqlite3_stmt *stmt;
  int code;
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (code!=SQLITE_OK){
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errstr(code));
    return NULL;
  }
  code=sqlite3_step(stmt);
  if (code==SQLITE_ROW){
    char *ret;
    ret=(char *)sqlite3_column_text(stmt, 0);
    if (ret)
      ret=psync_strdup(ret);
    sqlite3_finalize(stmt);
    return ret;
  }
  else {
    sqlite3_finalize(stmt);
    if (code!=SQLITE_DONE)
      debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errstr(code));
    return NULL;
  }
}

int64_t psync_sql_cellint(const char *sql, int64_t dflt){
  sqlite3_stmt *stmt;
  int code;
  code=sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (code!=SQLITE_OK){
    debug(D_ERROR, "error running sql statement: %s: %s", sql, sqlite3_errstr(code));
  }
  else{
    code=sqlite3_step(stmt);
    if (code==SQLITE_ROW)
      dflt=sqlite3_column_int64(stmt, 0);
    else {
      if (code!=SQLITE_DONE)
        debug(D_ERROR, "sqlite3_step returned error: %s: %s", sql, sqlite3_errstr(code));
    }
    sqlite3_finalize(stmt);
  }
  return dflt;
}

void psync_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...){
}
