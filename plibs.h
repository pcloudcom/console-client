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

#ifndef _PSYNC_LIBS_H
#define _PSYNC_LIBS_H

#include <sqlite3.h>

#include "pcompat.h"
#include "psynclib.h"

#define D_NONE     0
#define D_BUG      10
#define D_CRITICAL 20
#define D_ERROR    30
#define D_WARNING  40
#define D_NOTICE   50

#define DEBUG_LEVELS {\
 {D_BUG, "BUG"},\
 {D_CRITICAL, "CRITICAL ERROR"},\
 {D_ERROR, "ERROR"},\
 {D_WARNING, "WARNING"},\
 {D_NOTICE, "NOTICE"}\
}

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL D_ERROR
#endif

#define DEBUG_FILE "/tmp/psync_err.log"

#define debug(level, ...) do {if (level<=DEBUG_LEVEL) psync_debug(__FILE__, __FUNCTION__, __LINE__, level, __VA_ARGS__);} while (0)
#define assert(cond, ...) do {if (!(cond)) debug(D_ERROR, __VA_ARGS__);} while (0)

#define PSYNC_TNUMBER 1
#define PSYNC_TSTRING 2
#define PSYNC_TREAL   3
#define PSYNC_TNULL   4

#define psync_get_number(v) ((v).type==PSYNC_TNUMBER?(v).num:psync_err_number_expected(__FILE__, __FUNCTION__, __LINE__, &(v)))
#define psync_get_string(v) ((v).type==PSYNC_TSTRING?(v).str:psync_err_string_expected(__FILE__, __FUNCTION__, __LINE__, &(v)))
#define psync_get_lstring(v, l) ((v).type==PSYNC_TSTRING?((v).str, *l=(v).length):psync_err_lstring_expected(__FILE__, __FUNCTION__, __LINE__, &(v), l))
#define psync_get_real(v) ((v).type==PSYNC_TREAL?(v).num:psync_err_real_expected(__FILE__, __FUNCTION__, __LINE__, &(v)))

typedef struct {
  uint32_t type;
  uint32_t length;
  union {
    uint64_t num;
    int64_t snum;
    const char *str;
    double real;
  };
} psync_variant;

typedef struct {
  sqlite3_stmt *stmt;
  int column_count;
  psync_variant row[];
} psync_sql_res;

extern int psync_do_run;
extern pstatus_t psync_status;

char *psync_strdup(const char *str) PSYNC_MALLOC;
char *psync_strcat(const char *str, ...) PSYNC_MALLOC PSYNC_SENTINEL;

int psync_sql_connect(const char *db);
void psync_sql_close();
void psync_sql_lock();
void psync_sql_unlock();

int psync_sql_statement(const char *sql);
char *psync_sql_cellstr(const char *sql);
int64_t psync_sql_cellint(const char *sql, int64_t dflt);
char **psync_sql_rowstr(const char *sql);
psync_variant *psync_sql_row(const char *sql);
psync_sql_res *psync_sql_query(const char *sql);
void psync_sql_free_result(psync_sql_res *res);
psync_variant *psync_sql_fetch_row(psync_sql_res *res);
char **psync_sql_fetch_rowstr(psync_sql_res *res);
int64_t *psync_sql_fetch_rowint(psync_sql_res *res);

void psync_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...)
#if defined(__GNUC__)
  __attribute__ ((cold))
  __attribute__ ((format (printf, 5, 6)))
#endif
;

#if defined(__GNUC__)
#define PSYNC_COLD __attribute__ ((cold))
#else
#define PSYNC_COLD
#endif

uint64_t psync_err_number_expected(const char *file, const char *function, int unsigned line, psync_variant *v) PSYNC_COLD;
const char *psync_err_string_expected(const char *file, const char *function, int unsigned line, psync_variant *v) PSYNC_COLD;
const char *psync_err_lstring_expected(const char *file, const char *function, int unsigned line, psync_variant *v, size_t *len) PSYNC_COLD;
double psync_err_real_expected(const char *file, const char *function, int unsigned line, psync_variant *v) PSYNC_COLD;

#endif
