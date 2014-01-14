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

#include "psettings.h"
#include "plibs.h"
#include "ptimer.h"
#include <string.h>
#include <ctype.h>

typedef void (*setting_callback)();
typedef void (*filter_callback)(void *);

typedef struct {
  const char *name;
  setting_callback change_callback;
  filter_callback fix_callback;
  union {
    char *str;
    uint64_t num;
    int64_t snum;
    int boolean;
  };
  psync_uint_t type;
} psync_setting_t;

static void lower_patterns(void *ptr);

static psync_setting_t settings[]={
  {"usessl", psync_timer_do_notify_exception, NULL, {(char*)PSYNC_USE_SSL_DEFAULT}, PSYNC_TBOOL},
  {"saveauth", NULL, NULL, {(char*)1}, PSYNC_TBOOL},
  {"maxdownloadspeed", NULL, NULL, {(char*)PSYNC_DWL_SHAPER_DEFAULT}, PSYNC_TNUMBER},
  {"maxuploadspeed", NULL, NULL, {(char*)PSYNC_UPL_SHAPER_DEFAULT}, PSYNC_TNUMBER},
  {"ignorepatterns", NULL, lower_patterns, {PSYNC_IGNORE_PATTERNS_DEFAULT}, PSYNC_TSTRING}
};

void psync_settings_init(){
  psync_sql_res *res;
  psync_str_row row;
  const char *name;
  psync_settingid_t i;
  for (i=0; i<ARRAY_SIZE(settings); i++){
    if (settings[i].type==PSYNC_TSTRING){
      settings[i].str=psync_strdup(settings[i].str);
      if (settings[i].fix_callback)
        settings[i].fix_callback(&settings[i].str);
    }
    else if (settings[i].fix_callback){
      if (settings[i].type==PSYNC_TNUMBER)
        settings[i].fix_callback(&settings[i].num);
      else if (settings[i].type==PSYNC_TBOOL)
        settings[i].fix_callback(&settings[i].boolean);
    }
  }
  res=psync_sql_query("SELECT id, value FROM setting");
  while ((row=psync_sql_fetch_rowstr(res))){
    name=row[0];
    for (i=0; i<ARRAY_SIZE(settings); i++)
      if (!strcmp(name, settings[i].name)){
        if (settings[i].type==PSYNC_TSTRING){
          psync_free(settings[i].str);
          settings[i].str=psync_strdup(row[1]);
          if (settings[i].fix_callback)
            settings[i].fix_callback(&settings[i].str);
        }
        else if (settings[i].type==PSYNC_TNUMBER){
          settings[i].num=atoll(row[1]);
          if (settings[i].fix_callback)
            settings[i].fix_callback(&settings[i].num);
        }
        else if (settings[i].type==PSYNC_TBOOL){
          settings[i].boolean=atoll(row[1])?1:0;
          if (settings[i].fix_callback)
            settings[i].fix_callback(&settings[i].boolean);
        }
        else
          debug(D_BUG, "bad setting type for settingid %d (%s) expected %"P_PRI_U, i, name, settings[i].type);
      }
  }
  psync_sql_free_result(res);
}

psync_settingid_t psync_setting_getid(const char *name){
  psync_settingid_t i;
  for (i=0; i<ARRAY_SIZE(settings); i++)
    if (!strcmp(name, settings[i].name))
      return i;
  debug(D_BUG, "setting witn name %s not found", name);
  return PSYNC_INVALID_SETTINGID;
}

#define CHECK_SETTINGID_AND_TYPE(ret, stype) \
  do {\
    if (unlikely(settingid<0 || settingid>=ARRAY_SIZE(settings))){\
      debug(D_BUG, "invalid settingid %d", settingid);\
      return ret;\
    }\
    if (unlikely(settings[settingid].type!=stype)){\
      debug(D_BUG, "invalid setting type requested for settingid %d (%s)", settingid, settings[settingid].name);\
      return ret;\
    }\
  } while (0)\

int psync_setting_get_bool(psync_settingid_t settingid){
  CHECK_SETTINGID_AND_TYPE(0, PSYNC_TBOOL);
  return settings[settingid].boolean;
}

int psync_setting_set_bool(psync_settingid_t settingid, int value){
  psync_sql_res *res;
  CHECK_SETTINGID_AND_TYPE(-1, PSYNC_TBOOL);
  if (value)
    value=1;
  else
    value=0;
  if (settings[settingid].fix_callback)
    settings[settingid].fix_callback(&value);
  settings[settingid].boolean=value;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_string(res, 1, settings[settingid].name);
  psync_sql_bind_uint(res, 2, value);
  psync_sql_run(res);
  psync_sql_free_result(res);
  if (settings[settingid].change_callback)
    settings[settingid].change_callback();
  return 0;
}

uint64_t psync_setting_get_uint(psync_settingid_t settingid){
  CHECK_SETTINGID_AND_TYPE(0, PSYNC_TNUMBER);
  return settings[settingid].num;
}

int psync_setting_set_uint(psync_settingid_t settingid, uint64_t value){
  psync_sql_res *res;
  CHECK_SETTINGID_AND_TYPE(-1, PSYNC_TNUMBER);
  if (settings[settingid].fix_callback)
    settings[settingid].fix_callback(&value);
  settings[settingid].num=value;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_string(res, 1, settings[settingid].name);
  psync_sql_bind_uint(res, 2, value);
  psync_sql_run(res);
  psync_sql_free_result(res);
  if (settings[settingid].change_callback)
    settings[settingid].change_callback();
  return 0;
}

int64_t psync_setting_get_int(psync_settingid_t settingid){
  CHECK_SETTINGID_AND_TYPE(0, PSYNC_TNUMBER);
  return settings[settingid].snum;
}

int psync_setting_set_int(psync_settingid_t settingid, int64_t value){
  psync_sql_res *res;
  CHECK_SETTINGID_AND_TYPE(-1, PSYNC_TNUMBER);
  if (settings[settingid].fix_callback)
    settings[settingid].fix_callback(&value);
  settings[settingid].snum=value;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_string(res, 1, settings[settingid].name);
  psync_sql_bind_int(res, 2, value);
  psync_sql_run(res);
  psync_sql_free_result(res);
  if (settings[settingid].change_callback)
    settings[settingid].change_callback();
  return 0;
}

const char *psync_setting_get_string(psync_settingid_t settingid){
  CHECK_SETTINGID_AND_TYPE("", PSYNC_TSTRING);
  return settings[settingid].str;
}

int psync_setting_set_string(psync_settingid_t settingid, const char *value){
  psync_sql_res *res;
  char *oldval, *newval;
  CHECK_SETTINGID_AND_TYPE(-1, PSYNC_TSTRING);
  oldval=settings[settingid].str;
  newval=psync_strdup(value);
  if (settings[settingid].fix_callback)
    settings[settingid].fix_callback(&newval);
  settings[settingid].str=newval;
  res=psync_sql_prep_statement("REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_string(res, 1, settings[settingid].name);
  psync_sql_bind_string(res, 2, value);
  psync_sql_run(res);
  psync_sql_free_result(res);
  if (settings[settingid].change_callback)
    settings[settingid].change_callback();
  psync_free_after_sec(oldval, 600);
  return 0;
}

static void lower_patterns(void *ptr){
  unsigned char *str;
  str=*((unsigned char **)ptr);
  while (*str){
    *str=tolower(*str);
    str++;
  }
}
