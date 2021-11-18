/* Copyright (c) 2013-2015 pCloud Ltd.
 * All rights reserved.
 *
 * Library containing tool functions, not used in the main
 * functionality. Keeping statistics, getting data for them etc.
 */
#pragma once

#include "papi.h"

#define EVENT_WS "loganalyticsevent"

#define EPARAM_CATEG  "category"
#define EPARAM_ACTION "action"
#define EPARAM_LABEL  "label"
#define EPARAM_OS     "os"
#define EPARAM_TIME   "etime"
#define EPARAM_AUTH   "auth"
#define EPARAM_MAC    "mac_address"
#define EPARAM_KEY    "keys"

#define INST_EVENT_CATEG  "INSTALLATION_PROCESS"
#define INST_EVENT_FLOGIN "FIRST_LOGIN"

//Syncs count constants
#define PSYNC_SYNCS_COUNT  "syncs_count"

#define PSYNC_EVENT_CATEG  "SYNCS_EVENTS"
#define PSYNC_EVENT_ACTION "SYNCS_LOG_COUNT"
#define PSYNC_EVENT_LABEL  "SYNCS_COUNT"


//Payload name constants
#define FOLDER_META "metadata"
#define NO_PAYLOAD         ""

//Parameter name constants
#define FOLDER_ID          "folderid"
#define PARENT_FOLDER_NAME "parentname"

//Parser delimeter symbols
#define DELIM_SEMICOLON ';'

#if defined(P_OS_WINDOWS)
#define DELIM_DIR   '\\'
#endif

#if defined(P_OS_LINUX)
#define DELIM_DIR  '/'
#endif

#if defined(P_OS_MACOSX)
#define DELIM_DIR  '/'
#endif

typedef struct _eventParams {
  int paramCnt;
  binparam Params[100];
} eventParams;

typedef struct _folderPath {
  int cnt;
  char* folders[50];
} folderPath;
/**********************************************************************************************************/
int create_backend_event(
  const char* binapi,
  const char* category,
  const char* action,
  const char* label,
  const char* auth,
  int          os,
  time_t          etime,
  eventParams* params,
  char** err);
/**********************************************************************************************************/
int backend_call(const char* binapi,
  const char*  wsPath,
  const char* payloadName,
  eventParams* requiredParams,
  eventParams* optionalParams,
  binresult**  resData,
  char** err);
/**********************************************************************************************************/
char* getMACaddr();
/**********************************************************************************************************/
char* get_machine_name();
/**********************************************************************************************************/
void parse_os_path(char* path, folderPath* folders, char* delim, int mode);
/**********************************************************************************************************/
void send_psyncs_event(const char* binapi,
                       const char* auth);
/**********************************************************************************************************/
int set_be_file_dates(uint64_t fileid, time_t ctime, time_t mtime);
/**********************************************************************************************************/
 uint32_t get_sync_id_from_fid(uint64_t fid);
/**********************************************************************************************************/
 char* get_sync_folder_by_syncid(uint64_t syncId);
 /**********************************************************************************************************/
 char* get_folder_name_from_path(char* path);
 /**********************************************************************************************************/