#ifndef _PSYNC_LIB_H
#define _PSYNC_LIB_H

#include <stdint.h>
#include <stdlib.h>

typedef struct {
  uint64_t fileid;
  uint64_t size;
} pfile_t;

typedef struct {
  uint64_t folderid;
  uint8_t cansyncup;
  uint8_t cansyncdown;
} pfolder_t;

typedef struct {
  const char *name;
  union {
    pfolder_t folder;
    pfile_t file;
  };
  uint8_t isfolder;
} pentry_t;

typedef struct {
  size_t entrycnt;
  pentry_t entries[];
} pfolder_list_t;

#define PSTATUS_READY                   0
#define PSTATUS_DOWNLOADING             1
#define PSTATUS_UPLOADING               2
#define PSTATUS_DOWNLOADINGANDUPLOADING 3
#define PSTATUS_LOGIN_REQUIRED          4
#define PSTATUS_BAD_LOGIN_DATA          5
#define PSTATUS_ACCOUNT_FULL            6
#define PSTATUS_DISK_FULL               7
#define PSTATUS_PAUSED                  8
#define PSTATUS_OFFLINE                 9
#define PSTATUS_CONNECTING             10
#define PSTATUS_USER_MISMATCH          11

typedef struct {
  uint64_t bytestoupload; /* sum of the sizes of files that need to be uploaded to sync state */
  uint64_t bytestouploadcurrent; /* sum of the sizes of files in filesuploading */
  uint64_t bytesuploaded; /* bytes uploaded in files accounted in filesuploading */
  uint64_t bytestodownload; /* sum of the sizes of files that need to be downloaded to sync state */
  uint64_t bytestodownloadcurrent; /* sum of the sizes of files in filesdownloading */
  uint64_t bytesdownloaded; /* bytes downloaded in files accounted in filesdownloading */
  uint32_t status; /* current status, one of PSTATUS_ constants */
  uint32_t filestoupload; /* number of files to upload in order to sync state, including filesuploading*/
  uint32_t filesuploading; /* number of files currently uploading */
  uint32_t uploadspeed; /* in bytes/sec */
  uint32_t filestodownload;  /* number of files to download in order to sync state, including filesdownloading*/
  uint32_t filesdownloading; /* number of files currently downloading */
  uint32_t downloadspeed; /* in bytes/sec */
  uint8_t remoteisfull; /* account is full and no files will be synced upwards*/
  uint8_t localisfull; /* (some) local hard drive is full and no files will be synced from the cloud */
  uint8_t needaction; /* current state requires an action in order to resume/start sync, e.g. login is required */
} pstatus_t;

#define PEVENT_LOCAL_FOLDER_CREATED   1
#define PEVENT_REMOTE_FOLDER_CREATED  2
#define PEVENT_FILE_DOWNLOAD_STARTED  3
#define PEVENT_FILE_DOWNLOAD_FINISHED 4
#define PEVENT_FILE_UPLOAD_STARTED    5
#define PEVENT_FILE_UPLOAD_FINISHED   6

#define PSYNC_DOWNLOAD_ONLY  1
#define PSYNC_UPLOAD_ONLY    2
#define PSYNC_FULL           3

#define PERROR_LOCAL_FOLDER_NOT_FOUND  1
#define PERROR_REMOTE_FOLDER_NOT_FOUND 2

typedef struct {
  const char *localname;
  const char *localpath;
  const char *remotename;
  const char *remotepath;
  uint64_t folderid;
  uint32_t syncid;
  uint32_t synctype;
} psync_folder_t;

typedef struct {
  size_t foldercnt;
  psync_folder_t folders[];
} psync_folder_list_t;

#ifdef __cplusplus
extern "C" {
#endif
  
/* Status change callback is called every time value is changed. It may be called quite often
 * when there are active uploads/downloads. Callbacks are issued from a special callback thread
 * (e.g. the same thread all the time) and are guaranteed not to overlap.
 */
  
typedef void (*pstatus_change_callback_t)(pstatus_t *status);


/* Event callback is called every time a download/upload is started/finished.
 * It is unsafe to use pointers to strings that are passed as parameters after
 * the callback return, if you need to use them this way, strdup() will do the
 * job. Event callbacks will not overlap.
 */

typedef void (*pevent_callback_t)(uint32_t event, const char *name, const char *localpath, const char *remotepath);

/* Init the sync library. Both callbacks can be NULL, but most of the time setting
 * at least status_callback will make sense. Applications should expect immediate
 * status_callback with needaction set and status of PSTATUS_LOGIN_REQUIRED after first
 * run of psync_init(). 
 * 
 * Returns 0 on success and -1 otherwise.
 */

int psync_init(pstatus_change_callback_t status_callback, pevent_callback_t event_callback);

/* returns current status.
 */

void psync_get_status(pstatus_t *status);

/* psync_set_user_pass and psync_set_auth functions can be used for initial login 
 * (PSTATUS_LOGIN_REQUIRED) and when PSTATUS_BAD_LOGIN_DATA error is returned, however
 * if the username do not match previously logged in user, PSTATUS_USER_MISMATCH event
 * will be generated. Preferably on PSTATUS_BAD_LOGIN_DATA the user should be only prompted
 * for new password and psync_set_pass should be called. To change the current user, psync_unlink
 * is to be called first and then the new user may log in.
 * 
 * The pointer returned by psync_get_username() is to be free()d.
 */

char *psync_get_username();
void psync_set_user_pass(const char *username, const char *password);
void psync_set_pass(const char *password);
void psync_set_auth(const char *auth);
void psync_unlink();

/* psync_add_sync_by_path and psync_add_sync_by_folderid are to be used to add a folder to be synced,
 * on success syncid is returned, on error -1. The value of synctype should always be one of PSYNC_DOWNLOAD_ONLY,
 * PSYNC_UPLOAD_ONLY or PSYNC_FULL.
 * 
 * psync_change_synctype changes the sync type, on success returns 0 and -1 on error.
 * 
 * psync_delete_sync deletes the sync relationship between folders, on success returns 0
 * and -1 on error (it is only likely to fail if syncid is invalid). No files or folders
 * are deleted either in the cloud or locally.
 * 
 * psync_get_sync_list returns all folders that are set for sync. On error returns NULL.
 * On success the returned pointer is to be free()d.
 * 
 */

int32_t psync_add_sync_by_path(const char *localpath, const char *remotepath, uint32_t synctype);
int32_t psync_add_sync_by_folderid(const char *localpath, uint64_t folderid, uint32_t synctype);
int psync_change_synctype(uint32_t syncid, uint32_t synctype);
int psync_delete_sync(uint32_t syncid);
psync_folder_list_t *psync_get_sync_list();

/* Use the following functions to list local or remote folders.
 * For local folders fileid and folderid will have undefined values.
 * Remote paths use slashes (/) and start with one.
 * In case of success the returned folder list is to be freed with a
 * single call to free(). In case of error NULL is returned.
 */

pfolder_list_t *psync_list_local_folder(const char *localpath);
pfolder_list_t *psync_list_remote_folder_by_path(const char *remotepath);
pfolder_list_t *psync_list_remote_folder_by_folderid(uint64_t folderid);

/* Returns the code of the last error that occured when calling psync_* functions
 * in the given thread. The error is one of PERROR_* constants.
 * 
 */

uint32_t psync_get_last_error();

/* Pause and resume the sync.
 * 
 */

int psync_pause();
int psync_resume();


  
#ifdef __cplusplus
}
#endif

#endif