
#ifdef __cplusplus
extern "C" {
#endif

  #include "psynclib.h"
  
  psync_syncid_t psync_add_sync_by_path(const char *localpath, const char *remotepath, psync_synctype_t synctype);
  psync_syncid_t psync_add_sync_by_folderid(const char *localpath, psync_folderid_t folderid, psync_synctype_t synctype);
  int psync_add_sync_by_path_delayed(const char *localpath, const char *remotepath, psync_synctype_t synctype);
  int psync_change_synctype(psync_syncid_t syncid, psync_synctype_t synctype);
  int psync_delete_sync(psync_syncid_t syncid);
  psync_folder_list_t *psync_get_sync_list();
  
  typedef void (*status_callback_t)(int status,  const char * stat_string); 
  
  int init(const char* user, const char* pass, int save);
  int statrt_crypto (const char* pass);
  int stop_crypto ();
  int finalize ();
  char * get_token();
  void set_status_callback(status_callback_t); 
 
#ifdef __cplusplus
};
#endif