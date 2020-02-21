
#ifdef __cplusplus
extern "C" {
#endif

  #include "psynclib.h"
  
  void psync_fs_pause_until_login();
  
  typedef void (*status_callback_t)(int status,  const char * stat_string); 
  
  int init();
  void statrt_crypto (const char* pass);
  void stop_crypto ();
  void finalize ();
  char * get_token();
  void set_status_callback(status_callback_t); 
  int logout();
  int unlinklib();
  int login(const char* user, const char* pass, int save);
 
#ifdef __cplusplus
};
#endif
