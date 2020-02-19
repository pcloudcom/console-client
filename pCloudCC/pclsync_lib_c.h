
#ifdef __cplusplus
extern "C" {
#endif

  #include "psynclib.h"
  #include "ptimer.h"
  void psync_fs_pause_until_login();
  
  typedef void (*status_callback_t)(int status,  const char * stat_string, 
    const char * down_string, const char * up_string
  ); 
  
  int init();
  int statrt_crypto (const char* pass);
  int stop_crypto ();
  int finalize ();
  char * get_token();
  void set_status_callback(status_callback_t); 
  void set_event_callback(pevent_callback_t);
  int logout();
  int unlinklib();
  int login(const char* user, const char* pass, int save);
  
#ifdef __cplusplus
};
#endif