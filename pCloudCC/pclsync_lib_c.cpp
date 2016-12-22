#include "pclsync_lib_c.h"
#include "pclsync_lib.h"



#ifdef __cplusplus
extern "C" {
#endif
 namespace cc = console_client::clibrary;
 
int init(const char* user, const char* pass, int save) {
  cc::pclsync_lib::get_lib().set_username(user);
  cc::pclsync_lib::get_lib().set_password(pass);
  cc::pclsync_lib::get_lib().set_savepass((bool)save);
  return cc::pclsync_lib::get_lib().init();
}

 int statrt_crypto (const char* pass) {
  cc::pclsync_lib::statrt_crypto (pass, NULL);
}
 int stop_crypto () {
  cc::pclsync_lib::stop_crypto (NULL, NULL);
}
 int finalize () { 
  cc::pclsync_lib::finalize(NULL, NULL);
}
void set_status_callback(status_callback_t c)
{
  cc::pclsync_lib::get_lib().set_status_callback(c);
}

char * get_token(){
  return cc::pclsync_lib::get_lib().get_token();
}
 #ifdef __cplusplus
}
#endif