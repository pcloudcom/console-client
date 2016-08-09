#include "pclsync_lib_c.h"
#include "pclsync_lib.h"



#ifdef __cplusplus
extern "C" {
#endif
 namespace cc = console_client::clibrary;
 
 int init() {
  cc::pclsync_lib::init();
 }
 int statrt_crypto (const char* pass) {
  cc::pclsync_lib::statrt_crypto (pass);
}
 int stop_crypto (const char* path) {
  cc::pclsync_lib::stop_crypto (path);
}
 int finalize () { 
  cc::pclsync_lib::finalize(NULL);
}
 
 #ifdef __cplusplus
}
#endif