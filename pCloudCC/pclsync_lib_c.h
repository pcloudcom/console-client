
#ifdef __cplusplus
extern "C" {
#endif
 int init();
 int statrt_crypto (const char* pass);
 int stop_crypto (const char* path);
 int finalize ();
#ifdef __cplusplus
};
#endif