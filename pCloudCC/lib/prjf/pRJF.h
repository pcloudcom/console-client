//#include "jsmn.h"
#include <stdint.h>

typedef void (/*_cdecl*/ *fb_err_callback)(int result, char * msg,const char * token);

/*
  Method used to get facebook authorization. Returns constructed URL that has to be set in user's browser
  in order to get authorization. Given callback is used to get login result. 
  
    Result 0 means login successful and new pcloud authentication token had been acquired. pCloud authentication token
    is stored in the database also userid and Facebook access token as "fb_access_token".
    
    Result 2262 - "Provided 'request_id' expired.". This means user has not authorized us at all. 
    Token parameter is NULL in this case.
    
    Result 2266 - "Access denied.". The user was denied us access in Facebook page.
    Token parameter is NULL in this case.
    
    Result 1033 - Please provide 'mail'. Facebook returns empty email. We should ask the user to provide email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 
    
    Result 2018 - Invalid 'mail' provided. Facebook returns invalid email. We should ask the user to provide email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 
    
    Result 2038 - User with this email is already registered. We should ask the user to provide another email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 

    Result 4000 - Too many login tries from this IP address.
  
  Returned char * must be freed at the end.
  
*/

char * fb_authorize(fb_err_callback callback);
char * gl_authorize(fb_err_callback callback);

/*
  Method used to login in pcloud using facebook token. 
  
    Result 0 means login successful and new pcloud authentication token had been acquired. pCloud authentication token
    is stored in the database also userid and Facebook access token as "fb_access_token".
    
    Result 1033 - Please provide 'mail'. Facebook returns empty email. We should ask the user to provide email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 
    
    Result 2018 - Invalid 'mail' provided. Facebook returns invalid email. We should ask the user to provide email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 
    
    Result 2038 - User with this email is already registered. We should ask the user to provide another email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 

    Result 4000 - Too many login tries from this IP address.
  
  Returned err must be freed at the end.
    
*/

int fb_login(const char* fb_token, char **err);
int gl_login(const char* gl_token, char **err);

/*
  Method used to login in pcloud using facebook token. If email is null login attempt without an email is made. This may be useful when 
  trying to login with stored fb_access_token.
  
    Result 0 means login successful and new pcloud authentication token had been acquired. pCloud authentication token
    is stored in the database also userid and Facebook access token as "fb_access_token".
    
    Result 1033 - Please provide 'mail'. Facebook returns empty email. We should ask the user to provide email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 
    
    Result 2018 - Invalid 'mail' provided. Facebook returns invalid email. We should ask the user to provide email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 
    
    Result 2038 - User with this email is already registered. We should ask the user to provide another email and 
    try to login manually using fb_login_register. Token parameter contains acquired facebook access token. 

    Result 4000 - Too many login tries from this IP address.
  
  Returned err must be freed at the end.
    
*/

int fb_login_register(const char *email,  const char* fb_token, int termsaccepted, char **err);
int gl_login_register(const char *email, const char* gl_token, int termsaccepted, char **err);

/*
 Assigns facebook token to a existing account. Login required. 
 */

int fb_assign(const char* fb_token, char **err);
int gl_assign(const char* fb_token, char **err);

/*
 Returns facbook application client id to be used with facebook API. Checks for stored in database id or uses a static one.
 Returned value must be freed.
 */

char * fb_get_client_id();
char * gl_get_client_id();

/*
 Returns next requestid  to be used with facebook API. Checks for stored in database id or uses a static one.
 Returned value must be freed.
 */

char * fb_get_request_id();

/*
  Initiates a call to a WEB API command. 
  url is the URL of the webapi followed by the command. The result is returned result memory has to be freed at the end.
  The numparam is number of parameters passed. The fmt is parameters formats string containing their names and types. 
  Available types are b, s, d for bool, string, int. Then type is followed by g or p so the parameter is passed in post
  or in get request.
  Example:
  send_webapi_command("https://api.pcloud.com/userinfo", 
                      &result, 2, "username%sg&password%sg", "ivan.stoev@pcloud.com", "hrehrhrh");
 

  
int send_webapi_command(const char *URL, char **result, int numparam, const char * fmt, ...);*/