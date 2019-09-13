#include "pRJF.h"
#include "curl/curl.h"
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "psynclib.h"
#include "plibs.h"
#include "papi.h"
#include "pnetlibs.h"

CURL *curl;
CURLcode res;


typedef struct {
  char *ptr;
  size_t len;
} string;

typedef struct{
  uint64_t buffsize;
  int paramcnt;
  char * params;
} parambuffer;

#define CONSTRUCT(class, varname) class *varname  = malloc(sizeof(class)); init_##class(varname);

//static char empty[1] = {0};
static char *client_id_ = "397181747048725";
static char *gl_client_id = "972093246167-v9cg3f1ln0v4bg520qhvk3d30e71qvak.apps.googleusercontent.com";
static char *dummy_request_id_ = "Justadummyrequestid";

void init_string(string *s);

void init_parambuffer(parambuffer *s);

static uint64_t process_api_result(binresult* res) {
  uint64_t result;
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  if (result){
    return result;
  } else return 0;
  return 1;
}

// static int count_digits (uint64_t n) {
//    // if (n < 0) n = (n == -0xFFFFFFFFFFFFFFFF) ? 0xFFFFFFFFFFFFFFFF : -n;
//     if (n > 9999999999999999999U) return 20;
//     if (n > 999999999999999999) return 19;
//     if (n > 99999999999999999) return 18;
//     if (n > 9999999999999999) return 17;
//     if (n > 999999999999999) return 16;
//     if (n > 99999999999999) return 15;
//     if (n > 9999999999999) return 14;
//     if (n > 999999999999) return 13;
//     if (n > 99999999999) return 12;
//     if (n > 9999999999) return 11;
//     if (n > 999999999) return 10;
//     if (n > 99999999) return 9;
//     if (n > 9999999) return 8;
//     if (n > 999999) return 7;
//     if (n > 99999) return 6;
//     if (n > 9999) return 5;
//     if (n > 999) return 4;
//     if (n > 99) return 3;
//     if (n > 9) return 2;
//     return 1;
// }

/*static void add_param_str(const char *name, const char* val, parambuffer *params) {
  char * newp;
  int64_t nsize = strlen(name) + strlen(val) + 2 + params->buffsize;
  
  newp = realloc(params->params, nsize);
  if (newp) {
    params->params = newp;
    newp += params->buffsize;
    sprintf(newp,"&%s=%s", name, val);
  }
  params->buffsize = nsize;
  params->paramcnt++;
}

static void add_param_bool(const char *name, uint64_t val, parambuffer *params) {
  char * newp;
  int64_t nsize = strlen(name) + 1 + 2 + params->buffsize;
  
  newp = realloc(params->params, nsize);
  if (newp) {
    params->params = newp;
    newp += params->buffsize;
    sprintf(newp,"&%s=%d", name, (val)?1:0);
  }
  params->buffsize = nsize;
  params->paramcnt++;
}

static void add_param_int(const char *name, uint64_t val, parambuffer *params) {
  char * newp;
  int64_t nsize = strlen(name) + count_digits(val) + 2 + params->buffsize;
  
  newp = realloc(params->params, nsize);
  if (newp) {
    params->params = newp;
    newp +=  params->buffsize;
    sprintf(newp,"&%s=%lu", name, val);
  }
  params->buffsize = nsize;
  params->paramcnt++;
}
*/

void init_string(string *s) {
  s->len = 0;
  s->ptr = malloc(1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

void init_parambuffer(parambuffer *s) {
  s->paramcnt = 0;
  s->buffsize = 0;
  char *par = malloc(1);
  if (par == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  par[0] = '\0';
  s->params = par;
}
/*
size_t writefunc(void *ptr, size_t size, size_t nmemb, string *s)
{
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}

int send_webapi_command(const char *url, char **result, int numparam, const char * fmt, ...) {
   
  va_list ap;
  int j;
  long pint = 0;
  char * pstr = NULL;
  char * next = NULL;
//  int fmtlen = strlen(fmt);
  const char * fmtind = fmt;
  char *params;
  
  CONSTRUCT(parambuffer, parambufpost);
  CONSTRUCT(parambuffer, parambufget);
  
  va_start(ap, fmt); //Requires the last fixed parameter (to get the address)
  for(j=0; j<numparam; j++) {
    next = strchr(fmtind,'%');
    if (!next)
      break;
    char * name = strndup(fmtind, (next - fmtind));
    if (next[1] == 's') {  
      pstr = va_arg(ap, char *);
      if (next[2] == 'p')
        add_param_str(name, pstr, parambufpost);
      else if (next[2] == 'g')
        add_param_str(name, pstr, parambufget);
    } else if (next[1] == 'b') {
      pint = va_arg(ap, long);
      if (next[2] == 'p')
        add_param_bool(name, pint, parambufpost);
      else if (next[2] == 'g')
        add_param_bool(name, pint, parambufget);
    } else if (next[1] == 'd') {
      pint = va_arg(ap, long);
      if (next[2] == 'p')
        add_param_int(name, pint, parambufpost);
      else if (next[2] == 'g')
        add_param_int(name, pint, parambufget);
    }
    fmtind = next+4;
  }
  va_end(ap);
  
  // By now the parameters look good (from what I can tell)
  curl = curl_easy_init();
  if (curl) {
    
    CONSTRUCT(string, s);
    
    int geturlsize = parambufget->buffsize + 2 + strlen(url);
    char *GETURL = (char *)malloc(geturlsize);
    strcpy (GETURL, url);
    strcat (GETURL, "?");
    strcat (GETURL, parambufget->params);
 
    // Set up options and attempt to submit POST form
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36");
    curl_easy_setopt(curl, CURLOPT_URL, GETURL);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);

    // Convert params to url encoded string (takes care of special chars)
    params = curl_easy_escape(curl, parambufpost->params, 0);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params);
    res = curl_easy_perform(curl);      
    if(res != CURLE_OK)
        fprintf(stderr, "Facebook curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
  *  else {
      char *url;
      res = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);

      if((CURLE_OK == res) && url)
                 printf("CURLINFO_EFFECTIVE_URL: %s\n", url);
    }*
    curl_easy_cleanup(curl);

    //printf("End the result is %s\n", s->ptr);
    *result = strdup(s->ptr);
    free(params);
    free(parambufpost);
    free(parambufget);
    free(GETURL);
    free(s);
  }
  return 0;
}
*/

static void fb_update_user()
{
	int cnt = 100;
	while (cnt-- > 0){
		psync_milisleep(500);
		if (psync_my_auth[0]){
			binresult *res;
			uint64_t err;
			binparam params[] = { P_STR("auth", psync_my_auth), P_STR("timeformat", "timestamp") };
			res = psync_api_run_command("userinfo", params);
			if (!res) {
				debug(D_WARNING, "fb_update_user command returned invalid result.\n");
				psync_free(res);
				continue;
			}
			
			err = process_api_result(res);
			if (err)
			{
				psync_free(res);
				continue;
			}
				
			const char *email = psync_find_result(res, "email", PARAM_STR)->str;
			psync_set_string_value("user", email);
			psync_free(res);
			return;
		}
	}
}

char * fb_get_client_id() {
  char * ret = psync_get_string_value("client_id");
  if (ret) 
    return ret;
  else 
    return psync_strdup(client_id_);
}

char * gl_get_client_id() {
	char * ret = psync_get_string_value("gl_client_id");
	if (ret)
		return ret;
	else
		return psync_strdup(gl_client_id);
}

char * fb_get_request_id() {
  binparam params[] = { P_STR("MS", "Sucks") };
  binresult *res;
  char * result = NULL;

  res = psync_api_run_command("getrequestid", params);
  if (unlikely_log(!res))
    return psync_strdup(dummy_request_id_);

  uint64_t err = process_api_result(res);
  if (err)
    debug(D_WARNING, "getrequestid returned error %lu: %s", err, psync_find_result(res, "error", PARAM_STR)->str);
  else {
    const char * request_id = psync_find_result(res, "request_id",  PARAM_STR)->str;
    if (request_id) {
      result = psync_strdup(request_id);
    } else {
      debug(D_WARNING, "No request_id found!");
      result = psync_strdup(dummy_request_id_);
    }
  }
  psync_free(res);
  return result;
}

typedef struct {
  char *requestid;
  fb_err_callback callback;
} wait_params;

void fb_wait_authorized(void *p) {
	uint64_t ret;
  wait_params *param = (wait_params *)p;
  binparam params[] = { P_STR("request_id", param->requestid), P_NUM("os", P_OS_ID) };
  binresult *res;
  fb_err_callback clb = param->callback;
  char * deviceid;

  res = psync_api_run_command("fb_oauth2_token", params);
  if (unlikely_log(!res)){
    goto freeparam;
  }

  ret = process_api_result(res);
  if (ret) {
    char * msg = psync_strdup(psync_find_result(res, "error", PARAM_STR)->str);
    debug(D_NOTICE, "Error getting result %llu msg [%s]", (unsigned long long)ret, msg);
    clb(ret, msg, NULL);
  }
  else {
    const char * fb_token = psync_find_result(res, "access_token",  PARAM_STR)->str;
	deviceid = psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");
	if (!deviceid)
		deviceid = generate_device_id();
	char * device = psync_device_string();
	char * osversion = psync_deviceos();
	char * appversion = psync_appname();

    if (fb_token) {
		binparam params[] = { P_STR("fb_access_token", fb_token), 
			P_STR("osversion", osversion), 
			P_STR("device", device), 
			P_NUM("os", P_OS_ID), 
			P_STR("appversion", appversion),
			P_STR("deviceid", deviceid) };
		uint64_t result;
		binresult *loginres;
      psync_set_string_value("fb_access_token", fb_token);
      loginres = psync_api_run_command("fb_login", params);
	  if (unlikely_log(!loginres)){
		  psync_free(deviceid);
		  psync_free(device);
		  goto theend;
	  }
     
      result = process_api_result(loginres);
      if (!result) {
		uint64_t olduserid;
		uint64_t newuserid;
        const char * auth1 = psync_find_result(loginres, "auth",  PARAM_STR)->str;
        olduserid = psync_get_uint_value("userid");
        newuserid = psync_find_result(loginres, "userid",  PARAM_NUM)->num;
        if (olduserid && (olduserid != newuserid)) {
          char *msg1 = psync_strdup("This Facebook account is not linked to your current pCloud account.\nYou can link both accounts in Settings on my.pcloud.com or Unlink to continue with this Facebook account.");
          result = 43;
          clb(result, msg1, fb_token);
        } else {
          psync_set_auth(auth1, 1);
          psync_set_int_value("userid",  psync_find_result(loginres, "userid",  PARAM_NUM)->num);
          debug(D_NOTICE, "Found user token  [%s] form fb access token [%s]", auth1, fb_token);
          clb(0, NULL, NULL);
        }
      } else {
		  uint64_t olduserid = psync_get_uint_value("userid");
		  uint64_t newuserid = psync_find_result(loginres, "userid", PARAM_NUM)->num;
		  char * msg = NULL;
		  if (olduserid && (olduserid != newuserid)) {
			  char *msg1 = psync_strdup("This Facebook account is not linked to your current pCloud account.\nYou can link both accounts in Settings on my.pcloud.com or Unlink to continue with this Facebook account.");
			  result = 43;
			  clb(result, msg1, fb_token);
			  psync_free(loginres);
			  goto theend;
		  }
		  else {
			  
			  if (result == 2037) {
				  //msg = psync_strdup("Warning new account will be registered!");
				  msg = psync_strdup(psync_find_result(loginres, "email", PARAM_STR)->str);
				  result = 42;
			  }
			  else if (result == 2297)
			  {
				  psync_set_status(2, 64);
				  psync_free(psync_my_2fa_token);
				  psync_my_2fa_token = psync_strdup(psync_find_result(loginres, "token", PARAM_STR)->str);
				  psync_my_2fa_has_devices = psync_find_result(loginres, "hasdevices", PARAM_BOOL)->num;
				  psync_my_2fa_type = psync_find_result(loginres, "tfatype", PARAM_NUM)->num;
				  psync_my_2fa_code_type = 0;
				  psync_my_2fa_code[0] = 0;
				  psync_wait_status(2, 1);
				  psync_set_user_pass("pass", "dummy", 0);
				  clb(0, NULL, NULL);
				  psync_free(loginres);
				  psync_free(deviceid);
				  psync_free(device);
				  psync_run_thread("fb update dummy user", fb_update_user);

				  goto theend;
			  }
			  else
				  msg = psync_strdup(psync_find_result(loginres, "error", PARAM_STR)->str);
		  }
        debug(D_NOTICE, "Error getting result %llu msg [%s] fb access token [%s]", (unsigned long long)result, msg, fb_token);
        clb(result, msg, fb_token);
      }

	  psync_free(deviceid);
	  psync_free(device);
      psync_free(loginres);
    }
  }
theend:
  psync_free(res);
freeparam:
  psync_free(param->requestid);
  psync_free(param);
}

void gl_wait_authorized(void *p) {
	uint64_t ret;
	wait_params *param = (wait_params *)p;
	binparam params[] = { P_STR("request_id", param->requestid), P_NUM("os", P_OS_ID) };
	binresult *res;
	fb_err_callback clb = param->callback;
	char * deviceid;

	res = psync_api_run_command("gl_oauth2_token", params);
	if (unlikely_log(!res)){
		goto freeparam;
	}

	ret = process_api_result(res);
	if (ret) {
		char * msg = psync_strdup(psync_find_result(res, "error", PARAM_STR)->str);
		debug(D_NOTICE, "Error getting result %llu msg [%s]", (unsigned long long)ret, msg);
		clb(ret, msg, NULL);
	}
	else {
		const char * gl_token = psync_find_result(res, "access_token", PARAM_STR)->str;
		deviceid = psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");
		if (!deviceid)
			deviceid = generate_device_id();
		char * device = psync_device_string();
		char * osversion = psync_deviceos();
		char * appversion = psync_appname();

		if (gl_token) {
			binparam params[] = { P_STR("gl_access_token", gl_token),
				P_STR("osversion", osversion),
				P_STR("device", device),
				P_NUM("os", P_OS_ID),
				P_STR("appversion", appversion),
				P_STR("deviceid", deviceid) };
			uint64_t result;
			binresult *loginres;
			psync_set_string_value("gl_access_token", gl_token);
			loginres = psync_api_run_command("gl_login", params);
			if (unlikely_log(!loginres)){
				psync_free(deviceid);
				psync_free(device);
				goto theend;
			}

			result = process_api_result(loginres);
			if (!result) {
				uint64_t olduserid;
				uint64_t newuserid;
				const char * auth1 = psync_find_result(loginres, "auth", PARAM_STR)->str;
				olduserid = psync_get_uint_value("userid");
				newuserid = psync_find_result(loginres, "userid", PARAM_NUM)->num;
				if (olduserid && (olduserid != newuserid)) {
					debug(D_NOTICE, "Old userid  [%d] and new userid [%d]", olduserid, newuserid);
					char *msg1 = psync_strdup("This Google account is not linked to your current pCloud account.\nYou can link both accounts in Settings on my.pcloud.com or Unlink to continue with this Google account.");
					result = 43;
					clb(result, msg1, gl_token);
				}
				else {
					psync_set_auth(auth1, 1);
					psync_set_int_value("userid", psync_find_result(loginres, "userid", PARAM_NUM)->num);
					debug(D_NOTICE, "Found user token  [%s] form fb access token [%s]", auth1, gl_token);
					clb(0, NULL, NULL);
				}
			}
			else {
				uint64_t olduserid = psync_get_uint_value("userid");
				uint64_t newuserid = psync_find_result(loginres, "userid", PARAM_NUM)->num;
				char * msg = NULL;
				if (olduserid && (olduserid != newuserid)) {
					debug(D_NOTICE, "Old userid  [%d] and new userid [%d]", olduserid, newuserid);
					char *msg1 = psync_strdup("This Google account is not linked to your current pCloud account.\nYou can link both accounts in Settings on my.pcloud.com or Unlink to continue with this Google account.");
					result = 43;
					clb(result, msg1, gl_token);
					psync_free(loginres);
					goto theend;
				}
				else {

					if (result == 2037) {
						//msg = psync_strdup("Warning new account will be registered!");
						msg = psync_strdup(psync_find_result(loginres, "email", PARAM_STR)->str);
						result = 42;
					}
					else if (result == 2297)
					{
						psync_set_status(2, 64);
						psync_free(psync_my_2fa_token);
						psync_my_2fa_token = psync_strdup(psync_find_result(loginres, "token", PARAM_STR)->str);
						psync_my_2fa_has_devices = psync_find_result(loginres, "hasdevices", PARAM_BOOL)->num;
						psync_my_2fa_type = psync_find_result(loginres, "tfatype", PARAM_NUM)->num;
						psync_my_2fa_code_type = 0;
						psync_my_2fa_code[0] = 0;
						psync_wait_status(2, 1);
						psync_set_user_pass("pass", "dummy", 0);
						clb(0, NULL, NULL);
						psync_free(loginres);
						psync_free(deviceid);
						psync_free(device);
						psync_run_thread("fb update dummy user", fb_update_user);

						goto theend;
					}
					else
						msg = psync_strdup(psync_find_result(loginres, "error", PARAM_STR)->str);
				}
				debug(D_NOTICE, "Error getting result %llu msg [%s] fb access token [%s]", (unsigned long long)result, msg, gl_token);
				clb(result, msg, gl_token);
			}

			psync_free(deviceid);
			psync_free(device);
			psync_free(loginres);
		}
	}
theend:
	psync_free(res);
freeparam:
	psync_free(param->requestid);
	psync_free(param);
}

char * fb_authorize(fb_err_callback callback){
  char *clientid = fb_get_client_id();
  char *requestid = fb_get_request_id();
  const char * fb_call = "https://www.facebook.com/dialog/oauth?scope=email&display=popup&response_type=token&client_id=%s&state={\"request_id\":\"%s\"}&redirect_uri=https://my.pcloud.com/fbpoll.html";
  int bufsize = strlen(fb_call) - 4 /*2 %s*/ + 1 /*zero terminator*/ + strlen (clientid) + strlen (requestid);
  char * buff = (char *)malloc(bufsize);
  int ret = sprintf(buff, fb_call, clientid, requestid);
  psync_free(clientid);
  if (++ret != bufsize) {
    debug(D_NOTICE, "Size missmatch %d %d", ret, bufsize);
  }
  wait_params *thrparams = (wait_params *) psync_malloc(sizeof(wait_params));
  thrparams->requestid = requestid;
  thrparams->callback = callback;
  psync_run_thread1("fb waiter thread",fb_wait_authorized, thrparams);
  return buff;
}

char * gl_authorize(fb_err_callback callback){
	wait_params *thrparams;
	char *clientid = gl_get_client_id();
	char *requestid = fb_get_request_id();
	const char * gl_call = "https://accounts.google.com/o/oauth2/auth?client_id=%s&scope=https://www.googleapis.com/auth/userinfo.profile%%20https://www.googleapis.com/auth/userinfo.email&response_type=token&state={\"request_id\":\"%s\"}&redirect_uri=https://my.pcloud.com/glpoll.html";
	
	int bufsize = strlen(gl_call) - 4 /*2 %s*/ + 1 /*zero terminator*/ + strlen(clientid) + strlen(requestid);
	char * buff = (char *)malloc(bufsize);
	int ret = sprintf(buff, gl_call, clientid, requestid);
	psync_free(clientid);
	if (++ret != bufsize) {
		debug(D_NOTICE, "Size missmatch %d %d", ret, bufsize);
	}
	thrparams = (wait_params *)psync_malloc(sizeof(wait_params));
	thrparams->requestid = requestid;
	thrparams->callback = callback;
	psync_run_thread1("fb waiter thread", gl_wait_authorized, thrparams);
	return buff;
}

int fb_login_register(const char *email,  const char* fb_token, int termsaccepted, char **err){
  binresult *loginres = NULL;
  uint64_t result;
  char * device = psync_device_string();
  char * deviceid;
  char * osversion = psync_deviceos();
  char * appversion = psync_appname();
  deviceid = psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");
  if (!deviceid)
	  deviceid = generate_device_id();
  if (email) {
	  binparam params[] = { P_STR("mail", email), 
		  P_STR("fb_access_token", fb_token), 
		  P_STR("termsaccepted", termsaccepted ? "yes" : "0"), 
		  P_STR("osversion", osversion), 
		  P_NUM("os", P_OS_ID), 
		  P_STR("deviceid", deviceid), 
		  P_STR("appversion", appversion),
		  P_STR("device", device) };
    loginres = psync_api_run_command("fb_login", params);
  } else if (termsaccepted == 0) {
	  binparam params[] = { P_STR("fb_access_token", fb_token), 
		  P_STR("osversion", osversion), 
		  P_STR("device", device), 
		  P_STR("deviceid", deviceid),
		  P_STR("appversion", appversion),
		  P_NUM("os", P_OS_ID) };
    loginres = psync_api_run_command("fb_login", params);
  } else {
	  binparam params[] = { P_STR("fb_access_token", fb_token), 
		  P_STR("termsaccepted", termsaccepted ? "yes" : "0"), 
		  P_STR("osversion", osversion), 
		  P_NUM("os", P_OS_ID), 
		  P_STR("deviceid", deviceid), 
		  P_STR("appversion", appversion),
		  P_STR("device", device) };
    loginres = psync_api_run_command("fb_login", params);
  }
  if (unlikely_log(!loginres)){
    *err = psync_strdup("Facebook login returned invalid result!");
	psync_free(deviceid);
	psync_free(device);
    return 1;
  }
  result = process_api_result(loginres);
  if (!result) {
    const char * auth1 = psync_find_result(loginres, "auth",  PARAM_STR)->str;
    psync_set_auth(auth1, 1);
    psync_set_int_value("userid",  psync_find_result(loginres, "userid",  PARAM_NUM)->num);
    debug(D_NOTICE, "Found user token  [%s] form fb access token [%s]", auth1, fb_token);
  } else {
	if ((unsigned long long)result == 2037)
	{
      *err = psync_strdup(psync_find_result(loginres, "email", PARAM_STR)->str);
	}
	else if (result == 2297)
	{
		psync_set_status(2, 64);
		psync_free(psync_my_2fa_token);
		psync_my_2fa_token = psync_strdup(psync_find_result(loginres, "token", PARAM_STR)->str);
		psync_my_2fa_has_devices = psync_find_result(loginres, "hasdevices", PARAM_BOOL)->num;
		psync_my_2fa_type = psync_find_result(loginres, "tfatype", PARAM_NUM)->num;
		psync_my_2fa_code_type = 0;
		psync_my_2fa_code[0] = 0;
		psync_wait_status(2, 1);
		psync_set_user_pass("pass", "dummy", 0);
		psync_free(loginres);
		psync_free(deviceid);
		psync_free(device);
		psync_run_thread("fb update dummy user", fb_update_user);
		return 0;
	}
	else
	{
      *err = psync_strdup(psync_find_result(loginres, "error", PARAM_STR)->str);
      debug(D_NOTICE, "Error getting result %llu msg [%s] fb access token [%s] email [%s]", (unsigned long long)result, *err, fb_token, email);
	}
  }
  psync_free(loginres);
  psync_free(deviceid);
  psync_free(device);
  return (int) result;
}

int gl_login_register(const char *email, const char* gl_token, int termsaccepted, char **err){
	binresult *loginres = NULL;
	uint64_t result;
	char * device = psync_device_string();
	char * deviceid;
	char * osversion = psync_deviceos();
	char * appversion = psync_appname();
	deviceid = psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");
	if (!deviceid)
		deviceid = generate_device_id();
	if (email) {
		binparam params[] = { P_STR("mail", email),
			P_STR("gl_access_token", gl_token),
			P_STR("termsaccepted", termsaccepted ? "yes" : "0"),
			P_STR("osversion", osversion),
			P_NUM("os", P_OS_ID),
			P_STR("deviceid", deviceid),
			P_STR("appversion", appversion),
			P_STR("device", device) };
		loginres = psync_api_run_command("gl_login", params);
	}
	else if (termsaccepted == 0) {
		binparam params[] = { P_STR("gl_access_token", gl_token),
			P_STR("osversion", osversion),
			P_STR("device", device),
			P_STR("deviceid", deviceid),
			P_STR("appversion", appversion),
			P_NUM("os", P_OS_ID) };
		loginres = psync_api_run_command("gl_login", params);
	}
	else {
		binparam params[] = { P_STR("gl_access_token", gl_token),
			P_STR("termsaccepted", termsaccepted ? "yes" : "0"),
			P_STR("osversion", osversion),
			P_NUM("os", P_OS_ID),
			P_STR("deviceid", deviceid),
			P_STR("appversion", appversion),
			P_STR("device", device) };
		loginres = psync_api_run_command("gl_login", params);
	}
	if (unlikely_log(!loginres)){
		*err = psync_strdup("Google login returned invalid result!");
		psync_free(deviceid);
		psync_free(device);
		return 1;
	}
	result = process_api_result(loginres);
	if (!result) {
		const char * auth1 = psync_find_result(loginres, "auth", PARAM_STR)->str;
		psync_set_auth(auth1, 1);
		psync_set_int_value("userid", psync_find_result(loginres, "userid", PARAM_NUM)->num);
		debug(D_NOTICE, "Found user token  [%s] form gl access token [%s]", auth1, gl_token);
	}
	else {
		if ((unsigned long long)result == 2037)
		{
			*err = psync_strdup(psync_find_result(loginres, "email", PARAM_STR)->str);
		}
		else if (result == 2297)
		{
			psync_set_status(2, 64);
			psync_free(psync_my_2fa_token);
			psync_my_2fa_token = psync_strdup(psync_find_result(loginres, "token", PARAM_STR)->str);
			psync_my_2fa_has_devices = psync_find_result(loginres, "hasdevices", PARAM_BOOL)->num;
			psync_my_2fa_type = psync_find_result(loginres, "tfatype", PARAM_NUM)->num;
			psync_my_2fa_code_type = 0;
			psync_my_2fa_code[0] = 0;
			psync_wait_status(2, 1);
			psync_set_user_pass("pass", "dummy", 0);
			psync_free(loginres);
			psync_free(deviceid);
			psync_free(device);
			psync_run_thread("fb update dummy user", fb_update_user);
			return 0;
		}
		else
		{
			*err = psync_strdup(psync_find_result(loginres, "error", PARAM_STR)->str);
			debug(D_NOTICE, "Error getting result %llu msg [%s] fb access token [%s] email [%s]", (unsigned long long)result, *err, gl_token, email);
		}
	}
	psync_free(loginres);
	psync_free(deviceid);
	psync_free(device);
	return (int)result;
}

int fb_assign(const char* fb_token, char **err) {
  const char *auth = psync_get_auth_string();
  char * device = psync_device_string();
  char * deviceid;
  char * osversion = psync_deviceos();
  char * appversion = psync_appname();
  deviceid = psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");
  if (!deviceid)
	  deviceid = generate_device_id();
  binparam params[] = { P_STR("fb_access_token", fb_token), 
	  P_STR("auth", auth), 
	  P_STR("osversion", osversion), 
	  P_STR("device", device), 
	  P_STR("deviceid", deviceid), 
	  P_STR("appversion", appversion), 
	  P_NUM("os", P_OS_ID) };
  psync_set_string_value("fb_access_token", fb_token);
  return psync_run_command("fb_login_assign", params, err);
}

int gl_assign(const char* gl_token, char **err) {
	const char *auth = psync_get_auth_string();
	char * device = psync_device_string();
	char * deviceid;
	char * osversion = psync_deviceos();
	char * appversion = psync_appname();
	deviceid = psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");
	if (!deviceid)
		deviceid = generate_device_id();
	binparam params[] = { P_STR("gl_access_token", gl_token),
		P_STR("auth", auth),
		P_STR("osversion", osversion),
		P_STR("device", device),
		P_STR("deviceid", deviceid),
		P_STR("appversion", appversion),
		P_NUM("os", P_OS_ID) };
	psync_set_string_value("gl_access_token", gl_token);
	return psync_run_command("gl_login_assign", params, err);
}

int fb_login(const char* fb_token, char **err) {
  return fb_login_register(NULL, fb_token, 0, err);
}

int gl_login(const char* gl_token, char **err) {
	return gl_login_register(NULL, gl_token, 0, err);
}
