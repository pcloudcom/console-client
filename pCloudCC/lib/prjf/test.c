#include "pRJF.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/jsmn/jsmn.h"

int main() {
  char *result = NULL;
  int r;
  jsmn_parser p;
  jsmntok_t t[1024]; /* We expect no more than 128 tokens */

  int ret = 
  send_webapi_command("https://api.pcloud.com/userinfo", 
                      &result, 2, "username%sg&password%sg", "ivan.stoev@pcloud.com", "hrehrhrh");
  printf("Result is [%d] json body [%s] \n", ret, result);
  
  jsmn_init(&p);
  r = jsmn_parse(&p, result, strlen(result), t, sizeof(t)/sizeof(t[0]));
  if (r < 0) {
    printf("Failed to parse JSON: %d\n", r);
    return 1;
  }

  /* Assume the top-level element is an object */
  if (r < 1 || t[0].type != JSMN_OBJECT) {
    printf("Object expected\n");
    return 1;
  }
  
  free (result);
}