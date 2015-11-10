/* Copyright (c) 2013-2015 pCloud Ltd.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of pCloud Ltd nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL pCloud Ltd BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "pcompat.h"
#include "plibs.h"
#include "poverlay.h"


#if defined(P_OS_WINDOWS)

#include "poverlay_win.c"

#elif defined(P_OS_LINUX) || definef(P_OS_MACOSX) || defined(P_OS_BSD)

#include "poverlay_lin.c"

#else 

void overlay_main_loop(VOID){}
void instance_thread(LPVOID){}

#endif //defined(P_OS_WINDOWS)

void get_answer_to_request(message *request, message *replay)
{
  char msg[4] = "Ok.";
  msg[3] = '\0';

  debug(D_NOTICE, "Client Request type [%u] len [%llu] string: [%s]", request->type, request->length, request->value);

  if (strstr(request->value, "InSync") != 0) {
    replay->type = 10;
  }
  else if (strstr(request->value, "NoSync") != 0) {
    replay->type = 11;
  }
  else if (strstr(request->value, "InProgress") != 0) {
    replay->type = 12;
  }
  else {
    replay->type = 13;
    strncpy(msg,"No.",3);
  }
  replay->length = sizeof(message)+4;
  strncpy(replay->value, msg, 4);

}

