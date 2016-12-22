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
#include "ppathstatus.h"
#include "pcache.h"

int overlays_running = 1;
int callbacks_running = 1;

#if defined(P_OS_WINDOWS)

#include "poverlay_win.c"

#elif defined(P_OS_LINUX)

#include "poverlay_lin.c"

#elif defined(P_OS_MACOSX)

#include "poverlay_mac.c"

#else

void overlay_main_loop(VOID){}
void instance_thread(LPVOID){}

#endif //defined(P_OS_WINDOWS)

poverlay_callback * callbacks;
static int callbacks_size = 15;
static const int calbacks_lower_band = 20;

int psync_add_overlay_callback(int id, poverlay_callback callback)
{
  poverlay_callback * callbacks_old = callbacks;
  int callbacks_size_old = callbacks_size;
  if (id < calbacks_lower_band)
    return -1;
  if (id > (calbacks_lower_band + callbacks_size)) {
     callbacks_size = id - calbacks_lower_band + 1;
     init_overlay_callbacks();
     memcpy(callbacks,callbacks_old, callbacks_size_old*sizeof(poverlay_callback));
     psync_free(callbacks_old);
  }
  callbacks[id - calbacks_lower_band] = callback;
  return 0;
}

void init_overlay_callbacks() {
  callbacks = (poverlay_callback *) psync_malloc(sizeof(poverlay_callback)*callbacks_size);
  memset(callbacks, 0, sizeof(poverlay_callback)*callbacks_size);
}

void psync_stop_overlays(){
  overlays_running = 0;
}
void psync_start_overlays(){
  overlays_running = 1;
}

void psync_stop_overlay_callbacks(){
  callbacks_running = 0;
}
void psync_start_overlay_callbacks(){
  callbacks_running = 1;
}

void get_answer_to_request(message *request, message *replay)
{
  psync_path_status_t stat=PSYNC_PATH_STATUS_NOT_OURS;
  memcpy(replay->value, "Ok.", 4);
  replay->length=sizeof(message)+4;
  //debug(D_NOTICE, "Client Request type [%u] len [%lu] string: [%s]", request->type, request->length, request->value);
  if (request->type < 20 ) {
    if (overlays_running)
      stat=psync_path_status_get(request->value);
    switch (psync_path_status_get_status(stat)) {
      case PSYNC_PATH_STATUS_IN_SYNC:
        replay->type=10;
        break;
      case PSYNC_PATH_STATUS_IN_PROG:
        replay->type=12;
        break;
      case PSYNC_PATH_STATUS_PAUSED:
      case PSYNC_PATH_STATUS_REMOTE_FULL:
      case PSYNC_PATH_STATUS_LOCAL_FULL:
        replay->type=11;
        break;
      default:
        replay->type=13;
        memcpy(replay->value, "No.", 4);
    }
  } else if ((callbacks_running)&&(request->type < (calbacks_lower_band + callbacks_size))) {
    int ind = request->type - 20;
    int ret = 0;
    message *rep = NULL;
    
    if (callbacks[ind]) {
      if ((ret = callbacks[ind](request->value, rep)) == 0) {
        if (rep) {
          psync_free(replay);
          replay = rep;
        }
        else 
        replay->type = 0;
      } else {
        replay->type = ret;
        memcpy(replay->value, "No.", 4);
      }
    } else {
      replay->type = 13;
      memcpy(replay->value, "No callback with this id registered.", 37);
      replay->length = sizeof(message)+37;
    }
  } else {
      replay->type = 13;
      memcpy(replay->value, "Invalid type.", 14);
      replay->length = sizeof(message)+14;
    }

}


int psync_overlays_running(){return overlays_running;}
int psync_ovr_callbacks_running(){return callbacks_running;}
