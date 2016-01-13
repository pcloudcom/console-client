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

#if defined(P_OS_LINUX) || defined(P_OS_MACOSX) || defined(P_OS_BSD)

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#define POVERLAY_BUFSIZE 512

#include "poverlay.h"

char *mysoc = "/tmp/pcloud_unix_soc.sock";

void overlay_main_loop()
{
  struct sockaddr_un addr;
  int fd,cl;
  
  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    //debug(D_NOTICE, "Unix socket error failed to open %s", mysoc);
    return;
  }
  
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, mysoc, sizeof(addr.sun_path)-1);

  unlink(mysoc);
  
  if (bind(fd, (struct sockaddr*)&addr,  strlen(mysoc) + sizeof(addr.sun_family)) == -1) {
    debug(D_ERROR,"Unix socket bind error");
    return;
  }

  if (listen(fd, 5) == -1) {
    debug(D_ERROR,"Unix socket listen error");
    return;
  }

  while (1) {
    if ( (cl = accept(fd, NULL, NULL)) == -1) {
      debug(D_ERROR,"Unix socket accept error");
      continue;
    }
    psync_run_thread1(
      "Pipe request handle routine",
      instance_thread,    // thread proc
      (LPVOID)&cl     // thread parameter
      ); 
  }

  return;
}

void instance_thread(void* lpvParam)
{
  int *cl, rc;
  char  chbuf[POVERLAY_BUFSIZE];
  message* request = NULL; 
  char * curbuf = &chbuf[0];
  int bytes_read = 0;
  message* reply = (message*)psync_malloc(POVERLAY_BUFSIZE);

  memset(reply, 0, POVERLAY_BUFSIZE);
  memset(chbuf, 0, POVERLAY_BUFSIZE);
  
  cl = (int *)lpvParam;
  
  while ( (rc=read(*cl,curbuf,(POVERLAY_BUFSIZE - bytes_read))) > 0) {
    bytes_read += rc;
    //debug(D_ERROR, "Read %u bytes: %u %s", bytes_read, rc, curbuf );
    curbuf = curbuf + rc;
    if (bytes_read > 12){
      request = (message *)chbuf;
      if(request->length == bytes_read)
        break;
    }
  }
  if (rc == -1) {
    //debug(D_ERROR,"Unix socket read");
    close(*cl);
    return;
  }
  else if (rc == 0) {
    //debug(D_NOTICE,"Message received");
    close(*cl);
  }
  request = (message *)chbuf;
  if (request) {
  get_answer_to_request(request, reply);
    if (reply ) {
      rc = write(*cl,reply,reply->length);
      if (rc != reply->length)
        debug(D_ERROR,"Unix socket reply not sent.");
    
    }
  }
  if (cl) {
    close(*cl);
  }
  //debug(D_NOTICE, "InstanceThread exitting.\n");
  return;
};

#endif //defined(P_OS_LINUX) || definef(P_OS_MACOSX) || defined(P_OS_BSD)
