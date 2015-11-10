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

#if defined(P_OS_LINUX) || definef(P_OS_MACOSX) || defined(P_OS_BSD)

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>  
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define POVERLAY_BUFSIZE 512


#include "poverlay.h"

char *myfifo = "/tmp/pclient_to_server_fifo";
char *myfifo2 = "/tmp/pserver_to_client_fifo";

void overlay_main_loop()
{
  BOOL   fConnected = FALSE;
  HANDLE hPipe = INVALID_HANDLE_VALUE;

  // The main loop creates an instance of the named pipe and
  // then waits for a client to connect to it. When the client
  // connects, a thread is created to handle communications
  // with that client, and this loop is free to wait for the
  // next client connect request. It is an infinite loop.

  for (;;)
  {
    debug(D_NOTICE, "\nPipe Server: Main thread awaiting client connection on %s\n", PORT);
    hPipe = CreateNamedPipe(
      PORT,                     // pipe name
      PIPE_ACCESS_DUPLEX,       // read/write access
      PIPE_TYPE_MESSAGE |       // message type pipe
      PIPE_READMODE_MESSAGE |   // message-read mode
      PIPE_WAIT,                // blocking mode
      PIPE_UNLIMITED_INSTANCES, // max. instances
      POVERLAY_BUFSIZE,         // output buffer size
      POVERLAY_BUFSIZE,         // input buffer size
      0,                        // client time-out
      NULL);                    // default security attribute

    if (hPipe == INVALID_HANDLE_VALUE)
    {
      debug(D_NOTICE, "CreateNamedPipe failed, GLE=%d.\n", GetLastError());
      return;
    }

    fConnected = ConnectNamedPipe(hPipe, NULL) ?
    TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (fConnected)
    {
      debug(D_NOTICE, "Client connected, creating a processing thread.\n");

      // Create a thread for this client.
      psync_run_thread1(
        "Pipe request handle routine",
        instance_thread,    // thread proc
        (LPVOID)hPipe     // thread parameter
        );
    }
    else
      CloseHandle(hPipe);
  }

  return;
}

void instance_thread(void* lpvParam)
{
  int c2s, s2c;
  char  chBuf[POVERLAY_BUFSIZE];

  /* create the FIFO (named pipe) */
  mkfifo(myfifo, 0666);
  mkfifo(myfifo2, 0666);
  
  message* request = NULL; //(message*)psync_malloc(POVERLAY_BUFSIZE);
  message* reply = (message*)psync_malloc(POVERLAY_BUFSIZE);
  memset(reply, 0, sizeof(reply));

  while (1)
  {
    c2s = open(myfifo, O_WRONLY);
    s2c = open(myfifo2, O_RDONLY);
    while(1)
    {
      read(c2s, chBuf, POVERLAY_BUFSIZE);
      message *request = (message *)chBuf;
      if (request->type==42)
      {
        debug(D_NOTICE, "Server OFF.\n");
        break;
      }
      
      debug(D_NOTICE, "bytes received  %d buffer[%s]\n", strlen(chBuf), chBuf);
      get_answer_to_request(request, reply);
      write(s2c,reply,reply->length);
    }
    close(c2s);
    close(s2c);
  }
  unlink(myfifo);
  unlink(myfifo2);

  debug(D_NOTICE, "InstanceThread exitting.\n");
  return;
}

#endif defined(P_OS_LINUX) || definef(P_OS_MACOSX) || defined(P_OS_BSD)
