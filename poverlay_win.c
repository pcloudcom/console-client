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

#if defined(P_OS_WINDOWS)

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>

#define POVERLAY_BUFSIZE 600
#define MAX_SEM_COUNT 10
#define THREADCOUNT 12

#include "poverlay.h"

LPCWSTR PORT = TEXT("\\\\.\\pipe\\pStatusPipe");

void overlay_main_loop(VOID)
{
  BOOL   fConnected = FALSE;
  HANDLE hPipe = INVALID_HANDLE_VALUE;
  HANDLE ghSemaphore;
  DWORD dwWaitResult;

  // The main loop creates an instance of the named pipe and
  // then waits for a client to connect to it. When the client
  // connects, a thread is created to handle communications
  // with that client, and this loop is free to wait for the
  // next client connect request. It is an infinite loop.

  ghSemaphore = CreateSemaphore(
    NULL,           // default security attributes
    MAX_SEM_COUNT,  // initial count
    MAX_SEM_COUNT,  // maximum count
    NULL);          // unnamed semaphore

  if (ghSemaphore == NULL)
  {
    printf("CreateSemaphore error: %d\n", GetLastError());
    return 1;
  }

  for (;;)
  {
    //debug(D_NOTICE, "\nPipe Server: Main thread awaiting client connection on %s\n", PORT);

    dwWaitResult = WaitForSingleObject(
      ghSemaphore,   // handle to semaphore
      INFINITE);           // zero-second time-out interval


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
      //debug(D_NOTICE, "CreateNamedPipe failed, GLE=%d.\n", GetLastError());
      return;
    }

    fConnected = ConnectNamedPipe(hPipe, NULL) ?
    TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (fConnected)
    {
      //debug(D_NOTICE, "Client connected, creating a processing thread.\n");

      // Create a thread for this client.
      psync_run_thread1(
        "Pipe request handle routine",
        instance_thread,    // thread proc
        (LPVOID)hPipe     // thread parameter
        );
    }
    else
      CloseHandle(hPipe);

    if (!ReleaseSemaphore(
      ghSemaphore,  // handle to semaphore
      1,            // increase count by one
      NULL))       // not interested in previous count
    {
      debug(D_WARNING,"ReleaseSemaphore error: %d\n", GetLastError());
    }

  }

  CloseHandle(ghSemaphore);
  return;
}

void instance_thread(LPVOID lpvParam)
{
  DWORD cbBytesRead = 0, cbWritten = 0;
  BOOL fSuccess = FALSE;
  HANDLE hPipe = NULL;
  char  chBuf[POVERLAY_BUFSIZE];

  message* request = NULL; //(message*)psync_malloc(POVERLAY_BUFSIZE);
  message* reply = (message*)psync_malloc(POVERLAY_BUFSIZE);
 // memset(request,0,sizeof(request));
  memset(reply, 0, POVERLAY_BUFSIZE);
  if (lpvParam == NULL)
  {
    debug(D_ERROR, "InstanceThread got an unexpected NULL value in lpvParam.\n");
    return;
  }

  // debug(D_NOTICE, "InstanceThread created, receiving and processing messages.\n");
  hPipe = (HANDLE)lpvParam;
  while (1)
  {
    do
    {
      fSuccess = ReadFile(
        hPipe,    // pipe handle 
        chBuf,    // buffer to receive reply 
        POVERLAY_BUFSIZE,  // size of buffer 
        &cbBytesRead,  // number of bytes read 
        NULL);    // not overlapped 

      if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
        break;
    } while (!fSuccess);  // repeat loop if ERROR_MORE_DATA 

    if (!fSuccess || cbBytesRead == 0)
    {
      if (GetLastError() == ERROR_BROKEN_PIPE){
        //debug(D_NOTICE, "InstanceThread: client disconnected.\n");
      }
      else{
        //debug(D_NOTICE, "InstanceThread ReadFile failed, GLE=%d.\n", GetLastError());
      }
      break;
    }
    message *request = (message *)chBuf;

    //debug(D_NOTICE, "bytes received  %d buffer[%s]\n", cbBytesRead, chBuf);
    get_answer_to_request(request, reply);
    fSuccess = WriteFile(
      hPipe,        // handle to pipe
      reply,     // buffer to write from
      reply->length, // number of bytes to write
      &cbWritten,   // number of bytes written
      NULL);        // not overlapped I/O

    if (!fSuccess || reply->length != cbWritten)
    {
      //debug(D_NOTICE, "InstanceThread WriteFile failed, GLE=%d.\n", GetLastError());
      break;
    }
  }
  FlushFileBuffers(hPipe);
  DisconnectNamedPipe(hPipe);
  CloseHandle(hPipe);
  psync_free(request);
  psync_free(reply);
  //debug(D_NOTICE, "InstanceThread exitting.\n");
  return;
}

#endif //defined(P_OS_WINDOWS)