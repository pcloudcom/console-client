#include "stdafx.h"
#include "ShellExt.h"
#include <windows.h> 
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <stdint.h>

typedef struct _message {
  uint32_t type;
  uint64_t length;
  char value[];
} message;


#define BUFSIZE 512

ShellExt::ShellExt(FileState state) :_state(state)
{
  map_init(_statetostr)
    (FileStateInSync, "INSYNC")
    (FileStateNoSync, "NOSYNC")
    (FileStateInProgress, "INPROGRESS")
    (FileStateInvalid, "INVALID")
    ;
  
  map_init(_strtostate)
    ("INSYNC", FileStateInSync)
    ("NOSYNC" , FileStateNoSync)
    ("INPROGRESS", FileStateInProgress)
    ("INVALID", FileStateInvalid)
    ;
  
  _logfile.open("c:\\tmp\\overlaydll.log", std::fstream::out | std::fstream::app | std::fstream::ate);
  _logfile << "New Shell Extension created for state " << _statetostr[_state] << std::endl;
}

// CMyOverlayIcon

// IShellIconOverlayIdentifier Method Implementation 
// IShellIconOverlayIdentifier::GetOverlayInfo
// returns The Overlay Icon Location to the system
STDMETHODIMP ShellExt::GetOverlayInfo(
  LPWSTR pwszIconFile,
  int cchMax, int* pIndex,
  DWORD* pdwFlags)
{
  GetModuleFileNameW(_AtlBaseModule.GetModuleInstance(), pwszIconFile, cchMax);
  PathRemoveFileSpecW(pwszIconFile);
  LPWSTR pwszIconPathEnd = pwszIconFile + wcslen(pwszIconFile);
  switch (_state)
  {
  case FileStateInSync:
    wcsncpy(pwszIconPathEnd, L"\\1.ico", 6);
    pwszIconPathEnd[6] = '\0';
    *pIndex = 0;
    break;
  case FileStateNoSync:
    wcsncpy(pwszIconPathEnd, L"\\2.ico", 6);
    pwszIconPathEnd[6] = '\0';
    *pIndex = 0;
    break;
  case FileStateInProgress:
    wcsncpy(pwszIconPathEnd, L"\\3.ico", 6);
    pwszIconPathEnd[6] = '\0';
    *pIndex = 0;
    break;
  default:
    *pIndex = 0;
    return S_FALSE;
  }
  _logfile << "IconInfo path " << pwszIconFile << std::endl;
  *pdwFlags = ISIOI_ICONFILE | ISIOI_ICONINDEX;

  return S_OK;
}

// IShellIconOverlayIdentifier Method Implementation 

// returns the priority of this overlay 0 being the highest. 
// this overlay is always selected do to its high priority 
STDMETHODIMP ShellExt::GetPriority(int* pPriority)
{
  // we want highest priority 
  _logfile << "GetPriority " << std::endl;
  if (pPriority == 0)
    return E_POINTER;
  switch (_state)
  {
  case FileStateInSync:
    *pPriority = 0;
    break;
  case FileStateNoSync:
    *pPriority = 1;
    break;
  case FileStateInProgress:
    *pPriority = 2;
    break;
  default:
    *pPriority = 100;
    return S_FALSE;
  }
  return S_OK;
}

// IShellIconOverlayIdentifier Method Implementation
// IShellIconOverlayIdentifier::IsMemberOf
// Returns Whether the object should have this overlay or not 
STDMETHODIMP ShellExt::IsMemberOf(LPCWSTR pwszPath, DWORD dwAttrib)
{
  wchar_t *s = _wcsdup(pwszPath);
  HRESULT r = S_FALSE;

  _wcslwr(s);

  // Criteria
  //if (wcsstr(s, L"p:") != 0) {
    if (QueryState(_state, pwszPath) == 0)
      r = S_OK;
  //}
  
  free(s);
  return r;
}

int ShellExt::QueryState(FileState state, LPCWSTR path)
{
  HANDLE hPipe;
  char  chBuf[BUFSIZE];
  BOOL   fSuccess = FALSE;
  DWORD  cbRead, cbToWrite, cbWritten, dwMode;
  LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\pStatusPipe");

  while (1)
  {
    hPipe = CreateFile(
      lpszPipename,   // pipe name 
      GENERIC_READ |  // read and write access 
      GENERIC_WRITE,
      0,              // no sharing 
      NULL,           // default security attributes
      OPEN_EXISTING,  // opens existing pipe 
      0,              // default attributes 
      NULL);          // no template file 

    if (hPipe != INVALID_HANDLE_VALUE)
      break;

    if (GetLastError() != ERROR_PIPE_BUSY)
    {
     // _logfile << "Could not open pipe. GLE=" << GetLastError() << std::endl;
      return -1;
    }
    if (!WaitNamedPipe(lpszPipename, 20000))
    {
      _logfile << L"Could not open pipe: 20 second wait timed out." << std::endl;
      return -1;
    }
  }

  dwMode = PIPE_READMODE_MESSAGE;
  fSuccess = SetNamedPipeHandleState(
    hPipe,    // pipe handle 
    &dwMode,  // new pipe mode 
    NULL,     // don't set maximum bytes 
    NULL);    // don't set maximum time 
  if (!fSuccess)
  {
    _logfile << L"SetNamedPipeHandleState failed. GLE=" << GetLastError() << std::endl;
    return -1;
  }

  int pathSize = WideCharToMultiByte(CP_UTF8, 0, path, wcslen(path) + 1, NULL, 0, NULL, NULL);
  int messSize = sizeof(message)+pathSize + 1;
  message* mes = (message *)malloc(messSize);
  if (state == FileStateInSync)
    mes->type = 1;
  else if (state == FileStateInProgress)
    mes->type = 2;
  else if (state == FileStateNoSync)
    mes->type = 3;
  else { 
    _logfile << L"Invalid file status type."<< std::endl;
    return -2; 
  }

  WideCharToMultiByte(CP_UTF8, 0, path, wcslen(path) + 1, &mes->value[0], messSize, NULL, NULL);

  //_logfile << L"Sending " << messSize << " yyyy differance is " << strlen(mes->value) << " byte message :" << mes->value << std::endl;

 // _logfile << L"DEBUG  messSize [" << messSize << "] message structure [" << sizeof(message) << "] pathSize [" << pathSize << "] converted size [" << strlen(mes->value) << "] " << mes->value << std::endl;

  mes->length = strlen(mes->value) + 17;
  fSuccess = WriteFile(
    hPipe,                  // pipe handle 
    mes,             // message 
    mes->length,              // message length 
    &cbWritten,             // bytes written 
    NULL);                  // not overlapped 

  if (!fSuccess)
  {
    _logfile << L"WriteFile to pipe failed. GLE=" << GetLastError() << std::endl;
    return -1;
  }

 // _logfile << L"\nMessage sent to server " << cbWritten << "bytes send, receiving reply as follows:\n";

  do
  {
    fSuccess = ReadFile(
      hPipe,    // pipe handle 
      chBuf,    // buffer to receive reply 
      BUFSIZE,  // size of buffer 
      &cbRead,  // number of bytes read 
      NULL);    // not overlapped 

    if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
      break;
  } while (!fSuccess);  // repeat loop if ERROR_MORE_DATA 

  if (!fSuccess)
  {
    _logfile << "ReadFile from pipe failed. GLE=" << GetLastError() << std::endl;
    return -1;
  }
  CloseHandle(hPipe);
  message *rep = (message *)chBuf;
 // _logfile << "mes type ["<<rep->type <<"] mes length ["<< rep->length <<"] mes value ["<< rep->value<<"]" << std::endl;
  int res = -4;
  if ((rep->type == (10 + _state)) && rep->type < 13)
    res = 0;
  free(mes);
  return res;
}