#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <map>

enum FileState
{
  FileStateInSync = 0,
  FileStateNoSync,
  FileStateInProgress,
  FileStateInvalid
};

class ShellExt : public IShellIconOverlayIdentifier
{
public:
  ShellExt(FileState state);

  virtual ~ShellExt(){}

  // IShellIconOverlayIdentifier Methods
  STDMETHOD(GetOverlayInfo)(LPWSTR pwszIconFile, int cchMax, int *pIndex, DWORD* pdwFlags);
  STDMETHOD(GetPriority)(int* pPriority);
  STDMETHOD(IsMemberOf)(LPCWSTR pwszPath, DWORD dwAttrib);

private:
  template<typename T> struct map_init_helper
  {
    T& data;
    map_init_helper(T& d) : data(d) {}
    map_init_helper& operator() (typename T::key_type const& key, typename T::mapped_type const& value)
    {
      data[key] = value;
      return *this;
    }
  };

  template<typename T> map_init_helper<T> map_init(T& item)
  {
    return map_init_helper<T>(item);
  } 

  int QueryState(FileState state, LPCWSTR path);

private:
  std::map< const char*, FileState > _strtostate;
  std::map< FileState, const char* > _statetostr;
  FileState _state;
  std::wofstream _logfile;
};

