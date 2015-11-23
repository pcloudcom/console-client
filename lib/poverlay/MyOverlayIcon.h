// MyOverlayIcon.h : Declaration of the CMyOverlayIcon

#pragma once
#include "resource.h"       // main symbols
#include "OverlayIcon.h"
#include "ShellExt.h"

EXTERN_C const CLSID CLSID_pCloud_INSYNC;
EXTERN_C const CLSID CLSID_pCloud_NOSYNC;
EXTERN_C const CLSID CLSID_pCloud_INPROGRESS;

// CMyOverlayIcon

class ATL_NO_VTABLE CMyOverlayIcon : 
	public CComObjectRootEx<CComSingleThreadModel>,
	//public CComCoClass<CMyOverlayIcon, &CLSID_MyOverlayIcon>,
  public CComCoClass<CMyOverlayIcon, &CLSID_pCloud_INSYNC>,
	public IDispatchImpl<IMyOverlayIcon, &IID_IMyOverlayIcon, &LIBID_OverlayIconLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
  public ShellExt
{
public:
  CMyOverlayIcon() :ShellExt(FileStateInSync)
  {}

DECLARE_REGISTRY_RESOURCEID(IDR_MYOVERLAYICON)


BEGIN_COM_MAP(CMyOverlayIcon)
	COM_INTERFACE_ENTRY(IMyOverlayIcon)
	COM_INTERFACE_ENTRY(IDispatch)
  COM_INTERFACE_ENTRY(IShellIconOverlayIdentifier)
END_COM_MAP()


	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}
	
	void FinalRelease() 
	{
	}

};


class ATL_NO_VTABLE CpCloudNoSync :
  public CComObjectRootEx<CComSingleThreadModel>,
  //public CComCoClass<CMyOverlayIcon, &CLSID_MyOverlayIcon>,
  public CComCoClass<CpCloudNoSync, &CLSID_pCloud_NOSYNC>,
  public IDispatchImpl<IMyOverlayIcon, &IID_IMyOverlayIcon, &LIBID_OverlayIconLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
  public ShellExt
{
public:
  CpCloudNoSync() :ShellExt(FileStateNoSync)
  {}

  DECLARE_REGISTRY_RESOURCEID(IDR_MYOVERLAYICON)


  BEGIN_COM_MAP(CpCloudNoSync)
    COM_INTERFACE_ENTRY(IMyOverlayIcon)
    COM_INTERFACE_ENTRY(IDispatch)
    COM_INTERFACE_ENTRY(IShellIconOverlayIdentifier)
  END_COM_MAP()


  DECLARE_PROTECT_FINAL_CONSTRUCT()

  HRESULT FinalConstruct()
  {
    return S_OK;
  }

  void FinalRelease()
  {
  }

};

class ATL_NO_VTABLE CpCloudInProgress :
  public CComObjectRootEx<CComSingleThreadModel>,
  //public CComCoClass<CMyOverlayIcon, &CLSID_MyOverlayIcon>,
  public CComCoClass<CpCloudInProgress, &CLSID_pCloud_INPROGRESS>,
  public IDispatchImpl<IMyOverlayIcon, &IID_IMyOverlayIcon, &LIBID_OverlayIconLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
  public ShellExt
{
public:
  CpCloudInProgress() :ShellExt(FileStateInProgress)
  {}

  DECLARE_REGISTRY_RESOURCEID(IDR_MYOVERLAYICON)


  BEGIN_COM_MAP(CpCloudInProgress)
    COM_INTERFACE_ENTRY(IMyOverlayIcon)
    COM_INTERFACE_ENTRY(IDispatch)
    COM_INTERFACE_ENTRY(IShellIconOverlayIdentifier)
  END_COM_MAP()


  DECLARE_PROTECT_FINAL_CONSTRUCT()

  HRESULT FinalConstruct()
  {
    return S_OK;
  }

  void FinalRelease()
  {
  }

};

OBJECT_ENTRY_AUTO(__uuidof(MyOverlayIcon), CMyOverlayIcon)

OBJECT_ENTRY_AUTO(__uuidof(pCloudNoSync), CpCloudNoSync)

OBJECT_ENTRY_AUTO(__uuidof(pCloudInProgress), CpCloudInProgress)
