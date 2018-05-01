

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


 /* File created by MIDL compiler version 8.00.0603 */
/* at Mon Nov 23 16:27:16 2015
 */
/* Compiler settings for OverlayIcon.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.00.0603 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


#ifdef __cplusplus
extern "C"{
#endif 


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, IID_IMyOverlayIcon,0x7BCA6879,0xA9F8,0x47DE,0xAE,0x05,0xF5,0xCE,0x7E,0xA3,0xA4,0x74);


MIDL_DEFINE_GUID(IID, LIBID_OverlayIconLib,0xADF1FA2A,0x6EAA,0x4A97,0xA5,0x5F,0x3C,0x8B,0x92,0x84,0x3E,0xF5);


MIDL_DEFINE_GUID(CLSID, CLSID_MyOverlayIcon,0x8D0C0582,0x552A,0x4A6B,0x94,0x55,0xDA,0x63,0xE1,0xF3,0x29,0xC0);


MIDL_DEFINE_GUID(CLSID, CLSID_pCloudNoSync,0x3858ED1B,0x8F1C,0x42ED,0xA8,0xA9,0xFD,0xBF,0x59,0x1E,0x3C,0x6B);


MIDL_DEFINE_GUID(CLSID, CLSID_pCloudInProgress,0xD8BFAFBD,0xB670,0x4252,0x9C,0x17,0x9C,0xF1,0xC6,0x4C,0x2B,0xAF);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



