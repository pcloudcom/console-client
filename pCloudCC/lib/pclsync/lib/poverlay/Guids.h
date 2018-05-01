/* Copyright (c) 2013 pCloud Ltd.
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
#pragma once

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
  DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)

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
  const type name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }

#endif !_MIDL_USE_GUIDDEF_

  // {8D0C0582-552A-4A6B-9455-DA63E1F329C0}
  MIDL_DEFINE_GUID(CLSID, CLSID_pCloud_INSYNC,
    0x8d0c0582, 0x552a, 0x4a6b, 0x94, 0x55, 0xda, 0x63, 0xe1, 0xf3, 0x29, 0xc0);

  // {3858ED1B-8F1C-42ED-A8A9-FDBF591E3C6B}
  MIDL_DEFINE_GUID(CLSID, CLSID_pCloud_NOSYNC,
    0x3858ed1b, 0x8f1c, 0x42ed, 0xa8, 0xa9, 0xfd, 0xbf, 0x59, 0x1e, 0x3c, 0x6b);

  // {D8BFAFBD-B670-4252-9C17-9CF1C64C2BAF}
  MIDL_DEFINE_GUID(CLSID, CLSID_pCloud_INPROGRESS,
    0xd8bfafbd, 0xb670, 0x4252, 0x9c, 0x17, 0x9c, 0xf1, 0xc6, 0x4c, 0x2b, 0xaf);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif


