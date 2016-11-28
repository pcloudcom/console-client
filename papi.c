/* Copyright (c) 2013 Anton Titov.
 * Copyright (c) 2013 pCloud Ltd.
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

#include "papi.h"
#include "psynclib.h"
#include "plibs.h"
#include "psettings.h"
#include "ptimer.h"
#include <string.h>
#include <stddef.h>

#define RPARAM_STR1  0
#define RPARAM_STR2  1
#define RPARAM_STR3  2
#define RPARAM_STR4  3
#define RPARAM_RSTR1 4
#define RPARAM_RSTR2 5
#define RPARAM_RSTR3 6
#define RPARAM_RSTR4 7
#define RPARAM_NUM1  8
#define RPARAM_NUM2  9
#define RPARAM_NUM3  10
#define RPARAM_NUM4  11
#define RPARAM_NUM5  12
#define RPARAM_NUM6  13
#define RPARAM_NUM7  14
#define RPARAM_NUM8  15
#define RPARAM_HASH  16
#define RPARAM_ARRAY 17
#define RPARAM_BFALSE 18
#define RPARAM_BTRUE 19
#define RPARAM_DATA 20
/* 100-149 inclusive - strings 0-49 bytes in length without additional len parameter */
#define RPARAM_SHORT_STR_BASE 100
/* 150-199 inclusive - reused strings id 0-49 bytes in length without additional id parameter */
#define RPARAM_SHORT_RSTR_BASE 150
/* 200-219 inclusive - small numbers 0-19 */
#define RPARAM_SMALL_NUM_BASE 200
#define RPARAM_END 255

#define VSHORT_STR_LEN 50
#define VSHORT_RSTR_CNT 50
#define VSMALL_NUMBER_NUM 20

static const binresult BOOL_TRUE={PARAM_BOOL, 0, {1}};
static const binresult BOOL_FALSE={PARAM_BOOL, 0, {0}};
static const binresult STR_EMPTY={PARAM_STR, 0, {0}};
static const binresult NUM_ZERO={PARAM_NUM, 0, {0}};
static const binresult HASH_EMPTY={PARAM_HASH, 0, {0}};
static const binresult ARRAY_EMPTY={PARAM_ARRAY, 0, {0}};
static const binresult DATA_EMPTY={PARAM_DATA, 0, {0}};

static const binresult *empty_types[]={&STR_EMPTY, &NUM_ZERO, &BOOL_FALSE, &ARRAY_EMPTY, &HASH_EMPTY, &DATA_EMPTY};
static const char *type_names[]={"string", "number", "boolean", "array", "hash", "data"};

static const binresult NUM_SMALL[VSMALL_NUMBER_NUM]={
  {PARAM_NUM, 0, {0}},
  {PARAM_NUM, 0, {1}},
  {PARAM_NUM, 0, {2}},
  {PARAM_NUM, 0, {3}},
  {PARAM_NUM, 0, {4}},
  {PARAM_NUM, 0, {5}},
  {PARAM_NUM, 0, {6}},
  {PARAM_NUM, 0, {7}},
  {PARAM_NUM, 0, {8}},
  {PARAM_NUM, 0, {9}},
  {PARAM_NUM, 0, {10}},
  {PARAM_NUM, 0, {11}},
  {PARAM_NUM, 0, {12}},
  {PARAM_NUM, 0, {13}},
  {PARAM_NUM, 0, {14}},
  {PARAM_NUM, 0, {15}},
  {PARAM_NUM, 0, {16}},
  {PARAM_NUM, 0, {17}},
  {PARAM_NUM, 0, {18}},
  {PARAM_NUM, 0, {19}}
};

static uint32_t connfailures=0;

psync_socket *psync_api_connect(const char *hostname, int usessl){
  static time_t notuntil=0;
  psync_socket *ret;
  if (psync_timer_time()>notuntil){
    ret=psync_socket_connect(hostname, usessl?PSYNC_API_PORT_SSL:PSYNC_API_PORT, usessl);
    if (ret)
      return ret;
    if (!strcmp(hostname, PSYNC_API_HOST))
      return NULL;
    ret=psync_socket_connect(PSYNC_API_HOST, usessl?PSYNC_API_PORT_SSL:PSYNC_API_PORT, usessl);
    if (ret) {
      debug(D_NOTICE, "failed to connect to %s, but was able to connect to %s", hostname, PSYNC_API_HOST);
      notuntil=psync_timer_time()+1800;
    }
    return ret;
  }
  return psync_socket_connect(PSYNC_API_HOST, usessl?PSYNC_API_PORT_SSL:PSYNC_API_PORT, usessl);
}

void psync_api_conn_fail_inc(){
  connfailures++;
}

void psync_api_conn_fail_reset(){
  if (connfailures%5==4)
    connfailures=4;
  else
    connfailures=0;
}

#define _NEED_DATA(cnt) if (unlikely_log(*datalen<(cnt))) return -1
#define ALIGN_BYTES psync_alignof(uint64_t)

static ssize_t calc_ret_len(unsigned char **restrict data, size_t *restrict datalen, size_t *restrict strcnt){
  size_t type, len;
  long cond;
  _NEED_DATA(1);
  type=**data;
  (*data)++;
  (*datalen)--;
  if ((cond=(type>=RPARAM_SHORT_STR_BASE && type<RPARAM_SHORT_STR_BASE+VSHORT_STR_LEN)) || (type>=RPARAM_STR1 && type<=RPARAM_STR4)){
    if (cond)
      len=type-RPARAM_SHORT_STR_BASE;
    else{
      size_t l=type-RPARAM_STR1+1;
      _NEED_DATA(l);
      len=0;
      memcpy(&len, *data, l);
      *data+=l;
      *datalen-=l;
    }
    _NEED_DATA(len);
    *data+=len;
    *datalen-=len;
    len=((len+ALIGN_BYTES)/ALIGN_BYTES)*ALIGN_BYTES;
    (*strcnt)++;
    return offsetof(binresult, str)+len;
  }
  else if ((cond=(type>=RPARAM_RSTR1 && type<=RPARAM_RSTR4)) || (type>=RPARAM_SHORT_RSTR_BASE && type<RPARAM_SHORT_RSTR_BASE+VSHORT_RSTR_CNT)){
    if (cond){
      size_t l=type-RPARAM_RSTR1+1;
      _NEED_DATA(l);
      len=0;
      memcpy(&len, *data, l);
      *data+=l;
      *datalen-=l;
    }
    else
      len=type-RPARAM_SHORT_RSTR_BASE;
    if (len<*strcnt)
      return 0;
    else
      return -1;
  }
  else if (type>=RPARAM_NUM1 && type<=RPARAM_NUM8){
    len=type-RPARAM_NUM1+1;
    _NEED_DATA(len);
    *data+=len;
    *datalen-=len;
    return sizeof(binresult);
  }
  else if (type>=RPARAM_SMALL_NUM_BASE && type<RPARAM_SMALL_NUM_BASE+VSMALL_NUMBER_NUM)
    return 0;
  else if (type==RPARAM_BFALSE || type==RPARAM_BTRUE)
    return 0;
  else if (type==RPARAM_ARRAY){
    ssize_t ret, r;
    int unsigned cnt;
    cnt=0;
    ret=sizeof(binresult);
    while (**data!=RPARAM_END){
      r=calc_ret_len(data, datalen, strcnt);
      if (r==-1)
        return -1;
      ret+=r;
      cnt++;
      _NEED_DATA(1);
    }
    (*data)++;
    (*datalen)--;
    ret+=sizeof(binresult *)*cnt;
    return ret;
  }
  else if (type==RPARAM_HASH){
    ssize_t ret, r;
    int unsigned cnt;
    cnt=0;
    ret=sizeof(binresult);
    while (**data!=RPARAM_END){
      r=calc_ret_len(data, datalen, strcnt);
      if (r==-1)
        return -1;
      ret+=r;
      r=calc_ret_len(data, datalen, strcnt);
      if (r==-1)
        return -1;
      ret+=r;
      cnt++;
      _NEED_DATA(1);
    }
    (*data)++;
    (*datalen)--;
    ret+=sizeof(hashpair)*cnt;
    return ret;
  }
  else if (type==RPARAM_DATA){
    _NEED_DATA(8);
    *data+=8;
    *datalen-=8;
    return sizeof(binresult);
  }
  else
    return -1;
}

static binresult *do_parse_result(unsigned char **restrict indata, unsigned char **restrict odata, binresult **restrict strings, size_t *restrict nextstrid){
  binresult *ret;
  long cond;
  psync_uint_t type, len;
  type=**indata;
  (*indata)++;
  if ((cond=(type>=RPARAM_SHORT_STR_BASE && type<RPARAM_SHORT_STR_BASE+VSHORT_STR_LEN)) || (type>=RPARAM_STR1 && type<=RPARAM_STR4)){
    if (cond)
      len=type-RPARAM_SHORT_STR_BASE;
    else{
      size_t l=type-RPARAM_STR1+1;
      len=0;
      memcpy(&len, *indata, l);
      *indata+=l;
    }
    ret=(binresult *)(*odata);
    *odata+=offsetof(binresult, str);
    ret->type=PARAM_STR;
    strings[*nextstrid]=ret;
    (*nextstrid)++;
    ret->length=len;
    memcpy(*odata, *indata, len);
    (*odata)[len]=0;
    *odata+=((len+ALIGN_BYTES)/ALIGN_BYTES)*ALIGN_BYTES;
    *indata+=len;
    return ret;
  }
  else if ((cond=(type>=RPARAM_RSTR1 && type<=RPARAM_RSTR4)) || (type>=RPARAM_SHORT_RSTR_BASE && type<RPARAM_SHORT_RSTR_BASE+VSHORT_RSTR_CNT)){
    size_t id;
    if (cond){
      len=type-RPARAM_RSTR1+1;
      id=0;
      memcpy(&id, *indata, len);
      *indata+=len;
    }
    else
      id=type-RPARAM_SHORT_RSTR_BASE;
    return strings[id];
  }
  else if (type>=RPARAM_NUM1 && type<=RPARAM_NUM8){
    ret=(binresult *)(*odata);
    *odata+=sizeof(binresult);
    ret->type=PARAM_NUM;
    len=type-RPARAM_NUM1+1;
    ret->num=0;
    memcpy(&ret->num, *indata, len);
    *indata+=len;
    return ret;
  }
  else if (type>=RPARAM_SMALL_NUM_BASE && type<RPARAM_SMALL_NUM_BASE+VSMALL_NUMBER_NUM)
    return (binresult *)&NUM_SMALL[type-RPARAM_SMALL_NUM_BASE];
  else if (type==RPARAM_BTRUE)
    return (binresult *)&BOOL_TRUE;
  else if (type==RPARAM_BFALSE)
    return (binresult *)&BOOL_FALSE;
  else if (type==RPARAM_ARRAY){
    binresult **arr;
    psync_uint_t cnt, alloc;
    ret=(binresult *)(*odata);
    *odata+=sizeof(binresult);
    ret->type=PARAM_ARRAY;
    arr=NULL;
    cnt=0;
    alloc=128;
    arr=(binresult **)psync_malloc(sizeof(binresult *)*alloc);
    while (**indata!=RPARAM_END){
      if (cnt==alloc){
        alloc*=2;
        arr=(binresult **)psync_realloc(arr, sizeof(binresult *)*alloc);
      }
      arr[cnt++]=do_parse_result(indata, odata, strings, nextstrid);
    }
    (*indata)++;
    ret->length=cnt;
    ret->array=(struct _binresult **)*odata;
    *odata+=sizeof(struct _binresult *)*cnt;
    memcpy(ret->array, arr, sizeof(struct _binresult *)*cnt);
    psync_free(arr);
    return ret;
  }
  else if (type==RPARAM_HASH){
    struct _hashpair *arr;
    psync_uint_t cnt, alloc;
    binresult *key;
    ret=(binresult *)(*odata);
    *odata+=sizeof(binresult);
    ret->type=PARAM_HASH;
    arr=NULL;
    cnt=0;
    alloc=32;
    arr=(struct _hashpair *)psync_malloc(sizeof(struct _hashpair)*alloc);
    while (**indata!=RPARAM_END){
      if (cnt==alloc){
        alloc*=2;
        arr=(struct _hashpair *)psync_realloc(arr, sizeof(struct _hashpair)*alloc);
      }
      key=do_parse_result(indata, odata, strings, nextstrid);
      arr[cnt].value=do_parse_result(indata, odata, strings, nextstrid);
      if (key->type==PARAM_STR){
        arr[cnt].key=key->str;
        cnt++;
      }
    }
    (*indata)++;
    ret->length=cnt;
    ret->hash=(struct _hashpair *)*odata;
    *odata+=sizeof(struct _hashpair)*cnt;
    memcpy(ret->hash, arr, sizeof(struct _hashpair)*cnt);
    psync_free(arr);
    return ret;
  }
  else if (type==RPARAM_DATA){
    ret=(binresult *)(*odata);
    *odata+=sizeof(binresult);
    ret->type=PARAM_DATA;
    memcpy(&ret->num, *indata, 8);
    *indata+=8;
    return ret;
  }
  return NULL;
}

static binresult *parse_result(unsigned char *data, size_t datalen){
  unsigned char *datac;
  binresult **strings;
  binresult *res;
  ssize_t retlen;
  size_t datalenc, strcnt;
  datac=data;
  datalenc=datalen;
  strcnt=0;
  retlen=calc_ret_len(&datac, &datalenc, &strcnt);
  if (retlen==-1)
    return NULL;
  datac=psync_new_cnt(unsigned char, retlen);
  strings=psync_new_cnt(binresult *, strcnt);
  strcnt=0;
  res=do_parse_result(&data, &datac, strings, &strcnt);
  psync_free(strings);
  return res;
}

binresult *get_result(psync_socket *sock){
  unsigned char *data;
  binresult *res;
  uint32_t ressize;
  if (unlikely_log(psync_socket_readall(sock, &ressize, sizeof(uint32_t))!=sizeof(uint32_t)))
    return NULL;
  data=(unsigned char *)psync_malloc(ressize);
  if (unlikely_log(psync_socket_readall(sock, data, ressize)!=ressize)){
    psync_free(data);
    return NULL;
  }
  res=parse_result(data, ressize);
  psync_free(data);
  return res;
}

binresult *get_result_thread(psync_socket *sock){
  unsigned char *data;
  binresult *res;
  uint32_t ressize;
  if (unlikely_log(psync_socket_readall_thread(sock, &ressize, sizeof(uint32_t))!=sizeof(uint32_t)))
    return NULL;
  data=(unsigned char *)psync_malloc(ressize);
  if (unlikely_log(psync_socket_readall_thread(sock, data, ressize)!=ressize)){
    psync_free(data);
    return NULL;
  }
  res=parse_result(data, ressize);
  psync_free(data);
  return res;
}

void async_result_reader_init(async_result_reader *reader){
  reader->state=0;
  reader->bytesread=0;
  reader->bytestoread=sizeof(uint32_t);
  reader->data=(unsigned char *)&reader->respsize;
}

void async_result_reader_destroy(async_result_reader *reader){
  if (reader->state==1)
    psync_free(reader->data);
}

int get_result_async(psync_socket *sock, async_result_reader *reader){
  int rd;
again:
  rd=psync_socket_read_noblock(sock, reader->data+reader->bytesread, reader->bytestoread-reader->bytesread);
  if (rd==PSYNC_SOCKET_WOULDBLOCK)
    return ASYNC_RES_NEEDMORE;
  else if (rd==PSYNC_SOCKET_ERROR || rd==0){
    if (reader->state==1)
      psync_free(reader->data);
    async_result_reader_init(reader);
    reader->result=NULL;
    return ASYNC_RES_READY;
  }
  reader->bytesread+=rd;
  if (reader->bytesread==reader->bytestoread){
    if (reader->state==0){
      reader->state=1;
      reader->bytesread=0;
      reader->bytestoread=reader->respsize;
      reader->data=(unsigned char *)psync_malloc(reader->respsize);
      goto again;
    }
    else{
      assert(reader->state==1);
      reader->result=parse_result(reader->data, reader->respsize);
      psync_free(reader->data);
      async_result_reader_init(reader);
      return ASYNC_RES_READY;
    }
  }
  else
    return ASYNC_RES_NEEDMORE;
}

unsigned char *do_prepare_command(const char *command, size_t cmdlen, const binparam *params, size_t paramcnt, int64_t datalen, size_t additionalalloc, size_t *retlen){
  size_t i, plen;
  unsigned char *data, *sdata;
  /* 2 byte len (not included), 1 byte cmdlen, 1 byte paramcnt, cmdlen bytes cmd*/
  plen=cmdlen+2;
  if (datalen!=-1)
    plen+=sizeof(uint64_t);
  for (i=0; i<paramcnt; i++)
    if (params[i].paramtype==PARAM_STR)
      plen+=params[i].paramnamelen+params[i].opts+5; /* 1byte type+paramnamelen, nbytes paramnamelen, 4byte strlen, nbytes str */
    else if (params[i].paramtype==PARAM_NUM)
      plen+=params[i].paramnamelen+1+sizeof(uint64_t);
    else if (params[i].paramtype==PARAM_BOOL)
      plen+=params[i].paramnamelen+2;
  if (unlikely_log(plen>0xffff))
    return NULL;
  sdata=data=(unsigned char *)psync_malloc(plen+2+additionalalloc);
  memcpy(data, &plen, 2);
  data+=2;
  if (datalen!=-1){
    *data++=cmdlen|0x80;
    memcpy(data, &datalen, sizeof(uint64_t));
    data+=sizeof(uint64_t);
  }
  else
    *data++=cmdlen;
  memcpy(data, command, cmdlen);
  data+=cmdlen;
  *data++=paramcnt;
  for (i=0; i<paramcnt; i++){
    *data++=(params[i].paramtype<<6)+params[i].paramnamelen;
    memcpy(data, params[i].paramname, params[i].paramnamelen);
    data+=params[i].paramnamelen;
    if (params[i].paramtype==PARAM_STR){
      memcpy(data, &params[i].opts, 4);
      data+=4;
      memcpy(data, params[i].str, params[i].opts);
      data+=params[i].opts;
    }
    else if (params[i].paramtype==PARAM_NUM){
      memcpy(data, &params[i].num, sizeof(uint64_t));
      data+=sizeof(uint64_t);
    }
    else if (params[i].paramtype==PARAM_BOOL)
      *data++=params[i].num&1;
  }
  plen+=2;
  *retlen=plen;
  return sdata;
}

binresult *do_send_command(psync_socket *sock, const char *command, size_t cmdlen, const binparam *params, size_t paramcnt, int64_t datalen, int readres){
  unsigned char *sdata;
  size_t plen;
  sdata=do_prepare_command(command, cmdlen, params, paramcnt, datalen, 0, &plen);
  if (!sdata)
    return NULL;
  if (readres&2){
    if (unlikely_log(psync_socket_writeall_thread(sock, sdata, plen)!=plen)){
      psync_free(sdata);
      return NULL;
    }
  }
  else{
    if (unlikely_log(psync_socket_writeall(sock, sdata, plen)!=plen)){
      psync_free(sdata);
      return NULL;
    }
  }
  psync_free(sdata);
  if (readres&1)
    return get_result(sock);
  else
    return PTR_OK;
}

const binresult *psync_do_find_result(const binresult *res, const char *name, uint32_t type, const char *file, const char *function, int unsigned line){
  uint32_t i;
  if (unlikely(!res || res->type!=PARAM_HASH)){
    if (D_CRITICAL<=DEBUG_LEVEL){
      const char *nm="NULL";
      if (res)
        nm=type_names[res->type];
      psync_debug(file, function, line, D_CRITICAL, "expecting hash as first parameter, got %s", nm);
    }
    return empty_types[type];
  }
  for (i=0; i<res->length; i++)
    if (!strcmp(res->hash[i].key, name)){
      if (likely(res->hash[i].value->type==type))
        return res->hash[i].value;
      else{
        if (D_CRITICAL<=DEBUG_LEVEL)
          psync_debug(file, function, line, D_CRITICAL, "type error for key %s, expected %s got %s", name, type_names[type], type_names[res->hash[i].value->type]);
        return empty_types[type];
      }
    }
  if (D_CRITICAL<=DEBUG_LEVEL)
    psync_debug(file, function, line, D_CRITICAL, "could not find key %s", name);
#if IS_DEBUG
  psync_debug(file, function, line, D_NOTICE, "dumping existing fields of the hash");
  for (i=0; i<res->length; i++)
    switch (res->hash[i].value->type){
      case PARAM_HASH:
        psync_debug(file, function, line, D_NOTICE, "  %s=[hash]", res->hash[i].key);
        break;
      case PARAM_ARRAY:
        psync_debug(file, function, line, D_NOTICE, "  %s=[array]", res->hash[i].key);
        break;
      case PARAM_DATA:
        psync_debug(file, function, line, D_NOTICE, "  %s=[data]", res->hash[i].key);
        break;
      case PARAM_NUM:
        psync_debug(file, function, line, D_NOTICE, "  %s=%llu", res->hash[i].key, (long long unsigned)res->hash[i].value->num);
        break;
      case PARAM_STR:
        psync_debug(file, function, line, D_NOTICE, "  %s=\"%s\"", res->hash[i].key, res->hash[i].value->str);
        break;
      case PARAM_BOOL:
        psync_debug(file, function, line, D_NOTICE, "  %s=%s", res->hash[i].key, res->hash[i].value->num?"true":"false");
        break;
      default:
        psync_debug(file, function, line, D_NOTICE, "  %s=!unknown type %u", res->hash[i].key, (unsigned)res->hash[i].value->type);
        break;
    }
#endif
  return empty_types[type];
}

const binresult *psync_do_check_result(const binresult *res, const char *name, uint32_t type, const char *file, const char *function, int unsigned line){
  uint32_t i;
  if (unlikely(!res || res->type!=PARAM_HASH)){
    if (D_CRITICAL<=DEBUG_LEVEL){
      const char *nm="NULL";
      if (res)
        nm=type_names[res->type];
      psync_debug(file, function, line, D_CRITICAL, "expecting hash as first parameter, got %s", nm);
    }
    return NULL;
  }
  for (i=0; i<res->length; i++)
    if (!strcmp(res->hash[i].key, name)){
      if (likely(res->hash[i].value->type==type))
        return res->hash[i].value;
      else{
        if (D_CRITICAL<=DEBUG_LEVEL)
          psync_debug(file, function, line, D_CRITICAL, "type error for key %s, expected %s got %s", name, type_names[type], type_names[res->hash[i].value->type]);
        return NULL;
      }
    }
  return NULL;
}
