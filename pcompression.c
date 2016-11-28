/* Copyright (c) 2015 Anton Titov.
 * Copyright (c) 2015 pCloud Ltd.
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

//#include "miniz.h"
#if defined(P_OS_WINDOWS)
#define ZLIB_WINAPI
#endif
#include "zlib.h"
#include "plibs.h"
#include "pcompression.h"

#define BUFFER_SIZE (4*1024)

#define FLAG_DEFLATE    1
#define FLAG_MORE_DATA  2
#define FLAG_STREAM_END 4

struct _psync_deflate_t {
  z_stream stream;
  unsigned char *flushbuff;
  uint32_t flushbufflen;
  uint32_t flushbuffoff;
  uint32_t bufferstartoff;
  uint32_t bufferendoff;
  uint32_t lastout;
  uint32_t flags;
  unsigned char buffer[BUFFER_SIZE];
};

psync_deflate_t *psync_deflate_init(int level){
  psync_deflate_t *def;
  int ret;
  def=psync_new(psync_deflate_t);
  memset(&def->stream, 0, sizeof(def->stream));
  def->flushbuff=NULL;
  def->bufferstartoff=0;
  def->bufferendoff=0;
  if (level==PSYNC_DEFLATE_DECOMPRESS){
    def->flags=0;
    ret=inflateInit2(&def->stream, 15);
  }
  else{
    def->flags=FLAG_DEFLATE;
    ret=deflateInit2(&def->stream, level, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
  }
  if (likely_log(ret==Z_OK))
    return def;
  else{
    psync_free(def);
    return NULL;
  }
}

void psync_deflate_destroy(psync_deflate_t *def){
  if (def->flags&FLAG_DEFLATE)
    deflateEnd(&def->stream);
  else
    inflateEnd(&def->stream);
  psync_free(def->flushbuff);
  psync_free(def);
}

static int psync_deflate_set_out_buff(psync_deflate_t *def){
  uint32_t end;
  if (def->bufferendoff-def->bufferstartoff==BUFFER_SIZE)
    return -1;
  end=def->bufferendoff%BUFFER_SIZE;
  def->stream.next_out=def->buffer+end;
  if (end<def->bufferstartoff)
    def->stream.avail_out=def->bufferstartoff-end;
  else
    def->stream.avail_out=BUFFER_SIZE-end;
  assert(def->stream.avail_out!=0);
  def->lastout=def->stream.avail_out;
  return 0;
}

static int psync_translate_flush(int flush){
  switch (flush){
    case PSYNC_DEFLATE_NOFLUSH:
      return Z_NO_FLUSH;
    case PSYNC_DEFLATE_FLUSH:
      return Z_PARTIAL_FLUSH;
    case PSYNC_DEFLATE_FLUSH_END:
      return Z_FINISH;
    default:
      debug(D_WARNING, "invalid flush value %d", flush);
      return Z_NO_FLUSH;
  }
}

static int psync_deflate_call_compressor(psync_deflate_t *def, int flush, int adjustbe){
  int ret;
  assert(def->stream.avail_out);
  if (def->flags&FLAG_DEFLATE)
    ret=deflate(&def->stream, psync_translate_flush(flush));
  else
    ret=inflate(&def->stream, Z_SYNC_FLUSH);
  if (adjustbe)
    def->bufferendoff+=def->lastout-def->stream.avail_out;
  if (def->stream.avail_out)
    def->flags&=~FLAG_MORE_DATA;
  else
    def->flags|=FLAG_MORE_DATA;
  return ret;
}

static int psync_deflate_finish_flush_add_buffer(psync_deflate_t *def, int flush){
  unsigned char *buff;
  uint32_t alloced, used, current;
  int ret;
  alloced=4096;
  buff=psync_new_cnt(unsigned char, alloced);
  current=alloced;
  used=0;
  def->flags&=~FLAG_MORE_DATA;
  def->flushbuffoff=0;
  while (1){
    def->stream.next_out=buff+used;
    def->stream.avail_out=current;
    ret=deflate(&def->stream, psync_translate_flush(flush));
    if (ret!=Z_OK){
      if (ret!=Z_BUF_ERROR)
        return ret;
      if (used==0){
        psync_free(buff);
        return Z_OK;
      }
      def->flushbuff=buff;
      def->flushbufflen=used;
      debug(D_NOTICE, "added additional buffer of size %u", (unsigned)def->flushbufflen);
      return Z_OK;
    }
    if (def->stream.avail_out){
      def->flushbuff=buff;
      def->flushbufflen=used+current-def->stream.avail_out;
      debug(D_NOTICE, "added additional buffer of size %u", (unsigned)def->flushbufflen);
      return Z_OK;
    }
    used+=current;
    alloced*=2;
    buff=(unsigned char *)psync_realloc(buff, alloced);
    current=alloced-used;
  }
}

int psync_deflate_write(psync_deflate_t *def, const void *data, int len, int flush){
  int ret;
  if (!len && flush==PSYNC_DEFLATE_NOFLUSH){
    debug(D_WARNING, "called with no len and no flush");
    return PSYNC_DEFLATE_ERROR;
  }
  if (def->flushbuff || psync_deflate_set_out_buff(def))
    return PRINT_RETURN_CONST(PSYNC_DEFLATE_FULL);
  def->stream.next_in=(unsigned char *)data;
  def->stream.avail_in=len;
  ret=psync_deflate_call_compressor(def, flush, 1);
  if (ret==Z_OK && (def->flags&FLAG_MORE_DATA) && !psync_deflate_set_out_buff(def)){
    ret=psync_deflate_call_compressor(def, flush, 1);
    if (ret==Z_BUF_ERROR)
      ret=Z_OK;
  }
  if (ret==Z_OK && def->flags&FLAG_DEFLATE && flush!=PSYNC_DEFLATE_NOFLUSH && (def->flags&FLAG_MORE_DATA))
    ret=psync_deflate_finish_flush_add_buffer(def, flush);
  if (ret==Z_STREAM_END)
    def->flags|=FLAG_STREAM_END;
  if (ret==Z_STREAM_ERROR || ret==Z_DATA_ERROR)
    return PSYNC_DEFLATE_ERROR;
  else
    return len-def->stream.avail_in;
}

int psync_deflate_read(psync_deflate_t *def, void *data, int len){
  int ret;
  assert(def->bufferstartoff<=def->bufferendoff);
  if (def->bufferendoff==def->bufferstartoff){
    if (def->flushbuff){
      if (len>def->flushbufflen-def->flushbuffoff)
        len=def->flushbufflen-def->flushbuffoff;
      memcpy(data, def->flushbuff+def->flushbuffoff, len);
      def->flushbuffoff+=len;
      if (def->flushbuffoff==def->flushbufflen){
        psync_free(def->flushbuff);
        def->flushbuff=NULL;
      }
      return len;
    }
    if (def->flags&FLAG_MORE_DATA){
      def->stream.next_in=(unsigned char *)"";
      def->stream.avail_in=0;
      def->stream.next_out=(unsigned char *)data;
      def->stream.avail_out=len;
      ret=psync_deflate_call_compressor(def, PSYNC_DEFLATE_NOFLUSH, 0);
      switch (ret){
        case Z_BUF_ERROR:
          return PSYNC_DEFLATE_NODATA;
        case Z_STREAM_ERROR:
        case Z_DATA_ERROR:
          return PRINT_RETURN_CONST(PSYNC_DEFLATE_ERROR);
        case Z_STREAM_END:
          def->flags|=FLAG_STREAM_END;
        default:
          len-=def->stream.avail_out;
          if (len==0)
            return PSYNC_DEFLATE_NODATA;
          else
            return len;
      }
    }
    else
      return (def->flags&FLAG_STREAM_END)?PSYNC_DEFLATE_EOF:PSYNC_DEFLATE_NODATA;
  }
  if (len>def->bufferendoff-def->bufferstartoff)
    len=def->bufferendoff-def->bufferstartoff;
  assert(len<=BUFFER_SIZE);
  assert(def->bufferstartoff<=BUFFER_SIZE);
  if (def->bufferstartoff+len<=BUFFER_SIZE)
    memcpy(data, def->buffer+def->bufferstartoff, len);
  else{
    assert(len-(BUFFER_SIZE-def->bufferstartoff)==def->bufferendoff%BUFFER_SIZE);
    memcpy(data, def->buffer+def->bufferstartoff, BUFFER_SIZE-def->bufferstartoff);
    memcpy((char *)data+BUFFER_SIZE-def->bufferstartoff, def->buffer, len-(BUFFER_SIZE-def->bufferstartoff));
  }
  def->bufferstartoff+=len;
  if (def->bufferstartoff==def->bufferendoff)
    def->bufferstartoff=def->bufferendoff=0;
  else if (def->bufferstartoff>=BUFFER_SIZE){
    def->bufferstartoff-=BUFFER_SIZE;
    assert(def->bufferendoff>=BUFFER_SIZE);
    def->bufferendoff-=BUFFER_SIZE;
  }
  return len;
}

int psync_deflate_pending(psync_deflate_t *def){
  return def->bufferendoff-def->bufferstartoff+(def->flushbuff?def->flushbufflen:0);
}
