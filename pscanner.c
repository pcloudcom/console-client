/* Copyright (c) 2013-2014 Anton Titov.
 * Copyright (c) 2013-2014 pCloud Ltd.
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
#include "pscanner.h"
#include "pscanexts.h"
#include "plist.h"
#include "plibs.h"
#include "psettings.h"
#include <string.h>
#include <stdio.h>

typedef struct {
  psync_list nextfolder;
  psync_list subfolders;
  const char *path;
  size_t pathlen;
  uint32_t filecnt[PSYNC_SCAN_TYPES_CNT];
} scan_folder;

typedef struct {
  psync_list list;
  scan_folder *folder;
  uint32_t filecnt;
} suggested_folder;


#define _IPATTERN(x) {x, sizeof(x)-1}
struct {
  const char *str;
  size_t len;
} ignore_patters[]={
  _IPATTERN(".*")
};

static uint32_t get_ext_id(const char *ext){
  uint32_t n;
  uint8_t ch, c;
  n=0;
  while ((ch=(unsigned char)*ext++)){
    n*=37;
    c=psync_character_map[ch];
    if (c)
      n+=c;
    else
      return 0;
  }
  return n;
}

static uint32_t get_extid_type(uint32_t extid){
  psync_uint_t lo, hi, mid;
  uint32_t n;
  lo=0;
  hi=PSYNC_SCAN_EXTENSIONS_CNT;
  while (hi>lo){
    mid=(lo+hi)/2;
    n=psync_scan_extensions[mid];
    if (extid>n)
      lo=mid+1;
    else if (extid<n)
      hi=mid;
    else
      return psync_scan_types[mid];
  }
  return 0;
}

static uint32_t get_file_type(const char *name){
  const char *ext;
  ext=strrchr(name, '.');
  if (ext)
    return get_extid_type(get_ext_id(ext+1));
  else
    return 0;
}

static void dir_scan(void *ptr, psync_pstat_fast *st){
  scan_folder *f=(scan_folder *)ptr;
  psync_uint_t i;
  for (i=0; i<ARRAY_SIZE(ignore_patters); i++)
    if (psync_match_pattern(st->name, ignore_patters[i].str, ignore_patters[i].len))
      return;
  if (st->isfolder){
    scan_folder *nf;
    char *path;
    size_t l, o;
    l=strlen(st->name);
    o=f->pathlen;
    nf=(scan_folder *)psync_malloc(sizeof(scan_folder)+o+l+2);
    psync_list_init(&nf->subfolders); 
    path=(char *)(nf+1);
    memcpy(path, f->path, o);
    path[o++]=PSYNC_DIRECTORY_SEPARATORC;
    memcpy(path+o, st->name, l);
    o+=l;
    path[o]=0;
    nf->path=path;
    nf->pathlen=o;
    memset(&nf->filecnt, 0, sizeof(nf->filecnt));
    psync_list_add_tail(&f->subfolders, &nf->nextfolder);
  }
  else
    f->filecnt[get_file_type(st->name)]++;
}

static void scan_folder_by_ptr(scan_folder *f){
  psync_list *e;
//  debug(D_NOTICE, "scanning directory %s", f->path);
  psync_list_dir_fast(f->path, dir_scan, f);
  psync_list_for_each(e, &f->subfolders)
    scan_folder_by_ptr(psync_list_element(e, scan_folder, nextfolder));
}

static void add_subfolder_counts(scan_folder *f){
  psync_list *e;
  scan_folder *s;
  psync_uint_t i;
  psync_list_for_each(e, &f->subfolders){
    s=psync_list_element(e, scan_folder, nextfolder);
    add_subfolder_counts(s);
    for (i=0; i<PSYNC_SCAN_TYPES_CNT; i++)
      f->filecnt[i]+=s->filecnt[i];
  }
}

static void suggest_folders(scan_folder *f, psync_list *suggestions){
  psync_list *e;
  suggested_folder *s;
  psync_uint_t i;
  uint32_t sum;
  sum=0;
  for (i=1; i<PSYNC_SCAN_TYPES_CNT; i++)
    sum+=f->filecnt[i];
  if (sum>=PSYNC_SCANNER_MIN_FILES && sum>=(f->filecnt[0]+sum)*PSYNC_SCANNER_PERCENT/100){
//    debug(D_NOTICE, "suggesting %s sum %u", f->path, sum);
    s=psync_new(suggested_folder);
    s->folder=f;
    s->filecnt=sum;
    psync_list_add_tail(suggestions, &s->list);
    return;
  }
  psync_list_for_each(e, &f->subfolders)
    suggest_folders(psync_list_element(e, scan_folder, nextfolder), suggestions);
}

static int sort_comp_rev(const psync_list *l1, const psync_list *l2){
  return (int)(psync_list_element(l2, suggested_folder, list)->filecnt)-(int)(psync_list_element(l1, suggested_folder, list)->filecnt);
}

static int sort_comp_tuple_rev(const void *p1, const void *p2){
  return *((int *)p2)-*((int *)p1);
}

static void free_folder(scan_folder *f){
  psync_list_for_each_element_call(&f->subfolders, scan_folder, nextfolder, free_folder);
  psync_free(f);
}

psuggested_folders_t *psync_scanner_scan_folder(const char *path){
  scan_folder *f;
  psync_list suggestions;
  suggested_folder *s, *sf[PSYNC_SCANNER_MAX_SUGGESTIONS];
  psync_uint_t cnt, i;
  size_t off, ln;
  psuggested_folders_t *ret;
  char *str;
  char *descs[PSYNC_SCANNER_MAX_SUGGESTIONS];
  size_t descslen[PSYNC_SCANNER_MAX_SUGGESTIONS];
  char buff[256];
  uint32_t scnt[PSYNC_SCAN_TYPES_CNT][2];
  f=psync_new(scan_folder);
  psync_list_init(&f->nextfolder); 
  psync_list_init(&f->subfolders);
  f->path=path;
  f->pathlen=strlen(path);
  memset(&f->filecnt, 0, sizeof(f->filecnt));
  scan_folder_by_ptr(f);
  add_subfolder_counts(f);
  psync_list_init(&suggestions);
  suggest_folders(f, &suggestions);
  psync_list_sort(&suggestions, sort_comp_rev);
  cnt=0;
  ln=0;
  psync_list_for_each_element(s, &suggestions, suggested_folder, list){
    off=0;
    for (i=0; i<PSYNC_SCAN_TYPES_CNT; i++){
      scnt[i][0]=s->folder->filecnt[i];
      scnt[i][1]=i;
    }
    qsort(scnt, PSYNC_SCAN_TYPES_CNT, sizeof(scnt[0]), sort_comp_tuple_rev);
    for (i=0; i<PSYNC_SCAN_TYPES_CNT; i++)
      if (scnt[i][1] && scnt[i][0]>=PSYNC_SCANNER_MIN_DISPLAY){
        off+=psync_slprintf(buff+off, sizeof(buff)-off, "%u %s, ", (unsigned)scnt[i][0], psync_scan_typenames[scnt[i][1]]);
        if (off>=sizeof(buff))
          break;
      }
    if (off)
      off-=2;
    buff[off]=0;
    ln+=s->folder->pathlen+off+2;
    sf[cnt]=s;
    descslen[cnt]=off+1;
    descs[cnt]=psync_malloc(descslen[cnt]);
    memcpy(descs[cnt], buff, descslen[cnt]);
    if (++cnt>=PSYNC_SCANNER_MAX_SUGGESTIONS)
      break;
  }
  ret=psync_malloc(offsetof(psuggested_folders_t, entries)+sizeof(psuggested_folder_t)*cnt+ln);
  str=((char *)ret)+offsetof(psuggested_folders_t, entries)+sizeof(psuggested_folder_t)*cnt;
  ret->entrycnt=cnt;
  for (i=0; i<cnt; i++){
    ret->entries[i].localpath=str;
    memcpy(str, sf[i]->folder->path, sf[i]->folder->pathlen+1);
    str+=sf[i]->folder->pathlen+1;
    ret->entries[i].name=strrchr(ret->entries[i].localpath, PSYNC_DIRECTORY_SEPARATORC);
    if (ret->entries[i].name)
      ret->entries[i].name++;
    else{
      ret->entries[i].name=strrchr(ret->entries[i].localpath, '/');
      if (ret->entries[i].name)
        ret->entries[i].name++;
    }
    ret->entries[i].description=str;
    memcpy(str, descs[i], descslen[i]);
    str+=descslen[i];
    psync_free(descs[i]);
    debug(D_NOTICE, "suggesting %s (%s, %s)", ret->entries[i].localpath, ret->entries[i].name, ret->entries[i].description);
  }
  psync_list_for_each_element_call(&suggestions, suggested_folder, list, psync_free);
  free_folder(f);
  return ret;
}
