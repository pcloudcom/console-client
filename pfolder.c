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

#include <string.h>
#include <stddef.h>
#include "pfolder.h"
#include "plibs.h"
#include "psettings.h"
#include "plist.h"

#define INITIAL_NAME_BUFF 2000
#define INITIAL_ENTRY_CNT 128

typedef struct {
  pentry_t *entries;
  char *namebuff;
  size_t nameoff;
  size_t namealloc;
  uint32_t entriescnt;
  uint32_t entriesalloc;
} folder_list;

typedef struct {
  folder_list *folderlist;
  psync_listtype_t listtype;
} flist_ltype;

typedef struct _string_list {
  psync_list list;
  char *str;
  size_t len;
} string_list;

psync_folderid_t psync_get_folderid_by_path(const char *path){
  psync_folderid_t cfolderid;
  const char *sl;
  psync_sql_res *res;
  psync_uint_row row;
  size_t len;
  res=NULL;
  if (*path!='/')
    goto err;
  cfolderid=0;
  while (1){
    while (*path=='/')
      path++;
    if (*path==0){
      if (res)
        psync_sql_free_result(res);
      return cfolderid;
    }
    sl=strchr(path, '/');
    if (sl)
      len=sl-path;
    else
      len=strlen(path);
    if (!res){
      res=psync_sql_query("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
      if (unlikely_log(!res)){
        psync_error=PERROR_DATABASE_ERROR;
        return PSYNC_INVALID_FOLDERID;
      }
    }
    else
      psync_sql_reset(res);
    psync_sql_bind_uint(res, 1, cfolderid);
    psync_sql_bind_lstring(res, 2, path, len);
    row=psync_sql_fetch_rowint(res);
    if (unlikely_log(!row))
      goto err;
    cfolderid=row[0];
    path+=len;
  }  
err:
  if (res)
    psync_sql_free_result(res);
  psync_error=PERROR_REMOTE_FOLDER_NOT_FOUND;
  return PSYNC_INVALID_FOLDERID;
}

static void psync_free_string_list(psync_list *lst){
  psync_list_for_each_element_call(lst, string_list, list, psync_free);
}

static string_list *str_to_list_element(const char *str, size_t len){
  string_list *le;
  le=(string_list *)psync_malloc(sizeof(string_list)+len+1);
  le->str=(char *)(le+1);
  le->len=len;
  memcpy(le->str, str, len+1);
  return le;
}

static int psync_add_path_to_list(psync_list *lst, psync_folderid_t folderid){
  string_list *e;
  psync_sql_res *res;
  psync_variant_row row;
  const char *str;
  size_t len;
  while (1){
    if (folderid==0){
      e=(string_list *)psync_malloc(sizeof(string_list));
      e->str=(char *)e;
      e->len=0;
      psync_list_add_head(lst, &e->list);
      return 0;
    }
    res=psync_sql_query("SELECT parentfolderid, name FROM folder WHERE id=?");
    psync_sql_bind_uint(res, 1, folderid);
    row=psync_sql_fetch_row(res);
    if (unlikely(!row))
      break;
    folderid=psync_get_number(row[0]);
    str=psync_get_lstring(row[1], &len);
    e=str_to_list_element(str, len);
    psync_list_add_head(lst, &e->list);
    psync_sql_free_result(res);
  }
  psync_sql_free_result(res);
  debug(D_ERROR, "folder %lu not found in database", (unsigned long)folderid);
  return -1;
}

char *psync_join_string_list(const char *sep, psync_list *lst, size_t *retlen){
  size_t slen, seplen, cnt;
  string_list *e;
  char *ret, *str;
  slen=cnt=0;
  psync_list_for_each_element(e, lst, string_list, list){
    slen+=e->len;
    cnt++;
  }
  if (unlikely(!cnt))
    return psync_strdup("");
  seplen=strlen(sep);
  ret=str=psync_malloc(slen+cnt*seplen+1);
  psync_list_for_each_element(e, lst, string_list, list){
    memcpy(str, e->str, e->len);
    str+=e->len;
    memcpy(str, sep, seplen);
    str+=seplen;
  }
  str-=seplen;
  *str=0;
  if (retlen)
    *retlen=str-ret;
  return ret;
}

char *psync_get_path_by_folderid(psync_folderid_t folderid, size_t *retlen){
  psync_list folderlist;
  char *ret;
  int res;
  psync_list_init(&folderlist);
  psync_sql_lock();
  res=psync_add_path_to_list(&folderlist, folderid);
  psync_sql_unlock();
  if (unlikely_log(res)){
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret=psync_join_string_list("/", &folderlist, retlen);
  psync_free_string_list(&folderlist);
  if (!ret[0]){
    psync_free(ret);
    ret=psync_strdup("/");
    if (retlen)
      *retlen=1;
  }
  return ret;
}

char *psync_get_path_by_fileid(psync_fileid_t fileid, size_t *retlen){
  psync_list folderlist;
  char *ret;
  psync_sql_res *res;
  psync_variant_row row;
  string_list *e;
  const char *str;
  psync_folderid_t folderid;
  size_t len;
  psync_list_init(&folderlist);
  psync_sql_lock();
  res=psync_sql_query("SELECT parentfolderid, name FROM file WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  row=psync_sql_fetch_row(res);
  if (unlikely_log(!row)){
    psync_sql_free_result(res);
    psync_sql_unlock();
    return PSYNC_INVALID_PATH;
  }
  folderid=psync_get_number(row[0]);
  str=psync_get_lstring(row[1], &len);
  e=str_to_list_element(str, len);
  psync_list_add_head(&folderlist, &e->list);
  psync_sql_free_result(res);
  if (unlikely_log(psync_add_path_to_list(&folderlist, folderid))){
    psync_sql_unlock();
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  psync_sql_unlock();
  ret=psync_join_string_list("/", &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

static int psync_add_local_path_to_list_by_localfolderid(psync_list *lst, psync_folderid_t localfolderid, psync_syncid_t syncid){
  string_list *e, *le;
  psync_sql_res *res;
  psync_variant_row row;
  const char *str;
  size_t len;
  res=psync_sql_query("SELECT localpath FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  row=psync_sql_fetch_row(res);
  if (unlikely(!row)){
    debug(D_ERROR, "could not find sync id %lu", (long unsigned)syncid);
    return -1;
  }
  str=psync_get_lstring(row[0], &len);
  le=str_to_list_element(str, len);
  psync_sql_free_result(res);
  while (1){
    if (localfolderid==0){
      psync_list_add_head(lst, &le->list);
      return 0;
    }
    res=psync_sql_query("SELECT localparentfolderid, name FROM localfolder WHERE id=?");
    psync_sql_bind_uint(res, 1, localfolderid);
    row=psync_sql_fetch_row(res);
    if (unlikely(!row))
      break;
    localfolderid=psync_get_number(row[0]);
    str=psync_get_lstring(row[1], &len);
    e=str_to_list_element(str, len);
    psync_list_add_head(lst, &e->list);
    psync_sql_free_result(res);
  }
  psync_sql_free_result(res);
  psync_list_add_head(lst, &le->list);
  debug(D_ERROR, "local folder %lu not found in database", (unsigned long)localfolderid);
  return -1;
}

char *psync_local_path_for_local_folder(psync_folderid_t localfolderid, psync_syncid_t syncid, size_t *retlen){
  psync_list folderlist;
  char *ret;
  int res;
  psync_list_init(&folderlist);
  psync_sql_lock();
  res=psync_add_local_path_to_list_by_localfolderid(&folderlist, localfolderid, syncid);
  psync_sql_unlock();
  if (unlikely_log(res)){
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret=psync_join_string_list(PSYNC_DIRECTORY_SEPARATOR, &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

char *psync_local_path_for_local_file(psync_fileid_t localfileid, size_t *retlen){
  psync_list folderlist;
  char *ret;
  const char *str;
  psync_sql_res *res;
  psync_variant_row row;
  string_list *e;
  psync_folderid_t localfolderid;
  size_t len;
  psync_syncid_t syncid;
  int rs;
  psync_list_init(&folderlist);
  psync_sql_lock();
  res=psync_sql_query("SELECT localparentfolderid, syncid, name FROM localfile WHERE id=?");
  psync_sql_bind_uint(res, 1, localfileid);
  if (unlikely_log(!(row=psync_sql_fetch_row(res)))){
    psync_sql_free_result(res);
    psync_sql_unlock();
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  localfolderid=psync_get_number(row[0]);
  syncid=psync_get_number(row[1]);
  str=psync_get_lstring(row[2], &len);
  e=str_to_list_element(str, len);
  psync_sql_free_result(res);
  psync_list_add_head(&folderlist, &e->list);
  rs=psync_add_local_path_to_list_by_localfolderid(&folderlist, localfolderid, syncid);
  psync_sql_unlock();
  if (unlikely_log(rs)){
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret=psync_join_string_list(PSYNC_DIRECTORY_SEPARATOR, &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

/*static int psync_add_local_path_to_list(psync_list *lst, psync_folderid_t folderid, psync_syncid_t syncid){
  string_list *e, *le;
  psync_sql_res *res;
  psync_variant *row;
  const char *str;
  size_t len;
  psync_syncid_t srootfolderid;
  res=psync_sql_query("SELECT folderid, localpath FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  row=psync_sql_fetch_row(res);
  if (unlikely(!row)){
    debug(D_ERROR, "could not find sync id %lu", (long unsigned)syncid);
    return -1;
  }
  srootfolderid=psync_get_number(row[0]);
  str=psync_get_lstring(row[1], &len);
  le=(string_list *)psync_malloc(sizeof(string_list)+len+1);
  le->str=(char *)(le+1);
  le->len=len;
  memcpy(le->str, str, len+1);
  psync_sql_free_result(res);
  while (1){
    if (folderid==srootfolderid){
      psync_list_add_head(lst, &le->list);
      return 0;
    }
    res=psync_sql_query("SELECT parentfolderid, name FROM folder WHERE id=?");
    psync_sql_bind_uint(res, 1, folderid);
    row=psync_sql_fetch_row(res);
    if (unlikely(!row))
      break;
    folderid=psync_get_number(row[0]);
    str=psync_get_lstring(row[1], &len);
    e=(string_list *)psync_malloc(sizeof(string_list)+len+1);
    e->str=(char *)(e+1);
    e->len=len;
    memcpy(e->str, str, len+1);
    psync_list_add_head(lst, &e->list);
    psync_sql_free_result(res);
  }
  psync_sql_free_result(res);
  psync_list_add_head(lst, &le->list);
  debug(D_ERROR, "folder %lu not found in database", (unsigned long)folderid);
  return -1;
}

char *psync_local_path_for_remote_folder(psync_folderid_t folderid, psync_syncid_t syncid, size_t *retlen){
  psync_list folderlist;
  char *ret;
  int res;
  psync_list_init(&folderlist);
  psync_sql_lock();
  res=psync_add_local_path_to_list(&folderlist, folderid, syncid);
  psync_sql_unlock();
  if (unlikely(res)){
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret=psync_join_string_list(PSYNC_DIRECTORY_SEPARATOR, &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

char *psync_local_path_for_remote_file(psync_fileid_t fileid, psync_syncid_t syncid, size_t *retlen){
  psync_list folderlist;
  char *ret;
  psync_sql_res *res;
  psync_variant *row;
  string_list *e;
  const char *str;
  psync_folderid_t folderid;
  size_t len;
  psync_list_init(&folderlist);
  psync_sql_lock();
  res=psync_sql_query("SELECT parentfolderid, name FROM file WHERE id=?");
  psync_sql_bind_uint(res, 1, fileid);
  row=psync_sql_fetch_row(res);
  if (unlikely(!row)){
    psync_sql_free_result(res);
    psync_sql_unlock();
    return PSYNC_INVALID_PATH;
  }
  folderid=psync_get_number(row[0]);
  str=psync_get_lstring(row[1], &len);
  e=(string_list *)psync_malloc(sizeof(string_list)+len+1);
  e->str=(char *)(e+1);
  e->len=len;
  memcpy(e->str, str, len+1);
  psync_list_add_head(&folderlist, &e->list);
  psync_sql_free_result(res);
  if (unlikely(psync_add_local_path_to_list(&folderlist, folderid, syncid))){
    psync_sql_unlock();
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  psync_sql_unlock();
  ret=psync_join_string_list(PSYNC_DIRECTORY_SEPARATOR, &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

char *psync_local_path_for_remote_file_or_folder_by_name(psync_folderid_t parentfolderid, const char *filename, psync_syncid_t syncid, size_t *retlen){
  psync_list folderlist;
  char *ret;
  string_list *e;
  size_t len;
  psync_list_init(&folderlist);
  len=strlen(filename);
  e=(string_list *)psync_malloc(sizeof(string_list)+len+1);
  e->str=(char *)(e+1);
  e->len=len;
  memcpy(e->str, filename, len+1);
  psync_list_add_head(&folderlist, &e->list);
  psync_sql_lock();
  if (unlikely(psync_add_local_path_to_list(&folderlist, parentfolderid, syncid))){
    psync_sql_unlock();
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  psync_sql_unlock();
  ret=psync_join_string_list(PSYNC_DIRECTORY_SEPARATOR, &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}*/

static folder_list *folder_list_init(){
  folder_list *list;
  list=(folder_list *)psync_malloc(sizeof(folder_list));
  list->entries=(pentry_t *)psync_malloc(sizeof(pentry_t)*INITIAL_ENTRY_CNT);
  list->namebuff=(char *)psync_malloc(INITIAL_NAME_BUFF);
  list->nameoff=0;
  list->namealloc=INITIAL_NAME_BUFF;
  list->entriescnt=0;
  list->entriesalloc=INITIAL_ENTRY_CNT;
  return list;
}

static void folder_list_add(folder_list *list, pentry_t *entry){
  if (list->entriescnt>=list->entriesalloc){
    list->entriesalloc*=2;
    list->entries=(pentry_t *)psync_realloc(list->entries, sizeof(pentry_t)*list->entriesalloc);
  }
  while (list->nameoff+entry->namelen>=list->namealloc){
    list->namealloc*=2;
    list->namebuff=(char *)psync_realloc(list->namebuff, list->namealloc);
  }
  memcpy(&list->entries[list->entriescnt++], entry, sizeof(pentry_t));
  memcpy(list->namebuff+list->nameoff, entry->name, entry->namelen);
  list->nameoff+=entry->namelen;
  list->namebuff[list->nameoff++]=0;
}

static void folder_list_free(folder_list *list){
  psync_free(list->entries);
  psync_free(list->namebuff);
  psync_free(list);
}

static pfolder_list_t *folder_list_finalize(folder_list *list){
  pfolder_list_t *ret;
  char *name;
  uint32_t i;
  debug(D_NOTICE, "allocating %u bytes for folder list, %u of which for names", 
        (unsigned)(offsetof(pfolder_list_t, entries)+sizeof(pentry_t)*list->entriescnt+list->nameoff), (unsigned)list->nameoff);
  ret=(pfolder_list_t *)psync_malloc(offsetof(pfolder_list_t, entries)+sizeof(pentry_t)*list->entriescnt+list->nameoff);
  name=((char *)ret)+offsetof(pfolder_list_t, entries)+sizeof(pentry_t)*list->entriescnt;
  ret->entrycnt=list->entriescnt;
  memcpy(ret->entries, list->entries, sizeof(pentry_t)*list->entriescnt);
  memcpy(name, list->namebuff, list->nameoff);
  for (i=0; i<list->entriescnt; i++){
    ret->entries[i].name=name;
    name+=list->entries[i].namelen+1;
  }
  folder_list_free(list);
  return ret;
}

pfolder_list_t *psync_list_remote_folder(psync_folderid_t folderid, psync_listtype_t listtype){
  folder_list *list;
  psync_sql_res *res;
  psync_variant_row row;
  size_t namelen;
  pentry_t entry;
  uint64_t perms;
  list=folder_list_init();
  if (listtype&PLIST_FOLDERS){
    res=psync_sql_query("SELECT id, permissions, name FROM folder WHERE parentfolderid=?");
    if (res){
      psync_sql_bind_uint(res, 1, folderid);
      while ((row=psync_sql_fetch_row(res))){
        entry.folder.folderid=psync_get_number(row[0]);
        perms=psync_get_number(row[1]);
        entry.name=psync_get_lstring(row[2], &namelen);
        entry.namelen=namelen;
        entry.isfolder=1;
        entry.folder.cansyncup=((perms&PSYNC_PERM_WRITE)==PSYNC_PERM_WRITE);
        entry.folder.cansyncdown=((perms&PSYNC_PERM_READ)==PSYNC_PERM_READ);
        folder_list_add(list, &entry);
      }
      psync_sql_free_result(res);
    }
  }  
  if (listtype&PLIST_FILES){
    res=psync_sql_query("SELECT id, size, name FROM file WHERE parentfolderid=?");
    if (res){
      psync_sql_bind_uint(res, 1, folderid);
      while ((row=psync_sql_fetch_row(res))){
        entry.file.fileid=psync_get_number(row[0]);
        entry.file.size=psync_get_number(row[1]);
        entry.name=psync_get_lstring(row[2], &namelen);
        entry.namelen=namelen;
        entry.isfolder=0;
        folder_list_add(list, &entry);
      }
      psync_sql_free_result(res);
    }
  }  
  return folder_list_finalize(list);
}

static void add_to_folderlist(void *ptr, psync_pstat *stat){
  flist_ltype *ft=(flist_ltype *)ptr;
  pentry_t entry;
  int isfolder=psync_stat_isfolder(&stat->stat);
  if (((ft->listtype&PLIST_FOLDERS) && isfolder) || ((ft->listtype&PLIST_FILES) && !isfolder)){
    entry.name=stat->name;
    entry.namelen=strlen(stat->name);
    if (isfolder){
      entry.isfolder=1;
      entry.folder.cansyncup=psync_stat_mode_ok(&stat->stat, 5);
      entry.folder.cansyncdown=psync_stat_mode_ok(&stat->stat, 7);
    }
    else{
      entry.isfolder=0;
      entry.file.size=psync_stat_size(&stat->stat);
    }
    folder_list_add(ft->folderlist, &entry);
  }
}

pfolder_list_t *psync_list_local_folder(const char *path, psync_listtype_t listtype){
  flist_ltype ft;
  ft.folderlist=folder_list_init();
  ft.listtype=listtype;
  if (psync_list_dir(path, add_to_folderlist, &ft)){
    folder_list_free(ft.folderlist);
    return NULL;
  }
  else
    return folder_list_finalize(ft.folderlist);
}

typedef struct {
  char *localpath;
  char *remotepath;
  size_t locallen;
  size_t remotelen;
  psync_folderid_t folderid;
  psync_syncid_t syncid;
  psync_synctype_t synctype;
} psync_tmp_folder_t;

psync_folder_list_t *psync_list_get_list(){
  psync_sql_res *res;
  psync_variant_row row;
  psync_tmp_folder_t *folders;
  const char *cstr;
  char *str;
  psync_folder_list_t *ret;
  size_t strlens, l;
  psync_folderid_t folderid;
  uint32_t alloced, lastfolder, i;
  folders=NULL;
  alloced=lastfolder=0;
  strlens=0;
  res=psync_sql_query("SELECT id, folderid, localpath, synctype FROM syncfolder");
  while ((row=psync_sql_fetch_row(res))){
    if (alloced==lastfolder){
      alloced=(alloced+32)*2;
      folders=(psync_tmp_folder_t *)psync_realloc(folders, sizeof(psync_tmp_folder_t)*alloced);
    }
    cstr=psync_get_lstring(row[2], &l);
    l++;
    str=(char *)psync_malloc(l);
    memcpy(str, cstr, l);
    strlens+=l;
    folders[lastfolder].localpath=str;
    folders[lastfolder].locallen=l;
    folderid=psync_get_number(row[1]);
    str=psync_get_path_by_folderid(folderid, &l);
    if (unlikely(!str)){
      str=psync_strdup("/Invalid/Path");
      l=strlen(str);
    }
    l++;
    strlens+=l;
    folders[lastfolder].remotepath=str;
    folders[lastfolder].remotelen=l;
    folders[lastfolder].folderid=folderid;
    folders[lastfolder].syncid=psync_get_number(row[0]);
    folders[lastfolder].synctype=psync_get_number(row[3]);
    lastfolder++;
  }
  psync_sql_free_result(res);
  l=offsetof(psync_folder_list_t, folders)+sizeof(psync_folder_t)*lastfolder;
  ret=(psync_folder_list_t *)psync_malloc(l+strlens);
  str=((char *)ret)+l;
  ret->foldercnt=lastfolder;
  for (i=0; i<lastfolder; i++){
    l=folders[i].locallen;
    memcpy(str, folders[i].localpath, l);
    psync_free(folders[i].localpath);
    ret->folders[i].localpath=str;
    while (l && str[l]!=PSYNC_DIRECTORY_SEPARATORC && str[l]!='/')
      l--;
    if (str[l]==PSYNC_DIRECTORY_SEPARATORC || str[l]=='/')
      l++;
    ret->folders[i].localname=str+l;
    str+=folders[i].locallen;
    l=folders[i].remotelen;
    memcpy(str, folders[i].remotepath, l);
    psync_free(folders[i].remotepath);
    ret->folders[i].remotepath=str;
    while (l && str[l]!='/')
      l--;
    if (str[l]=='/')
      l++;
    ret->folders[i].remotename=str+l;
    str+=folders[i].remotelen;
    ret->folders[i].folderid=folders[i].folderid;
    ret->folders[i].syncid=folders[i].syncid;
    ret->folders[i].synctype=folders[i].synctype;
  }
  psync_free(folders);
  return ret;
}