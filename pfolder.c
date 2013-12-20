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

#include <string.h>
#include <stddef.h>
#include "pfolder.h"
#include "plibs.h"
#include "psettings.h"

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

psync_folderid_t psync_get_folderid_by_path(const char *path){
  psync_folderid_t cfolderid;
  const char *sl;
  psync_sql_res *res;
  uint64_t *row;
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
      if (!res){
        psync_error=PERROR_DATABASE_ERROR;
        return PSYNC_INVALID_FOLDERID;
      }
    }
    else
      psync_sql_reset(res);
    psync_sql_bind_uint(res, 1, cfolderid);
    psync_sql_bind_lstring(res, 2, path, len);
    row=psync_sql_fetch_rowint(res);
    if (!row)
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
  psync_variant *row;
  size_t namelen;
  pentry_t entry;
  uint64_t perms;
  list=folder_list_init();
  if (listtype&PLIST_FOLDERS){
    res=psync_sql_query("SELECT id, permissons, name FROM folder WHERE parentfolderid=?");
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

static void add_to_folderlist(void *ptr, psync_stat *stat){
  flist_ltype *ft=(flist_ltype *)ptr;
  pentry_t entry;
  if (((ft->listtype&PLIST_FOLDERS) && stat->isfolder) || ((ft->listtype&PLIST_FILES) && !stat->isfolder)){
    entry.name=stat->name;
    entry.namelen=strlen(stat->name);
    if (stat->isfolder){
      entry.isfolder=1;
      entry.folder.cansyncup=stat->canread;
      entry.folder.cansyncdown=stat->canwrite;
    }
    else{
      entry.isfolder=0;
      entry.file.size=stat->size;
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
