/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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

#include "plocalscan.h"
#include "ptimer.h"
#include "pstatus.h"
#include "plibs.h"
#include "psettings.h"
#include "plist.h"
#include "ptasks.h"
#include <string.h>
#include <db.h>

typedef struct {
  psync_list list;
  psync_folderid_t folderid;
  psync_syncid_t syncid;
  psync_synctype_t synctype;
  char localpath[];
} sync_list;

typedef struct {
  psync_list list;
  psync_fileorfolderid_t localid;
  psync_fileorfolderid_t remoteid;
  psync_folderid_t localparentfolderid;
  psync_folderid_t parentfolderid;
  psync_inode_t inode;
  uint64_t mtimenat;
  uint64_t size;
  psync_syncid_t syncid;
  uint8_t isfolder;
  char name[];
} sync_folderlist;

typedef sync_folderlist sync_folderlist_tuple[2];

static pthread_mutex_t scan_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t scan_cond=PTHREAD_COND_INITIALIZER;
static uint32_t scan_wakes=0;

#define SCAN_LIST_CNT 7
#define SCAN_LIST_NEWFILES     0
#define SCAN_LIST_DELFILES     1
#define SCAN_LIST_NEWFOLDERS   2
#define SCAN_LIST_DELFOLDERS   3
#define SCAN_LIST_MODFILES     4
#define SCAN_LIST_RENFILESFROM 5
#define SCAN_LIST_RENFILESTO   6

static psync_list scan_lists[SCAN_LIST_CNT];
//static psync_uint_t scan_list_cnt[SCAN_LIST_CNT];

static uint64_t localsleepperfolder;
static time_t starttime;


static void scanner_set_syncs_to_list(psync_list *lst){
  psync_sql_res *res;
  psync_variant_row row;
  const char *lp;
  sync_list *l;
  size_t lplen;
  psync_list_init(lst);
  res=psync_sql_query("SELECT id, folderid, localpath, synctype FROM syncfolder WHERE synctype&"NTO_STR(PSYNC_UPLOAD_ONLY)"="NTO_STR(PSYNC_UPLOAD_ONLY));
  while ((row=psync_sql_fetch_row(res))){
    lp=psync_get_lstring(row[2], &lplen);
    l=(sync_list *)psync_malloc(offsetof(sync_list, localpath)+lplen+1);
    l->folderid=psync_get_number(row[1]);
    l->syncid=psync_get_number(row[0]);
    l->synctype=psync_get_number(row[3]);
    memcpy(l->localpath, lp, lplen+1);
    psync_list_add_tail(lst, &l->list);
  }
  psync_sql_free_result(res);
}

static void scanner_local_entry_to_list(void *ptr, psync_pstat *st){
  psync_list *lst;
  sync_folderlist *e;
  size_t l;
  lst=(psync_list *)ptr;
  l=strlen(st->name)+1;
  e=(sync_folderlist *)psync_malloc(offsetof(sync_folderlist, name)+l);
  e->localid=0;
  e->remoteid=0;
  e->inode=psync_stat_inode(&st->stat);
  e->mtimenat=psync_stat_mtime_native(&st->stat);
  e->size=psync_stat_size(&st->stat);
  e->isfolder=psync_stat_isfolder(&st->stat);
  memcpy(e->name, st->name, l);
  psync_list_add_tail(lst, &e->list);
}

static void scanner_local_folder_to_list(const char *localpath, psync_list *lst){
  psync_list_init(lst);
  psync_list_dir(localpath, scanner_local_entry_to_list, lst);
}

static void scanner_db_folder_to_list(psync_syncid_t syncid, psync_folderid_t localfolderid, psync_list *lst){
  psync_sql_res *res;
  psync_variant_row row;
  sync_folderlist *e;
  const char *name;
  size_t namelen;
  psync_list_init(lst);
  res=psync_sql_query("SELECT id, folderid, inode, mtimenative, name FROM localfolder WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  while ((row=psync_sql_fetch_row(res))){
    name=psync_get_lstring(row[4], &namelen);
    namelen++;
    e=(sync_folderlist *)psync_malloc(offsetof(sync_folderlist, name)+namelen);
    e->localid=psync_get_number(row[0]);
    e->remoteid=psync_get_number(row[1]);
    e->inode=psync_get_number(row[2]);
    e->mtimenat=psync_get_number(row[3]);
    e->size=0;
    e->isfolder=1;
    memcpy(e->name, name, namelen);
    psync_list_add_tail(lst, &e->list);
  }
  psync_sql_free_result(res);
  res=psync_sql_query("SELECT id, fileid, inode, mtimenative, size, name FROM localfile WHERE localparentfolderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, localfolderid);
  psync_sql_bind_uint(res, 2, syncid);
  while ((row=psync_sql_fetch_row(res))){
    name=psync_get_lstring(row[5], &namelen);
    namelen++;
    e=(sync_folderlist *)psync_malloc(offsetof(sync_folderlist, name)+namelen);
    e->localid=psync_get_number(row[0]);
    e->remoteid=psync_get_number(row[1]);
    e->inode=psync_get_number(row[2]);
    e->mtimenat=psync_get_number(row[3]);
    e->size=psync_get_number(row[4]);
    e->isfolder=0;
    memcpy(e->name, name, namelen);
    psync_list_add_tail(lst, &e->list);
  }
  psync_sql_free_result(res);
}

static int folderlist_cmp(const psync_list *l1, const psync_list *l2){
  return psync_filename_cmp(psync_list_element(l1, sync_folderlist, list)->name, psync_list_element(l2, sync_folderlist, list)->name);
}

static sync_folderlist *copy_folderlist_element(const sync_folderlist *e, psync_folderid_t folderid, psync_folderid_t localfolderid, psync_syncid_t syncid){
  sync_folderlist *ret;
  size_t l;
  l=offsetof(sync_folderlist, name)+strlen(e->name)+1;
  ret=(sync_folderlist *)psync_malloc(l);
  memcpy(ret, e, l);
  ret->localparentfolderid=localfolderid;
  ret->parentfolderid=folderid;
  ret->syncid=syncid;
  return ret;
}

static void add_element_to_scan_list(psync_uint_t id, sync_folderlist *e){
  psync_list_add_tail(&scan_lists[id], &e->list);
//  scan_list_cnt[id]++;
}

static void add_new_element(const sync_folderlist *e, psync_folderid_t folderid, psync_folderid_t localfolderid, psync_syncid_t syncid){
  sync_folderlist *c;
  if (psync_is_name_to_ignore(e->name))
    return;
  debug(D_NOTICE, "found new %s %s", e->isfolder?"folder":"file", e->name);
  c=copy_folderlist_element(e, folderid, localfolderid, syncid);
  if (e->isfolder)
    add_element_to_scan_list(SCAN_LIST_NEWFOLDERS, c);
  else
    add_element_to_scan_list(SCAN_LIST_NEWFILES, c);
}

static void add_deleted_element(const sync_folderlist *e, psync_folderid_t folderid, psync_folderid_t localfolderid, psync_syncid_t syncid){
  sync_folderlist *c;
  debug(D_NOTICE, "found deleted %s %s", e->isfolder?"folder":"file", e->name);
  c=copy_folderlist_element(e, folderid, localfolderid, syncid);
  if (e->isfolder)
    add_element_to_scan_list(SCAN_LIST_DELFOLDERS, c);
  else
    add_element_to_scan_list(SCAN_LIST_DELFILES, c);
}

static void add_modified_file(const sync_folderlist *e, psync_folderid_t folderid, psync_folderid_t localfolderid, psync_syncid_t syncid){
  debug(D_NOTICE, "found modified file %s", e->name);
  add_element_to_scan_list(SCAN_LIST_MODFILES, copy_folderlist_element(e, folderid, localfolderid, syncid));
}

static void scanner_scan_folder(const char *localpath, psync_folderid_t folderid, psync_folderid_t localfolderid, psync_syncid_t syncid, psync_synctype_t synctype){
  psync_list disklist, dblist, *ldisk, *ldb;
  sync_folderlist *l, *fdisk, *fdb;
  char *subpath;
  int cmp;
//  debug(D_NOTICE, "scanning folder %s", localpath);
  scanner_local_folder_to_list(localpath, &disklist);
  scanner_db_folder_to_list(syncid, localfolderid, &dblist);
  psync_list_sort(&dblist, folderlist_cmp);
  psync_list_sort(&disklist, folderlist_cmp);
  ldisk=disklist.next;
  ldb=dblist.next;
  while (ldisk!=&disklist && ldb!=&dblist){
    fdisk=psync_list_element(ldisk, sync_folderlist, list);
    fdb=psync_list_element(ldb, sync_folderlist, list);
    cmp=psync_filename_cmp(fdisk->name, fdb->name);
    if (cmp==0){
      if (likely_log(fdisk->isfolder==fdb->isfolder)){
        fdisk->localid=fdb->localid;
        fdisk->remoteid=fdb->remoteid;
        if (!fdisk->isfolder && (fdisk->mtimenat!=fdb->mtimenat || fdisk->size!=fdb->size || fdisk->inode!=fdb->inode))
          add_modified_file(fdisk, folderid, localfolderid, syncid);
      }
      ldisk=ldisk->next;
      ldb=ldb->next;
    }
    else if (cmp<0){ // new element on disk
      add_new_element(fdisk, folderid, localfolderid, syncid);
      ldisk=ldisk->next;
    }
    else { // deleted element from disk
      add_deleted_element(fdb, folderid, localfolderid, syncid);
      ldb=ldb->next;
    }
  }
  while (ldisk!=&disklist){
    fdisk=psync_list_element(ldisk, sync_folderlist, list);
    add_new_element(fdisk, folderid, localfolderid, syncid);
    ldisk=ldisk->next;
  }
  while (ldb!=&dblist){
    fdb=psync_list_element(ldb, sync_folderlist, list);
    add_deleted_element(fdb, folderid, localfolderid, syncid);
    ldb=ldb->next;
  }
  psync_list_for_each_element_call(&dblist, sync_folderlist, list, psync_free);
  if (localsleepperfolder){
    psync_milisleep(localsleepperfolder);
    if (psync_current_time-starttime>=PSYNC_LOCALSCAN_SLEEPSEC_PER_SCAN*2 && localsleepperfolder>=2)
      localsleepperfolder/=2;
  }
  else
    psync_yield_cpu();
  psync_list_for_each_element(l, &disklist, sync_folderlist, list)
    if (l->isfolder && l->localid){
      subpath=psync_strcat(localpath, PSYNC_DIRECTORY_SEPARATOR, l->name, NULL);
      scanner_scan_folder(subpath, l->remoteid, l->localid, syncid, synctype);
      psync_free(subpath);
    }
  psync_list_for_each_element_call(&disklist, sync_folderlist, list, psync_free);
}

static int compare_sizeinodemtime(const psync_list *l1, const psync_list *l2){
  const sync_folderlist *f1, *f2;
  int64_t d;
  f1=psync_list_element(l1, sync_folderlist, list);
  f2=psync_list_element(l2, sync_folderlist, list);
  d=f1->size-f2->size;
  if (d<0)
    return -1;
  else if (d>0)
    return 1;
  d=f1->inode-f2->inode;
  if (d<0)
    return -1;
  else if (d>0)
    return 1;
  d=f1->mtimenat-f2->mtimenat;
  if (d<0)
    return -1;
  else if (d>0)
    return 1;
  else
    return 0;
}

static void scan_rename_file(sync_folderlist *rnfr, sync_folderlist *rnto){
  psync_sql_res *res;
  res=psync_sql_prep_statement("UPDATE localfile SET localparentfolderid=?, syncid=?, name=? WHERE id=?");
  psync_sql_bind_uint(res, 1, rnto->localparentfolderid);
  psync_sql_bind_uint(res, 2, rnto->syncid);
  psync_sql_bind_string(res, 3, rnto->name);
  psync_sql_bind_uint(res, 4, rnfr->localid);
  psync_sql_run_free(res);
  psync_task_rename_remote_file(rnfr->syncid, rnto->syncid, rnfr->localid, rnto->localparentfolderid, rnto->name);
}

static void scanner_scan(int first){
  psync_list slist, *l1, *l2;
  sync_folderlist *f1, *f2;
  sync_list *l;
  psync_uint_t i;
  if (first)
    localsleepperfolder=0;
  else{
    localsleepperfolder=psync_sql_cellint("SELECT COUNT(*) FROM localfolder", 100);
    if (!localsleepperfolder)
      localsleepperfolder=1;
    localsleepperfolder=PSYNC_LOCALSCAN_SLEEPSEC_PER_SCAN*1000/localsleepperfolder;
    if (localsleepperfolder>1000)
      localsleepperfolder=1000;
    if (localsleepperfolder<1)
      localsleepperfolder=1;
  }
  starttime=psync_current_time;
  //memset(scan_list_cnt, 0, sizeof(scan_list_cnt));
  for (i=0; i<SCAN_LIST_CNT; i++)
    psync_list_init(&scan_lists[i]);
  scanner_set_syncs_to_list(&slist);
  psync_list_for_each_element(l, &slist, sync_list, list)
    scanner_scan_folder(l->localpath, l->folderid, 0, l->syncid, l->synctype);
  psync_list_extract_repeating(&scan_lists[SCAN_LIST_DELFILES], 
                               &scan_lists[SCAN_LIST_NEWFILES], 
                               &scan_lists[SCAN_LIST_RENFILESFROM], 
                               &scan_lists[SCAN_LIST_RENFILESTO],
                               compare_sizeinodemtime);
  l2=&scan_lists[SCAN_LIST_RENFILESTO];
  psync_list_for_each(l1, &scan_lists[SCAN_LIST_RENFILESFROM]){
    l2=l2->next;
    f1=psync_list_element(l1, sync_folderlist, list);
    f2=psync_list_element(l2, sync_folderlist, list);
    debug(D_NOTICE, "file renamed from %s to %s", f1->name, f2->name);
    scan_rename_file(f1, f2);
  }
  for (i=0; i<SCAN_LIST_CNT; i++)
    psync_list_for_each_element_call(&scan_lists[i], sync_folderlist, list, psync_free);
  psync_list_for_each_element_call(&slist, sync_list, list, psync_free);
}

static void scanner_wait(){
  struct timespec tm;
  tm.tv_sec=psync_current_time+PSYNC_LOCALSCAN_RESCAN_INTERVAL;
  tm.tv_nsec=0;
  pthread_mutex_lock(&scan_mutex);
  if (!scan_wakes)
    pthread_cond_timedwait(&scan_cond, &scan_mutex, &tm);
  scan_wakes=0;
  pthread_mutex_unlock(&scan_mutex);
}

static void scanner_thread(){
  psync_milisleep(10);
  psync_wait_status(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN|PSTATUS_RUN_PAUSE);
  scanner_scan(1);
  psync_set_status(PSTATUS_TYPE_LOCALSCAN, PSTATUS_LOCALSCAN_READY);
  scanner_wait();
  while (psync_do_run){
    psync_wait_status(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN|PSTATUS_RUN_PAUSE);
    scanner_scan(0);
    scanner_wait();
  }
}

void psync_wake_localscan(){
  pthread_mutex_lock(&scan_mutex);
  if (!scan_wakes++)
    pthread_cond_signal(&scan_cond);
  pthread_mutex_unlock(&scan_mutex);  
}

static void psync_wake_localscan_noscan(){
  pthread_mutex_lock(&scan_mutex);
  pthread_cond_signal(&scan_cond);
  pthread_mutex_unlock(&scan_mutex);  
}

void psync_localscan_init(){
  psync_timer_exception_handler(psync_wake_localscan_noscan);
  psync_run_thread(scanner_thread);
}
