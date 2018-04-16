#include "pdevicemap.h"
#include "plibs.h"
#include "pdevice_monitor.h"

#include <search.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

extern device_event_callback *device_callbacks;

extern int device_clbsize;
extern int device_clbnum;

typedef const char* list_key;
typedef pdevice_extended_info list_element;
typedef int (*Compare_func)(const list_key l, const list_element *r);

#define devicetree_step 128
static list_element *stree_root = NULL;
static list_element *stree_last = NULL;

static list_element * list_find(list_key key, Compare_func cmp )
{
  if (stree_root) {
    list_element * dev = stree_root;
    for (; dev ;) {
      if (!cmp(key, dev))
        return dev;
      if (dev->next)
        dev = dev->next;
      else break;
    }
  }
  return NULL;
}

static void list_add(list_element* new1)
{
  if (stree_root) {
    stree_last->next = new1;
    new1->prev = stree_last;
  } else {
    stree_root = new1;
    new1->prev = NULL;
  }
  stree_last = new1;
  stree_last->next = NULL;
}

static void list_remove(list_element* dev)
{
  
  if (dev) {
    if (dev == stree_root)
      stree_root = dev->next;
    if (dev == stree_last)
      stree_last = dev->prev;
      
    if (dev->prev)
      dev->prev->next = dev->next;
    if (dev->next) 
      dev->next->prev = dev->prev;
    
  }
}

/*static void list_remove_el(list_element* dev)
{
  if (dev) {
    dev->prev->next = dev->next;
    dev->next->prev = dev->prev;
  }
}*/

static int key_compar(const char* l, const pdevice_extended_info *r)
{
  if (r)
    return strcmp(l, r->filesystem_path);
  else return 1;
}

static int ext_compar(const pdevice_extended_info *lm, const pdevice_extended_info *lr)
{
  if (lm->isextended && lr->isextended)
  {
    int res = strcmp(lm->filesystem_path, lr->filesystem_path)+  
              strcmp(lm->device_id, lr->device_id) + 
              strcmp(lm->vendor, lr->vendor) + 
              strcmp(lm->product, lr->product);
    return res;
  }
  return strcmp(lm->filesystem_path, lr->filesystem_path);
}

static void do_notify_device_callbacks(void * param, device_event event) {
  int i = 0; 
  while (i < device_clbnum) {
    device_event_callback c = device_callbacks[i];
    c(event, param);
    i++;
  }
};


pdevice_extended_info* construct_deviceininfo( pdevice_types type, int isextended,const char *filesystem_path, 
                                               const char *vendor,const char *product,const char *device_id);
void destruct_deviceininfo(pdevice_extended_info* device);

void do_notify_device_callbacks_in(void * param) {
  do_notify_device_callbacks(param, Dev_Event_arrival);
}
void do_notify_device_callbacks_out(void * param) {
  do_notify_device_callbacks(param, Dev_Event_removed);
  destruct_deviceininfo((pdevice_extended_info*)param);
}

pdevice_extended_info* construct_deviceininfo( pdevice_types type, int isextended,const char *filesystem_path, 
                                               const char *vendor,const char *product,const char *device_id){
  pdevice_extended_info* ret = (pdevice_extended_info*)psync_malloc(sizeof(pdevice_extended_info));
  memset(ret, 0, sizeof(pdevice_extended_info));
  if (isextended && device_id){
    if (vendor)
      ret->vendor = psync_strdup(vendor);
    if (product)
      ret->product = psync_strdup(product);
    ret->device_id = psync_strdup(device_id);
  }
  ret->type = type;
  ret->isextended = isextended;
  ret->filesystem_path = psync_strdup(filesystem_path);
  return ret;
}

void destruct_deviceininfo(pdevice_extended_info* device) {
  psync_free (device->filesystem_path);
  if (device->isextended) {
    psync_free (device->vendor);
    psync_free (device->product);
    psync_free (device->device_id);
    psync_free (device);
  } else psync_free ((pdevice_info*) device);
}

void init_devices () {
  psync_sql_res *q;
  q=psync_sql_prep_statement("UPDATE devices SET connected = 0");
  psync_sql_run_free(q);
}

void add_device (pdevice_types type, int isextended,const char *filesystem_path,const char *vendor,const char *product,const char *device_id)
{
  psync_sql_res *q;
  pdevice_extended_info* data = construct_deviceininfo(type, isextended, filesystem_path, vendor,  product, device_id);
  //pdevice_extended_info* data = construct_deviceininfo(Dev_Types_Unknown, 1, "/test/", "test",  "just a test", "test device id");
  
  if (isextended) {
    uint64_t enabled = 1;
    psync_uint_row row;
    psync_sql_res * res=psync_sql_query("SELECT enabled FROM devices WHERE id = ? ");
    psync_sql_bind_string(res, 1, device_id);
    if ((row=psync_sql_fetch_rowint(res)))
        enabled = row[0];
    psync_sql_free_result(res);

    if (!enabled)
      return;
    
    q=psync_sql_prep_statement("INSERT or replace INTO devices (id, last_path, type, vendor, product, connected, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)");
    psync_sql_bind_string(q, 1, device_id);
    psync_sql_bind_string(q, 2, filesystem_path);
    psync_sql_bind_int(q, 3, (int)type);
    psync_sql_bind_string(q, 4, vendor);
    psync_sql_bind_string(q, 5, product);
    psync_sql_bind_int(q, 6, 1);
    psync_sql_bind_int(q, 7, 0);
    psync_sql_run_free(q);
  
    pdevice_extended_info * key = list_find(filesystem_path, key_compar);
    
    if (key) {
      if (ext_compar(key, data)) {
        pnotify_device_callbacks(key, Dev_Event_removed);
        q=psync_sql_prep_statement("UPDATE devices SET connected = 0 WHERE id = ? ");
        psync_sql_bind_string(q, 1, key->device_id);
        psync_sql_run_free(q);
        list_remove (key);
        destruct_deviceininfo(key);
        list_add(data);
        q=psync_sql_prep_statement("UPDATE devices SET connected = 1 WHERE id = ? ");
        psync_sql_bind_string(q, 1, data->device_id);
        psync_sql_run_free(q);
      } else {
        destruct_deviceininfo (data);
        return;
      }
    } else list_add(data);
  }
 pnotify_device_callbacks(data, Dev_Event_arrival);
}

void remove_device (const char *filesystem_path)
{
  pdevice_extended_info * key = list_find(filesystem_path, key_compar);
  if (key) {
    if (key->isextended && key->device_id) {
         psync_sql_res *q=psync_sql_prep_statement("UPDATE devices SET connected = 0 WHERE id = ? ");
        psync_sql_bind_string(q, 1, key->device_id);
        psync_sql_run_free(q);
    }
    list_remove(key);
    pnotify_device_callbacks(key, Dev_Event_removed);
  }
}

void filter_unconnected_device () {
  psync_variant_row row;
  char * path;
  int64_t conn = 0;
  psync_sql_res * res=psync_sql_query("SELECT last_path, connected FROM devices WHERE connected = 0");
  while ((row=psync_sql_fetch_row(res))){
      path=psync_dup_string(row[0]);
      conn=psync_get_number(row[1]);
      pdevice_extended_info * key = list_find(path, key_compar);
      if (key&&(!conn)) {
        list_remove(key);
        pnotify_device_callbacks(key, Dev_Event_removed);
      }
      if (conn&&!key) {
        //printf("database connected but no device [%s] \n", path);
      }
  }
  psync_sql_free_result(res);

}

void print_stree()
{
  if (stree_root) {
    pdevice_extended_info * dev = (pdevice_extended_info *) stree_root;
    for (; dev ;) {
      printf("{");
      print_device_info(dev);
      printf("}\n");
      if (dev->next)
        dev = dev->next;
      else break;
    }
  }
}

void print_device_info(pdevice_extended_info *ret ) {
  if (ret->isextended )
    debug(D_NOTICE, "DeviceID [%s]\n", ret->device_id );
  debug(D_NOTICE,"File system path [%s] \n", ret->filesystem_path);
  if (ret->isextended ) 
    debug(D_NOTICE,"Vendor [%s] / Product [%s] \n", ret->vendor, ret->product);
  debug(D_NOTICE,"Type [%d]; Extended [%d] \n",ret->type, ret->isextended);
}


void penable_device(const char* device_id) {
  psync_sql_res *q=psync_sql_prep_statement("UPDATE devices SET enabled = 1 WHERE id = ? ");
  psync_sql_bind_string(q, 1, device_id);
  psync_sql_run_free(q);
}

void pdisable_device(const char* device_id) {
  psync_sql_res *q=psync_sql_prep_statement("UPDATE devices SET enabled = 0 WHERE id = ? ");
  psync_sql_bind_string(q, 1, device_id);
  psync_sql_run_free(q);
}

void premove_device(const char* device_id) {
  psync_sql_res *q=psync_sql_prep_statement("DELETE FROM devices WHERE id = ? ");
  psync_sql_bind_string(q, 1, device_id);
  psync_sql_run_free(q);
}

static int create_device_item(psync_list_builder_t *builder, void *element, psync_variant_row row){
  pdevice_item_t *device;
  const char *str;
  size_t len;

  device=(pdevice_item_t *)element;
  str=psync_get_lstring(row[0], &len);
  device->device_id=str;
  psync_list_add_lstring_offset(builder, offsetof(pdevice_item_t, device_id), len);
  str=psync_get_lstring(row[1], &len);
  device->filesystem_path=str;
  psync_list_add_lstring_offset(builder, offsetof(pdevice_item_t, filesystem_path), len);
  device->type = psync_get_number(row[2]);
  str=psync_get_lstring(row[3], &len);
  device->vendor=str;
  psync_list_add_lstring_offset(builder, offsetof(pdevice_item_t, vendor), len);
  str=psync_get_lstring(row[4], &len);
  device->product=str;
  psync_list_add_lstring_offset(builder, offsetof(pdevice_item_t, product), len);
  device->connected = psync_get_number(row[5]);
  device->enabled = psync_get_number(row[6]);
  return 0;
}


pdevice_item_list_t * psync_list_devices(char **err /*OUT*/) {

  psync_list_builder_t *builder;
  psync_sql_res *res;
  *err = 0;

  builder=psync_list_builder_create(sizeof(pdevice_item_t), offsetof(pdevice_item_list_t, entries));

  res=psync_sql_query_rdlock("SELECT id, last_path, type, vendor, product, connected, enabled FROM devices");

  psync_list_bulder_add_sql(builder, res, create_device_item);


  return (pdevice_item_list_t *)psync_list_builder_finalize(builder);
}