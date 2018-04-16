#pragma once

#ifndef _PDEVICE_MAP
#define _PDEVICE_MAP
#include "pdevice_monitor.h"
void do_notify_device_callbacks_in(void * param);
void do_notify_device_callbacks_out(void * param);

pdevice_extended_info* construct_deviceininfo( pdevice_types type, int isextended,const char *filesystem_path, 
                                               const char *vendor,const char *product,const char *device_id);
void destruct_deviceininfo(pdevice_extended_info* device);

void add_device (pdevice_types type, int isextended, const char *filesystem_path, const char *vendor, const  char *product,const char *device_id);
void remove_device (const char *filesystem_path);
void filter_unconnected_device ();
void init_devices ();
void print_stree();
void print_device_info(pdevice_extended_info *ret );

#endif //_PDEVICE_MAP