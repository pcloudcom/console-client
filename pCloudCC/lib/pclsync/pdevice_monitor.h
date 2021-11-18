#pragma once

#ifndef _PDEVICE_MONITOR
#define _PDEVICE_MONITOR
#include <stdint.h>
#include "psynclib.h"

//typedef struct _pdevice_info pdevice_info;

//struct _pdevice_info {
//  pdevice_types type;
//  int isextended;
//  char * filesystem_path;
//};

//typedef struct _pdevice_extended_info pdevice_extended_info;

//struct _pdevice_extended_info {
//  pdevice_types type;
//  int isextended;
//  char *filesystem_path;
//  char *vendor;
//  char *product;
//  char *device_id;
//  pdevice_extended_info* next;
//  pdevice_extended_info* prev;
//};

#ifdef __cplusplus
extern "C" {
#endif
  void psync_devmon_init();
//  void psync_devmon_notify_device_callbacks(pdevice_extended_info *param, device_event event);
#ifdef __cplusplus
}
#endif

#endif //_PDEVICE_MONITOR
