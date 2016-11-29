#pragma once

#ifndef _PDEVICE_MONITOR
#define _PDEVICE_MONITOR
#include <stdint.h>
typedef enum {
  Dev_Types_UsbRemovableDisk = 1,
  Dev_Types_UsbFixedDisk,
  Dev_Types_CDRomMedia,
  Dev_Types_CameraDevice,
  Dev_Types_AndroidDevice
} pdevice_types;

typedef enum {
  Dev_Event_arrival = 1,
  Dev_Event_removed
} device_event;

typedef struct _pdevice_info pdevice_info;

struct _pdevice_info {
  pdevice_types type;
  device_event event;
  int size;
  int isextended;
  char * filesystem_path;
  pdevice_info *me;
};

typedef struct _pdevice_extended_info pdevice_extended_info;

struct _pdevice_extended_info {
  pdevice_types type;
  device_event event;
  int size;
  int isextended;
  char *filesystem_path;
  char *vendor;
  char *product;
  char *device_id;
  pdevice_extended_info * me;
};

typedef void(*device_event_callback)(void * device_info_);

#ifdef __cplusplus
extern "C" {
#endif

  void padd_monitor_callback(device_event_callback callback);

  void pinit_device_monitor();

#ifdef __cplusplus
}
#endif

#endif //_PDEVICE_MONITOR
