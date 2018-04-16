#include "pcompat.h"
#include "plibs.h"
#include "psynclib.h"
#include "pdevice_monitor.h"
#include "papi.h"
#include "pnetlibs.h"
#include "pbusinessaccount.h"
#include "pdevicemap.h"

#define P_DEVICE_VERBOSE


#ifdef P_OS_POSIX
#define _strdup strdup
#endif //P_OS_POSIX

#define MAX_LOADSTRING 100
device_event_callback *device_callbacks;

int device_clbsize = 10;
int device_clbnum = 0;

void padd_device_monitor_callback(device_event_callback callback) {
  if (callback) {
    if (device_clbnum == 0)
      device_callbacks = (device_event_callback *)psync_malloc(sizeof(device_event_callback)*device_clbsize);
    else {
      while (device_clbnum > device_clbsize) {
        device_event_callback *callbacks_old = device_callbacks;
        device_callbacks = (device_event_callback *)psync_malloc(sizeof(device_event_callback)*device_clbsize*2);
        memccpy(device_callbacks, callbacks_old, 0,sizeof(device_event_callback)*device_clbsize);
        device_clbsize = device_clbsize * 2;
        psync_free(callbacks_old);
      }
    }
    device_callbacks[device_clbnum] = callback;
    device_clbnum
    ++;
  }
}


// static pdevice_info * new_dev_info( char *szPath, pdevice_types type, device_event evt) {
//   /*int pathsize = strlen(szPath);
//   int infstrsize = sizeof(pdevice_info);
//   int infsize = pathsize + infstrsize + 1;*/
//  // pdevice_info *infop = (pdevice_info *)psync_malloc(infsize);
//   pdevice_info *infop = (pdevice_info *)psync_malloc(sizeof(pdevice_info));
//   //ZeroMemory(infop, infsize);
//   //infop->filesystem_path = (char *)(infop) + infstrsize;
//   infop->filesystem_path = strdup(szPath);
//   //memcpy(infop->filesystem_path, szPath, pathsize);
//   //infop->filesystem_path[pathsize] = '\0';
//   infop->type = type;
//   infop->isextended = 0;
//   return infop;
// }


// static pdevice_extended_info * new_dev_ext_info(char *szPath, char * vendor, char *product, char* deviceid, pdevice_types type, device_event evt) {
//  /*uint32_t pathsize = strlen(szPath);
//   uint32_t vndsize = strlen(vendor);
//   uint32_t prdsize = strlen(product);
//   uint32_t devsize = strlen(deviceid);
//   uint32_t infstrsize = sizeof(pdevice_extended_info);
//   uint32_t infsize = pathsize + infstrsize + pathsize + vndsize + prdsize + 5;
//   void * infovp = psync_malloc(infsize);
//   pdevice_extended_info *infop = (pdevice_extended_info *)infovp;
//   ZeroMemory(infop, infsize);
//   char *storage_begin = (char *)(infovp)+infstrsize;
//   put_into_storage(&infop->filesystem_path, &storage_begin, szPath, pathsize);
//   put_into_storage(&infop->vendor, &storage_begin, vendor, vndsize);
//   put_into_storage(&infop->product, &storage_begin, product, prdsize);
//   put_into_storage(&infop->device_id, &storage_begin, deviceid, devsize);
//   infop->type = type;
//   infop->event = evt;
//   infop->isextended = 1;
//   infop->size = infsize;
//   infop->me = infop;*/
//   pdevice_extended_info *infop = (pdevice_extended_info *)psync_malloc(sizeof(pdevice_extended_info));
//   infop->filesystem_path = strdup(szPath);
//   infop->vendor = strdup(vendor);
//   infop->product = strdup(product);
//   infop->device_id = strdup(deviceid);
//   infop->type = type;
//   infop->isextended = 1;
//   return infop;
// }


void pnotify_device_callbacks(pdevice_extended_info * param, device_event event) {
  if (event == Dev_Event_arrival)
    psync_run_thread1("Device notifications", do_notify_device_callbacks_in, (void*)param);
  else
    psync_run_thread1("Device notifications", do_notify_device_callbacks_out, (void*)param);
}

static void arivalmonitor(device_event event, void * device_info_)
{

  if (event == Dev_Event_arrival)
    debug(D_NOTICE, "Device arrived. \n{");
  else
    debug(D_NOTICE, "Device removed. \n{");
  if (device_info_)
    print_device_info((pdevice_extended_info *)device_info_);
  debug(D_NOTICE,"}\n");
}

#ifdef P_OS_MACOSX

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>

//#include <IOKit/IOUBSD.h>
//#include <IOKit/IOSerialKeys.h>

#include <stdio.h>
#include <stdlib.h>

typedef struct MyPrivateData {
    io_object_t notification;
    const char* systempath;
} MyPrivateData;


static IONotificationPortRef    gNotifyPort;
static io_iterator_t            gAddedIter;
static CFRunLoopRef             gRunLoop;
#define SYSPATHRPT 8
#define USLEEPINT 500000


static char * get_device_mountpoit (const char* device){
  FILE *fp;
  char path[1035];
  int buffsize = 63 + strlen(device);
  char* result = 0;
  char* command = (char *)malloc(buffsize);
  //sprintf (command, "cat /proc/mounts |grep %s | awk '{print $2}'", device);
  sprintf (command, "system_profiler SPUSBDataType | grep '%s' -A 25 |grep -E 'Mount'", device);

  /* Open the command for reading. */
  fp = popen(command, "r");
  if (fp == NULL) {
    fprintf(stderr, "Failed to run command\n" );
    return 0;
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (result) {
      int ressize = strlen(result);
      result = (char*)realloc(result, ressize + strlen (path)+1);
      strcat(result, path);
    }else {
      result = (char*)malloc(strlen (path)+1);
      result = strdup(path);
    }
  }

  if (result) {
    char * resol = result;
    result = strdup(strchr(result, '/'));
    free (resol);
  }
  /* close */
  pclose(fp);
  free(command);
  return result;

}

void DeviceNotification(void *refCon, io_service_t service, natural_t messageType, void *messageArgument)
{
  kern_return_t   kr;
  MyPrivateData   *privateDataRef = (MyPrivateData *) refCon;

  if (messageType == kIOMessageServiceIsTerminated) {
    //fprintf(stderr, "Device removed.\n");
    //fprintf(stderr, "privateDataRef->deviceName: %s \n", privateDataRef->systempath);
    remove_device(privateDataRef->systempath);
    free(privateDataRef->systempath);
    kr = IOObjectRelease(privateDataRef->notification);
    free(privateDataRef);
  }
}

void DeviceAdded(void *refCon, io_iterator_t iterator)
{
  kern_return_t kr;
  io_service_t usbDevice;
  IOCFPlugInInterface **plugInInterface = NULL;
  SInt32 score;
  HRESULT res;
  int rpt = 0;
  CFStringRef     deviceNameAsCFString;

  while ((usbDevice = IOIteratorNext(iterator))) {
    io_name_t deviceName;
    MyPrivateData *privateDataRef = NULL;
    UInt32 locationID;
    io_string_t pathName;
    const char* systemPath;

    privateDataRef = malloc(sizeof(MyPrivateData));
    bzero(privateDataRef, sizeof(MyPrivateData));


  // Ought to work now, regardless of version of OSX being ran.
    CFStringRef usbSerial = (CFStringRef) IORegistryEntrySearchCFProperty(
      usbDevice,
      kIOServicePlane,
      CFSTR("USB Serial Number"),
      kCFAllocatorDefault,
      kIORegistryIterateRecursively
      );

    if (!usbSerial) continue;

    // Ought to work now, regardless of version of OSX being ran.
    CFStringRef usbVendor = (CFStringRef) IORegistryEntrySearchCFProperty(
      usbDevice,
      kIOServicePlane,
      CFSTR("USB Vendor Name"),
      kCFAllocatorDefault,
      kIORegistryIterateRecursively
      );

    if (!usbVendor) continue;


    // Get the USB device's name.
    kr = IORegistryEntryGetName(usbDevice, deviceName);
    if (KERN_SUCCESS != kr) {
      deviceName[0] = '\0';
    }

    deviceNameAsCFString = CFStringCreateWithCString(kCFAllocatorDefault, deviceName,
                                                    kCFStringEncodingASCII);

    if (!deviceNameAsCFString) continue;

    //fprintf(stderr, "Device added.\n");
   // fprintf(stderr, "Serial number: "); CFShow(usbSerial);
    //fprintf(stderr, "Vendor: "); CFShow(usbVendor);
   // fprintf(stderr, "Product: "); CFShow(deviceNameAsCFString);

    systemPath = get_device_mountpoit(CFStringGetCStringPtr( usbSerial, kCFStringEncodingMacRoman ));

    while  (!systemPath ) {
      if (rpt < SYSPATHRPT) {
        debug(D_NOTICE, "Giving up ... \n");
        break;
      }
      //fprintf(stderr, "Sleeping ... \n");
      usleep(USLEEPINT);
      systemPath = get_device_mountpoit(CFStringGetCStringPtr( usbSerial, kCFStringEncodingMacRoman ));
      rpt++;
    }

    if (!systemPath) continue;

    privateDataRef->systempath = systemPath;

    add_device (Dev_Types_UsbRemovableDisk, 1, systemPath,
                CFStringGetCStringPtr( usbVendor, kCFStringEncodingMacRoman ),
                CFStringGetCStringPtr( deviceNameAsCFString, kCFStringEncodingMacRoman ),
                CFStringGetCStringPtr( usbSerial, kCFStringEncodingMacRoman ));

    // Register for an interest notification of this device being removed. Use a reference to our
    // private data as the refCon which will be passed to the notification callback.
    kr = IOServiceAddInterestNotification(gNotifyPort,                      // notifyPort
                                          usbDevice,                        // service
                                          kIOGeneralInterest,               // interestType
                                          DeviceNotification,               // callback
                                          privateDataRef,                   // refCon
                                          &(privateDataRef->notification)   // notification
                                          );

    if (KERN_SUCCESS != kr) {
      printf("IOServiceAddInterestNotification returned 0x%08x.\n", kr);
    }

    // Done with this USB device; release the reference added by IOIteratorNext
    kr = IOObjectRelease(usbDevice);
  }
}

void pinit_device_monitor() {
    CFMutableDictionaryRef  matchingDict;
    CFRunLoopSourceRef      runLoopSource;
    CFNumberRef             numberRef;
    kern_return_t           kr;


    matchingDict = IOServiceMatching(kIOUSBDeviceClassName);    // Interested in instances of class
                                                                // IOUSBDevice and its subclasses
    if (matchingDict == NULL) {
        debug(D_NOTICE, "IOServiceMatching returned NULL.\n");
        return;
    }


    gNotifyPort = IONotificationPortCreate(kIOMasterPortDefault);
    runLoopSource = IONotificationPortGetRunLoopSource(gNotifyPort);

    gRunLoop = CFRunLoopGetCurrent();
    CFRunLoopAddSource(gRunLoop, runLoopSource, kCFRunLoopDefaultMode);

    // Now set up a notification to be called when a device is first matched by I/O Kit.
    kr = IOServiceAddMatchingNotification(gNotifyPort,                  // notifyPort
                                          kIOFirstMatchNotification,    // notificationType
                                          matchingDict,                 // matching
                                          DeviceAdded,                  // callback
                                          NULL,                         // refCon
                                          &gAddedIter                   // notification
                                          );

    // Iterate once to get already-present devices and arm the notification
    DeviceAdded(NULL, gAddedIter);

    // Start the run loop. Now we'll receive notifications.
    debug(D_NOTICE, "Starting run loop.\n\n");
    CFRunLoopRun();

    // We should never get here
    debug(D_NOTICE, "Unexpectedly back from CFRunLoopRun()!");
    return;
}

#endif //P_OS_MACOSX

#ifdef P_OS_LINUX
#include <libudev.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>
static char * get_device_mountpoit (const char* device){
  FILE *fp;
  char path[1035];
  int buffsize = 50 + strlen(device);
  char* result = 0;
  char* command = (char *)malloc(buffsize);
  sprintf (command, "cat /proc/mounts |grep %s | awk '{print $2}'", device);

  /* Open the command for reading. */
  fp = popen(command, "r");
  if (fp == NULL) {
    debug(D_NOTICE,"Failed to run command\n" );
    return 0;
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (result) {
      int ressize = strlen(result);
      result = (char*)realloc(result, ressize + strlen (path)+1);
      strcat(result, path);
    }else {
      result = (char*)malloc(strlen (path)+1);
      result = strdup(path);
    }
  }

  if (result) {
    int i = strlen(result) - 1;
    if ((i > 0) && (result[i] == '\n')) result[i] = '\0';
  }
  /* close */
  pclose(fp);
  free(command);
  return result;

}

static struct udev_device*
get_child(struct udev* udevs, struct udev_device* parent, const char* subsystem)
{
    struct udev_device* child = NULL;
    struct udev_enumerate *enumerate = udev_enumerate_new(udevs);

    udev_enumerate_add_match_parent(enumerate, parent);
    udev_enumerate_add_match_subsystem(enumerate, subsystem);
    udev_enumerate_scan_devices(enumerate);

    struct udev_list_entry *devices = udev_enumerate_get_list_entry(enumerate);
    struct udev_list_entry *entry;

    udev_list_entry_foreach(entry, devices) {
        const char *path = udev_list_entry_get_name(entry);
        child = udev_device_new_from_syspath(udevs, path);
        break;
    }

    udev_enumerate_unref(enumerate);
    return child;
}

/*static void print_scsi (struct udev *udevs,struct udev_device *scsi) {
 struct udev_device *usb;
 struct udev_device* scsi_disk;
 struct udev_device* block;
 usb = udev_device_get_parent_with_subsystem_devtype(
           scsi,
           "usb",
           "usb_device");
  if (!usb) {
    return;
  }


 block = get_child(udevs, scsi, "block");
 scsi_disk = get_child(udevs, scsi, "scsi_disk");
 if (block && scsi_disk) {


  debug(D_NOTICE, "Device Node Path: %s\n", udev_device_get_devnode(block));
  debug(D_NOTICE, "  VID/PID: %s %s\n",
          udev_device_get_sysattr_value(usb,"idVendor"),
          udev_device_get_sysattr_value(usb, "idProduct"));
  debug(D_NOTICE, "  %s\n  %s\n",
          udev_device_get_sysattr_value(scsi,"vendor"),
          udev_device_get_sysattr_value(scsi,"model"));
  debug(D_NOTICE, "  serial: %s\n",
            udev_device_get_sysattr_value(usb, "serial"));
  debug(D_NOTICE, "   Subsystem: %s\n", udev_device_get_subsystem(scsi));
  debug(D_NOTICE,"   Devtype: %s\n", udev_device_get_devtype(scsi));

  udev_device_unref(block);
  udev_device_unref(scsi_disk);
 }
}

static void print_hidrow (struct udev *udevs,struct udev_device *dev) {
  struct udev_device *dev1;

  dev1 = udev_device_get_parent_with_subsystem_devtype(
           dev,
           "usb",
           "usb_device");
  if (!dev1) {
    return;
  }
  debug(D_NOTICE, "Device Node Path: %s\n", udev_device_get_devnode(dev));
  debug(D_NOTICE, "  VID/PID: %s %s\n",
          udev_device_get_sysattr_value(dev1,"idVendor"),
          udev_device_get_sysattr_value(dev1, "idProduct"));
  debug(D_NOTICE, "  %s\n  %s\n",
          udev_device_get_sysattr_value(dev1,"manufacturer"),
          udev_device_get_sysattr_value(dev1,"product"));
  debug(D_NOTICE, "  serial: %s\n", udev_device_get_sysattr_value(dev1, "serial"));
  debug(D_NOTICE, "   Subsystem: %s\n", udev_device_get_subsystem(dev1));
  debug(D_NOTICE, "   Devtype: %s\n", udev_device_get_devtype(dev1));
}*/

#define UDEV_SUBSYSTEMS_CNT 2
const char *subsystems[UDEV_SUBSYSTEMS_CNT] = { "scsi_device", "hidraw" };
void enumerate_devices (struct udev *udev,device_event event) {
  struct udev_enumerate *enumerate;
  struct udev_list_entry *devices,*dev_list_entry;
  struct udev_device *dev;
  const char * subsystem;
  struct udev_device *usb;
  struct udev_device* scsi_disk;
  struct udev_device* block;
  int i;

  init_devices();
  for (i = 0; i < UDEV_SUBSYSTEMS_CNT;++i ) {
    enumerate = udev_enumerate_new(udev);
    subsystem = subsystems[i];
    if (subsystem[0] == 's') {
      udev_enumerate_add_match_subsystem(enumerate, "scsi");
      udev_enumerate_add_match_property(enumerate, "DEVTYPE", subsystem);
    } else {
      udev_enumerate_add_match_subsystem(enumerate, subsystem);
    }
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);

    udev_list_entry_foreach(dev_list_entry, devices) {
      const char *path;

      path = udev_list_entry_get_name(dev_list_entry);
      dev = udev_device_new_from_syspath(udev, path);

      if (subsystem[0] == 's') {
        usb = udev_device_get_parent_with_subsystem_devtype(
                  dev,
                  "usb",
                  "usb_device");
        if (!usb)
          continue;
        block = get_child(udev, dev, "block");
        const char *device_path = udev_device_get_devnode(block);
        if (!device_path)
          continue;
        scsi_disk = get_child(udev, dev, "scsi_disk");
        if (block && scsi_disk) {
          char* fs_path = get_device_mountpoit(device_path);
          if (fs_path) {
            add_device (Dev_Types_UsbRemovableDisk, 1, fs_path, udev_device_get_sysattr_value(dev,"vendor"),
                       udev_device_get_sysattr_value(dev,"model"),udev_device_get_sysattr_value(usb, "serial"));
            udev_device_unref(block);
            udev_device_unref(scsi_disk);
       //     debug_execute(D_NOTICE, print_scsi (udev, dev));
          }
        }
      } else if (subsystem[0] == 'h') {
        struct udev_device *dev1;

        dev1 = udev_device_get_parent_with_subsystem_devtype(
                dev,
                "usb",
                "usb_device");
        if (!dev1) {
          continue;
        }

        const char *device_path = udev_device_get_devnode(dev);
        if (!device_path)
          continue;
        char* fs_path = get_device_mountpoit(device_path);
        if (fs_path) {
            add_device (Dev_Types_UsbRemovableDisk, 1, fs_path, udev_device_get_sysattr_value(dev1,"manufacturer"),
                        udev_device_get_sysattr_value(dev1,"product"), udev_device_get_sysattr_value(dev1, "serial"));
           // debug_execute(D_NOTICE, print_hidrow(udev, dev));
        }
      }

      udev_device_unref(dev);
    }
    udev_enumerate_unref(enumerate);
  }
  /* Free the enumerator object */
    filter_unconnected_device ();

}

void monitor_usb_dev () {
  struct udev *udev;
  struct udev_device *dev;
  struct udev_monitor *mon;
  int fd;

  /* Create the udev object */
  udev = udev_new();
  if (!udev) {
    debug(D_WARNING, "Can't create udev\n");
    return;
  }

  enumerate_devices(udev, Dev_Event_arrival);

  //debug_execute(D_NOTICE, print_stree());

  /* Set up a monitor to monitor hidraw devices */
  mon = udev_monitor_new_from_netlink(udev, "udev");
  udev_monitor_filter_add_match_subsystem_devtype(mon, "scsi_disk", NULL);
  udev_monitor_filter_add_match_subsystem_devtype(mon, "hidraw", NULL);
  udev_monitor_enable_receiving(mon);
  /* Get the file descriptor (fd) for the monitor.
     This fd will get passed to select() */
  fd = udev_monitor_get_fd(mon);

  while (1) {
    /* Set up the call to select(). In this case, select() will
       only operate on a single file descriptor, the one
       associated with our udev_monitor. Note that the timeval
       object is set to 0, which will cause select() to not
       block. */
    fd_set fds;
    struct timeval tv;
    int ret;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    ret = select(fd+1, &fds, NULL, NULL, &tv);

    /* Check if our file descriptor has received data. */
    if (ret > 0 && FD_ISSET(fd, &fds)) {

      /* Make the call to receive the device.
         select() ensured that this will not block. */
      dev = udev_monitor_receive_device(mon);
      if (dev) {
        enumerate_devices(udev, Dev_Event_arrival);
      //  debug_execute(D_NOTICE, print_stree());
      }
      else {
       // printf("No Device from receive_device(). An error occured.\n");
      }
    }
    usleep(250*1000);
    fflush(stdout);
  }


  udev_unref(udev);

  return;
}

void pinit_device_monitor() {
  debug(D_NOTICE, "waiting for new devices..");
  debug_execute(D_NOTICE, padd_device_monitor_callback(arivalmonitor));
  monitor_usb_dev();
}

#endif //P_OS_LINUX


#ifdef P_OS_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT   0x0601

#include <windows.h>
#include <dbt.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <winioctl.h>

#define CLS_NAME "DUMMY_CLASS"
#define HWND_MESSAGE     ((HWND)-3)

#define WM_USER_MEDIACHANGED WM_USER+88

#define MAX_LOADSTRING 100

static pdevice_types dev_decode_type(STORAGE_BUS_TYPE bustype, DWORD drivetype) {

  switch (bustype) {
  case BusTypeScsi:
  case BusTypeiScsi:
  case BusTypeUsb:
  case BusTypeSata:
    if (drivetype == DRIVE_REMOVABLE)
      return Dev_Types_UsbRemovableDisk;
    else
      return Dev_Types_UsbFixedDisk;
  break;
  case BusTypeSd:
    return Dev_Types_AndroidDevice;
  break;
  case BusTypeMmc:
    return Dev_Types_CameraDevice;
  default:
    return Dev_Types_Unknown;
  }
}

static DWORD GetPhysicalDriveParams(char *strdrivepath IN, DWORD drivetype, char *fspath)
{
  DWORD dwRet = NO_ERROR;

  HANDLE hDevice = CreateFileA(strdrivepath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, 0, NULL);

  if (INVALID_HANDLE_VALUE == hDevice)
    return GetLastError();

  STORAGE_PROPERTY_QUERY storagePropertyQuery;
  ZeroMemory(&storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY));
  storagePropertyQuery.PropertyId = StorageDeviceProperty;
  storagePropertyQuery.QueryType = PropertyStandardQuery;

  STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader = { 0 };
  DWORD dwBytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
    &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
    &storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER),
    &dwBytesReturned, NULL))
  {
    dwRet = GetLastError();
    CloseHandle(hDevice);
    return dwRet;
  }

  // Alloc the output buffer
  const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
  BYTE* pOutBuffer = (BYTE*)psync_malloc(dwOutBufferSize);
  ZeroMemory(pOutBuffer, dwOutBufferSize);

  // Get the storage device descriptor
  if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
    &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
    pOutBuffer, dwOutBufferSize,
    &dwBytesReturned, NULL))
  {
    dwRet = GetLastError();
    free(pOutBuffer);
    CloseHandle(hDevice);
    return dwRet;
  }

  STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = (STORAGE_DEVICE_DESCRIPTOR*)pOutBuffer;
  add_device(dev_decode_type(pDeviceDescriptor->BusType, drivetype),
    1,
    fspath,
    (char *)(pOutBuffer + pDeviceDescriptor->VendorIdOffset),
    (char *)(pOutBuffer + pDeviceDescriptor->ProductIdOffset),
    (char *)(pOutBuffer + pDeviceDescriptor->SerialNumberOffset));

  // Do cleanup and return
  free (pOutBuffer);
  CloseHandle(hDevice);

  return dwRet;
}


typedef struct {
  DWORD dwItem1;    // dwItem1 contains the previous PIDL or name of the folder.
  DWORD dwItem2;    // dwItem2 contains the new PIDL or name of the folder.
} SHNOTIFYSTRUCT;

static LRESULT message_handler(HWND *hwnd, UINT uint, WPARAM wparam, LPARAM lparam)
{
  switch (uint)
  {
  case WM_NCCREATE:
    return 1;
    break;
  case WM_CREATE:
    return 0;
    break;
  case WM_DEVICECHANGE:
    return 0;
    break;
  case WM_USER_MEDIACHANGED:
  {
    SHNOTIFYSTRUCT *shns = (SHNOTIFYSTRUCT *)wparam;
    char szPath[MAX_PATH];
    ZeroMemory(&szPath, MAX_PATH);
    switch (lparam)
    {
    case SHCNE_MEDIAINSERTED:        // media inserted event
    {
      SHGetPathFromIDListA((struct _ITEMIDLIST *)shns->dwItem1, szPath);
      //pdevice_info *p = new_dev_info(szPath, Dev_Types_CDRomMedia, Dev_Event_arrival);
      add_device(Dev_Types_CDRomMedia, 0, szPath, "","", "CDROM");
      break;
    }
    case SHCNE_MEDIAREMOVED:        // media removed event
    {
      SHGetPathFromIDListA((struct _ITEMIDLIST *)shns->dwItem1, szPath);
      remove_device(szPath);
      break;
    }
    case SHCNE_DRIVEADD:        // media removed event
    {

      DWORD  drivetype;
      HANDLE  hDevice;
      PSTORAGE_DEVICE_DESCRIPTOR pDevDesc;

      SHGetPathFromIDListA((struct _ITEMIDLIST *)shns->dwItem1, szPath);
      // "X:\"    -> for GetDriveType
      char szRootPath[] = "X:\\";
      szRootPath[0] = szPath[0];
      // "X:"     -> for QueryDosDevice
      char szDevicePath[] = "X:";
      szDevicePath[0] = szPath[0];

      // "\\.\X:" -> to open the volume
      char szVolumeAccessPath[] = "\\\\.\\X:";
      szVolumeAccessPath[4] = szPath[0];
      drivetype = GetDriveTypeA(szRootPath);
      switch (drivetype)
      {
      case 0:          // The drive type cannot be determined.
        debug(D_NOTICE, "The drive type cannot be determined!");
        break;
      case 1:          // The root directory does not exist.
        debug(D_NOTICE, "The root directory does not exist!");
        break;
      case DRIVE_CDROM:    // The drive is a CD-ROM drive.
        debug(D_NOTICE, "The drive is a CD-ROM drive.");
      case DRIVE_REMOVABLE:  // The drive can be removed from the drive.
      case DRIVE_FIXED:    // The disk cannot be removed from the drive.
      case DRIVE_REMOTE:    // The drive is a remote (network) drive.
        if (GetPhysicalDriveParams(szVolumeAccessPath, drivetype, szPath) != NO_ERROR)
        {
          add_device(dev_decode_type(BusTypeUsb, drivetype),
            0,
            szDevicePath,
            "",
            "",
            "UnknowenDevice");
        }

      case DRIVE_RAMDISK:    // The drive is a RAM disk.
        break;
      }
      break;
    }
    case SHCNE_DRIVEREMOVED:        // media removed event
    {
      SHGetPathFromIDListA((struct _ITEMIDLIST *)shns->dwItem1, szPath);
      remove_device(szPath);
      break;
    }
    }
    break;
  }
  }
  return 0;

}

static void device_change(void *param) {
  pdevice_info * pd = (pdevice_info*)param;
  debug(D_NOTICE, "type [%d] isex [%d] fspath [%s] \n", pd->type, pd->isextended, pd->filesystem_path);
  if (pd->isextended) {
    pdevice_extended_info* pde = (pdevice_extended_info*)param;
    debug(D_NOTICE, "vendor [%s] product [%s] deviceid [%s] \n", pde->vendor, pde->product, pde->device_id);
  }

}

void pinit_device_monitor() {
  HWND hWnd = NULL;
  WNDCLASSEXA wx;

  debug(D_NOTICE, "waiting for new devices..");
  debug_execute(D_NOTICE, padd_device_monitor_callback(arivalmonitor));

  ZeroMemory(&wx, sizeof(wx));

  wx.cbSize = sizeof(WNDCLASSEXA);
  wx.lpfnWndProc = (WNDPROC) (message_handler);
  wx.hInstance = (HINSTANCE) (GetModuleHandleA(0));
  wx.style = CS_HREDRAW | CS_VREDRAW;
  //wx.hInstance = GetModuleHandle(0);
  wx.hbrBackground = (HBRUSH)(COLOR_WINDOW);
  wx.lpszClassName = CLS_NAME;

  if (RegisterClassExA(&wx)) {
    hWnd = CreateWindowA(CLS_NAME, L"DevNotifWnd", WS_ICONIC,
      0, 0, CW_USEDEFAULT, 0, HWND_MESSAGE,
      NULL, GetModuleHandleA(0), NULL);//(void*)&guid);
  }

  if (hWnd == NULL) {
    debug(D_NOTICE, "Could not create message window! %d", GetLastError());
    return 1;
  }

  ULONG m_ulSHChangeNotifyRegister;
  LPITEMIDLIST ppidl;
  if (SHGetSpecialFolderLocation(hWnd, CSIDL_DESKTOP, &ppidl) == NOERROR)
  {
    SHChangeNotifyEntry shCNE;
    shCNE.pidl = ppidl;
    shCNE.fRecursive = TRUE;

    m_ulSHChangeNotifyRegister = SHChangeNotifyRegister(hWnd,
      SHCNE_DISKEVENTS,
      SHCNE_MEDIAINSERTED | SHCNE_MEDIAREMOVED | SHCNE_DRIVEREMOVED | SHCNE_DRIVEADD,
      WM_USER_MEDIACHANGED,
      1,
      &shCNE);

    if (m_ulSHChangeNotifyRegister == 0) {
      debug(D_NOTICE, "Shell Device Notify registration CD failed with error %d", GetLastError());
      return 2;
    }
  }
  else
    debug(D_NOTICE, "Shell Device Notify registration CD failed with error %d ", GetLastError());


  debug(D_NOTICE, "waiting for new devices..");

  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0))
  {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return 0;
}
#endif  //P_OS_WINDOWS
