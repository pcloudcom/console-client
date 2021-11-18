#include "plibs.h"
#include "psynclib.h"
//#include "pdevice_monitor.h"
#include "papi.h"
#include "pnetlibs.h"
#include "pbusinessaccount.h"
#include "pdevicemap.h"

#define P_DEVICE_VERBOSE

#include "pdevice_monitor.h"
// #include "pdevicemap.h"
#include "plocalscan.h"
#include "ptimer.h"

#ifdef P_OS_POSIX
#define _strdup strdup
#endif //P_OS_POSIX
#define DEV_MONITOR_ACTIVITY_TIMER_INT 20

static pthread_mutex_t devmon_mutex=PTHREAD_MUTEX_INITIALIZER;
static psync_timer_t devmon_activity_timer=NULL;

void devmon_activity_timer_action(){
  psync_timer_stop(devmon_activity_timer);
  pthread_mutex_lock(&devmon_mutex);
  devmon_activity_timer=NULL;
  pthread_mutex_unlock(&devmon_mutex);
  psync_restat_sync_folders();
}

void devmon_activity_timer_start(){
  pthread_mutex_lock(&devmon_mutex);
  if (!devmon_activity_timer)
    devmon_activity_timer = psync_timer_register(devmon_activity_timer_action, DEV_MONITOR_ACTIVITY_TIMER_INT, NULL);
  pthread_mutex_unlock(&devmon_mutex);
}

//device_event_callback *device_callbacks;
//int device_clbsize = 10;
//int device_clbnum = 0;


//void psync_add_device_monitor_callback(device_event_callback callback) {
//  if (callback) {
//    if (device_clbnum == 0)
//      device_callbacks = (device_event_callback *)psync_malloc(sizeof(device_event_callback)*device_clbsize);
//    else {
//      while (device_clbnum > device_clbsize) {
//        device_event_callback *callbacks_old = device_callbacks;
//        device_callbacks = (device_event_callback *)psync_malloc(sizeof(device_event_callback)*device_clbsize*2);
//        memccpy(device_callbacks, callbacks_old, 0,sizeof(device_event_callback)*device_clbsize);
//        device_clbsize = device_clbsize * 2;
//        psync_free(callbacks_old);
//      }
//    }
//    device_callbacks[device_clbnum] = callback;
//    device_clbnum
//    ++;
//  }
//}


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


//void psync_devmon_notify_device_callbacks(pdevice_extended_info * param, device_event event) {
//  if (event == Dev_Event_arrival)
//    psync_run_thread1("Device notifications", do_notify_device_callbacks_in, (void*)param);
//  else
//    psync_run_thread1("Device notifications", do_notify_device_callbacks_out, (void*)param);
//}

//static void psync_devmon_arivalmonitor(device_event event, void * device_info)
//{
//  pdevice_extended_info *pDevExtInfo = (pdevice_extended_info*)device_info;
//  if (event == Dev_Event_arrival){
//	debug(D_NOTICE, "Device arrived.");
//	psync_do_restat_sync_folders();	  
//  }
//  else{
//	debug(D_NOTICE, "Device removed.");
//	psync_do_restat_sync_folders();
//  }
//  if (pDevExtInfo)
//	print_device_info(pDevExtInfo);
//}

#ifdef P_OS_MACOSX
#include <stdio.h>
#include <stdlib.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>

typedef struct MyPrivateData {
    io_object_t notification;
    const char* systempath;
} MyPrivateData;

static IONotificationPortRef    gNotifyPort;
static io_iterator_t            gAddedIter;
static CFRunLoopRef             gRunLoop;

void DeviceNotification(void *refCon, io_service_t service, natural_t messageType, void *messageArgument)
{
  kern_return_t   kr;
  MyPrivateData   *privateDataRef = (MyPrivateData *) refCon;

  if (messageType == kIOMessageServiceIsTerminated) {
//    remove_device(privateDataRef->systempath);
//    debug(D_NOTICE, "Device removed. Mountpoint: %s\n", privateDataRef->systempath);
    free(privateDataRef->systempath);
    kr = IOObjectRelease(privateDataRef->notification);
    free(privateDataRef);
    devmon_activity_timer_start();
  }
}

void DeviceAdded(void *refCon, io_iterator_t iterator)
{
  kern_return_t kr;
  io_service_t usbDevice;
  CFStringRef     deviceNameAsCFString;
  static int first_call=1;

  while ((usbDevice = IOIteratorNext(iterator))) {
    io_name_t deviceName;
    MyPrivateData *privateDataRef = NULL;
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
//    if (!usbSerial) continue;
    // Ought to work now, regardless of version of OSX being ran.
    CFStringRef usbVendor = (CFStringRef) IORegistryEntrySearchCFProperty(
      usbDevice,
      kIOServicePlane,
      CFSTR("USB Vendor Name"),
      kCFAllocatorDefault,
      kIORegistryIterateRecursively
      );
//    if (!usbVendor) continue;
    // Get the USB device's name.
    kr = IORegistryEntryGetName(usbDevice, deviceName);
    if (KERN_SUCCESS != kr) {
      deviceName[0] = '\0';
    }
    deviceNameAsCFString = CFStringCreateWithCString(kCFAllocatorDefault, deviceName,
                                                    kCFStringEncodingASCII);
//    if (!deviceNameAsCFString) continue;
    if (!first_call){
      debug(D_NOTICE, "start deviceactivity timer");
      devmon_activity_timer_start();
    }
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
      debug(D_NOTICE, "IOServiceAddInterestNotification returned 0x%08x.\n", kr);
    }
    // Done with this USB device; release the reference added by IOIteratorNext
    kr = IOObjectRelease(usbDevice);
  }
  first_call=0;
}

void device_monitor_thread() {
    CFMutableDictionaryRef  matchingDict;
    CFRunLoopSourceRef      runLoopSource;
//    CFNumberRef             numberRef;
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

void psync_devmon_init(){
  psync_run_thread("Device monitor main thread", device_monitor_thread);
}
#endif //P_OS_MACOSX

#ifdef P_OS_LINUX
#include <libudev.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>


void enumerate_devices (struct udev *udev,device_event event) {
  devmon_activity_timer_start();
}

void monitor_usb_dev(){
  struct udev *udev;
  struct udev_device *dev;
  struct udev_monitor *mon;
  int fd;

  udev = udev_new();
  if (!udev) {
    debug(D_WARNING, "Can't create udev\n");
    return;
  }
  mon = udev_monitor_new_from_netlink(udev, "udev");
  udev_monitor_filter_add_match_subsystem_devtype(mon, "usb", NULL);
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
    if (ret > 0 && FD_ISSET(fd, &fds)){

      /* Make the call to receive the device.
         select() ensured that this will not block. */
      dev = udev_monitor_receive_device(mon);
      if (dev) {
        enumerate_devices(udev, Dev_Event_arrival);
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

void device_monitor_thread(){
  debug(D_NOTICE, "Waiting for USB devices connect/disconnect events");
  monitor_usb_dev();
}

void psync_devmon_init(){
  psync_run_thread("libusb handle events completed thread", device_monitor_thread);
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

static GUID WusbGUID = { 0x88BAE032, 0x5A81, 0x49f0, 0xBC,0x3D,0xA4,0xFF,0x13,0x82,0x16,0xD6 };
static HDEVNOTIFY hDeviceNotify;
static HWND hWnd = NULL;

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

BOOL DoRegisterDeviceInterfaceToHwnd( 
    IN GUID InterfaceClassGuid, 
    IN HWND hWnd,
    OUT HDEVNOTIFY *hDeviceNotify 
)
{
    DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
    ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
    NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
    NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE; //DBT_DEVTYP_DEVICEINTERFACE, DBT_DEVTYP_DEVNODE, DBT_DEVTYP_OEM, DBT_DEVTYP_VOLUME;
    NotificationFilter.dbcc_classguid = InterfaceClassGuid;
    *hDeviceNotify = RegisterDeviceNotification(
        hWnd,                       // events recipient
        &NotificationFilter,        // type of device
        DEVICE_NOTIFY_WINDOW_HANDLE|DEVICE_NOTIFY_ALL_INTERFACE_CLASSES // type of recipient handle
        );
    if (NULL == *hDeviceNotify){
        debug(D_NOTICE, "RegisterDeviceNotification failed");
        return FALSE;
    }
    return TRUE;
}


static DWORD GetPhysicalDriveParams(char *strdrivepath IN, DWORD drivetype, char *fspath)
{
  DWORD dwRet = NO_ERROR;
  STORAGE_PROPERTY_QUERY storagePropertyQuery;

  HANDLE hDevice = CreateFileA(strdrivepath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  
  if (INVALID_HANDLE_VALUE == hDevice) {
      return GetLastError();
  }

  ZeroMemory(&storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY));
  storagePropertyQuery.PropertyId = StorageDeviceProperty;
  storagePropertyQuery.QueryType = PropertyStandardQuery;
  STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader = { 0 };
  DWORD dwBytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
    &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
    &storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER),
    &dwBytesReturned, NULL)){
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
    devmon_activity_timer_start();
    //switch (wparam)
    //{
    //case DBT_DEVICEARRIVAL:
    //  debug(D_NOTICE, "Message %d: DBT_DEVICEARRIVAL\n");
    //  break;
    //case DBT_DEVICEREMOVECOMPLETE:
    //  debug(D_NOTICE, "Message %d: DBT_DEVICEREMOVECOMPLETE\n");
    //  break;
    //case DBT_DEVNODES_CHANGED:
    //  debug(D_NOTICE, "Message %d: DBT_DEVNODES_CHANGED\n");
    //  break;
    //default:
    //  debug(D_NOTICE, "Message %d: WM_DEVICECHANGE message received, value %d unhandled.\n");
    //break;
    //}
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
      devmon_activity_timer_start();
      break;
    }
    case SHCNE_MEDIAREMOVED:        // media removed event
    {
      SHGetPathFromIDListA((struct _ITEMIDLIST *)shns->dwItem1, szPath);
      devmon_activity_timer_start();
      break;
    }
    case SHCNE_DRIVEADD:        // media added event
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
        devmon_activity_timer_start();
		break;
      case DRIVE_RAMDISK:    // The drive is a RAM disk.
        break;
      }
      break;
    }
    case SHCNE_DRIVEREMOVED:        // media removed event
    {
	  DWORD  drivetype;
      SHGetPathFromIDListA((struct _ITEMIDLIST *)shns->dwItem1, szPath);
	  drivetype = GetDriveTypeA(szPath);
      devmon_activity_timer_start();
      break;
    }
    }
    break;
  }
  }
  return 0;

}

void device_monitor_thread() {
  WNDCLASSEXA wx;
//  debug_execute(D_NOTICE, psync_add_device_monitor_callback(psync_devmon_arivalmonitor));
  HINSTANCE hExe = GetModuleHandleA(0);
  ZeroMemory(&wx, sizeof(wx));
  wx.cbSize = sizeof(WNDCLASSEXA);
  wx.lpfnWndProc = (WNDPROC) (message_handler);
  wx.hInstance = (HINSTANCE) (hExe);
  wx.style = CS_HREDRAW|CS_VREDRAW;
  wx.hbrBackground = (HBRUSH)(COLOR_WINDOW);
  wx.lpszClassName = CLS_NAME;
  if (RegisterClassExA(&wx)){
    hWnd=CreateWindowA(CLS_NAME, L"DevNotifWnd", WS_ICONIC, 0, 0,
                       CW_USEDEFAULT, 0, HWND_MESSAGE, NULL, hExe, NULL);
  }
  if (hWnd==NULL){
    debug(D_ERROR, "Could not create message window. Error: %d", GetLastError());
    return;
  }
  if (!DoRegisterDeviceInterfaceToHwnd(WusbGUID, hWnd, &hDeviceNotify)){
    debug(D_ERROR, "DoRegisterDeviceInterfaceToHwnd failed. Error: %d", GetLastError());
    return;
  }
  //ULONG m_ulSHChangeNotifyRegister;
  //LPITEMIDLIST ppidl;
  //if (SHGetSpecialFolderLocation(hWnd, CSIDL_DESKTOP, &ppidl) == NOERROR)
  //{
  //  SHChangeNotifyEntry shCNE;
  //  shCNE.pidl = ppidl;
  //  shCNE.fRecursive = TRUE;
  //  m_ulSHChangeNotifyRegister = SHChangeNotifyRegister(hWnd,
  //    SHCNE_DISKEVENTS,
  //    SHCNE_MEDIAINSERTED | SHCNE_MEDIAREMOVED | SHCNE_DRIVEREMOVED | SHCNE_DRIVEADD,
  //    WM_USER_MEDIACHANGED,
  //    1,
  //    &shCNE);
  //  if (m_ulSHChangeNotifyRegister == 0) {
  //    debug(D_NOTICE, "Shell Device Notify registration CD failed with error %d", GetLastError());
  //    return 2;
  //  }
  //}
  //else
  //  debug(D_NOTICE, "Shell Device Notify registration CD failed with error %d ", GetLastError());
  debug(D_NOTICE, "Device monitor - waiting for device arrival/removal");
  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0)){
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
}
void psync_devmon_init(){
  psync_run_thread("Device monitor main thread", device_monitor_thread);
}
#endif  //P_OS_WINDOWS
