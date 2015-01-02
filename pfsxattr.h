#ifndef _PSYNC_FSXATTR_H
#define _PSYNC_FSXATTR_H

#include "pcompat.h"
#include "psynclib.h"

#if defined(P_OS_MACOSX)
#define PFS_XATTR_IGN , uint32_t ign
#else
#define PFS_XATTR_IGN
#endif

int psync_fs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags PFS_XATTR_IGN);
int psync_fs_getxattr(const char *path, const char *name, char *value, size_t size PFS_XATTR_IGN);
int psync_fs_listxattr(const char *path, char *list, size_t size);
int psync_fs_removexattr(const char *path, const char *name);

void psync_fs_file_deleted(psync_fileid_t fileid);
void psync_fs_folder_deleted(psync_folderid_t folderid);
void psync_fs_task_deleted(uint64_t taskid);

void psync_fs_task_to_file(uint64_t taskid, psync_fileid_t fileid);
void psync_fs_task_to_folder(uint64_t taskid, psync_folderid_t folderid);
void psync_fs_static_to_task(uint64_t statictaskid, uint64_t taskid);
void psync_fs_file_to_task(psync_fileid_t fileid, uint64_t taskid);

#endif