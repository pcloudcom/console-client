#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64

#include "pfsxattr.h"
#include "plibs.h"
#include "pfsfolder.h"
#include "pfstasks.h"
#include <fuse.h>
#include <errno.h>
#include <string.h>

#if IS_DEBUG
#define psync_fs_set_thread_name() do {psync_thread_name=__FUNCTION__;} while (0)
#else
#define psync_fs_set_thread_name() do {} while (0)
#endif

// Do we have this in Win?
#if !defined(P_OS_WINDOWS)
#include <sys/xattr.h>
#else
// No xattr in win.
// Value get from standard xattr.h
enum
{
  XATTR_CREATE = 1,	/* set value, fail if attr already exists.  */
#define XATTR_CREATE	XATTR_CREATE
  XATTR_REPLACE = 2	/* set value, fail if attr does not exist.  */
#define XATTR_REPLACE	XATTR_REPLACE
};
#endif

#ifndef ENODATA
#define ENODATA 61
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#define OBJECT_MULTIPLIER   8
#define OBJECT_FOLDER       0
#define OBJECT_FILE         1
#define OBJECT_TASK         2
#define OBJECT_STATICFILE   3

#define folderid_to_objid(id) ((id)*OBJECT_MULTIPLIER+OBJECT_FOLDER)
#define fileid_to_objid(id) ((id)*OBJECT_MULTIPLIER+OBJECT_FILE)
#define taskid_to_objid(id) ((id)*OBJECT_MULTIPLIER+OBJECT_TASK)
#define static_taskid_to_objid(id) ((UINT64_MAX-id+1)*OBJECT_MULTIPLIER+OBJECT_STATICFILE)

static void delete_object_id(uint64_t oid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("DELETE FROM fsxattr WHERE objectid=?");
  psync_sql_bind_uint(res, 1, oid);
  psync_sql_run_free(res);
}

void psync_fs_file_deleted(psync_fileid_t fileid){
  delete_object_id(fileid_to_objid(fileid));
}

void psync_fs_folder_deleted(psync_folderid_t folderid){
  delete_object_id(folderid_to_objid(folderid));
}

void psync_fs_task_deleted(uint64_t taskid){
  delete_object_id(taskid_to_objid(taskid));
}

static void update_object_id(uint64_t ooid, uint64_t noid){
  psync_sql_res *res;
  res=psync_sql_prep_statement("UPDATE OR REPLACE fsxattr SET objectid=? WHERE objectid=?");
  psync_sql_bind_uint(res, 1, noid);
  psync_sql_bind_uint(res, 2, ooid);
  psync_sql_run_free(res);
}

void psync_fs_task_to_file(uint64_t taskid, psync_fileid_t fileid){
  update_object_id(taskid_to_objid(taskid), fileid_to_objid(fileid));
}

void psync_fs_task_to_folder(uint64_t taskid, psync_folderid_t folderid){
  update_object_id(taskid_to_objid(taskid), folderid_to_objid(folderid));
}

void psync_fs_static_to_task(uint64_t statictaskid, uint64_t taskid){
  update_object_id(static_taskid_to_objid(statictaskid), taskid_to_objid(taskid));
}

void psync_fs_file_to_task(psync_fileid_t fileid, uint64_t taskid){
  update_object_id(fileid_to_objid(fileid), taskid_to_objid(taskid));
}

static int64_t xattr_get_object_id_locked(const char *path){
  psync_fspath_t *fspath;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_fstask_creat_t *cr;
  psync_sql_res *res;
  psync_uint_row row;
  int64_t ret;
  int checkfile, checkfolder;
  if (path[1]==0 && path[0]=='/')
    return 0;
  fspath=psync_fsfolder_resolve_path(path);
  if (!fspath){
    debug(D_NOTICE, "path component of %s not found", path);
    return -1;
  }
  checkfile=1;
  checkfolder=1;
  folder=psync_fstask_get_folder_tasks_rdlocked(fspath->folderid);
  if (folder){
    mk=psync_fstask_find_mkdir(folder, fspath->name, 0);
    if (mk){
      psync_free(fspath);
      assertw(mk->folderid!=0);
      if (mk->folderid>0)
        return folderid_to_objid(mk->folderid);
      else
        return taskid_to_objid(-mk->folderid);
    }
    cr=psync_fstask_find_creat(folder, fspath->name, 0);
    if (cr){
      psync_free(fspath);
      if (cr->fileid>0)
        return fileid_to_objid(cr->fileid);
      else if (cr->fileid==0)
        return static_taskid_to_objid(cr->taskid);
      else{
        res=psync_sql_query_nolock("SELECT type, fileid FROM fstask WHERE id=?");
        psync_sql_bind_uint(res, 1, -cr->fileid);
        if ((row=psync_sql_fetch_rowint(res))){
          if (row[0]==PSYNC_FS_TASK_CREAT)
            ret=taskid_to_objid(-cr->fileid);
          else{
            assertw(row[0]==PSYNC_FS_TASK_MODIFY);
            ret=fileid_to_objid(row[1]);
          }
        }
        else{
          debug(D_WARNING, "found temporary file for path %s but could not find task %lu", path, (unsigned long)(-cr->fileid));
          ret=-1;
        }
        psync_sql_free_result(res);
        return ret;
      }
    }
    checkfolder=!psync_fstask_find_rmdir(folder, fspath->name, 0);
    checkfile=!psync_fstask_find_unlink(folder, fspath->name, 0);
  }
  if (fspath->folderid<0){
    psync_free(fspath);
    debug(D_NOTICE, "path %s not found in temporary folder", path);
    return -1;
  }
  if (checkfolder){
    res=psync_sql_query_nolock("SELECT id FROM folder WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fspath->folderid);
    psync_sql_bind_string(res, 2, fspath->name);
    if ((row=psync_sql_fetch_rowint(res)))
      ret=folderid_to_objid(row[0]);
    else
      ret=-1;
    psync_sql_free_result(res);
    if (ret!=-1){
      psync_free(fspath);
      return ret;
    }
  }
  if (checkfile){
    res=psync_sql_query_nolock("SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psync_sql_bind_uint(res, 1, fspath->folderid);
    psync_sql_bind_string(res, 2, fspath->name);
    if ((row=psync_sql_fetch_rowint(res)))
      ret=fileid_to_objid(row[0]);
    else
      ret=-1;
    psync_sql_free_result(res);
    if (ret!=-1){
      psync_free(fspath);
      return ret;
    }
  }
  psync_free(fspath);
  debug(D_NOTICE, "path %s not found", path);
  return -1;
}

#define LOCK_AND_LOOKUP() do {\
  psync_sql_lock();\
  oid=xattr_get_object_id_locked(path);\
  if (unlikely(oid==-1)){\
    psync_sql_unlock();\
    return -PRINT_RETURN_CONST(ENOENT);\
  }\
} while (0)

#define LOCK_AND_LOOKUPRD() do {\
  psync_sql_rdlock();\
  oid=xattr_get_object_id_locked(path);\
  if (unlikely(oid==-1)){\
    psync_sql_rdunlock();\
    return -PRINT_RETURN_CONST(ENOENT);\
  }\
} while (0)

int psync_fs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags PFS_XATTR_IGN){
  psync_sql_res *res;
  int64_t oid;
  int ret;
  psync_fs_set_thread_name();
  debug(D_NOTICE, "setting attribute %s of %s", name, path);
  LOCK_AND_LOOKUP();
  if (flags&XATTR_CREATE){
    res=psync_sql_prep_statement("INSERT OR IGNORE INTO fsxattr (objectid, name, value) VALUES (?, ?, ?)");
    psync_sql_bind_uint(res, 1, oid);
    psync_sql_bind_string(res, 2, name);
    psync_sql_bind_blob(res, 3, value, size);
    psync_sql_run_free(res);
    if (psync_sql_affected_rows())
      ret=0;
    else
      ret=-PRINT_RETURN_CONST(EEXIST);
  }
  else if (flags&XATTR_REPLACE){
    res=psync_sql_prep_statement("UPDATE fsxattr SET value=? WHERE objectid=? AND name=?");
    psync_sql_bind_blob(res, 1, value, size);
    psync_sql_bind_uint(res, 2, oid);
    psync_sql_bind_string(res, 3, name);
    psync_sql_run_free(res);
    if (psync_sql_affected_rows())
      ret=0;
    else
      ret=-PRINT_RETURN_CONST(ENOATTR);
  }
  else{
    res=psync_sql_prep_statement("REPLACE INTO fsxattr (objectid, name, value) VALUES (?, ?, ?)");
    psync_sql_bind_uint(res, 1, oid);
    psync_sql_bind_string(res, 2, name);
    psync_sql_bind_blob(res, 3, value, size);
    psync_sql_run_free(res);
    ret=0;
  }
  psync_sql_unlock();
  return ret;
}

int psync_fs_getxattr(const char *path, const char *name, char *value, size_t size PFS_XATTR_IGN){
  psync_sql_res *res;
  int64_t oid;
  int ret;
  psync_fs_set_thread_name();
  LOCK_AND_LOOKUPRD();
  if (size && value){
    psync_variant_row row;
    const char *str;
    size_t len;
    res=psync_sql_query_nolock("SELECT value FROM fsxattr WHERE objectid=? AND name=?");
    psync_sql_bind_uint(res, 1, oid);
    psync_sql_bind_string(res, 2, name);
    if ((row=psync_sql_fetch_row(res))){
      str=psync_get_lstring(row[0], &len);
      if (size>=len){
        debug(D_NOTICE, "returning attribute %s of %s", name, path);
        memcpy(value, str, len);
        ret=len;
      }
      else{
        debug(D_NOTICE, "buffer too small for attribute %s of %s", name, path);
        ret=-ERANGE;
      }
    }
    else{
      ret=-ENOATTR;
//      debug(D_NOTICE, "attribute %s not found for %s", name, path);
    }
    psync_sql_free_result(res);
  }
  else{
    psync_uint_row row;
    res=psync_sql_query_nolock("SELECT LENGTH(value) FROM fsxattr WHERE objectid=? AND name=?");
    psync_sql_bind_uint(res, 1, oid);
    psync_sql_bind_string(res, 2, name);
    if ((row=psync_sql_fetch_rowint(res))){
      ret=row[0];
      debug(D_NOTICE, "returning length of attribute %s of %s = %d", name, path, ret);
    }
    else{
      ret=-ENOATTR;
//      debug(D_NOTICE, "attribute %s not found for %s", name, path);
    }
    psync_sql_free_result(res);
  }
  psync_sql_rdunlock();
  return ret;
}

int psync_fs_listxattr(const char *path, char *list, size_t size){
  psync_sql_res *res;
  int64_t oid;
  const char *str;
  size_t len;
  int ret;
  psync_fs_set_thread_name();
  LOCK_AND_LOOKUPRD();
  if (size && list){
    psync_variant_row row;
    ret=0;
    res=psync_sql_query_nolock("SELECT name FROM fsxattr WHERE objectid=?");
    psync_sql_bind_uint(res, 1, oid);
    while ((row=psync_sql_fetch_row(res))){
      str=psync_get_lstring(row[0], &len);
      len++;
      if (ret+len>size){
        ret=-ERANGE;
        break;
      }
      memcpy(list+ret, str, len);
      ret+=len;
    }
    psync_sql_free_result(res);
    debug(D_NOTICE, "returning list of attributes of %s = %d", path, ret);
  }
  else{
    psync_uint_row row;
    res=psync_sql_query_nolock("SELECT SUM(LENGTH(name)+1) FROM fsxattr WHERE objectid=?");
    psync_sql_bind_uint(res, 1, oid);
    if ((row=psync_sql_fetch_rowint(res)))
      ret=row[0];
    else
      ret=0;
    psync_sql_free_result(res);
    debug(D_NOTICE, "returning length of attributes of %s = %d", path, ret);
  }
  psync_sql_rdunlock();
  return ret;
}

int psync_fs_removexattr(const char *path, const char *name){
  psync_sql_res *res;
  int64_t oid;
  uint32_t aff;
  psync_fs_set_thread_name();
  LOCK_AND_LOOKUP();
  res=psync_sql_prep_statement("DELETE FROM fsxattr WHERE objectid=? AND name=?");
  psync_sql_bind_uint(res, 1, oid);
  psync_sql_bind_string(res, 2, name);
  psync_sql_run_free(res);
  aff=psync_sql_affected_rows();
  psync_sql_unlock();
  if (aff){
    debug(D_NOTICE, "attribute %s deleted for %s", name, path);
    return 0;
  }
  else{
    debug(D_NOTICE, "attribute %s not found for %s", name, path);
    return -ENOATTR;
  }
}
