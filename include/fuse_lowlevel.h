/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#ifndef _FUSE_LOWLEVEL_H_
#define _FUSE_LOWLEVEL_H_

/* ----------------------------------------------------------- *
 * Low level API                                               *
 * ----------------------------------------------------------- */

#include <fuse_common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long fuse_ino_t;
typedef struct fuse_req *fuse_req_t;

struct fuse_entry_param {
    fuse_ino_t ino;
    unsigned long generation;
    const struct stat *attr;
    double attr_timeout;
    double entry_timeout;
    unsigned int direct_io : 1;
};

/* 'to_set' flags in setattr */
#define FUSE_SET_ATTR_MODE	(1 << 0)
#define FUSE_SET_ATTR_UID	(1 << 1)
#define FUSE_SET_ATTR_GID	(1 << 2)
#define FUSE_SET_ATTR_SIZE	(1 << 3)
#define FUSE_SET_ATTR_ATIME	(1 << 4)
#define FUSE_SET_ATTR_MTIME	(1 << 5)
#define FUSE_SET_ATTR_CTIME	(1 << 6)

struct fuse_lowlevel_operations {
    void (*lookup)  (fuse_req_t req, fuse_ino_t parent, const char *name);
    void (*forget)  (fuse_req_t req, fuse_ino_t ino);
    void (*getattr) (fuse_req_t req, fuse_ino_t ino);
    void (*setattr) (fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                     int to_set);
    void (*readlink)(fuse_req_t req, fuse_ino_t ino);
    void (*mknod)   (fuse_req_t req, fuse_ino_t parent, const char *name,
                     mode_t mode, dev_t rdev);
    void (*mkdir)   (fuse_req_t req, fuse_ino_t parent, const char *name,
                     mode_t mode);
    void (*unlink)  (fuse_req_t req, fuse_ino_t parent, const char *name);
    void (*rmdir)   (fuse_req_t req, fuse_ino_t parent, const char *name);
    void (*symlink) (fuse_req_t req, const char *link, fuse_ino_t parent,
                     const char *name);
    void (*rename)  (fuse_req_t req, fuse_ino_t parent, const char *name,
                     fuse_ino_t newparent, const char *newname);
    void (*link)    (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
                     const char *newname);
    void (*open)    (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *f);
    void (*read)    (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *f);
    void (*write)   (fuse_req_t req, fuse_ino_t ino, const char *buf,
                     size_t size, off_t off, struct fuse_file_info *f);
    void (*flush)   (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *f);
    void (*release) (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *f);
    void (*fsync)   (fuse_req_t req, fuse_ino_t ino, int datasync,
                     struct fuse_file_info *f);
    void (*opendir) (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *f);
    void (*readdir)  (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *f);
    void (*releasedir) (fuse_req_t req, fuse_ino_t ino,
                        struct fuse_file_info *f);
    void (*fsyncdir) (fuse_req_t req, fuse_ino_t ino, int datasync,
                      struct fuse_file_info *f);
    void (*statfs)  (fuse_req_t req, fuse_ino_t ino);
    void (*setxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     const char *value, size_t size, int flags);
    void (*getxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     size_t size);
    void (*listxattr)(fuse_req_t req, fuse_ino_t ino, size_t size);
    void (*removexattr)(fuse_req_t req, fuse_ino_t ino, const char *name);
};

/* all except release and forget */
int fuse_reply_err(fuse_req_t req, int err);

/* forget, unlink, rmdir, rename, setxattr, removexattr, release, releasedir */
int fuse_reply_ok(fuse_req_t req);

/* lookup, mknod, mkdir, symlink, link */
int fuse_reply_entry(fuse_req_t req, struct fuse_entry_param *e);

/* getattr, setattr */
int fuse_reply_attr(fuse_req_t req, int struct stat *attr, double attr_timeout);
/* readlink */
int fuse_reply_readlink(fuse_req_t req, const char *link);

/* open, flush, fsync, opendir, fsyncdir */
int fuse_reply_file_info(fuse_req_t req, const struct fuse_file_info *f);

/* write */
int fuse_reply_write(fuse_req_t req, size_t count,
                         const struct fuse_file_info *f);

/* read, readdir */
int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size,
                    const struct fuse_file_info *f);

/* statfs */
int fuse_reply_statfs(fuse_req_t req, const struct statfs *statfs);

/* getxattr, listxattr */
int fuse_reply_xattr(fuse_req_t req, const char *buf, size_t size);

/* return the size of a directory entry */
size_t fuse_dirent_size(size_t namelen);

/* add a directory entry to the buffer */
void fuse_add_dirent(char *buf, const char *name, const struct stat *stat,
                     off_t off);

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_LOWLEVEL_H_ */
