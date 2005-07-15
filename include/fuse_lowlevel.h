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

#include "fuse_common.h"

#include <utime.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The node ID of the root inode */
#define FUSE_ROOT_ID 1

typedef unsigned long fuse_ino_t;
typedef struct fuse_req *fuse_req_t;
struct fuse_ll;

struct fuse_entry_param {
    fuse_ino_t ino;
    unsigned long generation;
    struct stat attr;
    double attr_timeout;
    double entry_timeout;
};

struct fuse_ctx {
        /** User ID of the calling process */
    uid_t uid;

    /** Group ID of the calling process */
    gid_t gid;

    /** Thread ID of the calling process */
    pid_t pid;
};

/* 'to_set' flags in setattr */
#define FUSE_SET_ATTR_MODE	(1 << 0)
#define FUSE_SET_ATTR_UID	(1 << 1)
#define FUSE_SET_ATTR_GID	(1 << 2)
#define FUSE_SET_ATTR_SIZE	(1 << 3)
#define FUSE_SET_ATTR_ATIME	(1 << 4)
#define FUSE_SET_ATTR_MTIME	(1 << 5)
#define FUSE_SET_ATTR_CTIME	(1 << 6)

/* ------------------------------------------ */

struct fuse_ll_operations {
    void* (*init)   (void *);
    void (*destroy) (void *);

    void (*lookup)  (fuse_req_t req, fuse_ino_t parent, const char *name);
    void (*forget)  (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup);
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
    void (*open)    (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*read)    (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *fi);
    void (*write)   (fuse_req_t req, fuse_ino_t ino, const char *buf,
                     size_t size, off_t off, struct fuse_file_info *fi);
    void (*flush)   (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*release) (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*fsync)   (fuse_req_t req, fuse_ino_t ino, int datasync,
                     struct fuse_file_info *fi);
    void (*opendir) (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*readdir)  (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                      struct fuse_file_info *fi);
    void (*releasedir) (fuse_req_t req, fuse_ino_t ino,
                        struct fuse_file_info *fi);
    void (*fsyncdir) (fuse_req_t req, fuse_ino_t ino, int datasync,
                      struct fuse_file_info *fi);
    void (*statfs)  (fuse_req_t req);
    void (*setxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     const char *value, size_t size, int flags);
    void (*getxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     size_t size);
    void (*listxattr)(fuse_req_t req, fuse_ino_t ino, size_t size);
    void (*removexattr)(fuse_req_t req, fuse_ino_t ino, const char *name);
};

/* ------------------------------------------ */

/* all except forget */
int fuse_reply_err(fuse_req_t req, int err);

/* forget */
int fuse_reply_none(fuse_req_t req);

/* lookup, mknod, mkdir, symlink, link */
int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e);

/* getattr, setattr */
int fuse_reply_attr(fuse_req_t req, const struct stat *attr,
                    double attr_timeout);

/* readlink */
int fuse_reply_readlink(fuse_req_t req, const char *link);

/* open, opendir */
int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *fi);

/* write */
int fuse_reply_write(fuse_req_t req, size_t count);

/* read, readdir, getxattr, listxattr */
int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size);

/* statfs */
int fuse_reply_statfs(fuse_req_t req, const struct statfs *statfs);

/* getxattr, listxattr */
int fuse_reply_xattr(fuse_req_t req, size_t count);

/* ------------------------------------------ */

/* return the size of a directory entry */
size_t fuse_dirent_size(size_t namelen);

/* add a directory entry to the buffer */
char *fuse_add_dirent(char *buf, const char *name, const struct stat *stat,
                      off_t off);

/* ------------------------------------------ */

void *fuse_req_userdata(fuse_req_t req);

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req);

/* ------------------------------------------ */

typedef void (*fuse_ll_processor_t)(struct fuse_ll *, struct fuse_cmd *, void *);

struct fuse_ll *fuse_ll_new(int fd, const char *opts,
                            const struct fuse_ll_operations *op,
                            size_t op_size, void *userdata);

void fuse_ll_destroy(struct fuse_ll *f);

int fuse_ll_is_lib_option(const char *opt);

int fuse_ll_loop(struct fuse_ll *f);

void fuse_ll_exit(struct fuse_ll *f);

int fuse_ll_exited(struct fuse_ll* f);

struct fuse_cmd *fuse_ll_read_cmd(struct fuse_ll *f);

void fuse_ll_process_cmd(struct fuse_ll *f, struct fuse_cmd *cmd);

int fuse_ll_loop_mt(struct fuse_ll *f);

int fuse_ll_loop_mt_proc(struct fuse_ll *f, fuse_ll_processor_t proc, void *data);

/* ------------------------------------------ */

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_LOWLEVEL_H_ */
