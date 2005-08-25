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
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The node ID of the root inode */
#define FUSE_ROOT_ID 1

typedef unsigned long fuse_ino_t;
typedef struct fuse_req *fuse_req_t;

struct fuse_session;
struct fuse_chan;

struct fuse_entry_param {
    fuse_ino_t ino;
    unsigned long generation;
    struct stat attr;
    double attr_timeout;
    double entry_timeout;
};

struct fuse_lock_param {
    int type;
    off_t start;
    off_t end;
    unsigned long long owner;
    pid_t pid;
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

struct fuse_lowlevel_ops {
    void (*init)  (void *);
    void (*destroy)(void *);

    void (*lookup) (fuse_req_t req, fuse_ino_t parent, const char *name);
    void (*forget) (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup);
    void (*getattr)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*setattr)(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                    int to_set, struct fuse_file_info *fi);
    void (*access) (fuse_req_t req, fuse_ino_t ino, int mask);
    void (*readlink)(fuse_req_t req, fuse_ino_t ino);
    void (*mknod)  (fuse_req_t req, fuse_ino_t parent, const char *name,
                    mode_t mode, dev_t rdev);
    void (*mkdir)  (fuse_req_t req, fuse_ino_t parent, const char *name,
                    mode_t mode);
    void (*unlink) (fuse_req_t req, fuse_ino_t parent, const char *name);
    void (*rmdir)  (fuse_req_t req, fuse_ino_t parent, const char *name);
    void (*symlink)(fuse_req_t req, const char *link, fuse_ino_t parent,
                    const char *name);
    void (*rename) (fuse_req_t req, fuse_ino_t parent, const char *name,
                    fuse_ino_t newparent, const char *newname);
    void (*link)   (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
                    const char *newname);
    void (*create) (fuse_req_t req, fuse_ino_t parent, const char *name,
                    mode_t mode, struct fuse_file_info *fi);
    void (*open)   (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*read)   (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                    struct fuse_file_info *fi);
    void (*write)  (fuse_req_t req, fuse_ino_t ino, const char *buf,
                    size_t size, off_t off, struct fuse_file_info *fi);
    void (*flush)  (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*release)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*fsync)  (fuse_req_t req, fuse_ino_t ino, int datasync,
                    struct fuse_file_info *fi);
    void (*opendir)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    void (*readdir)(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                    struct fuse_file_info *fi);
    void (*releasedir)(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi);
    void (*fsyncdir)(fuse_req_t req, fuse_ino_t ino, int datasync,
                     struct fuse_file_info *fi);
    void (*statfs) (fuse_req_t req);
    void (*setxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     const char *value, size_t size, int flags);
    void (*getxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     size_t size);
    void (*listxattr)(fuse_req_t req, fuse_ino_t ino, size_t size);
    void (*removexattr)(fuse_req_t req, fuse_ino_t ino, const char *name);
    void (*getlk)  (fuse_req_t req, fuse_ino_t ino,
                    const struct fuse_lock_param *lk);
    void (*setlk)  (fuse_req_t req, fuse_ino_t ino, int sleep,
                    const struct fuse_lock_param *lk);
};

/* ------------------------------------------ */

/* all except forget */
int fuse_reply_err(fuse_req_t req, int err);

/* forget */
int fuse_reply_none(fuse_req_t req);

/* lookup, create, mknod, mkdir, symlink, link */
int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e);

/* create */
int fuse_reply_create(fuse_req_t req, const struct fuse_entry_param *e,
                      const struct fuse_file_info *fi);

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
int fuse_reply_statfs(fuse_req_t req, const struct statfs *stbuf);

/* getxattr, listxattr */
int fuse_reply_xattr(fuse_req_t req, size_t count);

/* getlk */
int fuse_reply_getlk(fuse_req_t req, const struct fuse_lock_param *lk);

/* ------------------------------------------ */

/* return the size of a directory entry */
size_t fuse_dirent_size(size_t namelen);

/* add a directory entry to the buffer */
char *fuse_add_dirent(char *buf, const char *name, const struct stat *stbuf,
                      off_t off);

/* ------------------------------------------ */

void *fuse_req_userdata(fuse_req_t req);

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req);

/* ------------------------------------------ */

int fuse_lowlevel_is_lib_option(const char *opt);

struct fuse_session *fuse_lowlevel_new(const char *opts,
                                       const struct fuse_lowlevel_ops *op,
                                       size_t op_size, void *userdata);

struct fuse_chan *fuse_kern_chan_new(int fd);

/* ------------------------------------------ */

struct fuse_session_ops {
    void (*process) (void *data, const char *buf, size_t len,
                     struct fuse_chan *ch);

    void (*exit) (void *data, int val);

    int (*exited) (void *data);
    
    void (*destroy) (void *data);
};

struct fuse_session *fuse_session_new(struct fuse_session_ops *op, void *data);

void fuse_session_add_chan(struct fuse_session *se, struct fuse_chan *ch);

struct fuse_chan *fuse_session_next_chan(struct fuse_session *se,
                                         struct fuse_chan *ch);

void fuse_session_process(struct fuse_session *se, const char *buf, size_t len,
                          struct fuse_chan *ch);

void fuse_session_destroy(struct fuse_session *se);

void fuse_session_exit(struct fuse_session *se);

void fuse_session_reset(struct fuse_session *se);

int fuse_session_exited(struct fuse_session *se);

int fuse_session_loop(struct fuse_session *se);

int fuse_session_loop_mt(struct fuse_session *se);

/* ------------------------------------------ */

struct fuse_chan_ops {
    int (*receive)(struct fuse_chan *ch, char *buf, size_t size);

    int (*send)(struct fuse_chan *ch, const struct iovec iov[],
                size_t count);

    void (*destroy)(struct fuse_chan *ch);
};

struct fuse_chan *fuse_chan_new(struct fuse_chan_ops *op, int fd,
                                size_t bufsize, void *data);

int fuse_chan_fd(struct fuse_chan *ch);

size_t fuse_chan_bufsize(struct fuse_chan *ch);

void *fuse_chan_data(struct fuse_chan *ch);

struct fuse_session *fuse_chan_session(struct fuse_chan *ch);

int fuse_chan_receive(struct fuse_chan *ch, char *buf, size_t size);

int fuse_chan_send(struct fuse_chan *ch, const struct iovec iov[],
                   size_t count);

void fuse_chan_destroy(struct fuse_chan *ch);

/* ------------------------------------------ */

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_LOWLEVEL_H_ */
