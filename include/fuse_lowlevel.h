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

/** Low level filesystem operations */
struct fuse_lowlevel_ops {
    /** Initialize filesystem
     *
     * Called before any other filesystem method
     *
     * 'userdata' from fuse_lowlevel_new() is passed to this function
     *
     * There's no reply to this function
     */
    void (*init)  (void *);

    /** Clean up filesystem
     *
     * Called on filesystem exit
     *
     * 'userdata' from fuse_lowlevel_new() is passed to this function
     *
     * There's no reply to this function
     */
    void (*destroy)(void *);

    /** Look up a directory entry by name
     *
     * Valid replies:
     *   fuse_reply_entry()
     *   fuse_reply_err()
     */
    void (*lookup) (fuse_req_t req, fuse_ino_t parent, const char *name);

    /**
     * Forget about an inode
     *
     * The nlookup parameter indicates the number of lookups
     * previously performed on this inode.
     *
     * If the filesystem implements inode lifetimes, it is recommended
     * that inodes acquire a single reference on each lookup, and lose
     * nlookup references on each forget.
     *
     * The filesystem may ignore forget calls, if the inodes don't
     * need to have a limited lifetime.
     *
     * On unmount it is not guaranteed, that all referenced inodes
     * will receive a forget message.
     *
     * Valid replies:
     *   fuse_reply_none()
     */
    void (*forget) (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup);

    /** Get file attributes
     *
     * Valid replies:
     *   fuse_reply_attr()
     *   fuse_reply_err()
     */
    void (*getattr)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);

    /** Set file attributes
     *
     * Valid replies:
     *   fuse_reply_attr()
     *   fuse_reply_err()
     */
    void (*setattr)(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                    int to_set, struct fuse_file_info *fi);

    /** Read symbolic link
     *
     * Valid replies:
     *   fuse_reply_readlink
     *   fuse_reply_err
     */
    void (*readlink)(fuse_req_t req, fuse_ino_t ino);

    /** Create file node
     *
     * Create a regular file, character device, block device, fifo or
     * socket node.
     *
     * Valid replies:
     *   fuse_reply_entry
     *   fuse_reply_err
     */
    void (*mknod)  (fuse_req_t req, fuse_ino_t parent, const char *name,
                    mode_t mode, dev_t rdev);

    /** Create a directory
     *
     * Valid replies:
     *   fuse_reply_entry
     *   fuse_reply_err
     */
    void (*mkdir)  (fuse_req_t req, fuse_ino_t parent, const char *name,
                    mode_t mode);

    /** Remove a file
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*unlink) (fuse_req_t req, fuse_ino_t parent, const char *name);

    /** Remove a directory
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*rmdir)  (fuse_req_t req, fuse_ino_t parent, const char *name);

    /** Create a symbolic link
     *
     * Valid replies:
     *   fuse_reply_entry
     *   fuse_reply_err
     */
    void (*symlink)(fuse_req_t req, const char *link, fuse_ino_t parent,
                    const char *name);

    /** Rename a file
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*rename) (fuse_req_t req, fuse_ino_t parent, const char *name,
                    fuse_ino_t newparent, const char *newname);

    /** Create a hard link
     *
     * Valid replies:
     *   fuse_reply_entry
     *   fuse_reply_err
     */
    void (*link)   (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
                    const char *newname);

    /** Open a file
     *
     * Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and
     * O_TRUNC) are available in fi->flags.
     *
     * Filesystem may store an arbitrary file handle (pointer, index,
     * etc) in fi->fh, and use this in other all other file operations
     * (read, write, flush, release, fsync).
     *
     * Filesystem may also implement stateless file I/O and not store
     * anything in fi->fh.
     *
     * There are also some flags (direct_io, keep_cache) which the
     * filesystem may set in fi, to change the way the file is opened.
     * See fuse_file_info structure in <fuse_common.h> for more details.
     *
     * Valid replies:
     *   fuse_reply_open
     *   fuse_reply_err
     */
    void (*open)   (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);

    /** Read data
     *
     * Read should send exactly the number of bytes requested except
     * on EOF or error, otherwise the rest of the data will be
     * substituted with zeroes.  An exception to this is when the file
     * has been opened in 'direct_io' mode, in which case the return
     * value of the read system call will reflect the return value of
     * this operation.
     *
     * fi->fh will contain the value set by the open method, or will
     * be undefined if the open method didn't set any value.
     *
     * Valid replies:
     *   fuse_reply_buf
     *   fuse_reply_err
     */
    void (*read)   (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                    struct fuse_file_info *fi);

    /** Write data
     *
     * Write should return exactly the number of bytes requested
     * except on error.  An exception to this is when the file has
     * been opened in 'direct_io' mode, in which case the return value
     * of the write system call will reflect the return value of this
     * operation.
     *
     * fi->fh will contain the value set by the open method, or will
     * be undefined if the open method didn't set any value.
     *
     * Valid replies:
     *   fuse_reply_write
     *   fuse_reply_err
     */
    void (*write)  (fuse_req_t req, fuse_ino_t ino, const char *buf,
                    size_t size, off_t off, struct fuse_file_info *fi);

    /** Flush method
     *
     * This is called on each close() of the opened file.
     *
     * Since file descriptors can be duplicated (dup, dup2, fork), for
     * one open call there may be many flush calls.
     *
     * fi->fh will contain the value set by the open method, or will
     * be undefined if the open method didn't set any value.
     *
     * NOTE: the name of the method is misleading, since (unlike
     * fsync) the filesystem is not forced to flush pending writes.
     * One reason to flush data, is if the filesystem wants to return
     * write errors.
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*flush)  (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);

    /** Release an open file
     *
     * Release is called when there are no more references to an open
     * file: all file descriptors are closed and all memory mappings
     * are unmapped.
     *
     * For every open call there will be exactly one release call.
     *
     * The filesystem may reply with an error, but error values are
     * not returned to close() or munmap() which triggered the
     * release.
     *
     * fi->fh will contain the value set by the open method, or will
     * be undefined if the open method didn't set any value.
     * fi->flags will contain the same flags as for open.
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*release)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);

    /** Synchronize file contents
     *
     * If the datasync parameter is non-zero, then only the user data
     * should be flushed, not the meta data.
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*fsync)  (fuse_req_t req, fuse_ino_t ino, int datasync,
                    struct fuse_file_info *fi);

    /** Open a directory
     *
     * Filesystem may store an arbitrary file handle (pointer, index,
     * etc) in fi->fh, and use this in other all other directory
     * stream operations (readdir, releasedir, fsyncdir).
     *
     * Filesystem may also implement stateless directory I/O and not
     * store anything in fi->fh, though that makes it impossible to
     * implement standard conforming directory stream operations in
     * case the contents of the directory can change between opendir
     * and releasedir.
     *
     * Valid replies:
     *   fuse_reply_open
     *   fuse_reply_err
     */
    void (*opendir)(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);

    /** Read directory
     *
     * Send a buffer filled using fuse_add_dirent(), with size not
     * exceeding the requested size.  Send an empty buffer on end of
     * stream.
     *
     * fi->fh will contain the value set by the opendir method, or
     * will be undefined if the opendir method didn't set any value.
     *
     * Valid replies:
     *   fuse_reply_buf
     *   fuse_reply_err
     */
    void (*readdir)(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                    struct fuse_file_info *fi);

    /** Release an open directory
     *
     * For every opendir call there will be exactly one releasedir
     * call.
     *
     * Any errors sent by releasedir will be ignored.
     *
     * fi->fh will contain the value set by the opendir method, or
     * will be undefined if the opendir method didn't set any value.
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*releasedir)(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi);

    /** Synchronize directory contents
     *
     * If the datasync parameter is non-zero, then only the directory
     * contents should be flushed, not the meta data.
     *
     * fi->fh will contain the value set by the opendir method, or
     * will be undefined if the opendir method didn't set any value.
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*fsyncdir)(fuse_req_t req, fuse_ino_t ino, int datasync,
                     struct fuse_file_info *fi);

    /** Get file system statistics
     *
     * Valid replies:
     *   fuse_reply_statfs
     *   fuse_reply_err
     */
    void (*statfs) (fuse_req_t req);

    /** Set an extended attribute
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*setxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     const char *value, size_t size, int flags);

    /** Get an extended attribute
     *
     * If size is zero, the size of the value should be sent with
     * fuse_reply_xattr.
     *
     * If the size is non-zero, and the value fits in the buffer, the
     * value should be sent with fuse_reply_buf.
     *
     * If the size is too small for the value, the ERANGE error should
     * be sent.
     *
     * Valid replies:
     *   fuse_reply_buf
     *   fuse_reply_xattr
     *   fuse_reply_err
     */
    void (*getxattr)(fuse_req_t req, fuse_ino_t ino, const char *name,
                     size_t size);

    /** List extended attribute names
     *
     * If size is zero, the total size of the attribute list should be
     * sent with fuse_reply_xattr.
     *
     * If the size is non-zero, and the null charater separated
     * attribute list fits in the buffer, the list should be sent with
     * fuse_reply_buf.
     *
     * If the size is too small for the list, the ERANGE error should
     * be sent.
     *
     * Valid replies:
     *   fuse_reply_buf
     *   fuse_reply_xattr
     *   fuse_reply_err
     */
    void (*listxattr)(fuse_req_t req, fuse_ino_t ino, size_t size);

    /** Remove an extended attribute
     *
     * Valid replies:
     *   fuse_reply_err
     */
    void (*removexattr)(fuse_req_t req, fuse_ino_t ino, const char *name);
};


/** Reply with an error code or success (zero)
 *
 * all except forget may send an error
 *
 * unlink, rmdir, rename, flush, release, fsync, fsyncdir, setxattr
 * and removexattr may send a succes code
*/
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
int fuse_reply_statfs(fuse_req_t req, const struct statfs *stbuf);

/* getxattr, listxattr */
int fuse_reply_xattr(fuse_req_t req, size_t count);

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
