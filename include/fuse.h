/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/* This file defines the library interface of FUSE */

#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>

/** Handle for a FUSE filesystem */
struct fuse;

/** Handle for a getdir() operation */
typedef struct fuse_dirhandle *fuse_dirh_t;

/** Function to add an entry in a getdir() operation */
typedef int (*fuse_dirfil_t) (fuse_dirh_t, const char *, int type);

/**
 * The file system operations:
 *
 * Most of these should work very similarly to the well known UNIX
 * file system operations.  Exceptions are:
 * 
 *  - All operations should return the negated error value (-errno) on
 *  error.
 * 
 *  - Getattr() doesn't need to fill in the following fields:
 *      st_ino
 *      st_dev
 *      st_blksize
 * 
 *  - readlink() should fill the buffer with a null terminated string.  The
 *  buffer size argument includes the space for the terminating null
 *  character.  If the linkname is too long to fit in the buffer, it should
 *  be truncated.  The return value should be 0 for success.
 *
 *  - getdir() is the opendir(), readdir(), ..., closedir() sequence
 *  in one call. For each directory entry the filldir parameter should
 *  be called. 
 *
 *  - There is no create() operation, mknod() will be called for
 *  creation of all non directory, non symlink nodes.
 *
 *  - open() should not return a filehandle, but 0 on success.  No
 *  creation, or trunctation flags (O_CREAT, O_EXCL, O_TRUNC) will be
 *  passed to open().  Open should only check if the operation is
 *  permitted for the given flags.
 * 
 *  - read(), write() are not passed a filehandle, but rather a
 *  pathname.  The offset of the read and write is passed as the last
 *  argument, like the pread() and pwrite() system calls.
 */
struct fuse_operations {
    int (*getattr)  (const char *, struct stat *);
    int (*readlink) (const char *, char *, size_t);
    int (*getdir)   (const char *, fuse_dirh_t, fuse_dirfil_t);
    int (*mknod)    (const char *, mode_t, dev_t);
    int (*mkdir)    (const char *, mode_t);
    int (*unlink)   (const char *);
    int (*rmdir)    (const char *);
    int (*symlink)  (const char *, const char *);
    int (*rename)   (const char *, const char *);
    int (*link)     (const char *, const char *);
    int (*chmod)    (const char *, mode_t);
    int (*chown)    (const char *, uid_t, gid_t);
    int (*truncate) (const char *, off_t);
    int (*utime)    (const char *, struct utimbuf *);
    int (*open)     (const char *, int);
    int (*read)     (const char *, char *, size_t, off_t);
    int (*write)    (const char *, const char *, size_t, off_t);
};

/* FUSE flags: */

/** Enable debuging output */
#define FUSE_DEBUG       (1 << 1)

/**
 * Create a new FUSE filesystem.
 *
 * @param fd the control file descriptor
 * @param flags any combination of the FUSE flags defined above, or 0
 * @return the created FUSE handle
 */
struct fuse *fuse_new(int fd, int flags);

/**
 * Set the filesystem operations. 
 * 
 * Operations which are initialised to NULL will return ENOSYS to the
 * calling process.
 * 
 * @param f the FUSE handle
 * @param op the operations
 */
void fuse_set_operations(struct fuse *f, const struct fuse_operations *op);

/**
 * FUSE event loop.
 *
 * Requests from the kernel are processed, and the apropriate
 * operations are called. 
 *
 * @param f the FUSE handle
 */
void fuse_loop(struct fuse *f);

/**
 * FUSE event loop with multiple threads
 *
 * Requests from the kernel are processed, and the apropriate
 * operations are called.  Request are processed in parallel by
 * distributing them between multiple threads.
 *
 * Calling this function requires the pthreads library to be linked to
 * the application.
 *
 * @param f the FUSE handle
 */
void fuse_loop_mt(struct fuse *f);

/**
 * Destroy the FUSE handle. 
 *
 * The filesystem is not unmounted.
 *
 * @param f the FUSE handle
 */
void fuse_destroy(struct fuse *f);


/* --------------------------------------------------- *
 * Advanced API, usually you need not bother with this *
 * --------------------------------------------------- */

struct fuse_cmd;

struct fuse_cmd *__fuse_read_cmd(struct fuse *f);

void __fuse_process_cmd(struct fuse *f, struct fuse_cmd *cmd);
