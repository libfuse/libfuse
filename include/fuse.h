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

/** Credentials for an operation, these are determined by the fsuid
    and fsgid of the calling process */
struct fuse_cred {
    uid_t uid;
    gid_t gid;
    /* FIXME: supplementary groups should also be included */
};

/**
 * The file system operations:
 *
 * Most of these should work very similarly to the well known UNIX
 * file system operations.  Exceptions are:
 * 
 *  - All operations get a fuse_cred structure by which the filesystem
 *  implementation can check, whether the operation is permitted or
 *  not.
 * 
 *  - All operations should return the negated error value (-errno) on
 *  error.
 * 
 *  - readlink() should fill the buffer with a null terminated string.
 *  The buffer size argument includes the space for the terminating
 *  null character.  If the linkname is too long to fit in the buffer,
 *  it should be truncated.  The return value should be 0 for success.
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
 *  argument, like the pread() and pwrite() system calls.  */
struct fuse_operations {
    int (*getattr)  (struct fuse_cred *, const char *, struct stat *);
    int (*readlink) (struct fuse_cred *, const char *, char *, size_t);
    int (*getdir)   (struct fuse_cred *, const char *, fuse_dirh_t, fuse_dirfil_t);
    int (*mknod)    (struct fuse_cred *, const char *, mode_t, dev_t);
    int (*mkdir)    (struct fuse_cred *, const char *, mode_t);
    int (*unlink)   (struct fuse_cred *, const char *);
    int (*rmdir)    (struct fuse_cred *, const char *);
    int (*symlink)  (struct fuse_cred *, const char *, const char *);
    int (*rename)   (struct fuse_cred *, const char *, const char *);
    int (*link)     (struct fuse_cred *, const char *, const char *);
    int (*chmod)    (struct fuse_cred *, const char *, mode_t);
    int (*chown)    (struct fuse_cred *, const char *, uid_t, gid_t);
    int (*truncate) (struct fuse_cred *, const char *, off_t);
    int (*utime)    (struct fuse_cred *, const char *, struct utimbuf *);
    int (*open)     (struct fuse_cred *, const char *, int);
    int (*read)     (struct fuse_cred *, const char *, char *, size_t, off_t);
    int (*write)    (struct fuse_cred *, const char *, const char *, size_t, off_t);
};

/* FUSE flags: */
#define FUSE_MULTITHREAD (1 << 0)

/**
 * Create a new FUSE filesystem. The filesystem is not yet mounted
 *
 * @param flags any combination of the FUSE flags defined above, or 0
 * @param root the file type of the root node. 0 is the default (directory).
 * @return the created FUSE handle
 */
struct fuse *fuse_new(int flags, mode_t root);

/**
 * Connect to the kernel and mount the filesystem.
 * 
 * @param f the FUSE handle
 * @param mnt the mount point
 * @return 0 on success -1 on failure
 */
int fuse_mount(struct fuse *f, const char *mnt);

/**
 * Set the filesystem operations. 
 * 
 * Operations which are initialised to NULL will return ENOSYS to the
 * calling process.  This function can be called anytime after
 * fuse_new() and before fuse_loop().
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
 * Disconnect from the kernel and unmount the filesystem
 *
 * @param f the FUSE handle
 */
int fuse_unmount(struct fuse *f);

/**
 * Destroy the filesystem. 
 *
 * The filesystem is not unmounted (call fuse_unmount() for that).
 * After a fork() system call it is possible to call fuse_destroy() in
 * one process, and leave the other process to service the filesystem
 * requests.
 *
 * @param f the FUSE handle
 */
void fuse_destroy(struct fuse *f);
