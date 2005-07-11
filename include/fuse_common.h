/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#if !defined(_FUSE_H_) && !defined(_FUSE_LOWLEVEL_H_)
#error "Never include <fuse_common.h> directly; use <fuse.h> or <fuse_lowlevel.h instead."
#endif

/** Information about open files */
struct fuse_file_info {
    /** Open flags.  Available in open() and release() */
    int flags;

    /** File handle.  May be filled in by filesystem in open().
        Available in all other file operations */
    unsigned long fh;

    /** In case of a write operation indicates if this was caused by a
        writepage */
    int writepage;
};

/** Extra context that may be needed by some filesystems
 *
 * The uid, gid and pid fields are not filled in case of a writepage
 * operation.
 */
struct fuse_context {
    /** Pointer to the fuse object */
    struct fuse *fuse;

    /** User ID of the calling process */
    uid_t uid;

    /** Group ID of the calling process */
    gid_t gid;

    /** Thread ID of the calling process */
    pid_t pid;

    /** Private filesystem data */
    void *private_data;
};


