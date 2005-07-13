/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#if !defined(_FUSE_H_) && !defined(_FUSE_LOWLEVEL_H_)
#error "Never include <fuse_common.h> directly; use <fuse.h> or <fuse_lowlevel.h instead."
#endif

#ifndef _FUSE_COMMON_H_
#define _FUSE_COMMON_H_

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

    /** Can be filled in by open, to use direct I/O on this file */
    unsigned int direct_io : 1;
};

#endif /* _FUSE_COMMON_H_ */
