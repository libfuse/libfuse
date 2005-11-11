/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

/* these definitions provide source compatibility to prior versions.
   Do not include this file directly! */

#include <sys/statfs.h>

struct fuse_file_info_compat {
    int flags;
    unsigned long fh;
    int writepage;
    unsigned int direct_io : 1;
    unsigned int keep_cache : 1;
};

int fuse_reply_statfs_compat(fuse_req_t req, const struct statfs *stbuf);

int fuse_reply_open_compat(fuse_req_t req,
                           const struct fuse_file_info_compat *fi);
