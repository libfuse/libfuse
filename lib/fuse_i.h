/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "fuse.h"

struct fuse_session;
struct fuse_chan;

struct fuse_cmd {
    char *buf;
    size_t buflen;
    struct fuse_chan *ch;
};

struct fuse_session *fuse_get_session(struct fuse *f);

struct fuse *fuse_new_common(int fd, struct fuse_args *args, 
                             const struct fuse_operations *op,
                             size_t op_size, int compat);
