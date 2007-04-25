/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "fuse.h"

struct fuse_session;
struct fuse_chan;
struct fuse_lowlevel_ops;
struct fuse_req;

struct fuse_cmd {
    char *buf;
    size_t buflen;
    struct fuse_chan *ch;
};

struct fuse *fuse_new_common(struct fuse_chan *ch, struct fuse_args *args,
                             const struct fuse_operations *op,
                             size_t op_size, void *user_data, int compat);

int fuse_sync_compat_args(struct fuse_args *args);

struct fuse_chan *fuse_kern_chan_new(int fd);

struct fuse_session *fuse_lowlevel_new_common(struct fuse_args *args,
                                       const struct fuse_lowlevel_ops *op,
                                       size_t op_size, void *userdata);

void fuse_kern_unmount_compat22(const char *mountpoint);
void fuse_kern_unmount(const char *mountpoint, int fd);
int fuse_kern_mount(const char *mountpoint, struct fuse_args *args);
