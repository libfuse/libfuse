/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/* This file defines the library interface of FUSE */

#include <sys/types.h>
#include <sys/stat.h>

struct fuse;
struct fuse_dh;

typedef int (*dirfiller_t) (struct fuse_dh *, const char *, int type);


struct fuse_operations {
    int (*getattr) (const char *path, struct stat *stbuf);
    int (*readlink) (const char *path, char *buf, size_t size);
    int (*getdir) (const char *path, struct fuse_dh *h, dirfiller_t filler);
    int (*mknod) (const char *path, int mode, int rdev);
    int (*mkdir) (const char *path, int mode);
    int (*symlink) (const char *from, const char *to);
    int (*unlink) (const char *path);
    int (*rmdir) (const char *path);
};

struct fuse *fuse_new();

int fuse_mount(struct fuse *f, const char *dir);

void fuse_set_operations(struct fuse *f, const struct fuse_operations *op);

void fuse_loop(struct fuse *f);

int fuse_unmount(struct fuse *f);

void fuse_destroy(struct fuse *f);
