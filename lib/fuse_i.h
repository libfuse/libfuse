/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse.h"
#include <glib.h>
#include <stdio.h>

#define FUSE_DEV "/proc/fs/fuse/dev"

typedef unsigned long fino_t;

struct node {
    char *name;
    fino_t parent;
    int mode;
};

struct fuse {
    char *dir;
    int fd;
    struct fuse_operations op;
    GHashTable *nametab;
};

struct fuse_dh {
    struct fuse *fuse;
    fino_t dir;
    FILE *fp;
};
