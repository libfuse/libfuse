/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse.h"
#include <glib.h>
#include <stdio.h>
#include <pthread.h>

#define FUSE_DEV "/proc/fs/fuse/dev"

typedef unsigned long fino_t;

struct node {
    char *name;
    fino_t parent;
    int mode;
    int rdev;
    int version;
};

struct fuse {
    int flags;
    char *mnt;
    mode_t rootmode;
    int fd;
    struct fuse_operations op;
    GHashTable *nametab;
    pthread_mutex_t lock;
};

struct fuse_dirhandle {
    struct fuse *fuse;
    fino_t dir;
    FILE *fp;
};
