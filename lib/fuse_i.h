/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"
#include <stdio.h>
#include <pthread.h>

typedef unsigned long fino_t;

struct node {
    struct node *name_next;
    struct node *ino_next;
    fino_t ino;
    fino_t parent;
    char *name;
    int mode;
    int rdev;
    int version;
};

struct fuse {
    int flags;
    int fd;
    struct fuse_operations op;
    struct node **name_table;
    size_t name_table_size;
    struct node **ino_table;
    size_t ino_table_size;
    fino_t ctr;
    pthread_mutex_t lock;
    int numworker;
    int numavail;
    struct fuse_context *(*getcontext)(struct fuse *);
    struct fuse_context context;
    pthread_key_t context_key;
    volatile int exited;
};

struct fuse_dirhandle {
    struct fuse *fuse;
    fino_t dir;
    FILE *fp;
};

struct fuse_cmd {
    struct fuse *f;
    char *buf;
    size_t buflen;
};
