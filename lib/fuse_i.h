/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"
#include <stdio.h>
#include <pthread.h>

/* FUSE flags: */

/** Enable debuging output */
#define FUSE_DEBUG       (1 << 1)

/** If a file is removed but it's still open, don't hide the file but
    remove it immediately */
#define FUSE_HARD_REMOVE (1 << 2)


typedef unsigned long fino_t;

struct node {
    struct node *name_next;
    struct node *ino_next;
    fino_t ino;
    unsigned int generation;
    fino_t parent;
    char *name;
    int mode;
    int rdev;
    int version;
    int open_count;
    int is_hidden;
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
    unsigned int generation;
    unsigned int hidectr;
    unsigned long fh_ctr;
    pthread_mutex_t lock;
    int numworker;
    int numavail;
    volatile int exited;
    int majorver;
    int minorver;
};

struct fuse_dirhandle {
    struct fuse *fuse;
    fino_t dir;
    FILE *fp;
};

struct fuse_cmd {
    char *buf;
    size_t buflen;
};
