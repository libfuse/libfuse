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

/** Use st_ino field in getattr instead of generating inode numbers  */
#define FUSE_USE_INO     (1 << 3)


typedef unsigned long nodeid_t;

struct node {
    struct node *name_next;
    struct node *id_next;
    nodeid_t nodeid;
    unsigned int generation;
    nodeid_t parent;
    char *name;
    int mode;
    int rdev;
    unsigned long ino;
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
    struct node **id_table;
    size_t id_table_size;
    nodeid_t ctr;
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
    nodeid_t dir;
    FILE *fp;
};

struct fuse_cmd {
    char *buf;
    size_t buflen;
};
