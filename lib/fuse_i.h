/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

/* For pthread_rwlock_t */
#define _GNU_SOURCE

#include <config.h>
#include "fuse.h"
#include <pthread.h>

typedef unsigned long nodeid_t;

struct fuse {
    int flags;
    int fd;
    struct fuse_operations op;
    int compat;
    struct node **name_table;
    size_t name_table_size;
    struct node **id_table;
    size_t id_table_size;
    nodeid_t ctr;
    unsigned int generation;
    unsigned int hidectr;
    pthread_mutex_t lock;
    pthread_mutex_t worker_lock;
    pthread_rwlock_t tree_lock;
    int numworker;
    int numavail;
    volatile int exited;
    int got_init;
    void *user_data;
    int major;
    int minor;
    uid_t owner;
    uid_t uid;
    gid_t gid;
    mode_t umask;
};

struct fuse *fuse_new_common(int fd, const char *opts,
                             const struct fuse_operations *op,
                             size_t op_size, int compat);
