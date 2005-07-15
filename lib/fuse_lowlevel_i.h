/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse_lowlevel.h"
#include <pthread.h>

struct fuse_ll {
    unsigned int debug : 1;
    unsigned int allow_root : 1;
    int fd;
    struct fuse_ll_operations op;
    volatile int exited;
    int got_init;
    void *userdata;
    int major;
    int minor;
    uid_t owner;
    pthread_mutex_t worker_lock;
    int numworker;
    int numavail;
};
