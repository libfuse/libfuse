/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>

#define FUSE_MAX_WORKERS 10

struct fuse_worker {
    struct fuse *f;
    void *data;
    fuse_processor_t proc;
};

static void start_thread(struct fuse_worker *w);

static void *do_work(void *data)
{
    struct fuse_worker *w = (struct fuse_worker *) data;
    struct fuse *f = w->f;

    while(1) {
        struct fuse_cmd *cmd = __fuse_read_cmd(w->f);
        if(cmd == NULL)
            pthread_exit(NULL);

        if(f->numavail == 0 && f->numworker < FUSE_MAX_WORKERS) {
            pthread_mutex_lock(&f->lock);
            f->numavail ++;
            f->numworker ++;
            pthread_mutex_unlock(&f->lock);
            start_thread(w);
        }

        w->proc(w->f, cmd, w->data);
    }

    return NULL;
}

static void start_thread(struct fuse_worker *w)
{
    pthread_t thrid;
    sigset_t oldset;
    sigset_t newset;
    int res;

    /* Disallow signal reception in worker threads */
    sigfillset(&newset);
    pthread_sigmask(SIG_SETMASK, &newset, &oldset);
    res = pthread_create(&thrid, NULL, do_work, w);
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    if(res != 0) {
        fprintf(stderr, "Error creating thread: %s\n", strerror(res));
        exit(1);
    }
    pthread_detach(thrid);
}

void __fuse_loop_mt(struct fuse *f, fuse_processor_t proc, void *data)
{
    struct fuse_worker *w;

    w = malloc(sizeof(struct fuse_worker));    
    w->f = f;
    w->data = data;
    w->proc = proc;

    f->numworker = 1;
    do_work(w);
}

void fuse_loop_mt(struct fuse *f)
{
    __fuse_loop_mt(f, (fuse_processor_t) __fuse_process_cmd, NULL);
}
