/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

struct fuse_thr_data {
    struct fuse *f;
    void *data;
    fuse_processor_t proc;
    struct fuse_cmd *cmd;
};

static void *do_work(void *data)
{
    struct fuse_thr_data *d = (struct fuse_thr_data *) data;
    d->proc(d->f, d->cmd, d->data);
    free(d);
    return NULL;
}

static void start_thread(struct fuse_thr_data *d)
{
    pthread_t thrid;
    sigset_t oldset;
    sigset_t newset;
    int res;
    
    /* Disallow signal reception in worker threads */
    sigfillset(&newset);
    pthread_sigmask(SIG_SETMASK, &newset, &oldset);
    res = pthread_create(&thrid, NULL, do_work, d);
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    if(res != 0) {
        fprintf(stderr, "Error creating thread: %s\n", strerror(res));
        exit(1);
    }
    pthread_detach(thrid);
}

void __fuse_loop_mt(struct fuse *f, fuse_processor_t proc, void *data)
{
    while(1) {
        struct fuse_thr_data *d;
        struct fuse_cmd *cmd = __fuse_read_cmd(f);
        if(cmd == NULL)
            exit(1);

        d = malloc(sizeof(struct fuse_thr_data));
        d->proc = proc;
        d->f = f;
        d->cmd = cmd;
        d->data = data;
        
        start_thread(d);
    }
}

void fuse_loop_mt(struct fuse *f)
{
    __fuse_loop_mt(f, (fuse_processor_t) __fuse_process_cmd, NULL);
}
