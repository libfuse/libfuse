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
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>


struct thread_common {
    struct fuse *f;
    struct fuse_cmd *cmd;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int avail;
};

/* Called with c->lock held */
static void *do_work(void *data)
{
    struct thread_common *c = (struct thread_common *) data;
    struct fuse *f = c->f;

    c->avail ++;
    while(1) {
        int res;
        struct timespec timeout;
        struct timeval now;
        struct fuse_cmd *cmd;

        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + 1;
        timeout.tv_nsec = now.tv_usec * 1000;
        
        res = 0;
        while(c->cmd == NULL && res != ETIMEDOUT) 
            res = pthread_cond_timedwait(&c->cond, &c->lock, &timeout);
        if(res == ETIMEDOUT)
            break;

        cmd = c->cmd;
        c->cmd = NULL;
        c->avail --;
        pthread_mutex_unlock(&c->lock);
        __fuse_process_cmd(f, cmd);
        pthread_mutex_lock(&c->lock);
        c->avail ++;
    }

    c->avail --;
    pthread_mutex_unlock(&c->lock);
    return NULL;
}

static void start_thread(struct thread_common *c)
{
    pthread_attr_t attr;
    pthread_t thrid;
    sigset_t oldset;
    sigset_t newset;
    int res;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    /* Disallow signal reception in worker threads */
    sigfillset(&newset);
    sigprocmask(SIG_SETMASK, &newset, &oldset);
    res = pthread_create(&thrid, &attr, do_work, c);
    sigprocmask(SIG_SETMASK, &oldset, NULL);
    pthread_mutex_lock(&c->lock);
    if(res != 0) {
        fprintf(stderr, "Error creating thread: %s\n", strerror(res));
        exit(1);
    }
}

void fuse_loop_mt(struct fuse *f)
{
    struct thread_common *c;

    c = (struct thread_common *) malloc(sizeof(struct thread_common));
    c->f = f;
    c->cmd = NULL;
    pthread_cond_init(&c->cond, NULL);
    pthread_mutex_init(&c->lock, NULL);
    c->avail = 0;

    while(1) {
        struct fuse_cmd *cmd = __fuse_read_cmd(f);
        if(cmd == NULL)
            exit(1);

        pthread_mutex_lock(&c->lock);
        c->cmd = cmd;
        while(c->avail == 0)
            start_thread(c);
        pthread_cond_signal(&c->cond);
        pthread_mutex_unlock(&c->lock);
    }
}
