/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
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
    pthread_t threads[FUSE_MAX_WORKERS];
    void *data;
    fuse_processor_t proc;
};

static void start_thread(struct fuse_worker *w, pthread_t *thread_id);

static void *do_work(void *data)
{
    struct fuse_worker *w = (struct fuse_worker *) data;
    struct fuse *f = w->f;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    while (1) {
        struct fuse_cmd *cmd;

        if (__fuse_exited(f))
            break;

        cmd = __fuse_read_cmd(w->f);
        if (cmd == NULL)
            continue;

        if (f->numavail == 0 && f->numworker < FUSE_MAX_WORKERS) {
            pthread_mutex_lock(&f->lock);
            if (f->numworker < FUSE_MAX_WORKERS) {
                pthread_t *thread_id = &w->threads[f->numworker];
                f->numavail ++;
                f->numworker ++;
                pthread_mutex_unlock(&f->lock);
                start_thread(w, thread_id);
            } else
                pthread_mutex_unlock(&f->lock);
        }

        w->proc(w->f, cmd, w->data);
    }

    return NULL;
}

static void start_thread(struct fuse_worker *w, pthread_t *thread_id)
{
    sigset_t oldset;
    sigset_t newset;
    int res;

    /* Disallow signal reception in worker threads */
    sigfillset(&newset);
    pthread_sigmask(SIG_SETMASK, &newset, &oldset);
    res = pthread_create(thread_id, NULL, do_work, w);
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    if (res != 0) {
        fprintf(stderr, "Error creating thread: %s\n", strerror(res));
        exit(1);
    }
    
    pthread_detach(*thread_id);
}

static struct fuse_context *mt_getcontext(struct fuse *f)
{
    struct fuse_context *ctx;

    ctx = (struct fuse_context *) pthread_getspecific(f->context_key);
    if (ctx == NULL) {
        ctx = (struct fuse_context *) malloc(sizeof(struct fuse_context));
        pthread_setspecific(f->context_key, ctx);
    }

    return ctx;
}

static void mt_freecontext(void *data)
{
    free(data);
}

void __fuse_loop_mt(struct fuse *f, fuse_processor_t proc, void *data)
{
    struct fuse_worker *w;
    int res;
    int i;

    w = malloc(sizeof(struct fuse_worker));    
    memset(w, 0, sizeof(struct fuse_worker));
    w->f = f;
    w->data = data;
    w->proc = proc;

    f->numworker = 1;
    res = pthread_key_create(&f->context_key, mt_freecontext);
    if (res != 0) {
        fprintf(stderr, "Failed to create thread specific key\n");
        exit(1);
    }
    f->getcontext = mt_getcontext;
    do_work(w);

    pthread_mutex_lock(&f->lock);
    for (i = 1; i < f->numworker; i++)
        pthread_cancel(w->threads[i]);
    pthread_mutex_unlock(&f->lock);
}

void fuse_loop_mt(struct fuse *f)
{
    if (f == NULL)
        return;

    __fuse_loop_mt(f, (fuse_processor_t) __fuse_process_cmd, NULL);
}
