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
#include <errno.h>
#include <sys/time.h>

#define FUSE_WORKER_IDLE 10

static pthread_mutex_t fuse_mt_lock = PTHREAD_MUTEX_INITIALIZER;


struct fuse_worker {
    struct fuse_worker *next;
    struct fuse_worker *prev;
    struct fuse *f;
    void *data;
    fuse_processor_t proc;
    struct fuse_cmd *cmd;
    int avail;
    pthread_cond_t start;
};

static void *do_work(void *data)
{
    struct fuse_worker *w = (struct fuse_worker *) data;
    int ret;
    
    do {
        struct timeval now;
        struct timespec timeout;

        w->proc(w->f, w->cmd, w->data);

        pthread_mutex_lock(&fuse_mt_lock);
        w->avail = 1;
        w->cmd = NULL;
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + FUSE_WORKER_IDLE;
        timeout.tv_nsec = now.tv_usec * 1000;

        ret = 0;
        while(w->cmd == NULL && ret != ETIMEDOUT)
            ret = pthread_cond_timedwait(&w->start, &fuse_mt_lock, &timeout);

        if(ret == ETIMEDOUT) {
            struct fuse_worker *next = w->next;
            struct fuse_worker *prev = w->prev;
            prev->next = next;
            next->prev = prev;
            pthread_cond_destroy(&w->start);
            free(w);
        }
        w->avail = 0;
        pthread_mutex_unlock(&fuse_mt_lock);

    } while(ret != ETIMEDOUT);

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
    struct fuse_worker *head;

    head = malloc(sizeof(struct fuse_worker));
    head->next = head;
    head->prev = head;

    while(1) {
        struct fuse_worker *w;
        struct fuse_cmd *cmd = __fuse_read_cmd(f);
        if(cmd == NULL)
            exit(1);

        pthread_mutex_lock(&fuse_mt_lock);
        for(w = head->next; w != head; w = w->next) 
            if(w->avail)
                break;

        if(w != head) {
            pthread_cond_signal(&w->start);
            w->cmd = cmd;
            w = NULL;
        }
        else {
            struct fuse_worker *prev = head->prev;
            struct fuse_worker *next = head;
            w = malloc(sizeof(struct fuse_worker));
            w->prev = prev;
            w->next = next;
            next->prev = w;
            prev->next = w;
            w->f = f;
            w->data = data;
            w->proc = proc;
            w->cmd = cmd;
            w->avail = 0;
            pthread_cond_init(&w->start, NULL);
        }
        pthread_mutex_unlock(&fuse_mt_lock);

        if(w != NULL)
            start_thread(w);
    }
}

void fuse_loop_mt(struct fuse *f)
{
    __fuse_loop_mt(f, (fuse_processor_t) __fuse_process_cmd, NULL);
}
