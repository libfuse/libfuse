/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>

#define FUSE_MAX_WORKERS 10

struct fuse_worker {
    pthread_mutex_t lock;
    int numworker;
    int numavail;
    struct fuse_session *se;
    struct fuse_chan *ch;
    struct fuse_chan *prevch;
    pthread_t threads[FUSE_MAX_WORKERS];
    int exit;
    int error;
};

#ifndef USE_UCLIBC
#define mutex_init(mut) pthread_mutex_init(mut, NULL)
#else
static void mutex_init(pthread_mutex_t *mut)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
    pthread_mutex_init(mut, &attr);
    pthread_mutexattr_destroy(&attr);
}
#endif

static int fuse_loop_mt_send(struct fuse_chan *ch, const struct iovec iov[],
                             size_t count)
{
    struct fuse_worker *w = (struct fuse_worker *) fuse_chan_data(ch);
    pthread_mutex_lock(&w->lock);
    w->numavail ++;
    pthread_mutex_unlock(&w->lock);
    return fuse_chan_send(w->prevch, iov, count);
}

static int start_thread(struct fuse_worker *w, pthread_t *thread_id);

static void *do_work(void *data)
{
    struct fuse_worker *w = (struct fuse_worker *) data;
    int is_mainthread = (w->numworker == 1);
    size_t bufsize = fuse_chan_bufsize(w->prevch);
    char *buf = (char *) malloc(bufsize);
    if (!buf) {
        fprintf(stderr, "fuse: failed to allocate read buffer\n");
        fuse_session_exit(w->se);
        w->error = -1;
        return NULL;
    }

    pthread_cleanup_push(free, buf);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    while (!fuse_session_exited(w->se)) {
        int res = fuse_chan_receive(w->prevch, buf, bufsize);
        if (!res)
            continue;
        if (res == -1) {
            fuse_session_exit(w->se);
            w->error = -1;
            break;
        }

        pthread_mutex_lock(&w->lock);
        if (w->exit) {
            pthread_mutex_unlock(&w->lock);
            break;
        }
        w->numavail--;
        if (w->numavail == 0 && w->numworker < FUSE_MAX_WORKERS) {
            if (w->numworker < FUSE_MAX_WORKERS) {
                /* FIXME: threads should be stored in a list instead
                   of an array */
                int start_res;
                pthread_t *thread_id = &w->threads[w->numworker];
                w->numavail ++;
                w->numworker ++;
                start_res = start_thread(w, thread_id);
                if (start_res == -1)
                    w->numavail --;
            }
        }
        pthread_mutex_unlock(&w->lock);
        fuse_session_process(w->se, buf, res, w->ch);
    }
    pthread_cleanup_pop(1);

    /* Wait for cancellation */
    if (!is_mainthread)
        pause();

    return NULL;
}

static int start_thread(struct fuse_worker *w, pthread_t *thread_id)
{
    int res = pthread_create(thread_id, NULL, do_work, w);
    if (res != 0) {
        fprintf(stderr, "fuse: error creating thread: %s\n", strerror(res));
        return -1;
    }

    return 0;
}

int fuse_session_loop_mt(struct fuse_session *se)
{
    int i;
    int err;
    struct fuse_worker *w;
    struct fuse_chan_ops cop = {
        .send = fuse_loop_mt_send,
    };

    w = (struct fuse_worker *) malloc(sizeof(struct fuse_worker));
    if (w == NULL) {
        fprintf(stderr, "fuse: failed to allocate worker structure\n");
        return -1;
    }
    memset(w, 0, sizeof(struct fuse_worker));
    w->se = se;
    w->prevch = fuse_session_next_chan(se, NULL);
    w->ch = fuse_chan_new(&cop, -1, 0, w);
    if (w->ch == NULL) {
        free(w);
        return -1;
    }
    w->error = 0;
    w->numworker = 1;
    w->numavail = 1;
    mutex_init(&w->lock);

    do_work(w);

    pthread_mutex_lock(&w->lock);
    for (i = 1; i < w->numworker; i++)
        pthread_cancel(w->threads[i]);
    w->exit = 1;
    pthread_mutex_unlock(&w->lock);
    for (i = 1; i < w->numworker; i++)
        pthread_join(w->threads[i], NULL);
    pthread_mutex_destroy(&w->lock);
    err = w->error;
    fuse_chan_destroy(w->ch);
    free(w);
    fuse_session_reset(se);
    return err;
}
