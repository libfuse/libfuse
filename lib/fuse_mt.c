/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse_i.h"
#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

static pthread_key_t context_key;
static pthread_mutex_t context_lock = PTHREAD_MUTEX_INITIALIZER;
static int context_ref;

static struct fuse_context *mt_getcontext(void)
{
    struct fuse_context *ctx;

    ctx = (struct fuse_context *) pthread_getspecific(context_key);
    if (ctx == NULL) {
        ctx = (struct fuse_context *) malloc(sizeof(struct fuse_context));
        if (ctx == NULL) {
            fprintf(stderr, "fuse: failed to allocate thread specific data\n");
            return NULL;
        }
        pthread_setspecific(context_key, ctx);
    }
    return ctx;
}

static void mt_freecontext(void *data)
{
    free(data);
}

static int mt_create_context_key(void)
{
    int err = 0;
    pthread_mutex_lock(&context_lock);
    if (!context_ref) {
        err = pthread_key_create(&context_key, mt_freecontext);
        if (err)
            fprintf(stderr, "fuse: failed to create thread specific key: %s\n",
                    strerror(err));
        else
            fuse_set_getcontext_func(mt_getcontext);
    }
    if (!err)
        context_ref ++;
    pthread_mutex_unlock(&context_lock);
    return err;
}

static void mt_delete_context_key(void)
{
    pthread_mutex_lock(&context_lock);
    context_ref--;
    if (!context_ref) {
        fuse_set_getcontext_func(NULL);
        free(pthread_getspecific(context_key));
        pthread_key_delete(context_key);
    }
    pthread_mutex_unlock(&context_lock);
}

struct procdata {
    struct fuse *f;
    struct fuse_chan *prevch;
    struct fuse_session *prevse;
    fuse_processor_t proc;
    void *data;
};

static void mt_session_proc(void *data, const char *buf, size_t len,
                            struct fuse_chan *ch)
{
    struct procdata *pd = (struct procdata *) data;
    struct fuse_cmd *cmd = *(struct fuse_cmd **) buf;

    (void) len;
    cmd->ch = ch;
    pd->proc(pd->f, cmd, pd->data);
}

static void mt_session_exit(void *data, int val)
{
    struct procdata *pd = (struct procdata *) data;
    if (val)
        fuse_session_exit(pd->prevse);
    else
        fuse_session_reset(pd->prevse);
}

static int mt_session_exited(void *data)
{
    struct procdata *pd = (struct procdata *) data;
    return fuse_session_exited(pd->prevse);
}

static int mt_chan_receive(struct fuse_chan *ch, char *buf, size_t size)
{
    struct fuse_cmd *cmd;
    struct procdata *pd = (struct procdata *) fuse_chan_data(ch);

    assert(size >= sizeof(cmd));

    cmd = fuse_read_cmd(pd->f);
    if (cmd == NULL)
        return 0;

    *(struct fuse_cmd **) buf = cmd;

    return sizeof(cmd);
}

static int mt_chan_send(struct fuse_chan *ch, const struct iovec iov[],
                        size_t count)
{
    struct procdata *pd = (struct procdata *) fuse_chan_data(ch);
    return fuse_chan_send(pd->prevch, iov, count);
}

int fuse_loop_mt_proc(struct fuse *f, fuse_processor_t proc, void *data)
{
    int res;
    struct procdata pd;
    struct fuse_session *prevse = fuse_get_session(f);
    struct fuse_session *se;
    struct fuse_chan *prevch = fuse_session_next_chan(prevse, NULL);
    struct fuse_chan *ch;
    struct fuse_session_ops sop = {
        .exit = mt_session_exit,
        .exited = mt_session_exited,
        .process = mt_session_proc,
    };
    struct fuse_chan_ops cop = {
        .receive = mt_chan_receive,
        .send = mt_chan_send,
    };

    pd.f = f;
    pd.prevch = prevch;
    pd.prevse = prevse;
    pd.proc = proc;
    pd.data = data;

    se = fuse_session_new(&sop, &pd);
    if (se == NULL)
        return -1;

    ch = fuse_chan_new(&cop, fuse_chan_fd(prevch), sizeof(struct fuse_cmd *),
                       &pd);
    if (ch == NULL) {
        fuse_session_destroy(se);
        return -1;
    }
    fuse_session_add_chan(se, ch);

    if (mt_create_context_key() != 0) {
        fuse_session_destroy(se);
        return -1;
    }

    res = fuse_session_loop_mt(se);

    mt_delete_context_key();
    fuse_session_destroy(se);
    return res;
}

int fuse_loop_mt(struct fuse *f)
{
    int res;

    if (f == NULL)
        return -1;

    if (mt_create_context_key() != 0)
        return -1;

    res = fuse_session_loop_mt(fuse_get_session(f));

    mt_delete_context_key();
    return res;
}

__asm__(".symver fuse_loop_mt_proc,__fuse_loop_mt@");
