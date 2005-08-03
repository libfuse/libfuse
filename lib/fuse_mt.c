/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"
#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


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
        pthread_key_delete(context_key);
    }
    pthread_mutex_unlock(&context_lock);
}

struct procdata {
    struct fuse *f;
    fuse_processor_t proc;
    void *data;
};

static void mt_generic_proc(struct fuse_ll *f, struct fuse_cmd *cmd, void *data)
{
    struct procdata *pd = (struct procdata *) data;
    (void) f;
    pd->proc(pd->f, cmd, pd->data);
}

int fuse_loop_mt_proc(struct fuse *f, fuse_processor_t proc, void *data)
{
    int res;
    struct procdata pd;

    pd.f = f;
    pd.proc = proc;
    pd.data = data;

    if (mt_create_context_key() != 0)
        return -1;

    res = fuse_ll_loop_mt_proc(fuse_get_lowlevel(f), mt_generic_proc, &pd);

    mt_delete_context_key();
    return res;
}

int fuse_loop_mt(struct fuse *f)
{
    int res;

    if (mt_create_context_key() != 0)
        return -1;

    res = fuse_ll_loop_mt(fuse_get_lowlevel(f));

    mt_delete_context_key();
    return res;
}

__asm__(".symver fuse_loop_mt_proc,__fuse_loop_mt@");
