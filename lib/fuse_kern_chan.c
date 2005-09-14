/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "fuse_lowlevel.h"
#include "fuse_kernel.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

static int fuse_kern_chan_receive(struct fuse_chan *ch, char *buf, size_t size)
{
    ssize_t res = read(fuse_chan_fd(ch), buf, size);
    int err = errno;
    struct fuse_session *se = fuse_chan_session(ch);

    assert(se != NULL);
    if (fuse_session_exited(se))
        return 0;
    if (res == -1) {
        /* EINTR means, the read() was interrupted, ENOENT means the
           operation was interrupted */
        if (err == EINTR || err == ENOENT)
            return 0;
        /* ENODEV means we got unmounted, so we silenty return failure */
        if (err != ENODEV)
            perror("fuse: reading device");
        return -1;
    }
    if ((size_t) res < sizeof(struct fuse_in_header)) {
        fprintf(stderr, "short read on fuse device\n");
        return -1;
    }
    return res;
}

static int fuse_kern_chan_send(struct fuse_chan *ch, const struct iovec iov[],
                               size_t count)
{
    ssize_t res = writev(fuse_chan_fd(ch), iov, count);
    int err = errno;

    if (res == -1) {
        struct fuse_session *se = fuse_chan_session(ch);

        assert(se != NULL);

        /* ENOENT means the operation was interrupted */
        if (!fuse_session_exited(se) && err != ENOENT)
            perror("fuse: writing device");
        return -err;
    }
    return 0;
}

static void fuse_kern_chan_destroy(struct fuse_chan *ch)
{
    close(fuse_chan_fd(ch));
}

struct fuse_chan *fuse_kern_chan_new(int fd)
{
    struct fuse_chan_ops op = {
        .receive = fuse_kern_chan_receive,
        .send = fuse_kern_chan_send,
        .destroy = fuse_kern_chan_destroy,
    };
    return fuse_chan_new(&op, fd, FUSE_MAX_IN, NULL);
}
