/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>

int fuse_session_loop(struct fuse_session *se)
{
    int res = 0;
    struct fuse_chan *ch = fuse_session_next_chan(se, NULL);
    size_t bufsize = fuse_chan_bufsize(ch);
    char *buf = (char *) malloc(bufsize);
    if (!buf) {
        fprintf(stderr, "fuse: failed to allocate read buffer\n");
        return -1;
    }

    while (!fuse_session_exited(se)) {
        res = fuse_chan_receive(ch, buf, bufsize);
        if (!res)
            continue;
        if (res == -1)
            break;
        fuse_session_process(se, buf, res, ch);
        res = 0;
    }

    free(buf);
    fuse_session_reset(se);
    return res;
}
