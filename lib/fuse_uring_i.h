/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025       Bernd Schubert <bschubert@ddn.com>
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB
 */

#ifndef FUSE_URING_I_H_
#define FUSE_URING_I_H_

#include "fuse_lowlevel.h"

struct fuse_in_header;

int fuse_uring_start(struct fuse_session *se);
int fuse_uring_stop(struct fuse_session *se);

#endif // FUSE_URING_I_H_
