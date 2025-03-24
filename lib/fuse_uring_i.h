/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025       Bernd Schubert <bschubert@ddn.com>
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB
 */

#ifndef FUSE_URING_I_H_
#define FUSE_URING_I_H_

#include "fuse_config.h"
#include "fuse_lowlevel.h"
#include "fuse_kernel.h"

#ifndef HAVE_URING
#include "util.h"
#endif

void fuse_session_process_uring_cqe(struct fuse_session *se,
				    struct fuse_req *req,
				    struct fuse_in_header *in, void *in_header,
				    void *in_payload, size_t payload_len);

#ifdef HAVE_URING

struct fuse_in_header;

int fuse_uring_start(struct fuse_session *se);
int fuse_uring_stop(struct fuse_session *se);

#else // HAVE_URING

static inline int fuse_uring_start(struct fuse_session *se FUSE_VAR_UNUSED)
{
	return -ENOTSUP;
}

static inline int fuse_uring_stop(struct fuse_session *se FUSE_VAR_UNUSED)
{
	return -ENOTSUP;
}

#endif // HAVE_URING

#endif // FUSE_URING_I_H_
