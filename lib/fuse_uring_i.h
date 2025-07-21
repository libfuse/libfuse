/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025       Bernd Schubert <bschubert@ddn.com>
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt
 */

#ifndef FUSE_URING_I_H_
#define FUSE_URING_I_H_

#include "fuse_config.h"
#include "fuse_lowlevel.h"
#include "fuse_kernel.h"

#ifndef HAVE_URING
#include "util.h"
#endif

#include <errno.h> // IWYU pragma: keep

/* io-uring defaults */
#define SESSION_DEF_URING_ENABLE (0)
#define SESSION_DEF_URING_Q_DEPTH (8)

void fuse_session_process_uring_cqe(struct fuse_session *se,
				    struct fuse_req *req,
				    struct fuse_in_header *in, void *in_header,
				    void *in_payload, size_t payload_len);

#ifdef HAVE_URING

struct fuse_in_header;

int fuse_uring_start(struct fuse_session *se);
void fuse_uring_wake_ring_threads(struct fuse_session *se);
int fuse_uring_stop(struct fuse_session *se);
int send_reply_uring(fuse_req_t req, int error, const void *arg,
		     size_t argsize);

int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
			  enum fuse_buf_copy_flags flags);
int fuse_send_msg_uring(fuse_req_t req, struct iovec *iov, int count);

#else // HAVE_URING

static inline int fuse_uring_start(struct fuse_session *se FUSE_VAR_UNUSED)
{
	return -ENOTSUP;
}

static inline void
fuse_uring_wake_ring_threads(struct fuse_session *se FUSE_VAR_UNUSED)
{
}

static inline int fuse_uring_stop(struct fuse_session *se FUSE_VAR_UNUSED)
{
	return -ENOTSUP;
}

static inline int send_reply_uring(fuse_req_t req FUSE_VAR_UNUSED,
				   int error FUSE_VAR_UNUSED,
				   const void *arg FUSE_VAR_UNUSED,
				   size_t argsize FUSE_VAR_UNUSED)
{
	return -ENOTSUP;
}

static inline int
fuse_reply_data_uring(fuse_req_t req FUSE_VAR_UNUSED,
		      struct fuse_bufvec *bufv FUSE_VAR_UNUSED,
		      enum fuse_buf_copy_flags flags FUSE_VAR_UNUSED)
{
	return -ENOTSUP;
}

static inline int fuse_send_msg_uring(fuse_req_t req FUSE_VAR_UNUSED,
				      struct iovec *iov FUSE_VAR_UNUSED,
				      int count FUSE_VAR_UNUSED)
{
	return -ENOTSUP;
}

#endif // HAVE_URING

#endif // FUSE_URING_I_H_
