/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025       Bernd Schubert <bschubert@ddn.com>
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB
 */

#ifndef FUSE_URING_I_H_
#define FUSE_URING_I_H_

#include "fuse_lowlevel.h"

/* io-uring defaults */
#define SESSION_DEF_URING_ENABLE (0)
#define SESSION_DEF_URING_Q_DEPTH (8)

struct fuse_in_header;

int fuse_uring_start(struct fuse_session *se);
int fuse_uring_stop(struct fuse_session *se);

void fuse_session_process_uring_cqe(struct fuse_session *se,
				    struct fuse_req *req,
				    struct fuse_in_header *in, void *in_header,
				    void *in_payload, size_t payload_len);

int send_reply_uring(fuse_req_t req, int error, const void *arg,
		     size_t argsize);

int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
			  enum fuse_buf_copy_flags flags);
int fuse_send_msg_uring(fuse_req_t req, struct iovec *iov, int count);

#endif // FUSE_URING_I_H_
