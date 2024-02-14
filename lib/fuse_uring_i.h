/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
                2022       Bernd Schubert <bschubert@ddn.com>
  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

struct fuse_ring_queue;
struct io_uring_cqe;

int send_reply_uring(fuse_req_t req, int error, const void *arg,
		      size_t argsize);
int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags);
int fuse_send_msg_uring(fuse_req_t req, struct iovec *iov, int count);

int fuse_uring_queue_handle_cqes(int qid, void *ring_pool);
int fuse_uring_submit_sqes(int qid, void *ring_pool, bool blocking);
int fuse_uring_init_queue(int qid, void *ring_pool);


void
fuse_session_process_uring_cqe(struct fuse_session *se, struct fuse_req *req,
                               struct fuse_in_header *in,
                               void *inarg, size_t in_arg_len);

int fuse_uring_start(struct fuse_session *se,
			     struct fuse_loop_config *config);
