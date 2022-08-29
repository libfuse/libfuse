/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
                2022       Bernd Schubert <bschubert@ddn.com>

  Implementation of (most of) the low-level FUSE API. The session loop
  functions are implemented in separate files.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#define _GNU_SOURCE

#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_lowlevel_i.h"
#include "fuse_uring_i.h"

#include <stdlib.h>
#include <liburing.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <numa.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/ioctl.h>

/**
 *  Size of the bulk data ring buffer
 * Different (smaller) values might be possible later, if zerocopy can
 * be implemented
 */
#define FUSE_RING_DATA_BUF_SIZE 1024 * 1024


/* defined somewhere in uring? */
#define FUSE_URING_MAX_SQE128_CMD_DATA 80

#define container_of(ptr, type, member) ({                              \
	unsigned long __mptr = (unsigned long)(ptr);                    \
	((type *)(__mptr - offsetof(type, member))); })


#define ROUND_UP(val, round_to) \
	(((val) + (round_to - 1)) & ~(round_to - 1))

/* Should be ideally in fuse_uring_i.h, but would cause a circular dependency */
struct fuse_ring_req {
	struct fuse_ring_queue *ring_queue; /* back pointer */
	struct fuse_req req;

	struct fuse_uring_buf_req *req_buf;

	int tag;
};

struct fuse_ring_queue {

	struct fuse_ring_pool *ring_pool; /* back pointer */

	unsigned int cmd_inflight; /* SQs sent to the kernel */

	int fd; /* dup of se->fd */

	int q_id;
	int numa_node;
	pthread_t tid;

	struct io_uring ring;

	/* size depends on queue depth */
	struct fuse_ring_req req[];
} ;

struct fuse_ring_pool {
	struct fuse_session *se;

	bool   per_core_queue;
	size_t num_queues;  /* number of queues */
	size_t queue_depth; /* number of per queue entries */
	size_t req_buf_size;

	struct fuse_ring_queue queue[];
};

/**
 * return a pointer to the 80B area
 */
static inline void *fuse_uring_get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (void *)&sqe->cmd[0];
}

static void fuse_uring_sqe_set_req_data(struct fuse_uring_cmd_req *req,
					const unsigned int qid,
					const unsigned int tag,
					void *addr, int addr_len)
{
	req->q_id = qid;
	req->tag = tag;
	req->req_buf = (uint64_t)addr;
	req->req_buf_len = addr_len;
}

static void
fuse_uring_sqe_prepare(struct io_uring_sqe *sqe, struct fuse_ring_req *req,
		       __u32 cmd_op)
{
	/* These fields should be written once, never change */
	sqe->opcode = IORING_OP_URING_CMD;

	/* IOSQE_FIXED_FILE: fd is the index to the fd *array*
	 * given to io_uring_register_files()  */
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->fd = 0;

	sqe->rw_flags = 0;
	sqe->ioprio = 0;
	sqe->off = 0;

	io_uring_sqe_set_data(sqe, req);

	sqe->cmd_op = cmd_op;
	sqe->__pad1 = 0;
}

static int fuse_uring_commit_sqe(struct fuse_ring_pool *ring_pool,
				 struct fuse_ring_queue *queue,
				 struct fuse_ring_req *ring_req)
{
	struct fuse_session *se = ring_pool->se;

	struct io_uring_sqe *sqe =
		io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		/* This is an impossible condition, unless there is a bug.
		 * The kernel sent back an SQEs, which is assigned to a request.
		 * There is no way to get out of SQEs, as the number of
		 * SQEs matches the number tof requests.
		 */

		se->error = -EIO;
		fuse_log(FUSE_LOG_ERR, "Failed to get a ring SQEs");

		return -EIO;
	}

	fuse_uring_sqe_prepare(sqe, ring_req, FUSE_URING_REQ_COMMIT_AND_FETCH);

	struct fuse_uring_buf_req *req_data = ring_req->req_buf;
	req_data->cmd = FUSE_RING_BUF_CMD_IOVEC;

	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
				    queue->q_id, ring_req->tag,
				    req_data, ring_pool->req_buf_size);

	/* leave io_uring_submit() to the main thread function */
	return 0;
}

int send_reply_uring(fuse_req_t req, int error, const void *arg,
		     size_t argsize)
{
	struct fuse_ring_req *ring_req =
		container_of(req, struct fuse_ring_req, req);

	struct fuse_ring_queue *queue = ring_req->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_buf_req *buf_req = ring_req->req_buf;
	size_t max_buf = sizeof(buf_req->in_out_arg) + ring_pool->req_buf_size;

	if (argsize > max_buf) {
		fuse_log(FUSE_LOG_ERR, "argsize %zu exceeds buffer size %zu",
			 argsize, max_buf);
		error = -EINVAL;
	}
	else if (argsize)
		memcpy(buf_req->in_out_arg, arg, argsize);
	buf_req->in_out_arg_len = argsize;
	fuse_log(FUSE_LOG_ERR, "argsize=%zu\n", argsize);

	struct fuse_out_header *out = &buf_req->out;
	out->error  = error;
	out->unique = req->unique;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_req);
}

int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags)
{
	struct fuse_ring_req *ring_req =
		container_of(req, struct fuse_ring_req, req);

	struct fuse_ring_queue *queue = ring_req->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_buf_req *buf_req = ring_req->req_buf;
	size_t max_buf = sizeof(buf_req->in_out_arg) + ring_pool->req_buf_size;
	struct fuse_bufvec dest_vec = FUSE_BUFVEC_INIT(max_buf);
	int res;

	dest_vec.buf[0].mem = buf_req->in_out_arg;
	dest_vec.buf[0].size = max_buf;

	res = fuse_buf_copy(&dest_vec, bufv, flags);

	struct fuse_out_header *out = &buf_req->out;
	out->error  = res < 0 ? res : 0;
	out->unique = req->unique;

	buf_req->in_out_arg_len = res > 0 ? res : 0;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_req);
}

/**
 * Copy the iov into the ring buffer and submit and commit/fetch sqe
 */
int fuse_send_msg_uring(fuse_req_t req, struct iovec *iov, int count)
{
	struct fuse_ring_req *ring_req =
		container_of(req, struct fuse_ring_req, req);

	struct fuse_ring_queue *queue = ring_req->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_buf_req *buf_req = ring_req->req_buf;
	size_t max_buf = sizeof(buf_req->in_out_arg) + ring_pool->req_buf_size;
	size_t off = 0;
	int res = 0;

	for (int idx = 0; idx < count; idx++) {
		struct iovec *cur = &iov[idx];

		if (off + cur->iov_len > max_buf) {
			fuse_log(FUSE_LOG_ERR,
				 "iov[%d] exceeds buffer size %zu",
				 idx, max_buf);
			res = -EINVAL; /* Gracefully handle this? */
			break;
		}

		memcpy(buf_req->in_out_arg + off, cur->iov_base, cur->iov_len);
		off += cur->iov_len;
	}

	buf_req->in_out_arg_len = off;
	fuse_log(FUSE_LOG_ERR, "res=%d off=%zu\n", res, off);

	struct fuse_out_header *out = &buf_req->out;
	out->error  = res;
	out->unique = req->unique;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_req);
}

static void
fuse_uring_handle_cqe(struct fuse_ring_queue *queue,
		      struct io_uring_cqe *cqe)
{
	struct fuse_ring_req *ring_req = io_uring_cqe_get_data(cqe);
	struct fuse_req *req = &ring_req->req;
	struct fuse_ring_pool *fuse_ring = queue->ring_pool;
	struct fuse_uring_buf_req *req_buf = ring_req->req_buf;

	struct fuse_in_header *in = &ring_req->req_buf->in;

	void *inarg = req_buf->in_out_arg;

	req->is_uring = true;
	req->ch = NULL; /* not needed for uring */

	fuse_session_process_uring_cqe(fuse_ring->se, req, in, inarg,
				       req_buf->in_out_arg_len);
}


static int fuse_setup_ring(struct io_uring *ring, size_t qid,
			   size_t depth, int fd)
{
	int rc;
	struct io_uring_params params = {0};

	int files[1] = {fd};


	params.flags =
		IORING_SETUP_CQSIZE | IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	params.cq_entries = depth;

	rc = io_uring_queue_init_params(depth, ring, &params);
	if (rc != 0) {
		rc = -errno;
		fuse_log(FUSE_LOG_ERR, "Failed to setup qid %zu: %s\n",
			 qid, strerror(errno));
		return rc;
	}

	rc = io_uring_register_files(ring, files, 1);
	if (rc != 0) {
		rc = -errno;
		fuse_log(FUSE_LOG_ERR, "Failed to register files for "
			 "ring idx %zu: %s", qid, strerror(errno));
		return rc;
	}

	return 0;
}

#if 0
static inline struct io_uring_sqe *
fuse_uring_get_sqe(struct io_uring *ring, int idx, bool is_sqe128)
{
	if (is_sqe128)
		return  &ring->sq.sqes[idx *= 2];
	return  &ring->sq.sqes[idx];
}
#endif

/**
 * Prepare fuse-kernel for uring
 */
static int
fuse_setup_configure_kernel(struct fuse_session *se,
			    struct fuse_loop_config *cfg, size_t n_queues,
			    size_t req_buf_size)
{
	int rc;

	struct fuse_uring_cfg ioc_cfg = {
		.compat_flags = 0,
		.num_queues = n_queues,
		.per_core_queue = cfg->uring.per_core_queue,
		.queue_depth = cfg->uring.queue_depth,
		.mmap_req_size = req_buf_size,
	};

	rc = ioctl(se->fd, FUSE_DEV_IOC_URING, &ioc_cfg);
	if (rc != 0) {
		if (errno == ENOTTY)
			fuse_log(FUSE_LOG_INFO, "Kernel does not support fuse uring\n");
		else
			fuse_log(FUSE_LOG_ERR,
				"Unexpected kernel uring ioctl result: %s\n",
				strerror(errno));
		return -1;
	}

	return 0;
}

static void fuse_session_destruct_uring(struct fuse_ring_pool *fuse_ring)
{
	for (size_t qid = 0; qid < fuse_ring->num_queues; qid++) {
		struct fuse_ring_queue *queue = &fuse_ring->queue[qid];

		if (queue->fd != -1)
			close(queue->fd);

		if (queue->ring.ring_fd != -1)
			close(queue->ring.ring_fd);

		for (int tag = 0; tag < fuse_ring->queue_depth; tag++) {
			struct fuse_ring_req *req = &queue->req[tag];
			munmap(req->req_buf, fuse_ring->req_buf_size);
		}
	}


	free(fuse_ring);
}

static size_t
fuse_ring_queue_size(const size_t n_queues, const size_t q_depth)
{
	/* FIXME: q_req_size not right + 1 not needed */
	const size_t q_req_size = sizeof(struct fuse_ring_req) * (q_depth + 1);
	const size_t fuse_ring_req_size =
		n_queues * (sizeof(struct fuse_ring_queue) + q_req_size);

	return fuse_ring_req_size;
}

static struct fuse_ring_pool *
fuse_create_user_ring(struct fuse_session *se,
		      struct fuse_loop_config *cfg)
{
	int rc;
	const size_t page_size = getpagesize();
	const size_t n_queues = cfg->uring.per_core_queue ? get_nprocs() : 1;
	const size_t q_depth = cfg->uring.queue_depth;

	const size_t ring_data_buf_size = FUSE_RING_DATA_BUF_SIZE;

	const size_t req_buf_size =
		ROUND_UP(sizeof(struct fuse_uring_buf_req) + ring_data_buf_size,
			 page_size);

	rc = fuse_setup_configure_kernel(se, cfg, 1, req_buf_size);
	if (rc != 0)
		return NULL;

	size_t ring_queue_sz = fuse_ring_queue_size(n_queues, q_depth);

	struct fuse_ring_pool *fuse_ring =
		calloc(1, sizeof(fuse_ring) + ring_queue_sz);
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}

	fuse_ring->se = se;
	fuse_ring->num_queues = n_queues;
	fuse_ring->queue_depth = q_depth;
	fuse_ring->per_core_queue = cfg->uring.per_core_queue;

	/* very basic queue initialization */
	for (int qid = 0; qid < n_queues; qid++) {
		struct fuse_ring_queue *queue = &fuse_ring->queue[qid];
		queue->fd = -1;
		queue->ring.ring_fd = -1;
		queue->numa_node = -1;
		queue->q_id = -1;
		queue->ring_pool = fuse_ring;

		for (int tag = 0; tag < q_depth; tag++) {
			struct fuse_ring_req *ring_req = &queue->req[0];
			ring_req->ring_queue = queue;
			ring_req->tag = tag;

			/* Allocate one big chunk of memory, which will be divided into per
			 * request buffers
			 */
			const int prot =  PROT_READ | PROT_WRITE;
			const int flags = MAP_SHARED_VALIDATE | MAP_POPULATE;

			ring_req->req_buf = mmap(NULL, req_buf_size, prot,
						 flags, se->fd,
						 tag + qid * n_queues);
			if (ring_req->req_buf == MAP_FAILED) {
				fuse_log(FUSE_LOG_ERR,
					 "qid=%d tag=%d mmap of size %zu failed");
				goto err;
			}

			struct fuse_req *req = &ring_req->req;
			req->se = se;
			pthread_mutex_init(&req->lock, NULL);
			req->is_uring = true;
		}
	}

	for (int qid = 0; qid < n_queues; qid++) {
		struct fuse_ring_queue *queue = &fuse_ring->queue[qid];

		fprintf(stderr, "%s:%d qid=%d here\n", __func__, __LINE__, qid);

		queue->q_id = qid;

		queue->fd = dup(se->fd);
		if (queue->fd == -1) {
			fuse_log(FUSE_LOG_ERR, "Session fd dup failed: %s\n",
				 strerror(errno));
			goto err;
		}

		rc = fuse_setup_ring(&queue->ring, qid, fuse_ring->queue_depth,
				     queue->fd);

		if (rc != 0) {
			fuse_log(FUSE_LOG_ERR, "qid=%d uring init failed\n",
				 strerror(errno));
			goto err;
		}

		for (int tag = 0; tag < q_depth; tag++) {
			struct fuse_ring_req *req = &queue->req[tag];

			if (fuse_ring->per_core_queue) {
				/* qid also the cpu core */
				queue->numa_node = numa_node_of_cpu(qid);
				numa_tonode_memory(req->req_buf, req_buf_size,
						   queue->numa_node);
			}
		}
	}

	return fuse_ring;

err:
	if (fuse_ring)
		fuse_session_destruct_uring(fuse_ring);

	return NULL;

}

static void *fuse_uring_thread(void *arg)
{
	struct fuse_ring_queue *queue = arg;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	int tag;
	int res;

	if (ring_pool->per_core_queue)
		numa_run_on_node(queue->q_id); // qid == core index

	char thread_name[16] = { 0 };
	snprintf(thread_name, 16, "fuse-ring-%d", queue->q_id);
	thread_name[15] = '\0';
	pthread_setname_np(queue->tid, thread_name);

	for (tag = 0; tag < ring_pool->queue_depth; tag++) {
		struct fuse_ring_req *req = &queue->req[tag];

		struct io_uring_sqe *sqe =
			io_uring_get_sqe(&queue->ring);
		if (sqe == NULL) {

			/* All SQEs are idle here - no good reason this
			 * could fail
			 */

			fuse_log(FUSE_LOG_ERR, "Failed to get all ring SQEs");
			goto err;
		}

		if (req->tag != tag) {
			fuse_log(FUSE_LOG_ERR, "tag mismatch, got %d expected %d\n");
			goto err;
		}


		fuse_uring_sqe_prepare(sqe, req, FUSE_URING_REQ_FETCH);
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->q_id, req->tag,
					    req->req_buf, ring_pool->req_buf_size);
	}

	res = io_uring_sq_ready(&queue->ring);
	if (res != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR, "SQE ready mismatch, expected %d got %d\n",
			 ring_pool->queue_depth, res);
		goto err;
	}

	res = io_uring_submit(&queue->ring);
	if (res != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR, "SQE submit mismatch, expected %d got %d\n",
			 ring_pool->queue_depth, res);
		goto err;
	}

	while (!se->exited) {
		struct io_uring_cqe *cqe;
//		unsigned head;
//		unsigned int count = 0;
		int ret;

		ret = io_uring_submit(&queue->ring);
		if (ret == -EINTR)
			continue;
		if (ret < 0) {
			fuse_log(FUSE_LOG_ERR,
				 "uring submit and wait failed %d\n", ret);
			goto err;
		}

		fuse_log(FUSE_LOG_ERR, "submit and wait: %d\n", ret);

		ret = io_uring_wait_cqe(&queue->ring, &cqe);
		if (ret < 0) {
			fuse_log(FUSE_LOG_ERR, "cqe wait failed %d\n", ret);
			goto err;
		}

		if (cqe->res != 0) {
			fuse_log(FUSE_LOG_ERR, "cqe res: %d\n", cqe->res);
			goto err;
		}

		fuse_uring_handle_cqe(queue, cqe);
		io_uring_cqe_seen(&queue->ring, cqe);

#if 0
		io_uring_for_each_cqe(&queue->ring, head, cqe) {

			fuse_uring_handle_cqe(queue, cqe);

			/* Unsure which is better - submit all at once or
			* submit one by one. The former has less overhead,
			* the latter has less latency.
			* XXX: Multiple queues per code - fast queue and
			*      async queue?
			*/
			io_uring_submit(&queue->ring);
			count += 1;
		}
		io_uring_cq_advance(&queue->ring, count);
		io_uring_submit_and_wait(&queue->ring, 1);
#endif
	}

	return NULL;

err:
	se->error = -EIO;
	se->exited = 1;
	return NULL;
}

static int fuse_session_run_uring(struct fuse_ring_pool *fuse_ring)
{
	for (int qid = 0; qid < fuse_ring->num_queues; qid++) {
		struct fuse_ring_queue *queue = &fuse_ring->queue[qid];
		pthread_create(&queue->tid, NULL, fuse_uring_thread, queue);
	}

	for (int qid = 0; qid < fuse_ring->num_queues; qid++) {
		struct fuse_ring_queue *queue = &fuse_ring->queue[qid];
		pthread_join(queue->tid, NULL);
	}

	return 0;
}

static int fuse_session_sanity_check(void)
{
	_Static_assert(sizeof(struct fuse_uring_cmd_req) <=
		       FUSE_URING_MAX_SQE128_CMD_DATA,
		       "SQE128_CMD_DATA has 80B cmd data");

	return 0;
}

int fuse_session_start_uring(struct fuse_session *se,
			     struct fuse_loop_config *config)
{
	int rc;
	struct fuse_ring_pool *fuse_ring;

	se->is_uring = true;

	fuse_session_sanity_check();

	fuse_ring = fuse_create_user_ring(se, config);
	if (fuse_ring == NULL) {
		rc = EADDRNOTAVAIL;
		goto out;
	}

	rc = fuse_session_run_uring(fuse_ring);

out:
	if (fuse_ring != NULL)
		fuse_session_destruct_uring(fuse_ring);

	if (rc != 0)
		se->is_uring = false;


	return rc;
}


