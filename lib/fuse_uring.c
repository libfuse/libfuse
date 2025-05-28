/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
                2022-2024  Bernd Schubert <bschubert@ddn.com>

  Implementation of (most of) the low-level FUSE API. The session loop
  functions are implemented in separate files.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#define _GNU_SOURCE

#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_uring_i.h"
#include "util.h"

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
#include <linux/sched.h>
#include <poll.h>
#include <sys/eventfd.h>

/* defined somewhere in uring? */
#define FUSE_URING_MAX_SQE128_CMD_DATA 80

#define container_of(ptr, type, member) ({                              \
	unsigned long __mptr = (unsigned long)(ptr);                    \
	((type *)(__mptr - offsetof(type, member))); })


#define ROUND_UP(val, round_to) \
	(((val) + (round_to - 1)) & ~(round_to - 1))

/* Should be ideally in fuse_uring_i.h, but would cause a circular dependency */
struct fuse_ring_ent {
	struct fuse_ring_queue *ring_queue; /* back pointer */
	struct fuse_req req;

	struct fuse_uring_req_header *req_header;
	size_t req_header_sz;
	void *op_payload;
	size_t req_payload_sz;

	/* commit id of a fuse request */
	uint64_t req_commit_id;

	struct iovec iov[2]; /* header and payload */

	/*
	 * Optional memory registration handle for the payload buffer.
	 * Used by transports that require registered memory for data transfers.
	 * For example: RDMA (via ibv_reg_mr), but could be used by other
	 * mechanisms that need memory registration.
	 */
	void *payload_mr;
};

struct fuse_ring_queue {

	struct fuse_ring_pool *ring_pool; /* back pointer */

	unsigned int cmd_inflight; /* SQs sent to the kernel */

	int fd; /* dup of se->fd */

	int qid;
	int numa_node;
	pthread_t tid;
	int eventfd;

	struct io_uring ring;

	/* size depends on queue depth */
	struct fuse_ring_ent ent[];
};

/**
 * Main fuse_ring structure, holds all fuse-ring data
 */
struct fuse_ring_pool {
	struct fuse_session *se;

	size_t nr_queues;  /* number of queues */
	size_t queue_depth; /* number of per queue entries */
	size_t max_req_payload_sz;
	size_t queue_mem_size;
	struct fuse_ring_queue *queues;
};

static size_t
fuse_ring_queue_size(const size_t q_depth)
{
	const size_t req_size = sizeof(struct fuse_ring_ent) * q_depth;
	return sizeof(struct fuse_ring_queue) + req_size;
}

static struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_ring_pool *fuse_ring, int qid)
{
	char *ptr =
		((char *)fuse_ring->queues) + (qid * fuse_ring->queue_mem_size);

	return (struct fuse_ring_queue *)ptr;
}

/**
 * return a pointer to the 80B area
 */
static void *fuse_uring_get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (void *)&sqe->cmd[0];
}

static void fuse_uring_sqe_set_req_data(struct fuse_uring_cmd_req *req,
					const unsigned int qid,
					const unsigned int commit_id)
{
	req->qid = qid;
	req->commit_id = commit_id;
	req->flags = 0;
}

static void
fuse_uring_sqe_prepare(struct io_uring_sqe *sqe, struct fuse_ring_ent *req,
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
				 struct fuse_ring_ent *ring_ent)
{
	struct fuse_session *se = ring_pool->se;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;

	struct io_uring_sqe *sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		/* This is an impossible condition, unless there is a bug.
		 * The kernel sent back an SQEs, which is assigned to a request.
		 * There is no way to get out of SQEs, as the number of
		 * SQEs matches the number tof requests.
		 */

		se->error = -EIO;
		fuse_log(FUSE_LOG_ERR, "Failed to get a ring SQEs\n");

		return -EIO;
	}

	fuse_uring_sqe_prepare(sqe, ring_ent,
			       FUSE_IO_URING_CMD_COMMIT_AND_FETCH);

	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe), queue->qid,
				    ring_ent->req_commit_id);

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "    unique: %llu, result=%d\n",
			 out->unique, ent_in_out->payload_sz);
	}

	/* XXX: This needs to be a ring config option */
	io_uring_submit(&queue->ring);

	return 0;
}

int fuse_req_get_payload(fuse_req_t req, void **payload, size_t *payload_sz,
			 void **mr)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	/* Not possible without io-uring interface */
	if (!req->is_uring)
		return -EINVAL;

	*payload = ring_ent->op_payload;
	*payload_sz = ring_ent->req_payload_sz;

	/*
	 * For now unused, but will be used later when the application can
	 * allocate the buffers itself and register them for rdma.
	 */
	if (mr)
		*mr = ring_ent->payload_mr;

	return 0;
}

int send_reply_uring(fuse_req_t req, int error, const void *arg, size_t argsize)
{
	int res;
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	size_t max_payload_sz = ring_pool->max_req_payload_sz;

	if (argsize > max_payload_sz) {
		fuse_log(FUSE_LOG_ERR, "argsize %zu exceeds buffer size %zu",
			 argsize, max_payload_sz);
		error = -EINVAL;
	} else if (argsize) {
		if (arg != ring_ent->op_payload)
			memcpy(ring_ent->op_payload, arg, argsize);
	}
	ent_in_out->payload_sz = argsize;

	out->error  = error;
	out->unique = req->unique;

	res = fuse_uring_commit_sqe(ring_pool, queue, ring_ent);

	fuse_free_req(req);

	return res;
}

int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	size_t max_payload_sz = ring_ent->req_payload_sz;
	struct fuse_bufvec dest_vec = FUSE_BUFVEC_INIT(max_payload_sz);
	int res;

	dest_vec.buf[0].mem = ring_ent->op_payload;
	dest_vec.buf[0].size = max_payload_sz;

	res = fuse_buf_copy(&dest_vec, bufv, flags);

	out->error  = res < 0 ? res : 0;
	out->unique = req->unique;

	ent_in_out->payload_sz = res > 0 ? res : 0;

	res = fuse_uring_commit_sqe(ring_pool, queue, ring_ent);

	fuse_free_req(req);

	return res;
}

/**
 * Copy the iov into the ring buffer and submit and commit/fetch sqe
 */
int fuse_send_msg_uring(fuse_req_t req, struct iovec *iov, int count)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	size_t max_buf = ring_pool->max_req_payload_sz;
	size_t off = 0;
	int res = 0;

	/* copy iov into the payload, idx=0 is the header section */
	for (int idx = 1; idx < count; idx++) {
		struct iovec *cur = &iov[idx];

		if (off + cur->iov_len > max_buf) {
			fuse_log(FUSE_LOG_ERR,
				 "iov[%d] exceeds buffer size %zu",
				 idx, max_buf);
			res = -EINVAL; /* Gracefully handle this? */
			break;
		}

		memcpy(ring_ent->op_payload + off, cur->iov_base, cur->iov_len);
		off += cur->iov_len;
	}

	ent_in_out->payload_sz = off;

	out->error  = res;
	out->unique = req->unique;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_ent);
}

static void
fuse_uring_handle_cqe(struct fuse_ring_queue *queue,
		      struct io_uring_cqe *cqe)
{
	struct fuse_ring_ent *ent = io_uring_cqe_get_data(cqe);

	if (!ent) {
		fuse_log(FUSE_LOG_ERR,
			 "cqe=%p io_uring_cqe_get_data returned NULL\n", cqe);
		return;
	}

	struct fuse_req *req = &ent->req;
	struct fuse_ring_pool *fuse_ring = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ent->req_header;

	struct fuse_in_header *in = (struct fuse_in_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;

	ent->req_commit_id = ent_in_out->commit_id;
	if (unlikely(ent->req_commit_id == 0)) {
		/*
		 * If this happens kernel will not find the response - it will
		 * be stuck forever - better to abort immediately.
		 */
		fuse_log(FUSE_LOG_ERR, "Received invalid commit_id=0\n");
		abort();
	}

	req->is_uring = true;
	req->ref_cnt++;
	req->ch = NULL; /* not needed for uring */

	fuse_session_process_uring_cqe(fuse_ring->se, req, in, &rrh->op_in,
				       ent->op_payload, ent_in_out->payload_sz);
}

static int fuse_queue_setup_io_uring(struct io_uring *ring, size_t qid,
				     size_t depth, int fd, int evfd)
{
	int rc;
	struct io_uring_params params = {0};
	int files[2] = { fd, evfd };

	depth += 1; /* for the eventfd poll SQE */

	params.flags = IORING_SETUP_SQE128;

	/* Avoid cq overflow */
	params.flags |= IORING_SETUP_CQSIZE;
	params.cq_entries = depth * 2;

	/* These flags should help to increase performance, but actually
	 * make it a bit slower - reason should get investigated.
	 */
	if (0) {
		/* Has the main slow down effect */
		params.flags |= IORING_SETUP_SINGLE_ISSUER;

		// params.flags |= IORING_SETUP_DEFER_TASKRUN;
		params.flags |= IORING_SETUP_TASKRUN_FLAG;

		/* Second main effect to make it slower */
		params.flags |= IORING_SETUP_COOP_TASKRUN;
	}

	rc = io_uring_queue_init_params(depth, ring, &params);
	if (rc != 0) {
		fuse_log(FUSE_LOG_ERR, "Failed to setup qid %zu: %d (%s)\n",
			 qid, rc, strerror(-rc));
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

static void free_payload(struct fuse_ring_ent *ent)
{
	struct fuse_ring_queue *queue = ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;

	if (se->uring.free_payload_buf)
		se->uring.free_payload_buf(ent->op_payload, ent->req_payload_sz,
					   ent->payload_mr);
	else
		numa_free(ent->op_payload, ent->req_payload_sz);
}

static void fuse_session_destruct_uring(struct fuse_ring_pool *fuse_ring)
{
	for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		if (queue->tid != 0)
			pthread_join(queue->tid, NULL);

		if (queue->fd != -1)
			close(queue->fd);

		if (queue->ring.ring_fd != -1)
			close(queue->ring.ring_fd);

		for (size_t idx = 0; idx < fuse_ring->queue_depth; idx++) {
			struct fuse_ring_ent *ent = &queue->ent[idx];

			free_payload(ent);
			numa_free(ent->req_header, ent->req_header_sz);
		}
	}

	free(fuse_ring->queues);
	free(fuse_ring);
}

static int fuse_uring_prepare_fetch_sqes(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	unsigned int sq_ready;
	struct io_uring_sqe *sqe;

	for (size_t idx = 0; idx < ring_pool->queue_depth; idx++) {
		struct fuse_ring_ent *ent = &queue->ent[idx];

		sqe = io_uring_get_sqe(&queue->ring);
		if (sqe == NULL) {

			/* All SQEs are idle here - no good reason this
			 * could fail
			 */

			fuse_log(FUSE_LOG_ERR, "Failed to get all ring SQEs");
			return -EIO;
		}

		fuse_uring_sqe_prepare(sqe, ent, FUSE_IO_URING_CMD_REGISTER);

		/* only needed for fetch */
		ent->iov[0].iov_base = ent->req_header;
		ent->iov[0].iov_len = ent->req_header_sz;

		ent->iov[1].iov_base = ent->op_payload;
		ent->iov[1].iov_len = ent->req_payload_sz;

		sqe->addr = (uint64_t)(ent->iov);
		sqe->len = 2;

		/* this is a fetch, kernel does not read commit id */
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, 0);
	}

	sq_ready = io_uring_sq_ready(&queue->ring);
	if (sq_ready != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR,
			 "SQE ready mismatch, expected %d got %d\n",
			 ring_pool->queue_depth, sq_ready);
		return -EINVAL;
	}

	// Add the poll SQE for the eventfd to wake up on teardown
	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to get eventfd SQE");
		return -EIO;
	}

	io_uring_prep_poll_add(sqe, queue->eventfd, POLLIN);
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)queue->eventfd);

	io_uring_submit(&queue->ring);
	/* */

	return 0;
}

static struct fuse_ring_pool *fuse_create_ring(struct fuse_session *se)
{
	struct fuse_ring_pool *fuse_ring = NULL;
	const size_t nr_queues = get_nprocs_conf();
	size_t payload_sz = se->bufsize - FUSE_BUFFER_HEADER_SIZE;

	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "starting io-uring q-depth=%d\n",
			 se->uring.q_depth);

	fuse_ring = calloc(1, sizeof(*fuse_ring));
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}

	size_t queue_sz = fuse_ring_queue_size(se->uring.q_depth);
	fuse_ring->queues = calloc(1, queue_sz * nr_queues);
	if (fuse_ring->queues == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the queues failed\n");
		goto err;
	}

	fuse_ring->se = se;
	fuse_ring->nr_queues = nr_queues;
	fuse_ring->queue_depth = se->uring.q_depth;
	fuse_ring->max_req_payload_sz = payload_sz;
	fuse_ring->queue_mem_size = queue_sz;

	/*
	 * very basic queue initialization, that cannot fail and will
	 * allow easy cleanup if something (like mmap) fails in the middle
	 * below
	 */
	for (size_t qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);
		queue->fd = -1;
		queue->ring.ring_fd = -1;
		queue->numa_node = numa_node_of_cpu(qid);
		queue->qid = qid;
		queue->ring_pool = fuse_ring;
	}

	for (size_t qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
				fuse_uring_get_queue(fuse_ring, qid);

		/*
		 * file descriptor per queue is a protocol requirement
		 */
		queue->fd = fcntl(se->fd, F_DUPFD_CLOEXEC, 0);
		if (queue->fd == -1) {
			fuse_log(FUSE_LOG_ERR, "Session fd dup failed: %s\n",
				 strerror(errno));
			goto err;
		}
	}

	return fuse_ring;

err:
	if (fuse_ring)
		fuse_session_destruct_uring(fuse_ring);

	return NULL;
}

/**
 * In per-core-queue configuration we have thread per core - the thread
 * to that core
 */
static void fuse_uring_set_thread_core(int qid)
{
	cpu_set_t mask;
	int rc;
	const int policy = SCHED_IDLE;
	const struct sched_param param = {
		.sched_priority = sched_get_priority_min(policy),
	};

	CPU_ZERO(&mask);
	CPU_SET(qid, &mask);

	rc = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if (rc != 0)
		fuse_log(FUSE_LOG_ERR, "Failed to bind qid=%d to its core: %s\n",
			 qid, strerror(errno));

	/* Set the lowest possible priority, so that the application submitting
	 * requests is not moved away from the current core.
	 */
	rc = sched_setscheduler(0, policy, &param);
	if (rc != 0)
		fuse_log(FUSE_LOG_ERR, "Failed to set scheduler: %s\n",
			 strerror(errno));
}

static int _fuse_uring_queue_handle_cqes(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	size_t num_completed = 0;
	struct io_uring_cqe *cqe;
	unsigned int head;
	int ret = 0;

	io_uring_for_each_cqe(&queue->ring, head, cqe) {
		int err = 0;

		num_completed++;

		err = cqe->res;
		if (err != 0) {
			if (err > 0 && ((uintptr_t)io_uring_cqe_get_data(cqe) ==
					(unsigned)queue->eventfd)) {
				/* teardown from eventfd */
				return -ENOTCONN;
			}

			// XXX: Needs rate limited logs, otherwise log spam
			//fuse_log(FUSE_LOG_ERR, "cqe res: %d\n", cqe->res);

			if (err != -EINTR && err != -EOPNOTSUPP &&
			    err != -EAGAIN) {
				se->error = cqe->res;

				/* return first error */
				if (ret == 0)
					ret = err;
			}

		} else {
			fuse_uring_handle_cqe(queue, cqe);
		}
	}

	if (num_completed)
		io_uring_cq_advance(&queue->ring, num_completed);

	return ret == 0 ? 0 : num_completed;
}

/**
 * CQE handler for external ring thread
 * Example, an external thread is using poll() on the ring fd, gets woken up
 * wants to handle CQEs
 */
int fuse_uring_queue_handle_cqes(int qid, void *ring_pool)
{
	struct fuse_ring_queue *queue = fuse_uring_get_queue(ring_pool, qid);
	if (queue == NULL)
		return -EIO;

	return _fuse_uring_queue_handle_cqes(queue);
}

/*
 * Submit SQEs - SQEs have the result of a CQE and will then be hold in kernel
 * waiting for the next fuse request, which is submitted from kernel to
 * userspace/server as CQE.
 */
static int _fuse_uring_submit(struct fuse_ring_queue *queue, bool blocking)
{
	/* either non-blocking (wait_nr = 0) or waiting for exactly one
	 * fuse requests. Waiting for more is not possible, as that request
	 * might never come - application might need to wait for completion
	 * of that request.
	 */
	unsigned int wait_nr = blocking ? 1 : 0;
	int res;

	res = io_uring_submit_and_wait(&queue->ring, wait_nr);

	return res;
}

int fuse_uring_submit_sqes(int qid, void *ring_pool, bool blocking)
{
	struct fuse_ring_queue *queue = fuse_uring_get_queue(ring_pool, qid);
	if (queue == NULL)
		return -EIO;

	return _fuse_uring_submit(queue, blocking);
}

/*
 * @return negative error code or io-uring file descriptor
 */
static int _fuse_uring_init_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring = queue->ring_pool;
	struct fuse_session *se = ring->se;
	int res;
	size_t page_sz = sysconf(_SC_PAGESIZE);

	queue->eventfd = eventfd(0, EFD_CLOEXEC);
	if (queue->eventfd < 0) {
		res = -errno;
		fuse_log(FUSE_LOG_ERR,
			 "Failed to create eventfd for qid %d: %s\n",
			 queue->qid, strerror(errno));
		return res;
	}

	res = fuse_queue_setup_io_uring(&queue->ring, queue->qid,
					ring->queue_depth, queue->fd,
					queue->eventfd);
	if (res != 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d io_uring init failed\n",
			 queue->qid);
		goto err;
	}

	for (size_t idx = 0; idx < ring->queue_depth; idx++) {
		struct fuse_ring_ent *ring_ent = &queue->ent[idx];
		ring_ent->ring_queue = queue;
		struct fuse_req *req = &ring_ent->req;

		/*
		 * Also allocate the header to have it page aligned, which
		 * is a requirement for page pinning
		 */
		size_t header_sz = sizeof(*ring_ent->req_header);
		ring_ent->req_header_sz = ROUND_UP(header_sz, page_sz);
		ring_ent->req_header =
			numa_alloc_local(ring_ent->req_header_sz);
		ring_ent->req_payload_sz = ring->max_req_payload_sz;

		/*
		 * The application might want to allocate the payload on
		 * on its own, for example to register RDMA memory.
		 */
		if (se->uring.alloc_payload)
			ring_ent->op_payload = se->uring.alloc_payload(
				ring_ent->req_payload_sz,
				&ring_ent->payload_mr);
		else
			ring_ent->op_payload =
				numa_alloc_local(ring_ent->req_payload_sz);

		req->se = se;
		pthread_mutex_init(&req->lock, NULL);
		req->is_uring = true;
		req->ref_cnt = 1;
	}

	res = fuse_uring_prepare_fetch_sqes(queue);
	if (res != 0) {
		fuse_log(
			FUSE_LOG_ERR,
			"Grave fuse-uring error on preparing SQEs, aborting\n");
		se->error = -EIO;
		fuse_session_exit(se);
	}

	return queue->ring.ring_fd;

err:
	close(queue->eventfd);
	return res;
}

int fuse_uring_init_queue(int qid, void *ring_pool)
{
	struct fuse_ring_queue *queue = fuse_uring_get_queue(ring_pool, qid);
	if (queue == NULL)
		return -EIO;

	return _fuse_uring_init_queue(queue);
}

static void *fuse_uring_thread(void *arg)
{
	struct fuse_ring_queue *queue = arg;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	int err;

	fuse_uring_set_thread_core(queue->qid);

	char thread_name[16] = { 0 };
	snprintf(thread_name, 16, "fuse-ring-%d", queue->qid);
	thread_name[15] = '\0';
	pthread_setname_np(queue->tid, thread_name);

	err = _fuse_uring_init_queue(queue);
	if (err < 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d queue setup failed\n",
			 queue->qid);
		goto err;
	}

	while (!se->exited) {
		/* is always blocking here from this internal thread */
		_fuse_uring_submit(queue, true);

		err = _fuse_uring_queue_handle_cqes(queue);
		if (err < 0) {
			/*
			 * fuse-over-io-uring is not supported, operation can
			 * continue over /dev/fuse
			 */
			if (err == -EOPNOTSUPP)
				goto ret;
			goto err;
		}
	}

	return NULL;

err:
	fuse_session_exit(se);
ret:
	return NULL;
}

static int fuse_uring_start_ring_threads(struct fuse_ring_pool *ring)
{
	int rc = 0;

	for (size_t qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);
		rc = pthread_create(&queue->tid, NULL, fuse_uring_thread, queue);
		if (rc != 0)
			break;
	}

	return rc;
}

static int fuse_uring_sanity_check(void)
{
	_Static_assert(sizeof(struct fuse_uring_cmd_req) <=
		       FUSE_URING_MAX_SQE128_CMD_DATA,
		       "SQE128_CMD_DATA has 80B cmd data");

	return 0;
}

static int fuse_uring_init_ext_threads(struct fuse_ring_pool *rp,
				       struct fuse_session *se)
{
	int err = 0;

	if (!rp->nr_queues)
		return -EINVAL;

	for (unsigned int qid = 0; qid < rp->nr_queues; qid++) {
		err = se->op.init_ring_ext_threads(
			se->userdata, qid, se->uring.pool,
			fuse_uring_init_queue, fuse_uring_submit_sqes,
			fuse_uring_queue_handle_cqes);
		if (err) {
			fuse_log(
				FUSE_LOG_ERR,
				"fuse ring queue (qid=%d) initialization failed\n",
				qid);
			break;
		}
	}

	return err;
}

int fuse_uring_start(struct fuse_session *se)
{
	int err = 0;
	struct fuse_ring_pool *fuse_ring;

	fuse_uring_sanity_check();

	fuse_ring = fuse_create_ring(se);
	if (fuse_ring == NULL) {
		err = -EADDRNOTAVAIL;
		goto out;
	}

	se->uring.pool = fuse_ring;

	if (!se->op.init_ring_ext_threads)
		err = fuse_uring_start_ring_threads(fuse_ring);
	else
		err = fuse_uring_init_ext_threads(fuse_ring, se);
out:
	return err;
}

int fuse_uring_stop(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	if (ring == NULL)
		return 0;

	for (size_t qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		// Signal the thread to stop using the eventfd
		uint64_t value = 1;
		write(queue->eventfd, &value, sizeof(value));
		if (!se->op.init_ring_ext_threads)
			pthread_join(queue->tid, NULL);
		close(queue->eventfd);
	}

	/* API bug workaround - no control when the queues are needed */
	if (!se->op.init_ring_ext_threads) {
		free(ring->queues);
		free(ring);
	}

	return 0;
}

void fuse_uring_set_payload_allocator(
	struct fuse_session *se,
	void *(*alloc_payload_buf)(size_t size, void **key),
	void (*free_payload_buf)(void *payload, size_t size, void *key))
{
	se->uring.alloc_payload = alloc_payload_buf;
	se->uring.free_payload_buf = free_payload_buf;
}

void *fuse_uring_get_req_payload_mr(struct fuse_req *req)
{
	if (!req->is_uring)
		return NULL; /* not a uring request */

	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);
	return ring_ent->payload_mr;
}
