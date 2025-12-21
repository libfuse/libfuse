/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025  Bernd Schubert <bschubert@ddn.com>
 *
 * Implementation of (most of) FUSE-over-io-uring.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt
 */

#define _GNU_SOURCE

#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_uring_i.h"

#include <stdlib.h>
#include <liburing.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <numa.h>
#include <pthread.h>
#include <stdio.h>
#include <linux/sched.h>
#include <poll.h>
#include <sys/eventfd.h>

/* Size of command data area in SQE when IORING_SETUP_SQE128 is used */
#define FUSE_URING_MAX_SQE128_CMD_DATA 80

struct fuse_ring_ent {
	struct fuse_ring_queue *ring_queue; /* back pointer */
	struct fuse_req req;

	struct fuse_uring_req_header *req_header;
	void *op_payload;
	size_t req_payload_sz;

	/* commit id of a fuse request */
	uint64_t req_commit_id;

	enum fuse_uring_cmd last_cmd;

	/* header and payload */
	struct iovec iov[2];
};

struct fuse_ring_queue {
	/* back pointer */
	struct fuse_ring_pool *ring_pool;
	int qid;
	int numa_node;
	pthread_t tid;
	int eventfd;
	size_t req_header_sz;
	struct io_uring ring;

	pthread_mutex_t ring_lock;
	bool cqe_processing;

	/* size depends on queue depth */
	struct fuse_ring_ent ent[];
};

/**
 * Main fuse_ring structure, holds all fuse-ring data
 */
struct fuse_ring_pool {
	struct fuse_session *se;

	/* number of queues */
	size_t nr_queues;

	/* number of per queue entries */
	size_t queue_depth;

	/* max payload size for fuse requests*/
	size_t max_req_payload_sz;

	/* size of a single queue */
	size_t queue_mem_size;

	unsigned int started_threads;
	unsigned int failed_threads;

	/* Avoid sending queue entries before FUSE_INIT reply*/
	sem_t init_sem;

	pthread_cond_t thread_start_cond;
	pthread_mutex_t thread_start_mutex;

	/* pointer to the first queue */
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
	void *ptr =
		((char *)fuse_ring->queues) + (qid * fuse_ring->queue_mem_size);

	return ptr;
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
					const uint64_t commit_id)
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

	/*
	 * IOSQE_FIXED_FILE: fd is the index to the fd *array*
	 * given to io_uring_register_files()
	 */
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
	bool locked = false;
	struct fuse_session *se = ring_pool->se;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	struct io_uring_sqe *sqe;

	if (pthread_self() != queue->tid) {
		pthread_mutex_lock(&queue->ring_lock);
		locked = true;
	}

	sqe = io_uring_get_sqe(&queue->ring);

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

	ring_ent->last_cmd = FUSE_IO_URING_CMD_COMMIT_AND_FETCH;
	fuse_uring_sqe_prepare(sqe, ring_ent, ring_ent->last_cmd);
	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe), queue->qid,
				    ring_ent->req_commit_id);

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "    unique: %" PRIu64 ", result=%d\n",
			 out->unique, ent_in_out->payload_sz);
	}

	if (!queue->cqe_processing)
		io_uring_submit(&queue->ring);

	if (locked)
		pthread_mutex_unlock(&queue->ring_lock);

	return 0;
}

int fuse_req_get_payload(fuse_req_t req, char **payload, size_t *payload_sz,
			 void **mr)
{
	struct fuse_ring_ent *ring_ent;

	/* Not possible without io-uring interface */
	if (!req->flags.is_uring)
		return -EINVAL;

	ring_ent = container_of(req, struct fuse_ring_ent, req);

	*payload = ring_ent->op_payload;
	*payload_sz = ring_ent->req_payload_sz;

	/*
	 * For now unused, but will be used later when the application can
	 * allocate the buffers itself and register them for rdma.
	 */
	if (mr)
		*mr = NULL;

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
	size_t len = 0;
	int res = 0;

	/* copy iov into the payload, idx=0 is the header section */
	for (int idx = 1; idx < count; idx++) {
		struct iovec *cur = &iov[idx];

		if (len + cur->iov_len > max_buf) {
			fuse_log(FUSE_LOG_ERR,
				 "iov[%d] exceeds buffer size %zu",
				 idx, max_buf);
			res = -EINVAL; /* Gracefully handle this? */
			break;
		}

		memcpy(ring_ent->op_payload + len, cur->iov_base, cur->iov_len);
		len += cur->iov_len;
	}

	ent_in_out->payload_sz = len;

	out->error  = res;
	out->unique = req->unique;
	out->len = len;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_ent);
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
		fuse_log(FUSE_LOG_ERR,
			 "Failed to register files for ring idx %zu: %s",
			 qid, strerror(errno));
		return rc;
	}

	return 0;
}

static void fuse_session_destruct_uring(struct fuse_ring_pool *fuse_ring)
{
	for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		if (queue->tid != 0) {
			uint64_t value = 1ULL;
			int rc;

			rc = write(queue->eventfd, &value, sizeof(value));
			if (rc != sizeof(value))
				fprintf(stderr,
					"Wrote to eventfd=%d err=%s: rc=%d\n",
					queue->eventfd, strerror(errno), rc);
			pthread_cancel(queue->tid);
			pthread_join(queue->tid, NULL);
			queue->tid = 0;
		}

		if (queue->eventfd >= 0) {
			close(queue->eventfd);
			queue->eventfd = -1;
		}

		if (queue->ring.ring_fd != -1)
			io_uring_queue_exit(&queue->ring);

		for (size_t idx = 0; idx < fuse_ring->queue_depth; idx++) {
			struct fuse_ring_ent *ent = &queue->ent[idx];

			numa_free(ent->op_payload, ent->req_payload_sz);
			numa_free(ent->req_header, queue->req_header_sz);
		}

		pthread_mutex_destroy(&queue->ring_lock);
	}

	free(fuse_ring->queues);
	pthread_cond_destroy(&fuse_ring->thread_start_cond);
	pthread_mutex_destroy(&fuse_ring->thread_start_mutex);
	free(fuse_ring);
}

static int fuse_uring_register_ent(struct fuse_ring_queue *queue,
				   struct fuse_ring_ent *ent)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		/*
		 * All SQEs are idle here - no good reason this
		 * could fail
		 */
		fuse_log(FUSE_LOG_ERR, "Failed to get all ring SQEs");
		return -EIO;
	}

	ent->last_cmd = FUSE_IO_URING_CMD_REGISTER;
	fuse_uring_sqe_prepare(sqe, ent, ent->last_cmd);

	/* only needed for fetch */
	ent->iov[0].iov_base = ent->req_header;
	ent->iov[0].iov_len = queue->req_header_sz;

	ent->iov[1].iov_base = ent->op_payload;
	ent->iov[1].iov_len = ent->req_payload_sz;

	sqe->addr = (uint64_t)(ent->iov);
	sqe->len = 2;

	/* this is a fetch, kernel does not read commit id */
	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe), queue->qid, 0);

	return 0;

}

static int fuse_uring_register_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	unsigned int sq_ready;
	struct io_uring_sqe *sqe;
	int res;

	for (size_t idx = 0; idx < ring_pool->queue_depth; idx++) {
		struct fuse_ring_ent *ent = &queue->ent[idx];

		res = fuse_uring_register_ent(queue, ent);
		if (res != 0)
			return res;
	}

	sq_ready = io_uring_sq_ready(&queue->ring);
	if (sq_ready != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR,
			 "SQE ready mismatch, expected %zu got %u\n",
			 ring_pool->queue_depth, sq_ready);
		return -EINVAL;
	}

	/* Poll SQE for the eventfd to wake up on teardown */
	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to get eventfd SQE");
		return -EIO;
	}

	io_uring_prep_poll_add(sqe, queue->eventfd, POLLIN);
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)queue->eventfd);

	/* Only preparation until here, no submission yet */

	return 0;
}

static struct fuse_ring_pool *fuse_create_ring(struct fuse_session *se)
{
	struct fuse_ring_pool *fuse_ring = NULL;
	const size_t nr_queues = get_nprocs_conf();
	size_t payload_sz = se->bufsize - FUSE_BUFFER_HEADER_SIZE;
	size_t queue_sz;

	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "starting io-uring q-depth=%d\n",
			 se->uring.q_depth);

	fuse_ring = calloc(1, sizeof(*fuse_ring));
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}

	queue_sz = fuse_ring_queue_size(se->uring.q_depth);
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

		queue->ring.ring_fd = -1;
		queue->numa_node = numa_node_of_cpu(qid);
		queue->qid = qid;
		queue->ring_pool = fuse_ring;
		queue->eventfd = -1;
		pthread_mutex_init(&queue->ring_lock, NULL);
	}

	pthread_cond_init(&fuse_ring->thread_start_cond, NULL);
	pthread_mutex_init(&fuse_ring->thread_start_mutex, NULL);
	sem_init(&fuse_ring->init_sem, 0, 0);

	return fuse_ring;

err:
	if (fuse_ring)
		fuse_session_destruct_uring(fuse_ring);

	return NULL;
}

static void fuse_uring_resubmit(struct fuse_ring_queue *queue,
				struct fuse_ring_ent *ent)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		/* This is an impossible condition, unless there is a bug.
		 * The kernel sent back an SQEs, which is assigned to a request.
		 * There is no way to get out of SQEs, as the number of
		 * SQEs matches the number tof requests.
		 */

		queue->ring_pool->se->error = -EIO;
		fuse_log(FUSE_LOG_ERR, "Failed to get a ring SQEs\n");

		return;
	}

	fuse_uring_sqe_prepare(sqe, ent, ent->last_cmd);

	switch (ent->last_cmd) {
	case FUSE_IO_URING_CMD_REGISTER:
		sqe->addr = (uint64_t)(ent->iov);
		sqe->len = 2;
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, 0);
		break;
	case FUSE_IO_URING_CMD_COMMIT_AND_FETCH:
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, ent->req_commit_id);
		break;
	default:
		fuse_log(FUSE_LOG_ERR, "Unknown command type: %d\n",
			 ent->last_cmd);
		queue->ring_pool->se->error = -EINVAL;
		break;
	}

	/* caller submits */
}

static void fuse_uring_handle_cqe(struct fuse_ring_queue *queue,
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
	struct fuse_uring_ent_in_out *ent_in_out = &rrh->ring_ent_in_out;

	ent->req_commit_id = ent_in_out->commit_id;
	if (unlikely(ent->req_commit_id == 0)) {
		/*
		 * If this happens kernel will not find the response - it will
		 * be stuck forever - better to abort immediately.
		 */
		fuse_log(FUSE_LOG_ERR, "Received invalid commit_id=0\n");
		abort();
	}

	memset(&req->flags, 0, sizeof(req->flags));
	memset(&req->u, 0, sizeof(req->u));
	req->flags.is_uring = 1;
	req->ref_cnt++;
	req->ch = NULL; /* not needed for uring */
	req->interrupted = 0;
	list_init_req(req);

	fuse_session_process_uring_cqe(fuse_ring->se, req, in, &rrh->op_in,
				       ent->op_payload, ent_in_out->payload_sz);
}

static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	size_t num_completed = 0;
	struct io_uring_cqe *cqe;
	unsigned int head;
	struct fuse_ring_ent *ent;
	int ret = 0;

	io_uring_for_each_cqe(&queue->ring, head, cqe) {
		int err = 0;

		num_completed++;

		err = cqe->res;
		if (unlikely(err != 0)) {
			if (err > 0 && ((uintptr_t)io_uring_cqe_get_data(cqe) ==
					(unsigned int)queue->eventfd)) {
				/* teardown from eventfd */
				return -ENOTCONN;
			}


			switch (err) {
			case -EAGAIN:
				fallthrough;
			case -EINTR:
				ent = io_uring_cqe_get_data(cqe);
				fuse_uring_resubmit(queue, ent);
				continue;
			default:
				break;
			}

			/* -ENOTCONN is ok on umount  */
			if (err != -ENOTCONN) {
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
 * In per-core-queue configuration we have thread per core - the thread
 * to that core
 */
static void fuse_uring_set_thread_core(int qid)
{
	cpu_set_t mask;
	int rc;

	CPU_ZERO(&mask);
	CPU_SET(qid, &mask);
	rc = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if (rc != 0)
		fuse_log(FUSE_LOG_ERR, "Failed to bind qid=%d to its core: %s\n",
			 qid, strerror(errno));

	if (0) {
		const int policy = SCHED_IDLE;
		const struct sched_param param = {
			.sched_priority = sched_get_priority_min(policy),
		};

		/* Set the lowest possible priority, so that the application
		 * submitting requests is not moved away from the current core.
		 */
		rc = sched_setscheduler(0, policy, &param);
		if (rc != 0)
			fuse_log(FUSE_LOG_ERR, "Failed to set scheduler: %s\n",
				strerror(errno));
	}
}

/*
 * @return negative error code or io-uring file descriptor
 */
static int fuse_uring_init_queue(struct fuse_ring_queue *queue)
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
					ring->queue_depth, se->fd,
					queue->eventfd);
	if (res != 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d io_uring init failed\n",
			 queue->qid);
		goto err;
	}

	queue->req_header_sz = ROUND_UP(sizeof(struct fuse_ring_ent),
				       page_sz);

	for (size_t idx = 0; idx < ring->queue_depth; idx++) {
		struct fuse_ring_ent *ring_ent = &queue->ent[idx];
		struct fuse_req *req = &ring_ent->req;

		ring_ent->ring_queue = queue;

		/*
		 * Also allocate the header to have it page aligned, which
		 * is a requirement for page pinning
		 */
		ring_ent->req_header =
			numa_alloc_local(queue->req_header_sz);
		ring_ent->req_payload_sz = ring->max_req_payload_sz;

		ring_ent->op_payload =
			numa_alloc_local(ring_ent->req_payload_sz);

		req->se = se;
		pthread_mutex_init(&req->lock, NULL);
		req->flags.is_uring = 1;
		req->ref_cnt = 1; /* extra ref to avoid destruction */
		list_init_req(req);
	}

	res = fuse_uring_register_queue(queue);
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

static void *fuse_uring_thread(void *arg)
{
	struct fuse_ring_queue *queue = arg;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	int err;
	char thread_name[16] = { 0 };

	snprintf(thread_name, 16, "fuse-ring-%d", queue->qid);
	thread_name[15] = '\0';
	fuse_set_thread_name(thread_name);

	fuse_uring_set_thread_core(queue->qid);

	err = fuse_uring_init_queue(queue);
	pthread_mutex_lock(&ring_pool->thread_start_mutex);
	if (err < 0)
		ring_pool->failed_threads++;
	ring_pool->started_threads++;
	pthread_cond_broadcast(&ring_pool->thread_start_cond);
	pthread_mutex_unlock(&ring_pool->thread_start_mutex);

	if (err < 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d queue setup failed\n",
			 queue->qid);
		goto err_non_fatal;
	}

	sem_wait(&ring_pool->init_sem);

	/* Not using fuse_session_exited(se), as that cannot be inlined */
	while (!atomic_load_explicit(&se->mt_exited, memory_order_relaxed)) {
		io_uring_submit_and_wait(&queue->ring, 1);

		pthread_mutex_lock(&queue->ring_lock);
		queue->cqe_processing = true;
		err = fuse_uring_queue_handle_cqes(queue);
		queue->cqe_processing = false;
		pthread_mutex_unlock(&queue->ring_lock);
		if (err < 0)
			goto err;
	}

	return NULL;

err:
	fuse_session_exit(se);
err_non_fatal:
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

static int fuse_uring_sanity_check(struct fuse_session *se)
{
	if (se->uring.q_depth == 0) {
		fuse_log(FUSE_LOG_ERR, "io-uring queue depth must be > 0\n");
		return -EINVAL;
	}

	_Static_assert(sizeof(struct fuse_uring_cmd_req) <=
		       FUSE_URING_MAX_SQE128_CMD_DATA,
		       "SQE128_CMD_DATA has 80B cmd data");

	return 0;
}

int fuse_uring_start(struct fuse_session *se)
{
	int err = 0;
	struct fuse_ring_pool *fuse_ring;

	fuse_uring_sanity_check(se);

	fuse_ring = fuse_create_ring(se);
	if (fuse_ring == NULL) {
		err = -EADDRNOTAVAIL;
		goto err;
	}

	se->uring.pool = fuse_ring;

	/* Hold off threads from send fuse ring entries (SQEs) */
	sem_init(&fuse_ring->init_sem, 0, 0);
	pthread_cond_init(&fuse_ring->thread_start_cond, NULL);
	pthread_mutex_init(&fuse_ring->thread_start_mutex, NULL);

	err = fuse_uring_start_ring_threads(fuse_ring);
	if (err)
		goto err;

	/*
	 * Wait for all threads to start or to fail
	 */
	pthread_mutex_lock(&fuse_ring->thread_start_mutex);
	while (fuse_ring->started_threads < fuse_ring->nr_queues)
		pthread_cond_wait(&fuse_ring->thread_start_cond,
				  &fuse_ring->thread_start_mutex);

	if (fuse_ring->failed_threads != 0)
		err = -EADDRNOTAVAIL;
	pthread_mutex_unlock(&fuse_ring->thread_start_mutex);

err:
	if (err) {
		/* Note all threads need to have been started */
		fuse_session_destruct_uring(fuse_ring);
		se->uring.pool = fuse_ring;
	}
	return err;
}

int fuse_uring_stop(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	if (ring == NULL)
		return 0;

	fuse_session_destruct_uring(ring);

	return 0;
}

void fuse_uring_wake_ring_threads(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	/* Wake up the threads to let them send SQEs */
	for (size_t qid = 0; qid < ring->nr_queues; qid++)
		sem_post(&ring->init_sem);
}
