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
#include <linux/sched.h>
#include <poll.h>


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

	struct fuse_ring_req *ring_req;

	int tag;
};

struct fuse_ring_queue {

	struct fuse_ring_pool *ring_pool; /* back pointer */

	unsigned int cmd_inflight; /* SQs sent to the kernel */

	int fd; /* dup of se->fd */

	int qid;
	int numa_node;
	pthread_t tid;

	/* memory buffer, which gets assigned per req */
	char *mmap_buf;

	struct io_uring ring;

	/* size depends on queue depth */
	struct fuse_ring_ent ent[];
};

/**
 * Main fuse_ring structure, holds all fuse-ring data
 */
struct fuse_ring_pool {
	struct fuse_session *se;

	bool per_core_queue:1; /* one queue per core */
	size_t nr_queues;  /* number of queues */
	size_t queue_depth; /* number of per queue entries */
	size_t req_arg_len;
	size_t queue_size;
	size_t queue_mmap_size;
	size_t queue_req_buf_size;
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
	char *ptr = ((char *)fuse_ring->queues) + (qid * fuse_ring->queue_size);

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
										const unsigned int tag)
{
	req->qid = qid;
	req->tag = tag;
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

	struct io_uring_sqe *sqe =
		io_uring_get_sqe(&queue->ring);
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

	fuse_uring_sqe_prepare(sqe, ring_ent, FUSE_URING_REQ_COMMIT_AND_FETCH);

	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
				    queue->qid, ring_ent->tag);

	if (se->debug) {
		struct fuse_ring_req *rreq = ring_ent->ring_req;
		struct fuse_out_header *out = &rreq->out;
		fuse_log(FUSE_LOG_DEBUG,
			 "    unique: %llu, result=%d\n",
			 out->unique, rreq->in_out_arg_len);

	}

	/* leave io_uring_submit() to the main thread function */
	return 0;
}

int send_reply_uring(fuse_req_t req, int error, const void *arg,
		     size_t argsize)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_ring_req *rreq = ring_ent->ring_req;
	size_t max_buf = ring_pool->req_arg_len;

	if (argsize > max_buf) {
		fuse_log(FUSE_LOG_ERR, "argsize %zu exceeds buffer size %zu",
			 argsize, max_buf);
		error = -EINVAL;
	}
	else if (argsize)
		memcpy(rreq->in_out_arg, arg, argsize);
	rreq->in_out_arg_len = argsize;

	struct fuse_out_header *out = &rreq->out;
	out->error  = error;
	out->unique = req->unique;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_ent);
}

int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_ring_req *rreq = ring_ent->ring_req;
	size_t max_buf = ring_pool->req_arg_len;
	struct fuse_bufvec dest_vec = FUSE_BUFVEC_INIT(max_buf);
	int res;

	dest_vec.buf[0].mem = rreq->in_out_arg;
	dest_vec.buf[0].size = max_buf;

	res = fuse_buf_copy(&dest_vec, bufv, flags);

	struct fuse_out_header *out = &rreq->out;
	out->error  = res < 0 ? res : 0;
	out->unique = req->unique;

	rreq->in_out_arg_len = res > 0 ? res : 0;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_ent);
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
	struct fuse_ring_req *rreq = ring_ent->ring_req;
	size_t max_buf = ring_pool->req_arg_len;
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

		memcpy(rreq->in_out_arg + off, cur->iov_base, cur->iov_len);
		off += cur->iov_len;
	}

	rreq->in_out_arg_len = off;
	fuse_log(FUSE_LOG_ERR, "res=%d off=%zu\n", res, off);

	struct fuse_out_header *out = &rreq->out;
	out->error  = res;
	out->unique = req->unique;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_ent);
}

static void
fuse_uring_handle_cqe(struct fuse_ring_queue *queue,
		      struct io_uring_cqe *cqe)
{
	struct fuse_ring_ent *ring_ent = io_uring_cqe_get_data(cqe);

	if (!ring_ent) {
		fprintf(stderr, "cqe=%p io_uring_cqe_get_data returned NULL\n", cqe);
		return;
	}

	struct fuse_req *req = &ring_ent->req;
	struct fuse_ring_pool *fuse_ring = queue->ring_pool;
	struct fuse_ring_req *rreq = ring_ent->ring_req;

	struct fuse_in_header *in = &ring_ent->ring_req->in;

	void *inarg = rreq->in_out_arg;

	req->is_uring = true;
	req->ch = NULL; /* not needed for uring */

	fuse_session_process_uring_cqe(fuse_ring->se, req, in, inarg,
				       rreq->in_out_arg_len);
}

static int fuse_queue_setup_io_uring(struct io_uring *ring, size_t qid,
				     size_t depth, int fd, bool per_core_queue)
{
	int rc;
	struct io_uring_params params = {0};

	int files[1] = {fd};

	params.flags = IORING_SETUP_CQSIZE | IORING_SETUP_SQE128;

	/* preparation for SQPOLL, but disabled as it makes it quite slower */
	if (0) {
		params.flags |= IORING_SETUP_SQPOLL;

		// causes persistent in kernel spinning
		// params.flags |= IORING_SETUP_IOPOLL;

		if (per_core_queue) {
			params.flags |= IORING_SETUP_SQ_AFF;
			params.sq_thread_cpu = qid;
			params.sq_thread_idle = 1;
		}
	}

	params.cq_entries = depth;

	/* These flags should help to increase performance, but actually
	 * make it a bit slower - reason should get investigated.
	 */
	if (0 && per_core_queue) {

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

/**
 * Prepare fuse-kernel for uring
 */
static int
fuse_uring_queue_ioctl(struct fuse_session *se, int queue_fd, int qid, void *uaddr)
{
	int rc;

	struct fuse_uring_cfg ioc_cfg = {
		.cmd = FUSE_URING_IOCTL_CMD_QUEUE_CFG,
		.qconf.qid = qid,
		.qconf.control_fd = se->fd,
		.qconf.uaddr = (uint64_t)uaddr,
	};

	rc = ioctl(queue_fd, FUSE_DEV_IOC_URING, &ioc_cfg);
	if (rc != 0) {
		if (errno == ENOTTY)
			fuse_log(FUSE_LOG_INFO, "Kernel does not support fuse uring\n");
		else
			fuse_log(FUSE_LOG_ERR,
				"Unexpected ioctl result for qid=%d: %s\n",
				qid, strerror(errno));
		return -errno;
	}

	return 0;
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

		for (int tag = 0; tag < fuse_ring->queue_depth; tag++) {
			struct fuse_ring_ent *req = &queue->ent[tag];
			req->ring_req = NULL;
		}

		if (queue->mmap_buf != NULL)
			munmap(queue->mmap_buf, fuse_ring->queue_mmap_size);

	}

	free(fuse_ring->queues);
	free(fuse_ring);
}

static int fuse_uring_setup_kernel_ring(int session_fd,
					int nr_queues, int sync_qdepth,
					int async_qdepth, int req_arg_len,
					int req_alloc_sz)
{
	int rc;

	struct fuse_ring_config rconf = {
		.nr_queues = nr_queues,
		.fg_queue_depth = sync_qdepth,
		.async_queue_depth = async_qdepth,
		.req_arg_len = req_arg_len,
		.user_req_buf_sz = req_alloc_sz,
		.numa_aware = nr_queues > 1,
	};

	struct fuse_uring_cfg ioc_cfg = {
		.flags = 0,
		.cmd = FUSE_URING_IOCTL_CMD_RING_CFG,
		.rconf = rconf,
	};

	rc = ioctl(session_fd, FUSE_DEV_IOC_URING, &ioc_cfg);
	if (rc)
		rc = -errno;

	return rc;
}


/*
 * Just open the device, must not clone (FUSE_DEV_IOC_CLONE) it as
 * FUSE_DEV_IOC_URING automatically does that in the fuse module
 */
static int fuse_uring_open_dev(void)
{
	int fd;
	const char *devname = "/dev/fuse";

	fd = open(devname, O_RDWR | O_CLOEXEC);
	if (fd == -1)
		fuse_log(FUSE_LOG_ERR, "fuse: failed to open %s: %s\n", devname,
			strerror(errno));

	return fd;
}

static int fuse_uring_prepare_fetch_sqes(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	int tag, res;

	for (tag = 0; tag < ring_pool->queue_depth; tag++) {
		struct fuse_ring_ent *req = &queue->ent[tag];

		if (req->tag != tag) {
			fuse_log(FUSE_LOG_ERR,
				 "req=%p tag mismatch, got %d expected %d\n",
				 req, req->tag, tag);
			return -EINVAL;
		}

		struct io_uring_sqe *sqe = io_uring_get_sqe(&queue->ring);
		if (sqe == NULL) {

			/* All SQEs are idle here - no good reason this
			 * could fail
			 */

			fuse_log(FUSE_LOG_ERR, "Failed to get all ring SQEs");
			return -EIO;
		}

		fuse_uring_sqe_prepare(sqe, req, FUSE_URING_REQ_FETCH);
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, req->tag);
	}

	res = io_uring_sq_ready(&queue->ring);
	if (res != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR, "SQE ready mismatch, expected %d got %d\n",
			 ring_pool->queue_depth, res);
		return -EINVAL;
	}

	io_uring_submit(&queue->ring);

	return 0;
}

static struct fuse_ring_pool *
fuse_create_ring(struct fuse_session *se,
		      struct fuse_loop_config *cfg)
{
	int rc;
	struct fuse_ring_pool *fuse_ring = NULL;

	const size_t pg_size = getpagesize();
	const size_t nr_queues = cfg->uring.per_core_queue ? get_nprocs_conf() : 1;
	const size_t q_depth = cfg->uring.sync_queue_depth +
			       cfg->uring.async_queue_depth;

	const size_t ring_req_arg_len = cfg->uring.ring_req_arg_len;

	const size_t req_buf_size =
		ROUND_UP(sizeof(struct fuse_ring_req) + ring_req_arg_len,
			 pg_size);

	size_t mmap_size = req_buf_size * q_depth;

	fuse_log(FUSE_LOG_ERR,
		 "Creating ring per-core-queue=%d "
		 "sync-depth=%d async-depth=%d arglen=%d\n",
		 cfg->uring.per_core_queue, cfg->uring.sync_queue_depth,
		 cfg->uring.async_queue_depth, cfg->uring.ring_req_arg_len);

	rc = fuse_uring_setup_kernel_ring(se->fd, nr_queues,
					  cfg->uring.sync_queue_depth,
					  cfg->uring.async_queue_depth,
					  cfg->uring.ring_req_arg_len,
					  req_buf_size);
	if (rc) {
		fuse_log(FUSE_LOG_ERR, "Kernel ring configuration failed: %s\n",
			 strerror(-rc));
		goto err;
	}

	fuse_ring = calloc(1, sizeof(*fuse_ring));
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}

	size_t queue_sz = fuse_ring_queue_size(q_depth);
	fuse_ring->queues = calloc(1, queue_sz * nr_queues);
	if (fuse_ring->queues == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the queues failed\n");
		goto err;
	}

	fuse_ring->se = se;
	fuse_ring->nr_queues = nr_queues;
	fuse_ring->queue_depth = q_depth;
	fuse_ring->per_core_queue = cfg->uring.per_core_queue;
	fuse_ring->req_arg_len = ring_req_arg_len;
	fuse_ring->queue_size = queue_sz;
	fuse_ring->queue_mmap_size = mmap_size;
	fuse_ring->queue_req_buf_size = req_buf_size;

	se->ring.external_threads = cfg->uring.external_threads;

	/*
	 * very basic queue initialization, that cannot fail and will
	 * allow easy cleanup if something (like mmap) fails in the middle
	 * below
	 */
	for (int qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);
		queue->fd = -1;
		queue->ring.ring_fd = -1;
		queue->numa_node = cfg->uring.per_core_queue ?
			numa_node_of_cpu(qid) : UINT32_MAX;
		queue->qid = qid;
		queue->ring_pool = fuse_ring;
		queue->mmap_buf = NULL;
	}

	for (int qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
				fuse_uring_get_queue(fuse_ring, qid);

		/*
		 * file descriptor per queue is a protocol requirement
		 */
		queue->fd = fuse_uring_open_dev();
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

	io_uring_for_each_cqe(&queue->ring, head, cqe) {
		if (cqe->res != 0) {
			fuse_log(FUSE_LOG_ERR, "cqe res: %d\n", cqe->res);
			se->error = cqe->res;
			return cqe->res;
		}
		fuse_uring_handle_cqe(queue, cqe);

		/* submit as soon as there is something availalble,
		 * so that possibly async kernel side can already
		 * move ahead?
		 */
		// io_uring_submit(&queue->ring);
		num_completed++;
	}

	if (num_completed)
		io_uring_cq_advance(&queue->ring, num_completed);

	return num_completed;
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

	int res = io_uring_submit_and_wait(&queue->ring, wait_nr);

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

	const int prot =  PROT_READ | PROT_WRITE;
	const int flags = MAP_SHARED_VALIDATE | MAP_POPULATE;

	/*
	 * Allocate the queue buffer. Done as one big chunk of memory per
	 * queue, which is then divided into per-request buffers
	 * Kernel allocation of this buffer is supposed to be
	 * on the right numa node (determined by qid), if run in
	 * multiple queue mode.
	 *
	 */
	queue->mmap_buf = mmap(NULL, ring->queue_mmap_size, prot,
				 flags, se->fd, 0);
	if (queue->mmap_buf == MAP_FAILED) {
		fuse_log(FUSE_LOG_ERR,
			 "qid=%d mmap of size %zu failed: %s\n",
			 queue->qid, ring->queue_mmap_size, strerror(errno));
		return -errno;
	}

	/* Configure the kernel side of the queue */
	res = fuse_uring_queue_ioctl(se, queue->fd, queue->qid, queue->mmap_buf);
	if (res != 0)
		return res;

	res = fuse_queue_setup_io_uring(&queue->ring, queue->qid,
					ring->queue_depth,
					queue->fd, ring->per_core_queue);
	if (res != 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d io_uring init failed\n",
			 queue->qid);
		return res;
	}

	for (int tag = 0; tag < ring->queue_depth; tag++) {
		struct fuse_ring_ent *ring_ent = &queue->ent[tag];
		ring_ent->ring_queue = queue;
		ring_ent->tag = tag;
		ring_ent->ring_req = (struct fuse_ring_req *)
			(queue->mmap_buf + ring->queue_req_buf_size * tag);

		struct fuse_req *req = &ring_ent->req;
		req->se = se;
		pthread_mutex_init(&req->lock, NULL);
		req->is_uring = true;
	}

	res = fuse_uring_prepare_fetch_sqes(queue);
	if (res != 0) {
		fuse_log(FUSE_LOG_ERR, "Grave fuse-uring error on preparing SQEs, aborting\n");
		se->error = -EIO;
		fuse_session_exit(se);
	}

	return queue->ring.ring_fd;
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
	int res;

	if (ring_pool->per_core_queue)
		fuse_uring_set_thread_core(queue->qid);

	char thread_name[16] = { 0 };
	snprintf(thread_name, 16, "fuse-ring-%d", queue->qid);
	thread_name[15] = '\0';
	pthread_setname_np(queue->tid, thread_name);

	res = _fuse_uring_init_queue(queue);
	if (res < 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d queue setup failed\n",
			 queue->qid);
		goto err;
	}

	while (!se->exited) {
		/* is always blocking here from this internal thread */
		_fuse_uring_submit(queue, true);

		res = _fuse_uring_queue_handle_cqes(queue);
		if (res) {
			se->error = res;
			goto err;
		}
	}

	return NULL;

err:
	fuse_session_exit(se);
	return NULL;
}

static int fuse_uring_start_ring_threads(struct fuse_ring_pool *ring)
{
	int rc;
	for (int qid = 0; qid < ring->nr_queues; qid++) {
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

int fuse_uring_start(struct fuse_session *se,
		     struct fuse_loop_config *config)
{
	int rc = 0;
	struct fuse_ring_pool *fuse_ring;

	fuse_uring_sanity_check();

	fuse_ring = fuse_create_ring(se, config);
	if (fuse_ring == NULL) {
		rc = -EADDRNOTAVAIL;
		goto out;
	}

	if (!se->ring.external_threads)
		rc = fuse_uring_start_ring_threads(fuse_ring);

out:
	se->ring.pool = fuse_ring;
	se->ring.nr_queues = fuse_ring ? fuse_ring->nr_queues : 0;

	return rc;
}
