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

	bool   per_core_queue;
	size_t num_queues;  /* number of queues */
	size_t queue_depth; /* number of per queue entries */
	size_t req_arg_len;
	size_t queue_size;
	size_t queue_mmap_size;
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
		fuse_log(FUSE_LOG_ERR, "Failed to get a ring SQEs");

		return -EIO;
	}

	fuse_uring_sqe_prepare(sqe, ring_ent, FUSE_URING_REQ_COMMIT_AND_FETCH);

	struct fuse_ring_req *rreq = ring_ent->ring_req;
	rreq->cmd = FUSE_RING_BUF_CMD_IOVEC;

	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
				    queue->qid, ring_ent->tag);

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

static int fuse_queue_setup_ring(struct io_uring *ring, size_t qid,
				 size_t depth, int fd)
{
	int rc;
	struct io_uring_params params = {0};

	int files[1] = {fd};

	params.flags = IORING_SETUP_CQSIZE | IORING_SETUP_SQE128;
	params.cq_entries = depth;

	/* seems to slow down runs */
#if 0
	params.flags |= IORING_SETUP_COOP_TASKRUN |
			IORING_SETUP_SINGLE_ISSUER;
#endif

	rc = io_uring_queue_init_params(depth, ring, &params);
	if (rc != 0) {
		rc = -errno;
		fuse_log(FUSE_LOG_ERR, "Failed to setup qid %zu: %d (%s)\n",
			 qid, errno, strerror(errno));
		return rc;
	}

	rc = io_uring_register_files(ring, files, 1);
	if (rc != 0) {
		rc = -errno;
		fuse_log(FUSE_LOG_ERR, "Failed to register files for "
			 "ring idx %zu: %s", qid, strerror(errno));
		return rc;
	}

	fuse_log(FUSE_LOG_INFO, "setup complete for qid=%zu\n", qid);

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
fuse_uring_configure_kernel_queue(struct fuse_session *se,
				  struct fuse_loop_config *cfg,
				  int qid, size_t nr_queues,
				  size_t req_arg_len,
				  uint32_t numa_node_id)
{
	int rc;

	struct fuse_uring_cfg ioc_cfg = {
		.cmd = FUSE_URING_IOCTL_CMD_QUEUE_CFG,
		.qid = qid,
		.nr_queues = nr_queues,
		.fg_queue_depth = cfg->uring.fg_queue_depth,
		.bg_queue_depth = cfg->uring.bg_queue_depth,
		.req_arg_len = req_arg_len,
		.numa_node_id = numa_node_id,
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

static void *
fuse_ring_cleanup_thread(void *arg)
{
	struct fuse_session *se = arg;
	int rc;

	/* Wait in the kernel till stop time and cleanup will then be done
	 * inside of the kernel without further action here
	 */
	struct fuse_uring_cfg ioc_cfg = {
		.cmd = FUSE_URING_IOCTL_CMD_WAIT,
	};

	while (!fuse_session_exited(se)) {
		rc = ioctl(se->fd, FUSE_DEV_IOC_URING, &ioc_cfg);
		if (rc != 0) {
			if (errno == ENOTTY)
				fuse_log(FUSE_LOG_INFO, "Kernel does not support fuse uring\n");
			else if (errno == EINTR)
				fuse_session_exit(se);
			else
				fuse_log(FUSE_LOG_ERR,
					"Unexpected kernel uring ioctl result: %s\n",
					strerror(errno));
			break;
		}
	}
	fuse_log(FUSE_LOG_INFO, "Exiting cleanup thread\n");

	return NULL;
}

/**
 * Not essential, but nice to have, to avoid recurring checks for
 * need of cleanup within the kernel. The cleanup thread basically
 * waits in kernel for termination, until userspace gets stopped
 * and then starts the kernel uring cleanup task.
 */
static int
fuse_ring_start_cleanup_thread(struct fuse_session *se)
{
	int rc = pthread_create(&se->ring.cleanup_tid, NULL,
				fuse_ring_cleanup_thread, se);

	if (rc != 0) {
		fuse_log(FUSE_LOG_ERR,
			"Failed to start the cleanup thread: %s\n",
			strerror(errno));
	} else {
		/* test/check with another ioctl when it is running `*/
	}

	return rc;
}

static struct fuse_ring_pool *
fuse_create_user_ring(struct fuse_session *se,
		      struct fuse_loop_config *cfg)
{
	int rc;
	const size_t pg_size = getpagesize();
	const size_t nr_queues = cfg->uring.per_core_queue ? get_nprocs() : 1;
	const size_t q_depth = cfg->uring.fg_queue_depth +
			       cfg->uring.bg_queue_depth;

	const size_t ring_req_arg_len = cfg->uring.ring_req_arg_len;

	const size_t req_buf_size =
		ROUND_UP(sizeof(struct fuse_ring_req) + ring_req_arg_len,
			 pg_size);

	size_t mmap_size = req_buf_size * q_depth;
	struct fuse_ring_pool *fuse_ring = calloc(1, sizeof(*fuse_ring));
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
	fuse_ring->num_queues = nr_queues;
	fuse_ring->queue_depth = q_depth;
	fuse_ring->per_core_queue = cfg->uring.per_core_queue;
	fuse_ring->req_arg_len = ring_req_arg_len;
	fuse_ring->queue_size = queue_sz;
	fuse_ring->queue_mmap_size = mmap_size;

	/* very basic queue initialization, that cannot fail and will
	 * allow easy cleanup if something (like mmap) fails in the middle
	 * below */
	for (int qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);
		queue->fd = -1;
		queue->ring.ring_fd = -1;
		queue->numa_node = cfg->uring.per_core_queue ?
			numa_node_of_cpu(qid) : UINT32_MAX;
		queue->qid = -1;
		queue->ring_pool = NULL;
		queue->mmap_buf = NULL;
	}

	for (int qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
				fuse_uring_get_queue(fuse_ring, qid);

		rc = fuse_uring_configure_kernel_queue(se, cfg, qid, nr_queues,
						       ring_req_arg_len,
						       queue->numa_node);
		if (rc != 0) {
			goto err;
		}

		queue->ring_pool = fuse_ring;
		queue->qid = qid;

		/* XXX Any advantage in cloning the session? */
		queue->fd = dup(se->fd);
		if (queue->fd == -1) {
			fuse_log(FUSE_LOG_ERR, "Session fd dup failed: %s\n",
				 strerror(errno));
			goto err;
		}

		const int prot =  PROT_READ | PROT_WRITE;
		const int flags = MAP_SHARED_VALIDATE | MAP_POPULATE;

		/* offset needs to be page aligned */
		loff_t off = (qid * q_depth) * pg_size;


		/* Allocate one big chunk of memory per queue, which will be
		 * divided into per-request buffers
		 * Kernel allocation of this buffer is supposed to be
		 * on the right numa node (determined by qid), if run in
		 * multiple queue mode
		 */
		queue->mmap_buf = mmap(NULL, mmap_size, prot,
					 flags, se->fd, off);

		for (int tag = 0; tag < q_depth; tag++) {
			struct fuse_ring_ent *ring_ent = &queue->ent[tag];
			ring_ent->ring_queue = queue;
			ring_ent->tag = tag;
			ring_ent->ring_req = (struct fuse_ring_req *)
				(queue->mmap_buf + req_buf_size * tag);

			if (ring_ent->ring_req == MAP_FAILED) {
				fuse_log(FUSE_LOG_ERR,
					 "qid=%d tag=%d mmap of size %zu failed: %s\n",
					 qid, tag, req_buf_size, strerror(errno));
				goto err;
			}

			struct fuse_req *req = &ring_ent->req;
			req->se = se;
			pthread_mutex_init(&req->lock, NULL);
			req->is_uring = true;
		}
	}

	fuse_ring_start_cleanup_thread(se);

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
		numa_run_on_node(queue->qid); // qid == core index

	char thread_name[16] = { 0 };
	snprintf(thread_name, 16, "fuse-ring-%d", queue->qid);
	thread_name[15] = '\0';
	pthread_setname_np(queue->tid, thread_name);

	res = fuse_queue_setup_ring(&queue->ring, queue->qid,
				    ring_pool->queue_depth,
				    queue->fd);
	if (res != 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d uring init failed\n",
			 queue->qid);
		goto err;
	}

	for (tag = 0; tag < ring_pool->queue_depth; tag++) {
		struct fuse_ring_ent *req = &queue->ent[tag];

		if (req->tag != tag) {
			fuse_log(FUSE_LOG_ERR,
				 "req=%p tag mismatch, got %d expected %d\n",
				 req, req->tag, tag);
			goto err;
		}

		struct io_uring_sqe *sqe = io_uring_get_sqe(&queue->ring);
		if (sqe == NULL) {

			/* All SQEs are idle here - no good reason this
			 * could fail
			 */

			fuse_log(FUSE_LOG_ERR, "Failed to get all ring SQEs");
			goto err;
		}

		fuse_uring_sqe_prepare(sqe, req, FUSE_URING_REQ_FETCH);
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, req->tag);
	}

	res = io_uring_sq_ready(&queue->ring);
	if (res != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR, "SQE ready mismatch, expected %d got %d\n",
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
			fuse_log(FUSE_LOG_ERR, "uring submit failed %d\n", ret);
			goto err;
		}

		ret = io_uring_wait_cqe(&queue->ring, &cqe);
		if (ret < 0) {
			fuse_log(FUSE_LOG_ERR, "cqe wait failed %d\n", ret);
		}

		if (ret == 0 && cqe->res != 0) {
			fuse_log(FUSE_LOG_ERR, "cqe res: %d\n", cqe->res);
			fuse_session_exit(se);
			ret = cqe->res;
		}

		if (ret == 0)
			fuse_uring_handle_cqe(queue, cqe);
		io_uring_cqe_seen(&queue->ring, cqe);

#if 0
		io_uring_for_each_cqe(&queues->ring, head, cqe) {

			fuse_uring_handle_cqe(queues, cqe);

			/* Unsure which is better - submit all at once or
			* submit one by one. The former has less overhead,
			* the latter has less latency.
			* XXX: Multiple queues per code - fast queue and
			*      async queue?
			*/
			io_uring_submit(&queues->ring);
			count += 1;
		}
		io_uring_cq_advance(&queues->ring, count);
		io_uring_submit_and_wait(&queues->ring, 1);
#endif
	}

	return NULL;

err:
	se->error = -EIO;
	fuse_session_exit(se);
	return NULL;
}

static int fuse_session_run_uring(struct fuse_ring_pool *ring)
{
	int rc;
	for (int qid = 0; qid < ring->num_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);
		rc = pthread_create(&queue->tid, NULL, fuse_uring_thread, queue);
		if (rc != 0)
			break;
	}

#if 0
	for (int qid = 0; qid < ring->nrm_queues; qid++) {
		struct fuse_ring_queue *queues = &ring->queues[qid];
		pthread_join(queues->tid, NULL);
	}
#endif

	return rc;
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
	if (rc != 0)
		se->is_uring = false;
	else
		se->ring.pool = fuse_ring;

	return rc;
}

int fuse_session_stop_uring(struct fuse_session *se)
{
	int rc;

	/* Wake up the waiting thread to let it stop uring within the kernel
	 */
	struct fuse_uring_cfg ioc_cfg = {
		.cmd = FUSE_URING_IOCTL_CMD_STOP,
	};

	fuse_log(FUSE_LOG_ERR, "Sending flag stop\n");

	rc = ioctl(se->fd, FUSE_DEV_IOC_URING, &ioc_cfg);
	if (rc != 0) {
		fuse_log(FUSE_LOG_ERR,
			 "Unexpected kernel uring ioctl result: %s\n",
			 strerror(errno));
	}

	fuse_log(FUSE_LOG_ERR, "Joining cleanup tid\n");
	if (se->ring.cleanup_tid != 0)
		pthread_join(se->ring.cleanup_tid, NULL);
	fuse_log(FUSE_LOG_ERR, "Joined cleanup tid\n");

	fuse_session_destruct_uring(se->ring.pool);

	return 0;
}
