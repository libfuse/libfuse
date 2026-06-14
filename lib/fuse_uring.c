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
#include <time.h>
#include <errno.h>

/* Size of command data area in SQE when IORING_SETUP_SQE128 is used */
#define FUSE_URING_MAX_SQE128_CMD_DATA 80

/*
 * Teardown drain bound. We wait, event-driven, for outstanding deferred
 * replies to complete before freeing ring memory. The wait is bounded so a
 * wedged filesystem callback can never hang teardown forever; if the deadline
 * is hit we leak the ring as a last resort (the OS reclaims it at exit).
 */
#define FUSE_URING_DRAIN_TIMEOUT_SEC 30

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

	bool req_lock_initialized;
};

struct fuse_ring_queue {
	/* back pointer */
	struct fuse_ring_pool *ring_pool;
	int qid;
	pthread_t tid;
	int eventfd;
	size_t req_header_sz;
	struct io_uring ring;
	bool exited;

	pthread_mutex_t ring_lock;
	bool ring_lock_initialized;
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

	/*
	 * Count of requests dispatched to the filesystem and not yet
	 * released via fuse_free_req(). Lets teardown wait for deferred
	 * replies to drain instead of polling per-entry ref_cnt.
	 */
	_Atomic uint64_t inflight;

	/*
	 * Set by teardown. While set, the request-release path takes
	 * drain_mutex and signals drain_cond when inflight reaches 0, so
	 * fuse_session_destruct_uring() can block until all outstanding
	 * replies are done touching the ring (and ring_pool->se) before
	 * freeing anything.
	 */
	_Atomic bool draining;
	_Atomic bool teardown_incomplete;
	pthread_mutex_t drain_mutex;
	bool drain_mutex_initialized;
	pthread_cond_t drain_cond;
	bool drain_cond_initialized;

	/* Avoid sending queue entries before FUSE_INIT reply*/
	sem_t init_sem;
	bool init_sem_initialized;

	pthread_cond_t thread_start_cond;
	bool thread_start_cond_initialized;
	pthread_mutex_t thread_start_mutex;
	bool thread_start_mutex_initialized;

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

		if (locked)
			pthread_mutex_unlock(&queue->ring_lock);

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

/*
 * Account a uring request as no longer in flight. Called from fuse_free_req()
 * once a request's dispatch reference is dropped, i.e. after the reply path
 * (send_reply_uring / fuse_reply_data_uring / fuse_send_msg_uring) has already
 * submitted the commit SQE and made its last access to ring memory and
 * ring_pool->se.
 *
 * Looking up the pool through se (rather than the request) deliberately avoids
 * touching ring memory here: the request's ring entry is freed by
 * fuse_session_destruct_uring() right after inflight reaches 0.
 *
 * Fast path (no teardown in progress) is a single atomic decrement. During
 * teardown we take drain_mutex so the decrement that empties the ring and the
 * cond signal are serialized with the waiter in fuse_session_destruct_uring();
 * that mutex hand-off guarantees the waiter only frees the pool after this
 * function has fully returned.
 */
void fuse_uring_req_released(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	if (ring == NULL)
		return;

	if (!atomic_load(&ring->draining)) {
		atomic_fetch_sub(&ring->inflight, 1);
		return;
	}

	pthread_mutex_lock(&ring->drain_mutex);
	if (atomic_fetch_sub(&ring->inflight, 1) == 1)
		pthread_cond_signal(&ring->drain_cond);
	pthread_mutex_unlock(&ring->drain_mutex);
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
		const struct iovec *cur = &iov[idx];

		if (len + cur->iov_len > max_buf) {
			fuse_log(FUSE_LOG_ERR,
				 "iov[%d] exceeds buffer size %zu",
				 idx, max_buf);
			res = -EINVAL; /* Gracefully handle this? */
			break;
		}

		memcpy((char *)ring_ent->op_payload + len, cur->iov_base, cur->iov_len);
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

/*
 * Wake one ring thread out of io_uring_submit_and_wait() via its eventfd.
 *
 * eventfd writes are all-or-nothing (8 bytes), so the only realistic failure
 * is EINTR; retry that. If the write ultimately fails the thread may stay
 * blocked, which the bounded thread-exit wait in the join loop guards against.
 * Returns 0 on success, -1 if the thread could not be woken.
 */
static int fuse_uring_wake_thread(struct fuse_ring_queue *queue)
{
	uint64_t value = 1ULL;

	if (queue->tid == 0 || queue->eventfd < 0)
		return 0;

	for (;;) {
		ssize_t rc = write(queue->eventfd, &value, sizeof(value));

		if (rc == sizeof(value))
			return 0;
		if (rc < 0 && errno == EINTR)
			continue;

		fuse_log(FUSE_LOG_ERR,
			 "eventfd=%d wake failed err=%s: rc=%zd\n",
			 queue->eventfd, strerror(errno), (ssize_t)rc);
		return -1;
	}
}

static int fuse_uring_cond_init_monotonic(pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	int rc;

	rc = pthread_condattr_init(&attr);
	if (rc != 0)
		return -rc;

	rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	if (rc == 0)
		rc = pthread_cond_init(cond, &attr);

	pthread_condattr_destroy(&attr);

	return rc == 0 ? 0 : -rc;
}

static int fuse_uring_sync_init(struct fuse_ring_pool *fuse_ring)
{
	int rc;

	rc = pthread_mutex_init(&fuse_ring->drain_mutex, NULL);
	if (rc != 0)
		return -rc;
	fuse_ring->drain_mutex_initialized = true;

	rc = pthread_mutex_init(&fuse_ring->thread_start_mutex, NULL);
	if (rc != 0)
		return -rc;
	fuse_ring->thread_start_mutex_initialized = true;

	rc = fuse_uring_cond_init_monotonic(&fuse_ring->drain_cond);
	if (rc != 0)
		return rc;
	fuse_ring->drain_cond_initialized = true;

	rc = fuse_uring_cond_init_monotonic(&fuse_ring->thread_start_cond);
	if (rc != 0)
		return rc;
	fuse_ring->thread_start_cond_initialized = true;

	if (sem_init(&fuse_ring->init_sem, 0, 0) != 0)
		return -errno;
	fuse_ring->init_sem_initialized = true;

	return 0;
}

static int fuse_uring_get_deadline(struct timespec *deadline, time_t seconds)
{
	if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0)
		return -errno;

	deadline->tv_sec += seconds;
	return 0;
}

static bool fuse_uring_timespec_reached(const struct timespec *now,
					const struct timespec *deadline)
{
	return now->tv_sec > deadline->tv_sec ||
	       (now->tv_sec == deadline->tv_sec &&
		now->tv_nsec >= deadline->tv_nsec);
}

static int fuse_uring_wait_thread_exit(struct fuse_ring_pool *fuse_ring,
				       const struct fuse_ring_queue *queue,
				       const struct timespec *deadline)
{
	int err = 0;

	pthread_mutex_lock(&fuse_ring->thread_start_mutex);
	while (!queue->exited) {
		int rc;

		rc = pthread_cond_timedwait(&fuse_ring->thread_start_cond,
					    &fuse_ring->thread_start_mutex,
					    deadline);
		if (rc == ETIMEDOUT && !queue->exited) {
			err = -ETIMEDOUT;
			break;
		}
		if (rc != 0) {
			err = -rc;
			break;
		}
	}
	pthread_mutex_unlock(&fuse_ring->thread_start_mutex);

	return err;
}

static void fuse_uring_mark_thread_exited(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *fuse_ring = queue->ring_pool;

	pthread_mutex_lock(&fuse_ring->thread_start_mutex);
	queue->exited = true;
	pthread_cond_broadcast(&fuse_ring->thread_start_cond);
	pthread_mutex_unlock(&fuse_ring->thread_start_mutex);
}

/*
 * Wait, event-driven, for all outstanding deferred replies to finish before
 * the caller frees ring memory. Returns 0 if fully drained, or a negative
 * errno if the bounded deadline expired with replies still in flight (caller
 * must then leak the ring rather than free memory still referenced by a live
 * reply).
 *
 * draining is published before the threads are joined; combined with the
 * drain_mutex hand-off in fuse_uring_req_released() this ensures the releasing
 * thread has fully returned before we observe inflight == 0 and free.
 */
static int fuse_uring_drain_wait(struct fuse_ring_pool *fuse_ring,
				 const struct timespec *deadline)
{
	int err = 0;

	pthread_mutex_lock(&fuse_ring->drain_mutex);
	while (atomic_load(&fuse_ring->inflight) > 0) {
		struct timespec slice;
		int rc;

		/*
		 * A short slice bounds the (tiny) window where a reply that
		 * observed draining == false before we set it releases without
		 * signalling; we re-check inflight each slice. A real signal
		 * wakes us immediately.
		 */
		err = fuse_uring_get_deadline(&slice, 0);
		if (err != 0)
			break;

		slice.tv_nsec += 100 * 1000 * 1000; /* 100ms */
		if (slice.tv_nsec >= 1000 * 1000 * 1000) {
			slice.tv_nsec -= 1000 * 1000 * 1000;
			slice.tv_sec += 1;
		}
		if (slice.tv_sec > deadline->tv_sec ||
		    (slice.tv_sec == deadline->tv_sec &&
		     slice.tv_nsec > deadline->tv_nsec))
			slice = *deadline;

		rc = pthread_cond_timedwait(&fuse_ring->drain_cond,
					    &fuse_ring->drain_mutex, &slice);
		if (atomic_load(&fuse_ring->inflight) == 0)
			break;
		if (rc == ETIMEDOUT) {
			struct timespec now;

			err = fuse_uring_get_deadline(&now, 0);
			if (err != 0)
				break;
			if (fuse_uring_timespec_reached(&now, deadline)) {
				err = -ETIMEDOUT;
				break;
			}
		} else if (rc != 0) {
			err = -rc;
			break;
		}
	}
	if (err == 0 && atomic_load(&fuse_ring->inflight) > 0)
		err = -ETIMEDOUT;
	pthread_mutex_unlock(&fuse_ring->drain_mutex);

	return err;
}

/*
 * Tear down the ring. Returns 0 if all resources were freed, or a negative
 * errno if the ring had to be leaked because outstanding replies (or a ring
 * thread that did not exit) could still reference it.
 */
static int fuse_session_destruct_uring(struct fuse_ring_pool *fuse_ring)
{
	struct fuse_session *se = fuse_ring->se;
	struct timespec deadline;
	int err = 0;

	if (atomic_load(&fuse_ring->teardown_incomplete))
		return -ETIMEDOUT;

	err = fuse_uring_get_deadline(&deadline, FUSE_URING_DRAIN_TIMEOUT_SEC);
	if (err != 0)
		return err;

	/*
	 * Do NOT use pthread_cancel() - it can kill a thread while it
	 * holds queue->ring_lock inside a filesystem callback, leaving
	 * the mutex permanently locked and deadlocking any application
	 * thread that tries to reply via fuse_uring_commit_sqe().
	 *
	 * Instead: signal teardown, wake all sleepers, join threads
	 * (stopping new dispatches), drain deferred replies, then free.
	 */

	/*
	 * Publish teardown before waking threads so the ring threads see
	 * the exit flag once their eventfd CQE breaks submit_and_wait, and
	 * so the reply-release path takes the drain_mutex synchronisation.
	 * fuse_create_ring()'s error path may call us with se == NULL.
	 */
	atomic_store(&fuse_ring->draining, true);
	if (se != NULL)
		atomic_store_explicit(&se->mt_exited, true,
				      memory_order_relaxed);

	/* Wake all sleepers: sem_wait (init path) and io_uring (main loop) */
	for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		if (fuse_ring->init_sem_initialized)
			sem_post(&fuse_ring->init_sem);
		fuse_uring_wake_thread(queue);
	}

	/*
	 * Join all threads - no new dispatches after this. Bound the join
	 * so a thread that could not be woken (eventfd write failure) cannot
	 * hang teardown forever; an un-joinable thread is detached and left
	 * to the OS at exit instead.
	 */
	for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);
		int rc;

		if (queue->tid == 0)
			continue;

		rc = fuse_uring_wait_thread_exit(fuse_ring, queue, &deadline);
		if (rc != 0) {
			fuse_log(FUSE_LOG_ERR,
				 "qid=%zu ring thread did not exit; "
				 "detaching and leaking ring: %s\n",
				 qid, strerror(-rc));
			pthread_detach(queue->tid);
			err = rc;
			continue;
		}

		rc = pthread_join(queue->tid, NULL);
		if (rc != 0) {
			fuse_log(FUSE_LOG_ERR,
				 "qid=%zu ring thread join failed; "
				 "leaking ring: %s\n",
				 qid, strerror(rc));
			err = -rc;
			continue;
		}
		queue->tid = 0;
	}

	if (err != 0) {
		atomic_store(&fuse_ring->teardown_incomplete, true);
		return err;
	}

	/*
	 * Wait for deferred replies still in progress. A live reply may call
	 * send_reply_uring -> fuse_uring_commit_sqe, dereferencing ring_pool,
	 * ring_pool->se, queue->ring_lock and queue->ring. Block until they
	 * are all done; if they never finish within the deadline we leak the
	 * ring (the OS reclaims it at process exit) rather than free memory a
	 * live reply still references.
	 */
	if (fuse_ring->drain_mutex_initialized &&
	    fuse_ring->drain_cond_initialized) {
		err = fuse_uring_drain_wait(fuse_ring, &deadline);
		if (err != 0) {
			fuse_log(FUSE_LOG_ERR,
				 "Leaked ring: %" PRIu64
				 " replies still in flight at shutdown: %s\n",
				 atomic_load(&fuse_ring->inflight),
				 strerror(-err));
			atomic_store(&fuse_ring->teardown_incomplete, true);
			return err;
		}
	} else if (atomic_load(&fuse_ring->inflight) > 0) {
		atomic_store(&fuse_ring->teardown_incomplete, true);
		return -EIO;
	}

	/* No live refs - safe to free everything */
	for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		if (queue->eventfd >= 0)
			close(queue->eventfd);

		if (queue->ring.ring_fd != -1)
			io_uring_queue_exit(&queue->ring);

		for (size_t idx = 0; idx < fuse_ring->queue_depth; idx++) {
			struct fuse_ring_ent *ent = &queue->ent[idx];

			if (ent->op_payload != NULL)
				numa_free(ent->op_payload, ent->req_payload_sz);
			if (ent->req_header != NULL)
				numa_free(ent->req_header, queue->req_header_sz);
			if (ent->req_lock_initialized)
				pthread_mutex_destroy(&ent->req.lock);
		}

		if (queue->ring_lock_initialized)
			pthread_mutex_destroy(&queue->ring_lock);
	}

	free(fuse_ring->queues);
	if (fuse_ring->init_sem_initialized)
		sem_destroy(&fuse_ring->init_sem);
	if (fuse_ring->thread_start_cond_initialized)
		pthread_cond_destroy(&fuse_ring->thread_start_cond);
	if (fuse_ring->thread_start_mutex_initialized)
		pthread_mutex_destroy(&fuse_ring->thread_start_mutex);
	if (fuse_ring->drain_cond_initialized)
		pthread_cond_destroy(&fuse_ring->drain_cond);
	if (fuse_ring->drain_mutex_initialized)
		pthread_mutex_destroy(&fuse_ring->drain_mutex);
	free(fuse_ring);

	return 0;
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

	for (size_t idx = 0; idx < ring_pool->queue_depth; idx++) {
		struct fuse_ring_ent *ent = &queue->ent[idx];
		int res;

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
	int err;

	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "starting io-uring q-depth=%d\n",
			 se->uring.q_depth);

	fuse_ring = calloc(1, sizeof(*fuse_ring));
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}

	err = fuse_uring_sync_init(fuse_ring);
	if (err != 0) {
		fuse_log(FUSE_LOG_ERR,
			 "Initializing uring teardown synchronization failed: %s\n",
			 strerror(-err));
		goto err;
	}

	queue_sz = fuse_ring_queue_size(se->uring.q_depth);
	fuse_ring->queues = calloc(1, queue_sz * nr_queues);
	if (fuse_ring->queues == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the queues failed\n");
		goto err;
	}

	fuse_ring->nr_queues = nr_queues;
	fuse_ring->queue_depth = se->uring.q_depth;
	fuse_ring->max_req_payload_sz = payload_sz;
	fuse_ring->queue_mem_size = queue_sz;

	/* Set cleanup-safe sentinels for every queue before fallible init. */
	for (size_t qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		queue->ring.ring_fd = -1;
		queue->qid = qid;
		queue->ring_pool = fuse_ring;
		queue->eventfd = -1;
	}

	for (size_t qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		err = pthread_mutex_init(&queue->ring_lock, NULL);
		if (err != 0) {
			fuse_log(FUSE_LOG_ERR,
				 "Initializing qid=%zu ring lock failed: %s\n",
				 qid, strerror(err));
			goto err;
		}
		queue->ring_lock_initialized = true;
	}

	fuse_ring->se = se;
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
	const struct fuse_uring_ent_in_out *ent_in_out = &rrh->ring_ent_in_out;

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
	atomic_fetch_add(&fuse_ring->inflight, 1);
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
		return res;
	}

	queue->req_header_sz = ROUND_UP(sizeof(struct fuse_uring_req_header),
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
		if (!ring_ent->req_header)
			return -ENOMEM;
		ring_ent->req_payload_sz = ring->max_req_payload_sz;

		ring_ent->op_payload =
			numa_alloc_local(ring_ent->req_payload_sz);
		if (!ring_ent->op_payload)
			return -ENOMEM;

		req->se = se;
		res = pthread_mutex_init(&req->lock, NULL);
		if (res != 0)
			return -res;
		ring_ent->req_lock_initialized = true;
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
		return res;
	}

	return queue->ring.ring_fd;
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
		int submit_err = 0;

		io_uring_submit_and_wait(&queue->ring, 1);

		pthread_mutex_lock(&queue->ring_lock);
		queue->cqe_processing = true;
		err = fuse_uring_queue_handle_cqes(queue);
		queue->cqe_processing = false;
		if (io_uring_sq_ready(&queue->ring) > 0)
			submit_err = io_uring_submit(&queue->ring);
		pthread_mutex_unlock(&queue->ring_lock);
		if (submit_err < 0) {
			err = submit_err;
			goto err;
		}
		if (err < 0)
			goto err;
	}

	goto out;

err:
	fuse_session_exit(se);
err_non_fatal:
out:
	fuse_uring_mark_thread_exited(queue);
	return NULL;
}

static int fuse_uring_start_ring_threads(struct fuse_ring_pool *ring)
{
	int rc = 0;

	for (size_t qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		rc = pthread_create(&queue->tid, NULL, fuse_uring_thread, queue);
		if (rc != 0)
			return -rc;
	}

	return 0;
}

static int fuse_uring_sanity_check(const struct fuse_session *se)
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
	struct fuse_ring_pool *fuse_ring = NULL;
	bool was_exited = atomic_load_explicit(&se->mt_exited,
					       memory_order_relaxed);

	err = fuse_uring_sanity_check(se);
	if (err != 0)
		goto err;

	fuse_ring = fuse_create_ring(se);
	if (fuse_ring == NULL) {
		err = -EADDRNOTAVAIL;
		goto err;
	}

	se->uring.pool = fuse_ring;
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
		int destruct_err = 0;

		/* Note all threads need to have been started */
		if (fuse_ring)
			destruct_err = fuse_session_destruct_uring(fuse_ring);
		if (destruct_err == 0) {
			se->uring.pool = NULL;
			atomic_store_explicit(&se->mt_exited, was_exited,
					      memory_order_relaxed);
		}
	}
	return err;
}

int fuse_uring_stop(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;
	int err;

	if (ring == NULL)
		return 0;

	/*
	 * Only clear the session's pool pointer if the ring was actually
	 * freed. If it had to be leaked (outstanding replies), keep the
	 * pointer valid so any late reply path still has a live ring.
	 */
	err = fuse_session_destruct_uring(ring);
	if (err == 0)
		se->uring.pool = NULL;

	return err;
}

void fuse_uring_wake_ring_threads(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	/* Wake up the threads to let them send SQEs */
	for (size_t qid = 0; qid < ring->nr_queues; qid++)
		sem_post(&ring->init_sem);
}
