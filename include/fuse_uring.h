/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025  Bernd Schubert <bschubert@ddn.com>
 *
 * Public interface for the app-owned ("reactor") FUSE-over-io-uring mode,
 * in which the application owns a single io_uring and multiplexes it across
 * FUSE protocol traffic and its own backend IO.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt
 */

#ifndef FUSE_URING_H_
#define FUSE_URING_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward declarations so <liburing.h> never has to be pulled into this
 * header; it is reachable from fuse_lowlevel.h, which every low-level
 * filesystem includes.
 */
struct io_uring_sqe;
struct io_uring_cqe;
struct fuse_session;

/**
 * io_uring user_data of every SQE on the app-owned ring.
 *
 * libfuse embeds one in each of its ring entries and sets it as the user_data
 * of the SQEs it fills. The application embeds one in its own IO structs and
 * finds them again with container_of(). For every CQE the application calls
 * comp->cqe_cb(comp, cqe) with comp = io_uring_cqe_get_data(cqe).
 */
struct fuse_uring_completion {
	/* called on the reactor thread only */
	void (*cqe_cb)(struct fuse_uring_completion *comp,
		       const struct io_uring_cqe *cqe);
};

/**
 * Application-provided hooks for the io-uring drivers.
 *
 * The op-payload allocator, used when the payload buffer has to be
 * application-allocated and registered (e.g. an RDMA MR), and the SQE source
 * of the app-owned mode. Only the op payload is application-allocatable; the
 * request header is kernel-facing and stays libfuse-allocated. The op_size
 * argument to fuse_uring_set_app_ops() lets this struct grow without breaking
 * ABI.
 */
struct fuse_uring_app_ops {
	/*
	 * Return @size page-aligned bytes for queue @qid, NULL on failure.
	 * *mr receives the app's registration handle (e.g. struct ibv_mr *),
	 * returned per request through fuse_req_get_payload().
	 */
	void *(*alloc_payload_mem)(void *userdata, int qid, size_t size,
				   void **mr);

	/* Free memory from alloc_payload_mem(); required with alloc_payload_mem */
	void (*free_payload_mem)(void *userdata, int qid, void *mem,
				 size_t size, void *mr);

	/*
	 * Return a free SQE on the app-owned ring, never NULL. On a full SQ the
	 * app submits to make room. libfuse never submits. Required in
	 * app-owned mode, called on the reactor thread only.
	 */
	struct io_uring_sqe *(*get_sqe)(void *userdata);

	/* future hooks appended here; presence gated by op_size */
};

/**
 * Install application hooks for the io-uring drivers.
 *
 * Call before FUSE_INIT (e.g. before fuse_session_mount()); applies to both
 * the app-owned and the libfuse-owned driver. The payload MR is delivered to
 * op handlers through fuse_req_get_payload(req, &payload, &sz, &mr).
 *
 * @param se the session
 * @param ops the hooks to install (copied)
 * @param op_size sizeof(struct fuse_uring_app_ops)
 * @param userdata opaque pointer passed back to every hook
 * @return 0 on success, negative errno on failure
 */
int fuse_uring_set_app_ops(struct fuse_session *se,
			   const struct fuse_uring_app_ops *ops,
			   size_t op_size, void *userdata);

/**
 * Enable the app-owned ("reactor") io-uring mode on @se. Must be called
 * before FUSE_INIT (e.g. before fuse_session_mount()). When @q_depth is
 * non-zero it also sets the per-queue depth; otherwise the session default
 * (or the io_uring_q_depth option) is kept. @fuse_fd_index is the fixed-file
 * index at which the app registers fuse_session_fd(se) on its ring; libfuse
 * puts it on every SQE it fills. The get_sqe hook of fuse_uring_set_app_ops()
 * is required.
 *
 * @return 0 on success, negative errno on failure
 */
int fuse_uring_set_app_owned(struct fuse_session *se, unsigned int q_depth,
			     unsigned int fuse_fd_index);

/* --- read-only accessors (valid once the session is mounted) --- */

/**
 * Number of qids the app must cover; the valid qid range is [0, count). On
 * the current kernel this is the number of configured CPUs.
 */
unsigned int fuse_uring_queue_count(struct fuse_session *se);

/** Entries per queue (mirrors the negotiated queue depth). */
unsigned int fuse_uring_queue_depth(struct fuse_session *se);

/** Maximum number of bytes one op-payload buffer holds. */
size_t fuse_uring_max_payload(struct fuse_session *se);

/*
 * --- reactor lifecycle ---
 *
 * One thread, the reactor, calls the functions below and cqe_cb, and sends
 * every reply to a ring request. libfuse calls get_sqe on that thread without
 * a lock, so a reply from a second thread corrupts the app's SQ.
 */

/**
 * Block the calling reactor thread until libfuse has allocated the queues
 * and sent the FUSE_INIT reply (registration is only valid afterwards), then
 * fill one REGISTER SQE per entry of every queue through get_sqe. The app's
 * ring must exist before this call.
 *
 * @return 0 when io-uring is up and the reactor may submit the REGISTER SQEs;
 * a negative errno (e.g. -ENODEV) when io-uring did not come up, no SQE was
 * filled and the reactor must not touch the ring.
 *
 * The reactor must reap every FUSE CQE, including the -ENOTCONN ones at
 * umount, before it exits its ring. A skipped CQE leaks the queues and session.
 * Join the reactor thread before fuse_session_destroy(), which frees the queues
 * the reactor reads.
 */
int fuse_uring_app_wait_submit(struct fuse_session *se);

#ifdef __cplusplus
}
#endif

#endif /* FUSE_URING_H_ */
