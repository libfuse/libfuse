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
struct fuse_session;

/**
 * Per-entry completion handle for the app-owned io-uring mode.
 *
 * libfuse fills this in when a ring entry is allocated. The application
 * references it from its own io_uring user_data and hands it back on
 * completion; libfuse never writes the io_uring user_data itself.
 */
struct fuse_uring_completion {
	/*
	 * libfuse's completion handler (the same function for every entry).
	 * @res is the io_uring cqe->res and @cqe_flags the cqe->flags of the
	 * entry's REGISTER or COMMIT_AND_FETCH completion (the app passes both;
	 * cqe_flags carries the buffer id once the kernel supports buf rings).
	 */
	void (*cqe_cb)(void *fuse_user_data, int res, unsigned cqe_flags);

	/* opaque libfuse context for this entry */
	void *fuse_user_data;

	/* free slot owned by the application; libfuse never touches it */
	void *app_data;
};

/**
 * Application-provided hooks for the io-uring drivers.
 *
 * Currently just the op-payload allocator, used when the payload buffer has
 * to be application-allocated and registered (e.g. an RDMA MR). Only the op
 * payload is application-allocatable; the request header is kernel-facing
 * and stays libfuse-allocated. The op_size argument to
 * fuse_uring_set_app_ops() lets this struct grow without breaking ABI.
 */
struct fuse_uring_app_ops {
	/**
	 * Allocate one queue's @count payload buffers at once, each @size bytes
	 * and page-aligned (@align is the page size; the kernel page-pin
	 * requires it), on NUMA node @node. Fill bufs[i] with the buffer
	 * address and mrs[i] with its opaque registration handle (e.g. a
	 * struct ibv_mr *) - the SAME handle for every i if one MR covers them
	 * all, distinct handles for per-buffer registration, or NULL if
	 * unregistered. libfuse points entry i's op_payload at bufs[i] and
	 * returns mrs[i] per request through fuse_req_get_payload(), never
	 * interpreting it. @return 0 on success, negative errno on failure.
	 */
	int (*alloc_payloads)(void *userdata, unsigned count, size_t size,
			      size_t align, int node, void **bufs, void **mrs);

	/** Free buffers from alloc_payloads() (same count, bufs, mrs). */
	void (*free_payloads)(void *userdata, unsigned count, void **bufs,
			      void **mrs);

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
 * (or the io_uring_q_depth option) is kept.
 *
 * @return 0 on success, negative errno on failure
 */
int fuse_uring_set_app_owned(struct fuse_session *se, unsigned int q_depth);

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

/* --- reactor lifecycle --- */

/**
 * Block the calling reactor thread until libfuse has allocated the queues
 * and sent the FUSE_INIT reply (registration is only valid afterwards).
 *
 * @return 0 when io-uring is up and the reactor may start submitting the
 * pending REGISTER SQEs for its qids; a negative errno (e.g. -ENODEV) when
 * io-uring did not come up and the reactor must not touch the ring.
 */
int fuse_uring_app_wait_submit(struct fuse_session *se);

/** Number of entries on @qid awaiting an SQE (REGISTER or COMMIT_AND_FETCH). */
unsigned int fuse_uring_pending_count(struct fuse_session *se,
				      unsigned int qid);

/**
 * Pop one pending entry of @qid and fill the app's @sqe with its REGISTER or
 * COMMIT_AND_FETCH content, stamping @fuse_fd_index (the app's fixed-file slot
 * where it registered fuse_session_fd(se) on its ring) as the SQE fd. Returns
 * the entry's completion for the app to wire into its io_uring user_data, or
 * NULL if nothing is pending. libfuse does not get_sqe / submit / set
 * user_data / lock - the app owns all four. The app MUST tolerate
 * io_uring_get_sqe() returning NULL (SQ full) and retry on the next loop
 * iteration.
 */
struct fuse_uring_completion *
fuse_uring_prep_sqe(struct fuse_session *se, unsigned int qid,
		    struct io_uring_sqe *sqe, unsigned int fuse_fd_index);

#ifdef __cplusplus
}
#endif

#endif /* FUSE_URING_H_ */
