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
 * Call before the first fuse_uring_attach_ring() (app-owned mode) or before
 * FUSE_INIT for the libfuse-owned mode. Applies to both drivers. The payload
 * MR is delivered to op handlers through
 * fuse_req_get_payload(req, &payload, &sz, &mr).
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

#ifdef __cplusplus
}
#endif

#endif /* FUSE_URING_H_ */
