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
	void (*cqe_cb)(struct fuse_uring_completion *comp,
		       const struct io_uring_cqe *cqe);
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
