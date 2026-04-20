/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025-2026 Oracle.
 * Author: Darrick J. Wong <djwong@kernel.org>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt.
 */
#ifndef FUSE_SERVICE_H_
#define FUSE_SERVICE_H_

/** @file
 *
 * Low level API
 *
 * IMPORTANT: you should define FUSE_USE_VERSION before including this
 * header.  To use the newest API define it to 319 (recommended for any
 * new application).
 */

#ifndef FUSE_USE_VERSION
#error FUSE_USE_VERSION not defined
#endif

#include "fuse_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if FUSE_MAKE_VERSION(3, 19) <= FUSE_USE_VERSION

struct fuse_service;

/**
 * Accept a socket created by mount.service for information exchange.
 *
 * @param sfp pointer to pointer to a service context.  The pointer will always
 *            be initialized by this function; use fuse_service_accepted to
 *            find out if the fuse server is actually running as a service.
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_accept(struct fuse_service **sfp);

/**
 * Has the fuse server accepted a service context?
 *
 * @param sf service context
 * @return true if it has, false if not
 */
static inline bool fuse_service_accepted(struct fuse_service *sf)
{
	return sf != NULL;
}

/**
 * Will the mount service helper accept the allow_other option?
 *
 * @param sf service context
 * @return true if it has, false if not
 */
bool fuse_service_can_allow_other(struct fuse_service *sf);

/**
 * Release all resources associated with the service context.
 *
 * @param sfp service context
 */
void fuse_service_release(struct fuse_service *sf);

/**
 * Destroy a service context and release all resources
 *
 * @param sfp pointer to pointer to a service context
 */
void fuse_service_destroy(struct fuse_service **sfp);

/**
 * Append the command line arguments from the mount service helper to an
 * existing fuse_args structure.  The fuse_args should have been initialized
 * with the argc and argv passed to main().
 *
 * @param sfp service context
 * @param args arguments to modify (input+output)
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_append_args(struct fuse_service *sf, struct fuse_args *args);

/**
 * Generate the effective fuse server command line from the args structure.
 * The args structure should be the outcome from fuse_service_append_args.
 * The resulting string is suitable for setproctitle and must be freed by the
 * callre.
 *
 * @param argc argument count passed to main()
 * @param argv argument vector passed to main()
 * @param args fuse args structure
 * @return effective command line string, or NULL
 */
char *fuse_service_cmdline(int argc, char *argv[], struct fuse_args *args);

struct fuse_cmdline_opts;

/**
 * Utility function to parse common options for simple file systems
 * using the low-level API. A help text that describes the available
 * options can be printed with `fuse_cmdline_help`. A single
 * non-option argument is treated as the mountpoint. Multiple
 * non-option arguments will result in an error.
 *
 * If neither -o subtype= or -o fsname= options are given, a new
 * subtype option will be added and set to the basename of the program
 * (the fsname will remain unset, and then defaults to "fuse").
 *
 * Known options will be removed from *args*, unknown options will
 * remain. The mountpoint will not be checked here; that is the job of
 * mount.service.
 *
 * @param args argument vector (input+output)
 * @param opts output argument for parsed options
 * @return 0 on success, -1 on failure
 */
int fuse_service_parse_cmdline_opts(struct fuse_args *args,
				    struct fuse_cmdline_opts *opts);

/**
 * Don't complain if this file cannot be opened.
 */
#define FUSE_SERVICE_REQUEST_FILE_QUIET		(1U << 0)

/**
 * Ask the mount.service helper to open a file on behalf of the fuse server.
 *
 * @param sf service context
 * @param path the path to file
 * @param open_flags O_ flags
 * @param create_mode mode with which to create the file
 * @param request_flags set of FUSE_SERVICE_REQUEST_* flags
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_request_file(struct fuse_service *sf, const char *path,
			      int open_flags, mode_t create_mode,
			      unsigned int request_flags);

/**
 * Ask the mount.service helper to open a block device on behalf of the fuse
 * server.
 *
 * @param sf service context
 * @param path the path to file
 * @param open_flags O_ flags
 * @param create_mode mode with which to create the file
 * @param request_flags set of FUSE_SERVICE_REQUEST_* flags
 * @param block_size set the block device block size to this value
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_request_blockdev(struct fuse_service *sf, const char *path,
				  int open_flags, mode_t create_mode,
				  unsigned int request_flags,
				  unsigned int block_size);

/**
 * Receive a file previously requested.
 *
 * @param sf service context
 * @param path to file
 * @fdp pointer to file descriptor, which will be set a non-negative file
 *      descriptor value on success, or negative errno on failure
 * @return 0 on success, or negative errno on socket communication failure
 */
int fuse_service_receive_file(struct fuse_service *sf,
			      const char *path, int *fdp);

/**
 * Prevent the mount.service server from sending us any more open files.
 *
 * @param sf service context
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_finish_file_requests(struct fuse_service *sf);

/**
 * Require that the filesystem mount point have the expected file format
 * (S_IFDIR/S_IFREG).  Can be overridden when calling
 * fuse_service_session_mount.
 *
 * @param sf service context
 * @param expected_fmt expected mode (S_IFDIR/S_IFREG) for mount point, or 0
 *                     to skip checks
 */
void fuse_service_expect_mount_format(struct fuse_service *sf,
				      mode_t expected_fmt);

/**
 * Bind a FUSE file system to the fuse session inside a fuse service process,
 * then ask the mount.service helper to mount the filesystem for us.  The fuse
 * client will begin sending requests to the fuse server immediately after
 * this.  Do not call fuse_daemonize() when running as a fuse service.
 *
 * @param sf service context
 * @param se fuse session
 * @param expected_fmt expected mode (S_IFDIR/S_IFREG) for mount point, or 0
 *                     to skip checks
 * @param opts command line options
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_session_mount(struct fuse_service *sf, struct fuse_session *se,
			       mode_t expected_fmt,
			       struct fuse_cmdline_opts *opts);

/**
 * Ask the mount helper to unmount th e filesystem.
 *
 * @param sf service context
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_session_unmount(struct fuse_service *sf);

/**
 * Bid farewell to the mount.service helper.  It is still necessary to call
 * fuse_service_destroy after this.
 *
 * @param sf service context
 * @param exitcode fuse server process exit status
 * @return 0 on success, or negative errno on failure
 */
int fuse_service_send_goodbye(struct fuse_service *sf, int exitcode);

/**
 * Exit routine for a fuse server running as a systemd service.
 *
 * @param ret 0 for success, nonzero for service failure.
 * @return a value to be passed to exit() or returned from main
 */
int fuse_service_exit(int ret);

#endif /* FUSE_USE_VERSION >= FUSE_MAKE_VERSION(3, 19) */

#ifdef __cplusplus
}
#endif

#endif /* FUSE_SERVICE_H_ */
