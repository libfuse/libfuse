/*  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt.
*/
#ifndef FUSE_SERVICE_H_
#define FUSE_SERVICE_H_

struct fuse_service;

/**
 * Accept a socket created by mount.service for information exchange.
 *
 * @param sfp pointer to pointer to a service context
 * @return -1 on error, 0 on success
 */
int fuse_service_accept(struct fuse_service **sfp);

/**
 * Has the fuse server accepted a service context?
 *
 * @param sf service context
 */
static inline bool fuse_service_accepted(struct fuse_service *sf)
{
	return sf != NULL;
}

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
 * @return -1 on error, 0 on success
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

/**
 * Take the fuse device fd passed from the mount.service helper
 *
 * @return device fd on success, -1 on error
 */
int fuse_service_take_fusedev(struct fuse_service *sfp);

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
 * Ask the mount.service helper to open a file on behalf of the fuse server.
 *
 * @param sf service context
 * @param path path to file
 * @param open_flags O_ flags
 * @param create_mode mode with which to create the file
 * @param request_flags set of FUSE_SERVICE_REQUEST_* flags
 * @return 0 on success, -1 on failure
 */
int fuse_service_request_file(struct fuse_service *sf, const char *path,
			      int open_flags, mode_t create_mode,
			      unsigned int request_flags);

/**
 * Ask the mount.service helper to open a block device on behalf of the fuse
 * server.
 *
 * @param sf service context
 * @param path path to file
 * @param open_flags O_ flags
 * @param create_mode mode with which to create the file
 * @param request_flags set of FUSE_SERVICE_REQUEST_* flags
 * @param block_size set the block device block size to this value
 * @return 0 on success, -1 on failure
 */
int fuse_service_request_blockdev(struct fuse_service *sf, const char *path,
				  int open_flags, mode_t create_mode,
				  unsigned int request_flags,
				  unsigned int block_size);

/**
 * Receive a file perviously requested.
 *
 * @param sf service context
 * @param path to file
 * @fdp pointer to file descriptor, which will be set to -1 if the file could
 *      not be opened
 * @return -1 on socket communication failure, 0 otherwise
 */
int fuse_service_receive_file(struct fuse_service *sf,
			      const char *path, int *fdp);

/**
 * Prevent the mount.service server from sending us any more open files.
 *
 * @param sf service context
 */
int fuse_service_finish_file_requests(struct fuse_service *sf);

/**
 * Bind a FUSE file system to the fuse session inside a fuse service process,
 * then ask the mount.service helper to mount the filesystem for us.  The fuse
 * client will begin sending requests to the fuse server immediately after
 * this.
 *
 * @param sf service context
 * @param se fuse session
 * @param opts command line options
 * @return 0 on success, -1 on error
 */
int fuse_service_session_mount(struct fuse_service *sf, struct fuse_session *se,
			       struct fuse_cmdline_opts *opts);

/**
 * Bid farewell to the mount.service helper.  It is still necessary to call
 * fuse_service_destroy after this.
 *
 * @param sf service context
 * @param error any additional errors to send to the mount helper
 * @return 0 on success, -1 on error
 */
int fuse_service_send_goodbye(struct fuse_service *sf, int error);

/**
 * Exit routine for a fuse server running as a systemd service.
 *
 * @param ret 0 for success, nonzero for service failure.
 * @return a value to be passed to exit() or returned from main
 */
int fuse_service_exit(int ret);

#endif /* FUSE_SERVICE_H_ */
