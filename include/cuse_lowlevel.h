/*
  CUSE: Character device in Userspace
  Copyright (C) 2008-2009  SUSE Linux Products GmbH
  Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt.

  Read example/cusexmp.c for usages.
*/

#ifndef CUSE_LOWLEVEL_H_
#define CUSE_LOWLEVEL_H_

/** @file
 *
 * Low level API
 *
 * IMPORTANT: you should define FUSE_USE_VERSION before including this
 * header.  To use the newest API define it to 319 (recommended for any
 * new application).
 */

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 30
#endif

#include "fuse_lowlevel.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CUSE_UNRESTRICTED_IOCTL		(1 << 0) /* use unrestricted ioctl */

struct fuse_session;

struct cuse_info {
	unsigned	dev_major;
	unsigned	dev_minor;
	unsigned	dev_info_argc;
	const char	**dev_info_argv;
	unsigned	flags;
};

/*
 * Most ops behave almost identically to the matching fuse_lowlevel
 * ops except that they don't take @ino.
 *
 * init_done	: called after initialization is complete
 * read/write	: always direct IO, simultaneous operations allowed
 * ioctl	: might be in unrestricted mode depending on ci->flags
 */
struct cuse_lowlevel_ops {
	void (*init) (void *userdata, struct fuse_conn_info *conn);
	void (*init_done) (void *userdata);
	void (*destroy) (void *userdata);
	void (*open) (fuse_req_t req, struct fuse_file_info *fi);
	void (*read) (fuse_req_t req, size_t size, off_t off,
		      struct fuse_file_info *fi);
	void (*write) (fuse_req_t req, const char *buf, size_t size, off_t off,
		       struct fuse_file_info *fi);
	void (*flush) (fuse_req_t req, struct fuse_file_info *fi);
	void (*release) (fuse_req_t req, struct fuse_file_info *fi);
	void (*fsync) (fuse_req_t req, int datasync, struct fuse_file_info *fi);
#if FUSE_USE_VERSION < 319
	void (*ioctl)(fuse_req_t req, int cmd,
		       void *arg, struct fuse_file_info *fi, unsigned int flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz);
#else
	void (*ioctl)(fuse_req_t req, unsigned int cmd,
		       void *arg, struct fuse_file_info *fi, unsigned int flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz);
#endif
	void (*poll) (fuse_req_t req, struct fuse_file_info *fi,
		      struct fuse_pollhandle *ph);
};

/* Do not call directly, use cuse_lowlevel_new() */
struct fuse_session *
cuse_lowlevel_new_319(struct fuse_args *args, const struct cuse_info *ci,
		      const struct cuse_lowlevel_ops *clop, size_t clop_size,
		      const struct libfuse_version *version, void *userdata);

static inline struct fuse_session *
cuse_lowlevel_new_fn(struct fuse_args *args, const struct cuse_info *ci,
		     const struct cuse_lowlevel_ops *clop, void *userdata)
{
	struct libfuse_version version = {
		.major = FUSE_MAJOR_VERSION,
		.minor = FUSE_MINOR_VERSION,
		.hotfix = FUSE_HOTFIX_VERSION,
		.padding = 0
	};

	return cuse_lowlevel_new_319(args, ci, clop,
				     sizeof(struct cuse_lowlevel_ops), &version,
				     userdata);
}
#define cuse_lowlevel_new(args, ci, clop, userdata) \
	cuse_lowlevel_new_fn(args, ci, clop, userdata)

/* Do not call directly, use cuse_lowlevel_setup() */
struct fuse_session *
cuse_lowlevel_setup_319(int argc, char *argv[], const struct cuse_info *ci,
			const struct cuse_lowlevel_ops *clop, size_t clop_size,
			const struct libfuse_version *version,
			int *multithreaded, void *userdata);

static inline struct fuse_session *
cuse_lowlevel_setup_fn(int argc, char *argv[], const struct cuse_info *ci,
		       const struct cuse_lowlevel_ops *clop, int *multithreaded,
		       void *userdata)
{
	struct libfuse_version version = {
		.major = FUSE_MAJOR_VERSION,
		.minor = FUSE_MINOR_VERSION,
		.hotfix = FUSE_HOTFIX_VERSION,
		.padding = 0
	};

	return cuse_lowlevel_setup_319(argc, argv, ci, clop,
				       sizeof(struct cuse_lowlevel_ops),
				       &version, multithreaded, userdata);
}
#define cuse_lowlevel_setup(argc, argv, ci, clop, multithreaded, userdata) \
	cuse_lowlevel_setup_fn(argc, argv, ci, clop, multithreaded, userdata)

void cuse_lowlevel_teardown(struct fuse_session *se);

/* Do not call directly, use cuse_lowlevel_main() */
int cuse_lowlevel_main_319(int argc, char *argv[], const struct cuse_info *ci,
			   const struct cuse_lowlevel_ops *clop,
			   size_t clop_size,
			   const struct libfuse_version *version,
			   void *userdata);

static inline int cuse_lowlevel_main_fn(int argc, char *argv[],
					const struct cuse_info *ci,
					const struct cuse_lowlevel_ops *clop,
					void *userdata)
{
	struct libfuse_version version = {
		.major = FUSE_MAJOR_VERSION,
		.minor = FUSE_MINOR_VERSION,
		.hotfix = FUSE_HOTFIX_VERSION,
		.padding = 0
	};

	return cuse_lowlevel_main_319(argc, argv, ci, clop,
				      sizeof(struct cuse_lowlevel_ops),
				      &version, userdata);
}
#define cuse_lowlevel_main(argc, argv, ci, clop, userdata) \
	cuse_lowlevel_main_fn(argc, argv, ci, clop, userdata)

#ifdef __cplusplus
}
#endif

#endif /* CUSE_LOWLEVEL_H_ */
