/*
  CUSE: Character device in Userspace
  Copyright (C) 2008-2009  SUSE Linux Products GmbH
  Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.

  Read example/cusexmp.c for usages.
*/

#ifndef CUSE_LOWLEVEL_H_
#define CUSE_LOWLEVEL_H_

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 29
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
	void (*ioctl) (fuse_req_t req, int cmd, void *arg,
		       struct fuse_file_info *fi, unsigned int flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz);
	void (*poll) (fuse_req_t req, struct fuse_file_info *fi,
		      struct fuse_pollhandle *ph);
};

struct fuse_session *cuse_lowlevel_new(struct fuse_args *args,
				       const struct cuse_info *ci,
				       const struct cuse_lowlevel_ops *clop,
				       void *userdata);

struct fuse_session *cuse_lowlevel_setup(int argc, char *argv[],
					 const struct cuse_info *ci,
					 const struct cuse_lowlevel_ops *clop,
					 int *multithreaded, void *userdata);

void cuse_lowlevel_teardown(struct fuse_session *se);

int cuse_lowlevel_main(int argc, char *argv[], const struct cuse_info *ci,
		       const struct cuse_lowlevel_ops *clop, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* CUSE_LOWLEVEL_H_ */
