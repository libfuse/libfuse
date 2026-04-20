/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025-2026 Oracle.
 * Author: Darrick J. Wong <djwong@kernel.org>
 *
 * Stub functions for platforms where we cannot have fuse servers run as "safe"
 * systemd containers.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt
 */

/* we don't use any parameters at all */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define _GNU_SOURCE
#include <errno.h>

#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_service.h"

int fuse_service_receive_file(struct fuse_service *sf, const char *path,
			      int *fdp)
{
	return -EOPNOTSUPP;
}

int fuse_service_request_file(struct fuse_service *sf, const char *path,
			      int open_flags, mode_t create_mode,
			      unsigned int request_flags)
{
	return -EOPNOTSUPP;
}

int fuse_service_request_blockdev(struct fuse_service *sf, const char *path,
				  int open_flags, mode_t create_mode,
				  unsigned int request_flags,
				  unsigned int block_size)
{
	return -EOPNOTSUPP;
}

int fuse_service_send_goodbye(struct fuse_service *sf, int error)
{
	return -EOPNOTSUPP;
}

int fuse_service_accept(struct fuse_service **sfp)
{
	*sfp = NULL;
	return 0;
}

int fuse_service_append_args(struct fuse_service *sf,
			     struct fuse_args *existing_args)
{
	return -EOPNOTSUPP;
}

char *fuse_service_cmdline(int argc, char *argv[], struct fuse_args *args)
{
	return NULL;
}

int fuse_service_finish_file_requests(struct fuse_service *sf)
{
	return -EOPNOTSUPP;
}

void fuse_service_expect_mount_format(struct fuse_service *sf,
				      mode_t expected_fmt)
{
}

int fuse_service_session_mount(struct fuse_service *sf, struct fuse_session *se,
			       mode_t expected_fmt,
			       struct fuse_cmdline_opts *opts)
{
	return -EOPNOTSUPP;
}

int fuse_service_session_unmount(struct fuse_service *sf)
{
	return -EOPNOTSUPP;
}

void fuse_service_release(struct fuse_service *sf)
{
}

void fuse_service_destroy(struct fuse_service **sfp)
{
	*sfp = NULL;
}

int fuse_service_parse_cmdline_opts(struct fuse_args *args,
				    struct fuse_cmdline_opts *opts)
{
	return -1;
}

int fuse_service_exit(int ret)
{
	return ret;
}
