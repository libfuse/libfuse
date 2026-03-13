/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  Stub functions for platforms where we cannot have fuse servers run as "safe"
  systemd containers.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt
*/

/* shut up gcc */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define _GNU_SOURCE
#include <errno.h>

#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_service_priv.h"
#include "fuse_service.h"

int fuse_service_receive_file(struct fuse_service *sf, const char *path,
			      int *fdp)
{
	errno = EOPNOTSUPP;
	return -1;
}

int fuse_service_request_file(struct fuse_service *sf, const char *path,
			      int open_flags, mode_t create_mode,
			      unsigned int request_flags)
{
	errno = EOPNOTSUPP;
	return -1;
}

int fuse_service_send_goodbye(struct fuse_service *sf, int error)
{
	errno = EOPNOTSUPP;
	return -1;
}

int fuse_service_accept(struct fuse_service **sfp)
{
	*sfp = NULL;
	errno = EOPNOTSUPP;
	return -1;
}

int fuse_service_append_args(struct fuse_service *sf,
			     struct fuse_args *existing_args)
{
	errno = EOPNOTSUPP;
	return -1;
}

int fuse_service_take_fusedev(struct fuse_service *sfp)
{
	return -1;
}

int fuse_service_finish_file_requests(struct fuse_service *sf)
{
	errno = EOPNOTSUPP;
	return -1;
}

int fuse_service_mount(struct fuse_service *sf, struct fuse_session *se,
		       const char *mountpoint)
{
	errno = EOPNOTSUPP;
	return -1;
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
	errno = EOPNOTSUPP;
	return -1;
}
