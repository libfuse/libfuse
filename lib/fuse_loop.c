/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Implementation of the single-threaded FUSE session loop.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse_config.h"
#include "fuse_lowlevel.h"
#include "fuse_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int fuse_session_loop(struct fuse_session *se)
{
	int res = 0;
	struct fuse_buf fbuf = {
		.mem = NULL,
	};

	while (!fuse_session_exited(se)) {
		res = fuse_session_receive_buf_internal(se, &fbuf, NULL);

		if (res == -EINTR)
			continue;
		if (res <= 0)
			break;

		fuse_session_process_buf(se, &fbuf);
	}

	fuse_buf_free(&fbuf);
	if(res > 0)
		/* No error, just the length of the most recently read
		   request */
		res = 0;
	if(se->error != 0)
		res = se->error;
	fuse_session_reset(se);
	return res;
}
