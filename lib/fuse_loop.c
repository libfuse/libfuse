/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "config.h"
#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int fuse_session_loop(struct fuse_session *se)
{
	int res = 0;
	struct fuse_chan *ch = fuse_session_chan(se);
	struct fuse_buf fbuf = {
		.mem = NULL,
	};

	while (!fuse_session_exited(se)) {
		res = fuse_session_receive_buf(se, &fbuf, ch);

		if (res == -EINTR)
			continue;
		if (res <= 0)
			break;

		fuse_session_process_buf(se, &fbuf, ch);
	}

	free(fbuf.mem);
	fuse_session_reset(se);
	return res < 0 ? -1 : 0;
}
