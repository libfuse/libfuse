/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "fuse.h"
#include "fuse_lowlevel.h"

int fuse_loop_mt(struct fuse *f)
{
	if (f == NULL)
		return -1;

	int res = fuse_start_cleanup_thread(f);
	if (res)
		return -1;

	res = fuse_session_loop_mt(fuse_get_session(f));
	fuse_stop_cleanup_thread(f);
	return res;
}
