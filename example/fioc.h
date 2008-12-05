/*
  FUSE-ioctl: ioctl support for FUSE
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

enum {
	FIOC_GET_SIZE = _IOR('E', 0, size_t),
	FIOC_SET_SIZE = _IOW('E', 1, size_t),
};
