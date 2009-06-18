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
	FIOC_GET_SIZE	= _IOR('E', 0, size_t),
	FIOC_SET_SIZE	= _IOW('E', 1, size_t),

	/*
	 * The following two ioctls don't follow usual encoding rules
	 * and transfer variable amount of data.
	 */
	FIOC_READ	= _IO('E', 2),
	FIOC_WRITE	= _IO('E', 3),
};

struct fioc_rw_arg {
	off_t		offset;
	void		*buf;
	size_t		size;
	size_t		prev_size;	/* out param for previous total size */
	size_t		new_size;	/* out param for new total size */
};
