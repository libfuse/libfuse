/*
  FUSE: Filesystem in Userspace

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <fuse_util.h>

int libfuse_strtol(const char *str, long *res)
{
	char *endptr;
	int base = 10;
	long val;

	errno = 0;

	if (!str)
		return -EINVAL;

	val = strtol(str, &endptr, base);

	if (errno)
		return -errno;

	if (endptr == str || *endptr != '\0')
		return -EINVAL;

	*res = val;
	return 0;
}
