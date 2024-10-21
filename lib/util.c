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

unsigned long fuse_calc_timeout_sec(const double t)
{
	if (t > (double)ULONG_MAX)
		return ULONG_MAX;
	else if (t < 0.0)
		return 0;
	else
		return (unsigned long)t;
}

unsigned int fuse_calc_timeout_nsec(const double t)
{
	double f = t - (double)fuse_calc_timeout_sec(t);
	if (f < 0.0)
		return 0;
	else if (f >= 0.999999999)
		return 999999999;
	else
		return (unsigned int)(f * 1.0e9);
}
