/*
  FUSE: Filesystem in Userspace

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#ifndef _FUSE_UTIL_H_
#define _FUSE_UTIL_H_

#include <stdbool.h>
#include <time.h>

static inline bool fuse_timeout_is_zero(struct timespec *ts)
{
	return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

int libfuse_strtol(const char *str, long *res);
unsigned long fuse_calc_timeout_sec(const double t);
unsigned int fuse_calc_timeout_nsec(const double t);

#endif /* _FUSE_UTIL_H_ */
