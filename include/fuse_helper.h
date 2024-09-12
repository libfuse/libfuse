/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2024   DataDirect Networks, Inc. All rights reserved.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#ifndef FUSE_HELPER_H
#define FUSE_HELPER_H

/** @file
 *
 * This file defines helper functions used by libfuse and applications using
 * libfuse
 */

#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif

static inline unsigned long fuse_calc_timeout_sec(const double t)
{
	if (t > (double) ULONG_MAX)
		return ULONG_MAX;
	else if (t < 0.0)
		return 0;
	else
		return (unsigned long) t;
}

static inline unsigned int fuse_calc_timeout_nsec(const double t)
{
	double f = t - (double) fuse_calc_timeout_sec(t);
	if (f < 0.0)
		return 0;
	else if (f >= 0.999999999)
		return 999999999;
	else
		return (unsigned int) (f * 1.0e9);
}

static inline bool fuse_timeout_is_zero(struct timespec *ts)
{
	return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* FUSE_HELPER_H */
