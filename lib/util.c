
#include "fuse_config.h"

#ifdef HAVE_PTHREAD_SETNAME_NP
#define _GNU_SOURCE
#include <pthread.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <errno.h>

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION (FUSE_MAKE_VERSION(3, 18))
#endif

#include "util.h"
#include "fuse_log.h"
#include "fuse_lowlevel.h"
#include <stdio.h>

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

void fuse_set_thread_name(const char *name)
{
#ifdef HAVE_PTHREAD_SETNAME_NP
	pthread_setname_np(pthread_self(), name);
#else
	(void)name;
#endif
}

