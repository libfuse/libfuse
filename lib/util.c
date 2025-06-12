
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

/**
 * Internal helper for string to long conversion with specified base
 * @param str String to convert
 * @param res Pointer to store the result
 * @param base Base for conversion (0 for auto-detection)
 * @return 0 on success, -errno on failure
 */
int _libfuse_strtol(const char *str, long *res, int base)
{
	char *endptr;
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

int libfuse_strtol(const char *str, long *res)
{
	return _libfuse_strtol(str, res, 10);
}

void fuse_set_thread_name(const char *name)
{
#ifdef HAVE_PTHREAD_SETNAME_NP
	pthread_setname_np(pthread_self(), name);
#else
	(void)name;
#endif
}

