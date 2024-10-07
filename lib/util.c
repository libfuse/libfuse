#include <stdlib.h>
#include <errno.h>

#include "util.h"

long libfuse_strtol(const char *str)
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

	return val;
}
