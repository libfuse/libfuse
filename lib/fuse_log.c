/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2019  Red Hat, Inc.

  Logging API.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

static void default_log_func(
		__attribute__(( unused )) enum fuse_log_level level,
		const char *fmt, va_list ap)
{
	//char log[512];
	vfprintf(stderr, fmt, ap);
	//vsnprintf(log, 512, fmt, ap);

	//syslog(LOG_INFO, "%s", log);
}

static fuse_log_func_t log_func = default_log_func;

void fuse_set_log_func(fuse_log_func_t func)
{
	if (!func)
		func = default_log_func;

	log_func = func;
}

void fuse_log(enum fuse_log_level level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_func(level, fmt, ap);
	va_end(ap);
}
