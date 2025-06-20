/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2019  Red Hat, Inc.

  Logging API.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt
*/

#include "fuse_log.h"

#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdarg.h>

#define MAX_SYSLOG_LINE_LEN 512

static bool to_syslog = false;

static void default_log_func(enum fuse_log_level level, const char *fmt, va_list ap)
{
	if (to_syslog)
		vsyslog(level, fmt, ap);
	else
		vfprintf(stderr, fmt, ap);
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

void fuse_log_enable_syslog(const char *ident, int option, int facility)
{
	to_syslog = true;

	openlog(ident, option, facility);
}

void fuse_log_close_syslog(void)
{
	closelog();
}
