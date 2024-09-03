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
#include <stdbool.h>
#include <syslog.h>

#define MAX_SYSLOG_LINE_LEN 512

static bool to_syslog = false;

static void default_log_func(__attribute__((unused)) enum fuse_log_level level,
			     const char *fmt, va_list ap)
{
	if (to_syslog) {
		int sys_log_level = LOG_ERR;

		/*
		 * with glibc fuse_log_level has identical values as
		 * syslog levels, but we also support BSD - better we convert to
		 * be sure.
		 */
		switch (level) {
		case FUSE_LOG_DEBUG:
			sys_log_level = LOG_DEBUG;
			break;
		case FUSE_LOG_INFO:
			sys_log_level = LOG_INFO;
			break;
		case FUSE_LOG_NOTICE:
			sys_log_level = LOG_NOTICE;
			break;
		case FUSE_LOG_WARNING:
			sys_log_level = LOG_WARNING;
			break;
		case FUSE_LOG_ERR:
			sys_log_level = LOG_ERR;
			break;
		case FUSE_LOG_CRIT:
			sys_log_level = LOG_CRIT;
			break;
		case FUSE_LOG_ALERT:
			sys_log_level = LOG_ALERT;
			break;
		case FUSE_LOG_EMERG:
			sys_log_level = LOG_EMERG;
		}

		char log[MAX_SYSLOG_LINE_LEN];
		vsnprintf(log, MAX_SYSLOG_LINE_LEN, fmt, ap);
		syslog(sys_log_level, "%s", log);
	} else {
		vfprintf(stderr, fmt, ap);
	}
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
