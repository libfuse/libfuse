/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Helper functions to create (simple) standalone programs. With the
  aid of these functions it should be possible to create full FUSE
  file system by implementing nothing but the request handlers.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

/* Description:
    This file has compatibility symbols for platforms that do not
    support version symboling
*/

#include "fuse_util.h"
#include "libfuse_config.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

struct fuse_args;
struct fuse_cmdline_opts;
struct fuse_cmdline_opts;
struct fuse_session;
struct fuse_custom_io;
struct fuse_file_info;

typedef uint64_t fuse_nodeid_t;

typedef struct fuse_req *fuse_req_t;

/** Directory entry parameters supplied to fuse_reply_entry() */
struct fuse_entry_param_old {
	fuse_nodeid_t ino;

	uint64_t generation;

	struct stat attr;

	double attr_timeout;
	double entry_timeout;
};

struct fuse_entry_param_new {
	fuse_nodeid_t ino;

	uint64_t generation;

	struct stat attr;

	union {
		double attr_timeout;
		struct timespec attr_timeout_ts;
	};

	union {
		double entry_timeout;
		struct timespec entry_timeout_ts;
	};
};

/**
 * Compatibility ABI symbol for systems that do not support version symboling
 */
#if (!defined(LIBFUSE_BUILT_WITH_VERSIONED_SYMBOLS))
/* With current libfuse fuse_parse_cmdline is a macro pointing to the
 * versioned function. Here in this file we need to provide the ABI symbol
 * and the redirecting macro is conflicting.
 */
#ifdef fuse_parse_cmdline
#undef fuse_parse_cmdline
#endif
int fuse_parse_cmdline_30(struct fuse_args *args,
                           struct fuse_cmdline_opts *opts);
int fuse_parse_cmdline(struct fuse_args *args,
		       struct fuse_cmdline_opts *opts);
int fuse_parse_cmdline(struct fuse_args *args,
		       struct fuse_cmdline_opts *opts)
{
	return fuse_parse_cmdline_30(args, opts);
}

int fuse_session_custom_io_30(struct fuse_session *se,
				const struct fuse_custom_io *io, int fd);
int fuse_session_custom_io(struct fuse_session *se,
				const struct fuse_custom_io *io, int fd);
int fuse_session_custom_io(struct fuse_session *se,
			const struct fuse_custom_io *io, int fd)

{
	return fuse_session_custom_io_30(se, io, fd);
}
#endif

int _fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param_new *e,
		      unsigned int timeout_as_double);
int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param_old *e);
int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param_old *e)
{
	struct fuse_entry_param_new entry = {
		.ino = e->ino,
		.generation = e->generation,
		.attr = e->attr,
		.attr_timeout = e->attr_timeout,
		.entry_timeout = e->entry_timeout,
	};

	return _fuse_reply_entry(req, &entry, 1);
}

int _fuse_reply_create(fuse_req_t req, const struct fuse_entry_param_new *e,
		       const struct fuse_file_info *f,
		       unsigned int timeout_as_double);
int fuse_reply_create(fuse_req_t req, const struct fuse_entry_param_old *e,
		      const struct fuse_file_info *fi);
int fuse_reply_create(fuse_req_t req, const struct fuse_entry_param_old *e,
		      const struct fuse_file_info *fi)
{
	struct fuse_entry_param_new entry = {
		.ino = e->ino,
		.generation = e->generation,
		.attr = e->attr,
		.attr_timeout = e->attr_timeout,
		.entry_timeout = e->entry_timeout,
	};

	return _fuse_reply_create(req, &entry, fi, 1);
}

int _fuse_reply_attr(fuse_req_t req, const struct stat *attr,
		     struct timespec *attr_timeout);
int fuse_reply_attr(fuse_req_t req, const struct stat *attr,
		    double attr_timeout);
int fuse_reply_attr(fuse_req_t req, const struct stat *attr,
		    double attr_timeout)
{
	struct timespec attr_timeout_ts;

	attr_timeout_ts.tv_sec = fuse_calc_timeout_sec(attr_timeout);
	attr_timeout_ts.tv_nsec = fuse_calc_timeout_nsec(attr_timeout);

	return _fuse_reply_attr(req, attr, &attr_timeout_ts);
}

size_t _fuse_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize,
			       const char *name,
			       const struct fuse_entry_param_new *e, off_t off,
			       unsigned int timeout_as_double);
size_t fuse_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize,
			      const char *name,
			      const struct fuse_entry_param_old *e, off_t off);
size_t fuse_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize,
			      const char *name,
			      const struct fuse_entry_param_old *e, off_t off)
{
	struct fuse_entry_param_new entry = {
		.ino = e->ino,
		.generation = e->generation,
		.attr = e->attr,
		.attr_timeout = e->attr_timeout,
		.entry_timeout = e->entry_timeout,
	};

	return _fuse_add_direntry_plus(req, buf, bufsize, name, &entry, off, 1);
}
