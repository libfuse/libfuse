/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Helper functions to create (simple) standalone programs. With the
  aid of these functions it should be possible to create full FUSE
  file system by implementing nothing but the request handlers.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt.
*/

/* Description:
    This file has compatibility symbols for platforms that do not
    support version symboling
*/

#include "libfuse_config.h"

#include <stddef.h>
#include <stdint.h>

struct fuse_args;
struct fuse_cmdline_opts;
struct fuse_cmdline_opts;
struct fuse_session;
struct fuse_custom_io;
struct fuse_operations;
struct fuse_lowlevel_ops;

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

#endif /* LIBFUSE_BUILT_WITH_VERSIONED_SYMBOLS */

int fuse_main_real_30(int argc, char *argv[], const struct fuse_operations *op,
		      size_t op_size, void *user_data);
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		   size_t op_size, void *user_data);
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		   size_t op_size, void *user_data)
{
	return fuse_main_real_30(argc, argv, op, op_size, user_data);
}

struct fuse_session *fuse_session_new_30(struct fuse_args *args,
					 const struct fuse_lowlevel_ops *op,
					 size_t op_size, void *userdata);
struct fuse_session *fuse_session_new(struct fuse_args *args,
				      const struct fuse_lowlevel_ops *op,
				      size_t op_size, void *userdata);
struct fuse_session *fuse_session_new(struct fuse_args *args,
				      const struct fuse_lowlevel_ops *op,
				      size_t op_size, void *userdata)
{
	return fuse_session_new_30(args, op, op_size, userdata);
}
