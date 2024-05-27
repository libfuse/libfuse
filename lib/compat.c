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

#include "libfuse_config.h"

struct fuse_args;
struct fuse_cmdline_opts;
struct fuse_cmdline_opts;


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
#endif


