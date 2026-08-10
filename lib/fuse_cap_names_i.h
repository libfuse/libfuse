/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  Bernd Schubert <bschubert@ddn.com>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt
 */

#ifndef FUSE_CAP_NAMES_I_H_
#define FUSE_CAP_NAMES_I_H_

#include "fuse_lowlevel.h" // IWYU pragma: keep

#include <stdint.h>
#include <stddef.h>

struct fuse_cap_name {
	uint64_t flag;		/* a FUSE_CAP_* value */
	const char *name;	/* its macro name, e.g. "FUSE_CAP_ASYNC_READ" */
};

/*
 * Every FUSE_CAP_* the library negotiates, shared by example/printcap.c and
 * the test suite's FUSE_INIT status report so the two lists cannot drift
 * apart. printcap reaches across the lib/example line on purpose, and can:
 * meson puts lib/ in the include path of both.
 *
 * Defined rather than declared because printcap links only the public
 * library, which does not export the array. __unused__ so an includer that
 * wants the struct alone still builds under -Dwerror=true.
 */
__attribute__((__unused__))
static const struct fuse_cap_name fuse_cap_names[] = {
	{ FUSE_CAP_ASYNC_READ,			"FUSE_CAP_ASYNC_READ"},
	{ FUSE_CAP_POSIX_LOCKS,			"FUSE_CAP_POSIX_LOCKS"},
	{ FUSE_CAP_ATOMIC_O_TRUNC,		"FUSE_CAP_ATOMIC_O_TRUNC"},
	{ FUSE_CAP_EXPORT_SUPPORT,		"FUSE_CAP_EXPORT_SUPPORT"},
	{ FUSE_CAP_DONT_MASK,			"FUSE_CAP_DONT_MASK"},
	{ FUSE_CAP_SPLICE_MOVE,			"FUSE_CAP_SPLICE_MOVE"},
	{ FUSE_CAP_SPLICE_READ,			"FUSE_CAP_SPLICE_READ"},
	{ FUSE_CAP_SPLICE_WRITE,		"FUSE_CAP_SPLICE_WRITE"},
	{ FUSE_CAP_FLOCK_LOCKS,			"FUSE_CAP_FLOCK_LOCKS"},
	{ FUSE_CAP_IOCTL_DIR,			"FUSE_CAP_IOCTL_DIR"},
	{ FUSE_CAP_AUTO_INVAL_DATA,		"FUSE_CAP_AUTO_INVAL_DATA"},
	{ FUSE_CAP_READDIRPLUS,			"FUSE_CAP_READDIRPLUS"},
	{ FUSE_CAP_READDIRPLUS_AUTO,		"FUSE_CAP_READDIRPLUS_AUTO"},
	{ FUSE_CAP_ASYNC_DIO,			"FUSE_CAP_ASYNC_DIO"},
	{ FUSE_CAP_WRITEBACK_CACHE,		"FUSE_CAP_WRITEBACK_CACHE"},
	{ FUSE_CAP_NO_OPEN_SUPPORT,		"FUSE_CAP_NO_OPEN_SUPPORT"},
	{ FUSE_CAP_PARALLEL_DIROPS,		"FUSE_CAP_PARALLEL_DIROPS"},
	{ FUSE_CAP_POSIX_ACL,			"FUSE_CAP_POSIX_ACL"},
	{ FUSE_CAP_CACHE_SYMLINKS,		"FUSE_CAP_CACHE_SYMLINKS"},
	{ FUSE_CAP_NO_OPENDIR_SUPPORT,		"FUSE_CAP_NO_OPENDIR_SUPPORT"},
	{ FUSE_CAP_EXPLICIT_INVAL_DATA,		"FUSE_CAP_EXPLICIT_INVAL_DATA"},
	{ FUSE_CAP_EXPIRE_ONLY,			"FUSE_CAP_EXPIRE_ONLY"},
	{ FUSE_CAP_SETXATTR_EXT,		"FUSE_CAP_SETXATTR_EXT"},
	{ FUSE_CAP_HANDLE_KILLPRIV,		"FUSE_CAP_HANDLE_KILLPRIV"},
	{ FUSE_CAP_HANDLE_KILLPRIV_V2,		"FUSE_CAP_HANDLE_KILLPRIV_V2"},
	{ FUSE_CAP_DIRECT_IO_ALLOW_MMAP,	"FUSE_CAP_DIRECT_IO_ALLOW_MMAP"},
	{ FUSE_CAP_NO_EXPORT_SUPPORT,		"FUSE_CAP_NO_EXPORT_SUPPORT"},
	{ FUSE_CAP_PASSTHROUGH,			"FUSE_CAP_PASSTHROUGH"},
	{ FUSE_CAP_OVER_IO_URING,		"FUSE_CAP_OVER_IO_URING"},
	{ FUSE_CAP_ALLOW_IDMAP,			"FUSE_CAP_ALLOW_IDMAP"},
	{ FUSE_CAP_SECURITY_CTX,		"FUSE_CAP_SECURITY_CTX"},
	// Add any new capabilities here
	{ 0, NULL} // Sentinel to mark the end of the array
};

#endif
