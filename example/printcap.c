/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2017 Nikolaus Rath <Nikolaus@rath.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/** @file
 *
 * minimal example filesystem that prints out all capabilities
 * supported by the kernel and then exits.
 *
 * Compile with:
 *
 *     gcc -Wall printcap.c `pkg-config fuse3 --cflags --libs` -o printcap
 *
 * ## Source code ##
 * \include printcap.c
 */

#define FUSE_USE_VERSION 31

#include <fuse_lowlevel.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

struct fuse_session *se;

// Define a structure to hold capability information
struct cap_info {
	uint64_t flag;
	const char *name;
};

// Define an array of all capabilities
static const struct cap_info capabilities[] = {
    {FUSE_CAP_ASYNC_READ,		"FUSE_CAP_ASYNC_READ"},
    {FUSE_CAP_POSIX_LOCKS,		"FUSE_CAP_POSIX_LOCKS"},
    {FUSE_CAP_ATOMIC_O_TRUNC,		"FUSE_CAP_ATOMIC_O_TRUNC"},
    {FUSE_CAP_EXPORT_SUPPORT,		"FUSE_CAP_EXPORT_SUPPORT"},
    {FUSE_CAP_DONT_MASK,		"FUSE_CAP_DONT_MASK"},
    {FUSE_CAP_SPLICE_MOVE,		"FUSE_CAP_SPLICE_MOVE"},
    {FUSE_CAP_SPLICE_READ,		"FUSE_CAP_SPLICE_READ"},
    {FUSE_CAP_SPLICE_WRITE,		"FUSE_CAP_SPLICE_WRITE"},
    {FUSE_CAP_FLOCK_LOCKS,		"FUSE_CAP_FLOCK_LOCKS"},
    {FUSE_CAP_IOCTL_DIR,		"FUSE_CAP_IOCTL_DIR"},
    {FUSE_CAP_AUTO_INVAL_DATA,		"FUSE_CAP_AUTO_INVAL_DATA"},
    {FUSE_CAP_READDIRPLUS,		"FUSE_CAP_READDIRPLUS"},
    {FUSE_CAP_READDIRPLUS_AUTO,		"FUSE_CAP_READDIRPLUS_AUTO"},
    {FUSE_CAP_ASYNC_DIO,		"FUSE_CAP_ASYNC_DIO"},
    {FUSE_CAP_WRITEBACK_CACHE,		"FUSE_CAP_WRITEBACK_CACHE"},
    {FUSE_CAP_NO_OPEN_SUPPORT,		"FUSE_CAP_NO_OPEN_SUPPORT"},
    {FUSE_CAP_PARALLEL_DIROPS,		"FUSE_CAP_PARALLEL_DIROPS"},
    {FUSE_CAP_POSIX_ACL,		"FUSE_CAP_POSIX_ACL"},
    {FUSE_CAP_CACHE_SYMLINKS,		"FUSE_CAP_CACHE_SYMLINKS"},
    {FUSE_CAP_NO_OPENDIR_SUPPORT,	"FUSE_CAP_NO_OPENDIR_SUPPORT"},
    {FUSE_CAP_EXPLICIT_INVAL_DATA,	"FUSE_CAP_EXPLICIT_INVAL_DATA"},
    {FUSE_CAP_EXPIRE_ONLY,		"FUSE_CAP_EXPIRE_ONLY"},
    {FUSE_CAP_SETXATTR_EXT,		"FUSE_CAP_SETXATTR_EXT"},
    {FUSE_CAP_HANDLE_KILLPRIV,		"FUSE_CAP_HANDLE_KILLPRIV"},
    {FUSE_CAP_HANDLE_KILLPRIV_V2,	"FUSE_CAP_HANDLE_KILLPRIV_V2"},
    {FUSE_CAP_DIRECT_IO_ALLOW_MMAP,	"FUSE_CAP_DIRECT_IO_ALLOW_MMAP"},
    {FUSE_CAP_NO_EXPORT_SUPPORT,	"FUSE_CAP_NO_EXPORT_SUPPORT"},
    {FUSE_CAP_PASSTHROUGH,		"FUSE_CAP_PASSTHROUGH"},
    // Add any new capabilities here
    {0, NULL} // Sentinel to mark the end of the array
};

static void print_capabilities(struct fuse_conn_info *conn)
{
	printf("Capabilities:\n");
	for (const struct cap_info *cap = capabilities; cap->name != NULL; cap++) {
		if (fuse_get_feature_flag(conn, cap->flag)) {
			printf("\t%s\n", cap->name);
		}
	}
}

static void pc_init(void *userdata, struct fuse_conn_info *conn)
{
	(void) userdata;

	printf("Protocol version: %d.%d\n", conn->proto_major,
	       conn->proto_minor);
	print_capabilities(conn);
	fuse_session_exit(se);
}


static const struct fuse_lowlevel_ops pc_oper = {
	.init		= pc_init,
};

int main(int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	char *mountpoint;
	int ret = -1;

	mountpoint = strdup("/tmp/fuse_printcap_XXXXXX");
	if(mkdtemp(mountpoint) == NULL) {
		perror("mkdtemp");
		return 1;
	}

	printf("FUSE library version %s\n", fuse_pkgversion());
	fuse_lowlevel_version();

	se = fuse_session_new(&args, &pc_oper,
			      sizeof(pc_oper), NULL);
	if (se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
	    goto err_out2;

	if (fuse_session_mount(se, mountpoint) != 0)
	    goto err_out3;

	ret = fuse_session_loop(se);

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	rmdir(mountpoint);
	free(mountpoint);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}
