/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2017 Nikolaus Rath <Nikolaus@rath.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
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

#include <config.h>

#include <fuse_lowlevel.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

struct fuse_session *se;

static void pc_init(void *userdata,
		    struct fuse_conn_info *conn)
{
	(void) userdata;
	
	printf("Protocol version: %d.%d\n", conn->proto_major,
	       conn->proto_minor);
	printf("Capabilities:\n");
	if(conn->capable & FUSE_CAP_WRITEBACK_CACHE)
		printf("\tFUSE_CAP_WRITEBACK_CACHE\n");
	if(conn->capable & FUSE_CAP_ASYNC_READ)
			printf("\tFUSE_CAP_ASYNC_READ\n");
	if(conn->capable & FUSE_CAP_POSIX_LOCKS)
			printf("\tFUSE_CAP_POSIX_LOCKS\n");
	if(conn->capable & FUSE_CAP_ATOMIC_O_TRUNC)
			printf("\tFUSE_CAP_ATOMIC_O_TRUNC\n");
	if(conn->capable & FUSE_CAP_EXPORT_SUPPORT)
			printf("\tFUSE_CAP_EXPORT_SUPPORT\n");
	if(conn->capable & FUSE_CAP_DONT_MASK)
			printf("\tFUSE_CAP_DONT_MASK\n");
	if(conn->capable & FUSE_CAP_SPLICE_MOVE)
			printf("\tFUSE_CAP_SPLICE_MOVE\n");
	if(conn->capable & FUSE_CAP_SPLICE_READ)
			printf("\tFUSE_CAP_SPLICE_READ\n");
	if(conn->capable & FUSE_CAP_SPLICE_WRITE)
			printf("\tFUSE_CAP_SPLICE_WRITE\n");
	if(conn->capable & FUSE_CAP_FLOCK_LOCKS)
			printf("\tFUSE_CAP_FLOCK_LOCKS\n");
	if(conn->capable & FUSE_CAP_IOCTL_DIR)
			printf("\tFUSE_CAP_IOCTL_DIR\n");
	if(conn->capable & FUSE_CAP_AUTO_INVAL_DATA)
			printf("\tFUSE_CAP_AUTO_INVAL_DATA\n");
	if(conn->capable & FUSE_CAP_READDIRPLUS)
			printf("\tFUSE_CAP_READDIRPLUS\n");
	if(conn->capable & FUSE_CAP_READDIRPLUS_AUTO)
			printf("\tFUSE_CAP_READDIRPLUS_AUTO\n");
	if(conn->capable & FUSE_CAP_ASYNC_DIO)
			printf("\tFUSE_CAP_ASYNC_DIO\n");
	if(conn->capable & FUSE_CAP_WRITEBACK_CACHE)
			printf("\tFUSE_CAP_WRITEBACK_CACHE\n");
	if(conn->capable & FUSE_CAP_NO_OPEN_SUPPORT)
			printf("\tFUSE_CAP_NO_OPEN_SUPPORT\n");
	if(conn->capable & FUSE_CAP_PARALLEL_DIROPS)
			printf("\tFUSE_CAP_PARALLEL_DIROPS\n");
	if(conn->capable & FUSE_CAP_POSIX_ACL)
			printf("\tFUSE_CAP_POSIX_ACL\n");
	if(conn->capable & FUSE_CAP_CACHE_SYMLINKS)
			printf("\tFUSE_CAP_CACHE_SYMLINKS\n");
	if(conn->capable & FUSE_CAP_NO_OPENDIR_SUPPORT)
			printf("\tFUSE_CAP_NO_OPENDIR_SUPPORT\n");
	if(conn->capable & FUSE_CAP_EXPLICIT_INVAL_DATA)
			printf("\tFUSE_CAP_EXPLICIT_INVAL_DATA\n");
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
