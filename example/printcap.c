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

#include "fuse_cap_names_i.h"

struct fuse_session *se;

static void print_capabilities(struct fuse_conn_info *conn)
{
	printf("Capabilities:\n");
	for (const struct fuse_cap_name *cap = fuse_cap_names; cap->name != NULL; cap++) {
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
