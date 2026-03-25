/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Oracle.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

/** @file
 *
 * minimal example filesystem using high-level API and systemd service api
 *
 * Compile with:
 *
 *     gcc -Wall single_file.c service_hl.c `pkg-config fuse3 --cflags --libs` -o service_hl
 *
 * Note: If the pkg-config command fails due to the absence of the fuse3.pc
 *     file, you should configure the path to the fuse3.pc file in the
 *     PKG_CONFIG_PATH variable.
 *
 * Change the ExecStart line in service_hl@.service:
 *
 *     ExecStart=/path/to/service_hl
 *
 * to point to the actual path of the service_hl binary.
 *
 * Finally, install the service_hl@.service and service_hl.socket files to the
 * systemd service directory, usually /run/systemd/system.
 *
 * ## Source code ##
 * \include service_hl.c
 * \include service_hl.socket
 * \include service_hl@.service
 * \include single_file.c
 * \include single_file.h
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fuse.h>
#include <fuse_service.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <linux/stat.h>
#define USE_SINGLE_FILE_HL_API
#include "single_file.h"

struct service_hl {
	char *device;
	struct fuse_service *service;

	/* really booleans */
	int debug;
};

static struct service_hl hl = { };

static void *service_hl_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;

	return NULL;
}

static int service_hl_read(const char *path, char *buf, size_t count,
			   off_t pos, struct fuse_file_info *fi)
{
	if (!is_single_open_file_path(fi, path))
		return -EIO;

	if (hl.debug)
		fprintf(stderr, "%s: pos 0x%llx count 0x%llx\n",
			__func__,
			(unsigned long long)pos,
			(unsigned long long)count);

	if (!single_file.allow_dio && fi->direct_io)
		return -ENOSYS;

	single_file_check_read(pos, &count);

	if (!count)
		return 0;

	return single_file_pread(buf, count, pos);
}

static int service_hl_write(const char *path, const char *buf, size_t count,
			    off_t pos, struct fuse_file_info *fi)
{
	int ret;

	if (!is_single_open_file_path(fi, path))
		return -EIO;

	if (hl.debug)
		fprintf(stderr, "%s: pos 0x%llx count 0x%llx\n",
			__func__,
			(unsigned long long)pos,
			(unsigned long long)count);

	if (!single_file.allow_dio && fi->direct_io)
		return -ENOSYS;

	ret = single_file_check_write(pos, &count);
	if (ret < 0)
		return ret;

	if (!count)
		return 0;

	return single_file_pwrite(buf, count, pos);
}

static const struct fuse_operations service_hl_oper = {
	.getattr	= single_file_hl_getattr,
	.readdir	= single_file_hl_readdir,
	.open		= single_file_hl_open,
	.opendir	= single_file_hl_opendir,
	.statfs		= single_file_hl_statfs,
	.chmod		= single_file_hl_chmod,
	.utimens	= single_file_hl_utimens,
	.fsync		= single_file_hl_fsync,
	.chown		= single_file_hl_chown,
	.truncate	= single_file_hl_truncate,
	.statx		= single_file_hl_statx,

	.init		= service_hl_init,
	.read		= service_hl_read,
	.write		= service_hl_write,
};

#define SERVICE_HL_OPT(t, p, v) { t, offsetof(struct service_hl, p), v }

static struct fuse_opt service_hl_opts[] = {
	SERVICE_HL_OPT("debug",		debug,			1),
	SINGLE_FILE_OPT_KEYS,
	FUSE_OPT_END
};

static int service_hl_opt_proc(void *data, const char *arg, int key,
			       struct fuse_args *outargs)
{
	int ret = single_file_opt_proc(data, arg, key, outargs);

	if (ret < 1)
		return ret;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		if (!hl.device) {
			hl.device = strdup(arg);
			return 0;
		}
		return 1;
	default:
		break;
	}

	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int ret = 1;

	if (fuse_service_accept(&hl.service))
		goto err_args;

	if (!fuse_service_accepted(hl.service))
		goto err_args;

	if (fuse_service_append_args(hl.service, &args))
		goto err_service;

	if (fuse_opt_parse(&args, &hl, service_hl_opts, service_hl_opt_proc))
		goto err_service;

	if (!hl.device) {
		printf("usage: %s [options] <device> <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		goto err_service;
	}

	if (single_file_service_open(hl.service, hl.device))
		goto err_service;

	if (fuse_service_finish_file_requests(hl.service))
		goto err_singlefile;

	if (single_file_configure(hl.device, NULL))
		goto err_singlefile;

	fuse_service_expect_mount_format(hl.service, S_IFDIR);

	ret = fuse_service_main(hl.service, &args, &service_hl_oper, NULL);

err_singlefile:
	single_file_close();
err_service:
	free(hl.device);
	fuse_service_send_goodbye(hl.service, ret);
	fuse_service_destroy(&hl.service);
err_args:
	fuse_opt_free_args(&args);
	return fuse_service_exit(ret);
}
