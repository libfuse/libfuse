/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Oracle.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

/** @file
 *
 * minimal example filesystem using low-level API and systemd service api
 *
 * Compile with:
 *
 *     gcc -Wall single_file.c service_ll.c `pkg-config fuse3 --cflags --libs` -o service_ll
 *
 * Note: If the pkg-config command fails due to the absence of the fuse3.pc
 *     file, you should configure the path to the fuse3.pc file in the
 *     PKG_CONFIG_PATH variable.
 *
 * Change the ExecStart line in service_ll@.service:
 *
 *     ExecStart=/path/to/service_ll
 *
 * to point to the actual path of the service_ll binary.
 *
 * Finally, install the service_ll@.service and service_ll.socket files to the
 * systemd service directory, usually /run/systemd/system.
 *
 * ## Source code ##
 * \include service_ll.c
 * \include service_ll.socket
 * \include service_ll@.service
 * \include single_file.c
 * \include single_file.h
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fuse_lowlevel.h>
#include <fuse_service.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include "single_file.h"

struct service_ll {
	struct fuse_session *se;
	char *device;
	struct fuse_service *service;

	/* really booleans */
	int debug;
};

static struct service_ll ll = { };

static void service_ll_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;

	conn->time_gran = 1;
}

static void service_ll_read(fuse_req_t req, fuse_ino_t ino, size_t count,
			    off_t pos, struct fuse_file_info *fi)
{
	void *buf = NULL;
	ssize_t got;
	int ret;

	if (!is_single_file_ino(ino)) {
		ret = EIO;
		goto out_reply;
	}

	if (ll.debug)
		fprintf(stderr, "%s: pos 0x%llx count 0x%llx\n",
			__func__,
			(unsigned long long)pos,
			(unsigned long long)count);

	if (!single_file.allow_dio && fi->direct_io) {
		ret = ENOSYS;
		goto out_reply;
	}

	single_file_check_read(pos, &count);

	if (!count) {
		fuse_reply_buf(req, buf, 0);
		return;
	}

	buf = malloc(count);
	if (!buf) {
		ret = ENOMEM;
		goto out_reply;
	}

	got = single_file_pread(buf, count, pos);
	if (got < 0) {
		ret = -got;
		goto out_reply;
	}

	fuse_reply_buf(req, buf, got);
	goto out_buf;

out_reply:
	fuse_reply_err(req, ret);
out_buf:
	free(buf);
}

static void service_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			     size_t count, off_t pos,
			     struct fuse_file_info *fi)
{
	ssize_t got;
	int ret;

	if (!is_single_file_ino(ino)) {
		ret = EIO;
		goto out_reply;
	}

	if (ll.debug)
		fprintf(stderr, "%s: pos 0x%llx count 0x%llx\n",
			__func__,
			(unsigned long long)pos,
			(unsigned long long)count);

	if (!single_file.allow_dio && fi->direct_io) {
		ret = ENOSYS;
		goto out_reply;
	}

	ret = -single_file_check_write(pos, &count);
	if (ret)
		goto out_reply;

	if (!count) {
		fuse_reply_write(req, 0);
		return;
	}

	got = single_file_pwrite(buf, count, pos);
	if (got < 0) {
		ret = -got;
		goto out_reply;
	}

	fuse_reply_write(req, got);
	return;

out_reply:
	fuse_reply_err(req, ret);
}

static const struct fuse_lowlevel_ops service_ll_oper = {
	.lookup		= single_file_ll_lookup,
	.getattr	= single_file_ll_getattr,
	.setattr	= single_file_ll_setattr,
	.readdir	= single_file_ll_readdir,
	.open		= single_file_ll_open,
	.statfs		= single_file_ll_statfs,
	.statx		= single_file_ll_statx,
	.fsync		= single_file_ll_fsync,

	.init		= service_ll_init,
	.read		= service_ll_read,
	.write		= service_ll_write,
};

#define SERVICE_LL_OPT(t, p, v) { t, offsetof(struct service_ll, p), v }

static struct fuse_opt service_ll_opts[] = {
	SERVICE_LL_OPT("debug",		debug,			1),
	SINGLE_FILE_OPT_KEYS,
	FUSE_OPT_END
};

static int service_ll_opt_proc(void *data, const char *arg, int key,
				 struct fuse_args *outargs)
{
	int ret = single_file_opt_proc(data, arg, key, outargs);

	if (ret < 1)
		return ret;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		if (!ll.device) {
			ll.device = strdup(arg);
			return 0;
		}
		return 1;
	}

	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts = { };
	struct fuse_loop_config *config = NULL;
	int ret = 1;

	if (fuse_service_accept(&ll.service))
		goto err_args;

	if (!fuse_service_accepted(ll.service))
		goto err_args;

	if (fuse_service_append_args(ll.service, &args))
		goto err_service;

	if (fuse_opt_parse(&args, &ll, service_ll_opts, service_ll_opt_proc))
		goto err_service;

	if (fuse_service_parse_cmdline_opts(&args, &opts))
		goto err_service;

	if (opts.show_help) {
		printf("usage: %s [options] <device> <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		ret = 0;
		goto err_service;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_service;
	}

	if (!opts.mountpoint || !ll.device) {
		printf("usage: %s [options] <device> <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		goto err_service;
	}

	if (single_file_service_open(ll.service, ll.device))
		goto err_service;

	if (fuse_service_finish_file_requests(ll.service))
		goto err_singlefile;

	if (single_file_configure(ll.device, NULL))
		goto err_singlefile;

	ll.se = fuse_session_new(&args, &service_ll_oper,
				 sizeof(service_ll_oper), NULL);
	if (ll.se == NULL)
		goto err_singlefile;

	if (!opts.singlethread) {
		config = fuse_loop_cfg_create();
		if (!config) {
			ret = 1;
			goto err_session;
		}
	}

	if (fuse_set_signal_handlers(ll.se))
		goto err_loopcfg;

	if (fuse_service_session_mount(ll.service, ll.se, S_IFDIR, &opts))
		goto err_signals;

	/* Block until ctrl+c or fusermount -u */
	if (opts.singlethread) {
		fuse_service_send_goodbye(ll.service, 0);
		fuse_service_release(ll.service);
		ret = fuse_session_loop(ll.se);
	} else {
		fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
		fuse_loop_cfg_set_max_threads(config, opts.max_threads);

		fuse_service_send_goodbye(ll.service, 0);
		fuse_service_release(ll.service);
		ret = fuse_session_loop_mt(ll.se, config);
	}

err_signals:
	fuse_remove_signal_handlers(ll.se);
err_loopcfg:
	fuse_loop_cfg_destroy(config);
err_session:
	fuse_session_destroy(ll.se);
err_singlefile:
	single_file_close();
err_service:
	free(opts.mountpoint);
	free(ll.device);
	fuse_service_send_goodbye(ll.service, ret);
	fuse_service_destroy(&ll.service);
err_args:
	fuse_opt_free_args(&args);
	return fuse_service_exit(ret);
}
