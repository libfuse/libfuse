/*
 * FUSE: Filesystem in Userspace
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 *
 * A fuse service server for the service mount tests. Each mode takes one
 * step against fuservicemount3 and prints the name of the errno that came
 * back, 0 for success.
 *
 *   test_service socket-path <subtype>
 *   test_service open <path>
 *   test_service open-bdev <path>
 *   test_service open-after-mount <path>
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

/* strerrorname_np() */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fuse_config.h"
#include <fuse_lowlevel.h>
#include <fuse_service.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static const struct fuse_lowlevel_ops test_service_oper = { };

/* @return "EPERM" and so on, "0" for no error */
static const char *errno_name(int error)
{
	const char *name;

	if (!error)
		return "0";

	name = strerrorname_np(error);
	return name ? name : "unknown errno";
}

/* The first non-option argument is the mount source, not the mountpoint */
static int skip_source(void *data, const char *arg, int key,
		       struct fuse_args *outargs)
{
	bool *source_seen = data;

	(void)arg;
	(void)outargs;

	if (key == FUSE_OPT_KEY_NONOPT && !*source_seen) {
		*source_seen = true;
		return 0;
	}
	return 1;
}

/*
 * Mount through the helper so that it has a mount point when the file is
 * requested.
 *
 * @return the mounted session, or NULL on failure
 */
static struct fuse_session *session_mounted(struct fuse_service *service,
					    const char *argv0)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_cmdline_opts opts = { };
	struct fuse_session *se = NULL;
	bool source_seen = false;

	if (fuse_opt_add_arg(&args, argv0) ||
	    fuse_service_append_args(service, &args) ||
	    fuse_opt_parse(&args, &source_seen, NULL, skip_source) ||
	    fuse_service_parse_cmdline_opts(&args, &opts))
		goto out;

	se = fuse_session_new(&args, &test_service_oper,
			      sizeof(test_service_oper), NULL);
	if (!se)
		goto out;

	if (fuse_service_session_mount(service, se, S_IFDIR, &opts)) {
		fuse_session_destroy(se);
		se = NULL;
	}

out:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);
	return se;
}

/* @return 0 when the result was printed, negative errno otherwise */
static int request_printed(const struct fuse_service *service,
			   const char *path, bool blockdev)
{
	int fd;
	int ret;

	if (blockdev)
		ret = fuse_service_request_blockdev(service, path, O_RDONLY,
						    0, 0, 0);
	else
		ret = fuse_service_request_file(service, path, O_RDONLY, 0, 0);
	if (ret)
		return ret;

	/* A refusal by the helper is a success return, with -errno in fd */
	ret = fuse_service_receive_file(service, path, &fd);
	if (ret)
		return ret;

	if (fd >= 0) {
		close(fd);
		printf("request result: 0\n");
	} else {
		printf("request result: %s\n", errno_name(-fd));
	}
	fflush(stdout);
	return 0;
}

int main(int argc, char *argv[])
{
	struct fuse_service *service = NULL;
	struct fuse_session *se = NULL;
	bool blockdev = false;
	int ret = 1;

	if (argc != 3) {
		fprintf(stderr, "usage: %s socket-path <subtype>\n", argv[0]);
		fprintf(stderr, "       %s open|open-bdev|open-after-mount <path>\n",
			argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "socket-path")) {
		printf("%s/%s\n", FUSE_SERVICE_SOCKET_DIR, argv[2]);
		return 0;
	}

	if (fuse_service_accept(&service) || !fuse_service_accepted(service)) {
		fprintf(stderr, "%s: not started as a fuse service\n", argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "open-after-mount")) {
		se = session_mounted(service, argv[0]);
		if (!se)
			goto out;
	} else if (!strcmp(argv[1], "open-bdev")) {
		blockdev = true;
	} else if (strcmp(argv[1], "open")) {
		fprintf(stderr, "%s: unknown case %s\n", argv[0], argv[1]);
		goto out;
	}

	if (request_printed(service, argv[2], blockdev))
		goto out;

	ret = 0;
out:
	fuse_service_send_goodbye(service, ret);
	fuse_service_destroy(&service);
	/* Closes /dev/fuse; the test script unmounts */
	if (se)
		fuse_session_destroy(se);
	return ret;
}
