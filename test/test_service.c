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
 *   test_service mount dir|file
 *   test_service mount-elsewhere <mountpoint>
 *   test_service caps
 *   test_service exit-early
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
 * Mount through the helper. On success *sep is the mounted session, which
 * keeps /dev/fuse open until it is destroyed.
 *
 * @param fmt         mount point type the helper has to find
 * @param mountpoint  sent in place of the one on the command line, or NULL
 * @return 0 when the result was printed, -1 otherwise
 */
static int mount_printed(struct fuse_service *service, const char *argv0,
			 mode_t fmt, const char *mountpoint,
			 struct fuse_session **sep)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_cmdline_opts opts = { };
	struct fuse_session *se;
	bool source_seen = false;
	int printed = -1;
	int ret;

	*sep = NULL;

	if (fuse_opt_add_arg(&args, argv0) ||
	    fuse_service_append_args(service, &args) ||
	    fuse_opt_parse(&args, &source_seen, NULL, skip_source) ||
	    fuse_service_parse_cmdline_opts(&args, &opts))
		goto out;

	if (mountpoint) {
		free(opts.mountpoint);
		opts.mountpoint = strdup(mountpoint);
		if (!opts.mountpoint)
			goto out;
	}

	se = fuse_session_new(&args, &test_service_oper,
			      sizeof(test_service_oper), NULL);
	if (!se)
		goto out;

	ret = fuse_service_session_mount(service, se, fmt, &opts);
	if (ret)
		fuse_session_destroy(se);
	else
		*sep = se;

	printf("mount result: %s\n", errno_name(-ret));
	printed = 0;
out:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);
	return printed;
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

/* @return S_IFDIR or S_IFREG, 0 for an unknown name */
static mode_t mount_format(const char *name)
{
	if (!strcmp(name, "dir"))
		return S_IFDIR;
	if (!strcmp(name, "file"))
		return S_IFREG;
	return 0;
}

int main(int argc, char *argv[])
{
	struct fuse_service *service = NULL;
	struct fuse_session *se = NULL;
	const char *mode;
	const char *arg;
	int ret = 1;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s socket-path <subtype>\n", argv[0]);
		fprintf(stderr, "       %s open|open-bdev|open-after-mount <path>\n",
			argv[0]);
		fprintf(stderr, "       %s mount dir|file\n", argv[0]);
		fprintf(stderr, "       %s mount-elsewhere <mountpoint>\n",
			argv[0]);
		fprintf(stderr, "       %s caps|exit-early\n", argv[0]);
		return 1;
	}
	mode = argv[1];
	/* argv[argc] is NULL */
	arg = argv[2];

	if (!strcmp(mode, "socket-path") && arg) {
		printf("%s/%s\n", FUSE_SERVICE_SOCKET_DIR, arg);
		return 0;
	}

	if (fuse_service_accept(&service) || !fuse_service_accepted(service)) {
		fprintf(stderr, "%s: not started as a fuse service\n", argv[0]);
		return 1;
	}

	if (!strcmp(mode, "exit-early")) {
		/* No goodbye, the helper only sees the connection close */
		fuse_service_destroy(&service);
		return 0;
	}

	if (!strcmp(mode, "caps")) {
		printf("caps result: allow_other=%d fuseblk=%d\n",
		       fuse_service_can_allow_other(service),
		       fuse_service_can_fuseblk(service));
	} else if (!strcmp(mode, "mount") && arg && mount_format(arg)) {
		if (mount_printed(service, argv[0], mount_format(arg), NULL,
				  &se))
			goto out;
	} else if (!strcmp(mode, "mount-elsewhere") && arg) {
		if (mount_printed(service, argv[0], S_IFDIR, arg, &se))
			goto out;
	} else if (!strcmp(mode, "open-after-mount") && arg) {
		if (mount_printed(service, argv[0], S_IFDIR, NULL, &se) || !se)
			goto out;
		if (request_printed(service, arg, false))
			goto out;
	} else if ((!strcmp(mode, "open") || !strcmp(mode, "open-bdev")) &&
		   arg) {
		if (request_printed(service, arg, !strcmp(mode, "open-bdev")))
			goto out;
	} else {
		fprintf(stderr, "%s: unknown case %s\n", argv[0], mode);
		goto out;
	}

	ret = 0;
out:
	fuse_service_send_goodbye(service, ret);
	fuse_service_destroy(&service);
	/* Closes /dev/fuse; the test script unmounts */
	if (se)
		fuse_session_destroy(se);
	return ret;
}
