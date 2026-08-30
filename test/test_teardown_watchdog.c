/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025  Bernd Schubert <bernd@bsbernd.com>
 *
 * Test for timeout thread feature in libfuse.
 * Tests that fuse_start_timeout_thread() correctly detects connection abort.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file GPL2.txt
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include "fuse_config.h"
#include "fuse_lowlevel.h"
#include "fuse_i.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef __linux__
#include <sys/types.h>
#else
#include <sys/sysmacros.h>
#endif

struct timeout_data {
	_Atomic bool triggered;
};

static void test_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	(void)parent;
	(void)name;
	fuse_reply_err(req, ENOENT);
}

static void test_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void)fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (ino == 1) {
		stbuf.st_ino = 1;
		stbuf.st_mode = S_IFDIR | 0755;
		stbuf.st_nlink = 2;
		fuse_reply_attr(req, &stbuf, 1.0);
	} else {
		fuse_reply_err(req, ENOENT);
	}
}

static const struct fuse_lowlevel_ops test_ll_ops = {
	.lookup = test_ll_lookup,
	.getattr = test_ll_getattr,
};

/* the watchdog timeout this test arms and measures against */
#define WATCHDOG_TIMEOUT_SEC 5

struct abort_thread_arg {
	const char *mountpoint;
	int delay_ms;

	/* when the abort was written, CLOCK_MONOTONIC */
	struct timespec aborted_at;

	int err;
};

/*
 * The connection directory is named after the mount's device number, printed
 * the way the kernel packs a dev_t: (major << MINORBITS) | minor, MINORBITS
 * being 20. glibc's dev_t packs the same pair differently, so the halves are
 * decoded with the <sys/sysmacros.h> accessors and repacked, not cast: below
 * a minor of 256 the two layouts happen to agree, above it they do not.
 */
static unsigned int kernel_dev(dev_t dev)
{
	const int minorbits = 20;

	return (major(dev) << minorbits) | minor(dev);
}

/*
 * Sever the connection the way 'umount -f' and an administrator do. The abort
 * file belongs to the user that mounted, so this works unprivileged.
 *
 * @param[out] when  timestamp of the abort
 * @return 0 on success, -1 on failure
 */
static int abort_connection(const char *mountpoint, struct timespec *when)
{
	char path[64];
	struct stat stbuf;
	ssize_t res;
	int fd;

	if (stat(mountpoint, &stbuf) == -1) {
		fprintf(stderr, "Failed to stat %s: %s\n", mountpoint,
			strerror(errno));
		return -1;
	}

	snprintf(path, sizeof(path), "/sys/fs/fuse/connections/%u/abort",
		 kernel_dev(stbuf.st_dev));

	fd = open(path, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", path,
			strerror(errno));
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, when);
	res = write(fd, "1", 1);
	close(fd);

	if (res != 1) {
		fprintf(stderr, "Failed to write %s: %s\n", path,
			strerror(errno));
		return -1;
	}

	return 0;
}

static void *abort_thread_func(void *arg)
{
	struct abort_thread_arg *ata = (struct abort_thread_arg *)arg;

	usleep(ata->delay_ms * 1000);
	printf("Aborting the kernel connection\n");
	ata->err = abort_connection(ata->mountpoint, &ata->aborted_at);
	return NULL;
}

static double seconds_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) +
	       (now.tv_nsec - start->tv_nsec) / 1e9;
}

/* @return true if the callback fired within <deadline> seconds of <start> */
static bool wait_triggered(const struct timeout_data *td,
			   const struct timespec *start, double deadline)
{
	while (!td->triggered && seconds_since(start) < deadline)
		usleep(100 * 1000);

	return td->triggered;
}

static void timeout_callback(void *data)
{
	struct timeout_data *td = (struct timeout_data *)data;

	printf("Timeout callback invoked\n");
	td->triggered = true;
}

static void fork_child(const char *mountpoint)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_session *se;
	struct fuse_loop_config *loop_config;
	void *timeout_thread = NULL;
	struct timeout_data td = { .triggered = false };
	pthread_t abort_thread;
	struct abort_thread_arg ata = { .mountpoint = mountpoint,
					.delay_ms = 1000 };
	bool passed = false;
	int ret = -1;
	int exited;

	if (fuse_opt_add_arg(&args, "test_timeout_thread")) {
		fprintf(stderr, "Failed to add argument\n");
		goto out_free_args;
	}

	se = fuse_session_new(&args, &test_ll_ops, sizeof(test_ll_ops), NULL);
	if (!se) {
		fprintf(stderr, "Failed to create FUSE session\n");
		goto out_free_args;
	}

	if (fuse_session_mount(se, mountpoint)) {
		fprintf(stderr, "Failed to mount FUSE filesystem\n");
		goto out_destroy_session;
	}

	loop_config = fuse_loop_cfg_create();
	if (!loop_config) {
		fprintf(stderr, "Failed to create loop config\n");
		goto out_unmount;
	}
	fuse_loop_cfg_set_clone_fd(loop_config, 0);
	fuse_loop_cfg_set_max_threads(loop_config, 2);

	if (fuse_set_signal_handlers(se)) {
		fprintf(stderr, "Failed to set up signal handlers\n");
		goto out_destroy_config;
	}

	timeout_thread = fuse_session_start_teardown_watchdog(
		se, WATCHDOG_TIMEOUT_SEC, timeout_callback, &td);
	if (!timeout_thread) {
		fprintf(stderr, "Failed to start timeout thread\n");
		goto out_remove_handlers;
	}

	/* Start thread that will abort the connection after 1 second */
	if (pthread_create(&abort_thread, NULL, abort_thread_func, &ata)) {
		fprintf(stderr, "Failed to create abort thread\n");
		goto out_stop_timeout;
	}

	printf("Entering FUSE loop, connection abort in 1 second\n");
	ret = fuse_session_loop_mt_312(se, loop_config);

	printf("fuse_session_loop_mt returned %d\n", ret);
	exited = fuse_session_exited(se);
	printf("session exited: %d\n", exited);

	pthread_join(abort_thread, NULL);
	if (ata.err)
		goto out_stop_timeout;

	/*
	 * The watchdog arms its timeout when it sees POLLERR, which cannot be
	 * before the abort, so both deadlines are measured from there.
	 */
	if (wait_triggered(&td, &ata.aborted_at, WATCHDOG_TIMEOUT_SEC - 1)) {
		printf("Test FAILED: callback fired before the timeout\n");
		goto out_stop_timeout;
	}

	printf("Waiting for timeout callback...\n");
	if (!wait_triggered(&td, &ata.aborted_at, WATCHDOG_TIMEOUT_SEC + 30)) {
		printf("Test FAILED: timeout callback was not invoked\n");
		goto out_stop_timeout;
	}

	printf("Test PASSED: timeout callback was invoked\n");
	passed = true;

out_stop_timeout:
	fuse_session_stop_teardown_watchdog(timeout_thread);
out_remove_handlers:
	fuse_remove_signal_handlers(se);
out_destroy_config:
	fuse_loop_cfg_destroy(loop_config);
out_unmount:
	fuse_session_unmount(se);
out_destroy_session:
	fuse_session_destroy(se);
out_free_args:
	fuse_opt_free_args(&args);
	exit(passed ? 0 : 1);
}

static int run_test_in_child(void (*test_func)(const char *),
			     const char *test_name, const char *mountpoint)
{
	pid_t child;
	int status;

	printf("Running test: %s\n", test_name);

	/* the child inherits this buffer and would flush a copy of it */
	fflush(NULL);

	child = fork();
	if (child == -1) {
		perror("fork");
		return 1;
	}

	if (child == 0)
		test_func(mountpoint);

	if (waitpid(child, &status, 0) == -1) {
		perror("waitpid");
		return 1;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	fprintf(stderr, "Child terminated abnormally\n");
	return 1;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]);
		return 1;
	}

	printf("Testing teardown watchdog feature\n");

	ret = run_test_in_child(fork_child, "connection abort triggers callback",
				argv[1]);
	if (ret != 0)
		return ret;

	printf("All tests PASSED\n");
	return 0;
}
