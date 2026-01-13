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
#include <sys/stat.h>
#include <sys/wait.h>

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

struct unmount_thread_arg {
	struct fuse_session *se;
	int delay_ms;
};

static void *unmount_thread_func(void *arg)
{
	struct unmount_thread_arg *uta = (struct unmount_thread_arg *)arg;

	usleep(uta->delay_ms * 1000);
	printf("Unmounting session\n");
	fuse_session_unmount(uta->se);
	return NULL;
}

static void timeout_callback(void *data)
{
	struct timeout_data *td = (struct timeout_data *)data;

	printf("Timeout callback invoked\n");
	td->triggered = true;
}

static void fork_child(void)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_session *se;
	struct fuse_loop_config *loop_config;
	void *timeout_thread = NULL;
	struct timeout_data td = { .triggered = false };
	pthread_t unmount_thread;
	struct unmount_thread_arg uta;
	char *mountpoint = NULL;
	int ret = -1;
	int exited;

	if (fuse_opt_add_arg(&args, "test_timeout_thread")) {
		fprintf(stderr, "Failed to add argument\n");
		goto out_free_args;
	}

	mountpoint = strdup("/tmp/fuse_timeout_test_XXXXXX");
	if (!mountpoint || !mkdtemp(mountpoint)) {
		fprintf(stderr, "Failed to create temp dir\n");
		goto out_free_args;
	}

	se = fuse_session_new(&args, &test_ll_ops, sizeof(test_ll_ops), NULL);
	if (!se) {
		fprintf(stderr, "Failed to create FUSE session\n");
		goto out_free_mountpoint;
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

	/* Start timeout thread with 5 second timeout */
	timeout_thread = fuse_session_start_teardown_watchdog(
		se, 5, timeout_callback, &td);
	if (!timeout_thread) {
		fprintf(stderr, "Failed to start timeout thread\n");
		goto out_remove_handlers;
	}

	/* Start thread that will unmount after 1 second */
	uta.se = se;
	uta.delay_ms = 1000;
	if (pthread_create(&unmount_thread, NULL, unmount_thread_func, &uta)) {
		fprintf(stderr, "Failed to create unmount thread\n");
		goto out_stop_timeout;
	}

	printf("Entering FUSE loop, unmount in 1 second\n");
	ret = fuse_session_loop_mt_312(se, loop_config);

	printf("fuse_session_loop_mt returned %d\n", ret);
	exited = fuse_session_exited(se);
	printf("session exited: %d\n", exited);

	pthread_join(unmount_thread, NULL);
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);
	fuse_loop_cfg_destroy(loop_config);

	/*
	 * Wait for timeout thread to invoke callback.
	 * The timeout thread should call the callback after
	 * the configured timeout (5 seconds).
	 */
	printf("Waiting for timeout callback...\n");
	sleep(10);

	fuse_session_stop_teardown_watchdog(timeout_thread);
	rmdir(mountpoint);
	free(mountpoint);
	fuse_opt_free_args(&args);

	if (td.triggered) {
		printf("Test PASSED: timeout callback was invoked\n");
		exit(0);
	}
	printf("Test FAILED: timeout callback was not invoked\n");
	exit(1);

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
out_free_mountpoint:
	rmdir(mountpoint);
	free(mountpoint);
out_free_args:
	fuse_opt_free_args(&args);
	exit(1);
}

static void run_test_in_child(void)
{
	pid_t child;
	int status;

	child = fork();
	if (child == -1) {
		perror("fork");
		exit(1);
	}

	if (child == 0)
		fork_child();

	if (waitpid(child, &status, 0) == -1) {
		perror("waitpid");
		exit(1);
	}

	if (WIFEXITED(status))
		exit(WEXITSTATUS(status));

	fprintf(stderr, "Child terminated abnormally\n");
	exit(1);
}

int main(void)
{
	printf("Testing timeout thread feature\n");
	run_test_in_child();
	return 0;
}

