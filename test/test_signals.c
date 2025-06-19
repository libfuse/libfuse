/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025  Bernd Schubert <bernd@bsbernd.com>
 *
 * Test for signal handling in libfuse.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file GPL2.txt
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#include "fuse_config.h"
#include "fuse_lowlevel.h"
#include "fuse_i.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

static void test_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	(void)parent;
	(void)name;
	/* Simulate slow lookup to test signal interruption */
	sleep(2);
	fuse_reply_err(req, ENOENT);
}

static void test_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi)
{
	(void)ino;
	(void)fi;
	/* Simulate slow getattr to test signal interruption */
	sleep(2);
	fuse_reply_err(req, ENOENT);
}

static const struct fuse_lowlevel_ops test_ll_ops = {
	.lookup = test_ll_lookup,
	.getattr = test_ll_getattr,
};

static void *signal_sender_thread(void *arg)
{
	(void)arg;

	usleep(2 * 1000 * 1000);

	/* Send SIGTERM to the process */
	kill(getpid(), SIGTERM);
	return NULL;
}

static void fork_child(void)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_session *se;
	struct fuse_loop_config *loop_config;
	pthread_t sig_thread;
	char *mountpoint = NULL;
	int ret = -1;

	/* Add the program name to arg[0] */
	if (fuse_opt_add_arg(&args, "test_signals")) {
		fprintf(stderr, "Failed to add argument\n");
		goto out_free_mountpoint;
	}

	/* Add debug flag to see more output */
	fuse_opt_add_arg(&args, "-d");

	/* Create temporary mount point */
	mountpoint = strdup("/tmp/fuse_test_XXXXXX");
	if (!mountpoint || !mkdtemp(mountpoint)) {
		fprintf(stderr, "Failed to create temp dir\n");
		goto out_free_args;
	}

	/* Create session */
	se = fuse_session_new(&args, &test_ll_ops, sizeof(test_ll_ops), NULL);
	if (!se) {
		fprintf(stderr, "Failed to create FUSE session\n");
		goto out_free_mountpoint;
	}

	/* Mount filesystem */
	if (fuse_session_mount(se, mountpoint)) {
		fprintf(stderr, "Failed to mount FUSE filesystem\n");
		goto out_destroy_session;
	}

	/* Create loop config */
	loop_config = fuse_loop_cfg_create();
	if (!loop_config) {
		fprintf(stderr, "Failed to create loop config\n");
		goto out_unmount;
	}
	fuse_loop_cfg_set_clone_fd(loop_config, 0);
	fuse_loop_cfg_set_max_threads(loop_config, 2);

	/* Set up signal handlers */
	if (fuse_set_signal_handlers(se)) {
		fprintf(stderr, "Failed to set up signal handlers\n");
		goto out_destroy_config;
	}

	/* Create thread that will send signals */
	if (pthread_create(&sig_thread, NULL, signal_sender_thread, NULL)) {
		fprintf(stderr, "Failed to create signal sender thread\n");
		goto out_remove_handlers;
	}

	/* Enter FUSE loop */
	ret = fuse_session_loop_mt_312(se, loop_config);

	printf("Debug: fuse_session_loop_mt_312 returned %d\n", ret);
	printf("Debug: session exited state: %d\n", fuse_session_exited(se));
	printf("Debug: session status: %d\n", se->error);

	/* Check exit status before cleanup */
	int clean_exit = (fuse_session_exited(se) && se->error == SIGTERM);

	/* Clean up */
	pthread_join(sig_thread, NULL);
	fuse_remove_signal_handlers(se);
	fuse_session_unmount(se);
	fuse_session_destroy(se);
	fuse_loop_cfg_destroy(loop_config);
	rmdir(mountpoint);
	free(mountpoint);
	fuse_opt_free_args(&args);

	/* Use saved exit status */
	if (clean_exit) {
		printf("Debug: Clean shutdown via SIGTERM\n");
		exit(0);
	}
	printf("Debug: Exiting with status %d\n", ret != 0);
	exit(ret != 0);

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

	/* In parent process */
	if (waitpid(child, &status, 0) == -1) {
		perror("waitpid");
		exit(1);
	}

	/* Check if child exited due to SIGTERM - this is expected */
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM) {
		printf("Child process terminated by SIGTERM as expected\n");
		exit(0);
	}

	/* For any other type of exit, maintain existing behavior */
	exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
}

int main(void)
{
	printf("Testing SIGTERM handling in libfuse\n");
	run_test_in_child();
	printf("SIGTERM handling test passed\n");
	return 0;
}
