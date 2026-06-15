/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025  Bernd Schubert <bernd@bsbernd.com>
 *
 * Test for the FUSE-over-io-uring teardown drain: a request whose reply is
 * deferred past the start of session teardown must keep the ring alive until
 * the application finally replies (ref_cnt drops back to 1).
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
#include <limits.h>
#include <signal.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* Exit code understood by the pytest wrapper as "skip this test". */
#define TEST_SKIP_EXIT 77

/* Trip a deadlocked teardown well before the pytest timeout. */
#define TEST_WATCHDOG_SEC 20

static struct deferred_test {
	struct fuse_session *se;
	sem_t captured;             /* posted once the lookup req is stashed */
	fuse_req_t deferred_req;    /* the stashed, not-yet-answered request */
	_Atomic bool is_uring;      /* did that request arrive via io-uring? */
	_Atomic bool taken;         /* only the first "deferred" lookup counts */
	char mountpoint[64];
} dt;

static void dt_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	if (parent == 1 && strcmp(name, "deferred") == 0 &&
	    !atomic_exchange(&dt.taken, true)) {
		/* Capture the request and return WITHOUT replying. */
		dt.is_uring = fuse_req_is_uring(req);
		dt.deferred_req = req;
		sem_post(&dt.captured);
		return;
	}

	fuse_reply_err(req, ENOENT);
}

static void dt_ll_getattr(fuse_req_t req, fuse_ino_t ino,
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

static const struct fuse_lowlevel_ops dt_ll_ops = {
	.lookup = dt_ll_lookup,
	.getattr = dt_ll_getattr,
};

/* Generates the request whose reply we defer; blocks until it is answered. */
static void *client_thread_func(void *arg)
{
	char path[PATH_MAX];
	struct stat stbuf;

	(void)arg;

	snprintf(path, sizeof(path), "%s/deferred", dt.mountpoint);
	stat(path, &stbuf);  /* ENOENT is expected; we only need the round trip */
	return NULL;
}

static void *orchestrator_thread_func(void *arg)
{
	(void)arg;

	sem_wait(&dt.captured);

	if (!dt.is_uring) {
		/* Kernel did not engage io-uring; reply and let main() skip. */
		fuse_reply_err(dt.deferred_req, ENOENT);
		fuse_session_exit(dt.se);
		return NULL;
	}

	/* Start teardown while the reply is still outstanding (ref_cnt == 2). */
	fuse_session_exit(dt.se);

	/* Let teardown reach the ref_cnt drain before we release the request. */
	usleep(300 * 1000);

	/* Deferred reply: drops ref_cnt 2 -> 1 so the drain can complete. */
	fuse_reply_err(dt.deferred_req, ENOENT);
	return NULL;
}

static void watchdog_handler(int sig)
{
	(void)sig;

	fprintf(stderr, "Test FAILED: teardown did not finish (deadlock?)\n");
}

static void install_watchdog(void)
{
	struct sigaction sa = {
		.sa_handler = watchdog_handler,
	};

	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);
	alarm(TEST_WATCHDOG_SEC);
}

static void child_main(void)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_loop_config *loop_config;
	pthread_t client_thread, orchestrator_thread;
	int ret;

	/* Ask for io-uring; the kernel may still decline (then we skip). */
	setenv("FUSE_URING_ENABLE", "1", 1);

	if (fuse_opt_add_arg(&args, "test_deferred_reply_teardown"))
		exit(1);

	strcpy(dt.mountpoint, "/tmp/fuse_deferred_test_XXXXXX");
	if (!mkdtemp(dt.mountpoint)) {
		perror("mkdtemp");
		exit(1);
	}

	sem_init(&dt.captured, 0, 0);

	dt.se = fuse_session_new(&args, &dt_ll_ops, sizeof(dt_ll_ops), NULL);
	if (!dt.se) {
		fprintf(stderr, "Failed to create FUSE session\n");
		exit(1);
	}

	if (fuse_session_mount(dt.se, dt.mountpoint)) {
		fprintf(stderr, "Failed to mount FUSE filesystem\n");
		fuse_session_destroy(dt.se);
		exit(1);
	}

	loop_config = fuse_loop_cfg_create();
	fuse_loop_cfg_set_clone_fd(loop_config, 0);
	fuse_loop_cfg_set_max_threads(loop_config, 2);

	/* A teardown deadlock must fail fast, not hang the whole suite. */
	install_watchdog();

	pthread_create(&client_thread, NULL, client_thread_func, NULL);
	pthread_create(&orchestrator_thread, NULL, orchestrator_thread_func, NULL);

	/* Returns only after fuse_session_destruct_uring() has run. */
	ret = fuse_session_loop_mt_312(dt.se, loop_config);

	pthread_join(client_thread, NULL);
	pthread_join(orchestrator_thread, NULL);

	fuse_session_unmount(dt.se);
	fuse_session_destroy(dt.se);
	fuse_loop_cfg_destroy(loop_config);
	rmdir(dt.mountpoint);
	fuse_opt_free_args(&args);
	sem_destroy(&dt.captured);

	if (!dt.is_uring) {
		printf("io-uring not engaged by the kernel; skipping\n");
		exit(TEST_SKIP_EXIT);
	}
	if (ret != 0) {
		printf("Test FAILED: session loop returned %d\n", ret);
		exit(1);
	}

	printf("Test PASSED: deferred reply drained during teardown\n");
	exit(0);
}

int main(void)
{
	pid_t child;
	int status;

	printf("Testing deferred-reply io-uring teardown\n");
	fflush(stdout); /* avoid the child inheriting an unflushed buffer */

	child = fork();
	if (child == -1) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		child_main();
		_exit(1); /* not reached */
	}

	if (waitpid(child, &status, 0) == -1) {
		perror("waitpid");
		return 1;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	fprintf(stderr, "Child terminated abnormally (signal %d)\n",
		WIFSIGNALED(status) ? WTERMSIG(status) : -1);
	return 1;
}
