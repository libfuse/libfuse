/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Bernd Schubert <bsbernd.com>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB.
 */

#define _GNU_SOURCE

#include "fuse_daemonize.h"
#include "fuse_daemonize_i.h"

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <err.h>

/**
 * Status values for fuse_daemonize_success() and fuse_daemonize_fail()
 */
#define FUSE_DAEMONIZE_SUCCESS 0
#define FUSE_DAEMONIZE_FAILURE 1

	/* Private/internal data  */
	struct fuse_daemonize {
	unsigned int flags;
	int signal_pipe_wr;	/* write end for signaling parent */
	int death_pipe_rd;	/* read end, POLLHUP when parent dies */
	int stop_pipe_rd;	/* read end for stop signal */
	int stop_pipe_wr;	/* write end for stop signal */
	pthread_t watcher;
	bool watcher_started;
	_Atomic bool active;
	_Atomic bool daemonized;
	_Atomic bool mounted;
};

/* Global daemonization object pointer */
static struct fuse_daemonize daemonize = {
	.signal_pipe_wr = -1,
	.death_pipe_rd = -1,
	.stop_pipe_rd = -1,
	.stop_pipe_wr = -1,
};

/* Watcher thread: polls for parent death or stop signal */
static void *parent_watcher_thread(void *arg)
{
	struct fuse_daemonize *di = arg;
	struct pollfd pfd[2];

	pfd[0].fd = di->death_pipe_rd;
	pfd[0].events = POLLIN;
	pfd[1].fd = di->stop_pipe_rd;
	pfd[1].events = POLLIN;

	while (1) {
		int rc = poll(pfd, 2, -1);

		if (rc < 0)
			continue;

		/* Parent died - death pipe write end closed */
		if (pfd[0].revents & (POLLHUP | POLLERR))
			_exit(EXIT_FAILURE);

		/* Stop signal received */
		if (pfd[1].revents & POLLIN)
			break;
	}
	return NULL;
}

static int start_parent_watcher(struct fuse_daemonize *dm)
{
	int rc;

	rc = pthread_create(&dm->watcher, NULL, parent_watcher_thread,
			    dm);
	if (rc != 0) {
		fprintf(stderr, "fuse_daemonize: pthread_create: %s\n",
			strerror(rc));
		return -rc;
	}
	dm->watcher_started = true;
	return 0;
}

static void stop_parent_watcher(struct fuse_daemonize *dm)
{
	char byte = 0;

	if (dm && dm->watcher_started) {
		/* Signal watcher to stop */
		if (write(dm->stop_pipe_wr, &byte, 1) != 1)
			perror("fuse_daemonize: stop write");
		pthread_join(dm->watcher, NULL);
		dm->watcher_started = false;
	}
}

static int daemonize_child(struct fuse_daemonize *dm)
{
	int stop_pipe[2], err = 0;

	if (pipe(stop_pipe) == -1) {
		err = -errno;
		perror("fuse_daemonize_start: stop pipe");
		return err;
	}
	dm->stop_pipe_rd = stop_pipe[0];
	dm->stop_pipe_wr = stop_pipe[1];

	if (setsid() == -1) {
		err = -errno;
		perror("fuse_daemonize_start: setsid");
		goto err_close_stop;
	}

	/* Close stdin immediately */
	int nullfd = open("/dev/null", O_RDWR, 0);

	if (nullfd != -1) {
		(void)dup2(nullfd, 0);
		if (nullfd > 0)
			close(nullfd);
	}

	/* Start watcher thread to detect parent death */
	err = start_parent_watcher(dm);
	if (err)
		goto err_close_stop;

	dm->daemonized = true;
	return 0;

err_close_stop:
	close(dm->stop_pipe_rd);
	close(dm->stop_pipe_wr);
	return err;
}

/* Fork and daemonize. Returns 0 in child, never returns in parent. */
static int do_daemonize(struct fuse_daemonize *dm)
{
	int signal_pipe[2], death_pipe[2], err;

	if (pipe(signal_pipe) == -1) {
		err = -errno;
		perror("fuse_daemonize_start: signal pipe");
		return err;
	}

	if (pipe(death_pipe) == -1) {
		err = -errno;
		perror("fuse_daemonize_start: death pipe");
		close(signal_pipe[0]);
		close(signal_pipe[1]);
		return err;
	}

	switch (fork()) {
	case -1:
		err = -errno;
		perror("fuse_daemonize_start: fork");
		close(signal_pipe[0]);
		close(signal_pipe[1]);
		close(death_pipe[0]);
		close(death_pipe[1]);
		return err;

	case 0:
		/* Child: signal write end, death read end */
		close(signal_pipe[0]);
		close(death_pipe[1]);
		dm->signal_pipe_wr = signal_pipe[1];
		dm->death_pipe_rd = death_pipe[0];
		return daemonize_child(dm);

	default: {
		/* Parent: signal read end, death write end (kept open) */
		int status;
		ssize_t res;

		close(signal_pipe[1]);
		close(death_pipe[0]);

		res = read(signal_pipe[0], &status, sizeof(status));
		close(signal_pipe[0]);
		close(death_pipe[1]);

		if (res != sizeof(status))
			_exit(EXIT_FAILURE);
		_exit(status);
	}
	}
}

int fuse_daemonize_early_start(unsigned int flags)
{
	struct fuse_daemonize *dm = &daemonize;
	int err = 0;

	dm->flags = flags;
	dm->signal_pipe_wr = -1;
	dm->death_pipe_rd = -1;
	dm->stop_pipe_rd = -1;
	dm->stop_pipe_wr = -1;
	dm->active = true;

	if (!(flags & FUSE_DAEMONIZE_NO_CHDIR))
		(void)chdir("/");

	if (!(flags & FUSE_DAEMONIZE_NO_BACKGROUND))
		err = do_daemonize(dm);

	return err;
}

static void close_if_valid(int *fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

static void fuse_daemonize_early_signal(int status)
{
	struct fuse_daemonize *dm = &daemonize;
	int rc;

	if (!dm->active)
		errx(EINVAL, "%s: not active and cannot signal status", __func__);

	/* Warn because there might be races */
	if (status == FUSE_DAEMONIZE_SUCCESS && !dm->mounted)
		fprintf(stderr, "fuse daemonize success without being mounted\n");

	dm->active = false;

	/* Stop watcher before signaling - parent will exit after this */
	stop_parent_watcher(dm);

	/* Signal status to parent */
	if (dm->signal_pipe_wr != -1) {
		rc = write(dm->signal_pipe_wr, &status, sizeof(status));
		if (rc != sizeof(status))
			fprintf(stderr, "%s: write failed\n", __func__);
	}

	/* Redirect stdout/stderr to /dev/null on success */
	if (status == FUSE_DAEMONIZE_SUCCESS && dm->daemonized) {
		int nullfd = open("/dev/null", O_RDWR, 0);

		if (nullfd != -1) {
			(void)dup2(nullfd, 1);
			(void)dup2(nullfd, 2);
			if (nullfd > 2)
				close(nullfd);
		}
	}

	close_if_valid(&dm->signal_pipe_wr);
	close_if_valid(&dm->death_pipe_rd);
	close_if_valid(&dm->stop_pipe_rd);
	close_if_valid(&dm->stop_pipe_wr);
}

void fuse_daemonize_early_success(void)
{
	/*
	 * Needs to be gracefully handled as automatically called libfuse
	 * internal from FUSE_INIT handler
	 */
	if (!fuse_daemonize_early_is_active())
		return;

	fuse_daemonize_early_signal(FUSE_DAEMONIZE_SUCCESS);
}

void fuse_daemonize_early_fail(int err)
{
	fuse_daemonize_early_signal(err);
}

bool fuse_daemonize_early_is_active(void)
{
	return daemonize.daemonized || daemonize.active;
}

void fuse_daemonize_early_set_mounted(void)
{
	daemonize.mounted = true;
}

/*
 * defined in fuse_common.h, but fuse_common.h is outside of the scope
 * of this file - duplicated definition is better here.
 */
int fuse_daemonize(int foreground);

int fuse_daemonize(int foreground)
{
	/* Check if the NEW API is used */
	if (fuse_daemonize_early_is_active()) {
		perror("Newer API fuse_daemonize_start() already used\n");
		return -1;
	}

	if (!foreground) {
		int nullfd;
		int waiter[2];
		char completed;

		if (pipe(waiter)) {
			err(errno, "%s: pipe\n", __func__);
			return -1;
		}

		/*
		 * demonize current process by forking it and killing the
		 * parent.  This makes current process as a child of 'init'.
		 */
		switch (fork()) {
		case -1:
			err(errno, "%s: fork\n", __func__);
			close(waiter[0]);
			close(waiter[1]);
			return -1;
		case 0:
			/* child */
			close(waiter[0]);
			waiter[0] = -1;
			break;
		default:
			/* parent */
			(void)read(waiter[0], &completed, sizeof(completed));
			close(waiter[0]);
			close(waiter[1]);
			_exit(0);
		}

		if (setsid() == -1) {
			err(errno, "%s: setsid", __func__);
			close(waiter[1]);
			return -1;
		}

		(void)chdir("/");

		nullfd = open("/dev/null", O_RDWR, 0);
		if (nullfd != -1) {
			(void)dup2(nullfd, 0);
			(void)dup2(nullfd, 1);
			(void)dup2(nullfd, 2);
			if (nullfd > 2)
				close(nullfd);
		}

		/* Propagate completion of daemon initialization */
		completed = 1;
		(void)write(waiter[1], &completed, sizeof(completed));
		close(waiter[1]);
		waiter[1] = -1;
	} else {
		(void)chdir("/");
	}

	return 0;
}
