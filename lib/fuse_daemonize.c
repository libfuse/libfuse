/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Bernd Schubert <bsbernd.com>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB.
 */

#define _GNU_SOURCE

#include "fuse_daemonize.h"

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

/* Private/internal data  */
struct fuse_daemonize {
	unsigned int flags;
	int signal_pipe_wr;	/* write end for signaling parent */
	int death_pipe_rd;	/* read end, POLLHUP when parent dies */
	int stop_pipe_rd;	/* read end for stop signal */
	int stop_pipe_wr;	/* write end for stop signal */
	pthread_t watcher;
	int watcher_started;

	_Atomic bool active;

	_Atomic bool daemonized;
};

/* Global daemonization object pointer */
static _Atomic(struct fuse_daemonize *) daemonize;

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
			_exit(1);

		/* Stop signal received */
		if (pfd[1].revents & POLLIN)
			break;
	}
	return NULL;
}

static int start_parent_watcher(struct fuse_daemonize *daemonize)
{
	int rc;

	rc = pthread_create(&daemonize->watcher, NULL, parent_watcher_thread,
			    daemonize);
	if (rc != 0) {
		perror("fuse_daemonize: pthread_create");
		return -1;
	}
	daemonize->watcher_started = 1;
	return 0;
}

static void stop_parent_watcher(struct fuse_daemonize *daemonize)
{
	char byte = 0;

	if (daemonize && daemonize->watcher_started) {
		/* Signal watcher to stop */
		if (write(daemonize->stop_pipe_wr, &byte, 1) != 1)
			perror("fuse_daemonize: stop write");
		pthread_join(daemonize->watcher, NULL);
		daemonize->watcher_started = 0;
	}
}

static int daemonize_child(struct fuse_daemonize *daemonize)
{
	int stop_pipe[2];

	if (pipe(stop_pipe) == -1) {
		perror("fuse_daemonize_start: stop pipe");
		return -1;
	}
	daemonize->stop_pipe_rd = stop_pipe[0];
	daemonize->stop_pipe_wr = stop_pipe[1];

	if (setsid() == -1) {
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
	if (start_parent_watcher(daemonize) != 0)
		goto err_close_stop;

	daemonize->daemonized = true;
	return 0;

err_close_stop:
	close(daemonize->stop_pipe_rd);
	close(daemonize->stop_pipe_wr);
	return -1;
}

/* Fork and daemonize. Returns 0 in child, never returns in parent. */
static int do_daemonize(struct fuse_daemonize *daemonize)
{
	int signal_pipe[2];
	int death_pipe[2];

	if (pipe(signal_pipe) == -1) {
		perror("fuse_daemonize_start: signal pipe");
		return -1;
	}

	if (pipe(death_pipe) == -1) {
		perror("fuse_daemonize_start: death pipe");
		close(signal_pipe[0]);
		close(signal_pipe[1]);
		return -1;
	}

	switch (fork()) {
	case -1:
		perror("fuse_daemonize_start: fork");
		close(signal_pipe[0]);
		close(signal_pipe[1]);
		close(death_pipe[0]);
		close(death_pipe[1]);
		return -1;

	case 0:
		/* Child: signal write end, death read end */
		close(signal_pipe[0]);
		close(death_pipe[1]);
		daemonize->signal_pipe_wr = signal_pipe[1];
		daemonize->death_pipe_rd = death_pipe[0];
		return daemonize_child(daemonize);

	default: {
		/* Parent: signal read end, death write end (kept open) */
		unsigned char status;
		ssize_t res;

		close(signal_pipe[1]);
		close(death_pipe[0]);

		res = read(signal_pipe[0], &status, sizeof(status));
		close(signal_pipe[0]);
		close(death_pipe[1]);

		if (res != sizeof(status))
			_exit(1);
		_exit(status);
	}
	}
}

int fuse_daemonize_start(unsigned int flags)
{
	struct fuse_daemonize *dm;
	struct fuse_daemonize *expected = NULL;

	dm = calloc(1, sizeof(*dm));
	if (dm == NULL) {
		fprintf(stderr, "%s: calloc failed\n", __func__);
		return -ENOMEM;
	}

	dm->flags = flags;
	dm->signal_pipe_wr = -1;
	dm->death_pipe_rd = -1;
	dm->stop_pipe_rd = -1;
	dm->stop_pipe_wr = -1;
	dm->active = true;

	if (!(flags & FUSE_DAEMONIZE_NO_CHDIR))
		(void)chdir("/");

	if (!(flags & FUSE_DAEMONIZE_NO_BACKGROUND)) {
		if (do_daemonize(dm) != 0) {
			free(dm);
			return -errno;
		}
	}

	/* Set global pointer using CAS - fail if already set */
	if (!atomic_compare_exchange_strong(&daemonize, &expected, dm)) {
		fprintf(stderr, "%s: already active\n", __func__);
		free(dm);
		return -EEXIST;
	}

	return 0;
}

static void close_if_valid(int *fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

void fuse_daemonize_signal(int status)
{
	struct fuse_daemonize *dm;
	unsigned char st;

	dm = atomic_load(&daemonize);
	if (dm == NULL || !dm->active)
		return;

	dm->active = false;

	/* Stop watcher before signaling - parent will exit after this */
	stop_parent_watcher(dm);

	/* Signal status to parent */
	if (dm->signal_pipe_wr != -1) {
		st = (status != 0) ? 1 : 0;
		if (write(dm->signal_pipe_wr, &st, sizeof(st)) != sizeof(st))
			fprintf(stderr, "%s: write failed\n", __func__);
	}

	/* Redirect stdout/stderr to /dev/null on success */
	if (status == 0) {
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

	/* Clear global pointer using CAS and free */
	if (atomic_compare_exchange_strong(&daemonize, &dm, NULL))
		free(dm);
}

bool fuse_daemonize_active(void)
{
	struct fuse_daemonize *dm = atomic_load(&daemonize);

	return dm != NULL && (dm->daemonized || dm->active);
}
