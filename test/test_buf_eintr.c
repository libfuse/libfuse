/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  ghz <48886505+ghz-max@users.noreply.github.com>
 *
 * fuse_buf_copy() retries a read from a FUSE_BUF_FD_RETRY socket that a
 * signal interrupts, until fuse_session_exit() is called.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file GPL2.txt
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#include "fuse_lowlevel.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define LEN (1024 * 1024)

static struct fuse_session *session;
static atomic_bool exiting;
static atomic_bool done;

static void on_signal(int sig)
{
	(void)sig;
	if (atomic_load(&exiting))
		fuse_session_exit(session);
}

/*
 * Linux fails an interrupted read of a socket with SO_RCVTIMEO with EINTR
 * even under SA_RESTART; FreeBSD restarts it. So exit the session without
 * SA_RESTART, as fuse_set_signal_handlers() does.
 */
static int set_handler(bool end_session)
{
	struct sigaction sa = { .sa_handler = on_signal,
				.sa_flags = end_session ? 0 : SA_RESTART };

	sigemptyset(&sa.sa_mask);
	atomic_store(&exiting, end_session);
	return sigaction(SIGUSR1, &sa, NULL);
}

struct peer {
	int fd;
	pthread_t reader;
	const char *buf;
	size_t first;
	bool failed;
};

static int send_all(int fd, const char *buf, size_t len)
{
	while (len) {
		ssize_t res = send(fd, buf, len, MSG_NOSIGNAL);

		if (res == -1 && errno == EINTR)
			continue;
		if (res <= 0)
			return -1;
		buf += res;
		len -= res;
	}
	return 0;
}

/* Send some data, interrupt the reader, then send the rest */
static void *sender(void *arg)
{
	struct peer *p = arg;

	usleep(50000);
	p->failed = send_all(p->fd, p->buf, p->first) == -1;
	usleep(50000);
	for (int i = 0; i < 20 && !atomic_load(&done); i++) {
		pthread_kill(p->reader, SIGUSR1);
		usleep(5000);
	}
	if (!p->failed && !atomic_load(&exiting))
		p->failed = send_all(p->fd, p->buf + p->first,
				     LEN - p->first) == -1;
	return NULL;
}

static int run(const char *name, bool end_session, size_t first)
{
	struct timeval timeout = { .tv_sec = 10 };
	char *in = malloc(LEN);
	char *out = malloc(LEN);
	struct fuse_bufvec src = FUSE_BUFVEC_INIT(LEN);
	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(LEN);
	struct peer p = { .reader = pthread_self(), .buf = in, .first = first };
	ssize_t want = end_session ? -EINTR : LEN;
	pthread_t thread;
	ssize_t res;
	int sv[2];
	int err = 1;

	if (!in || !out || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		goto out;
	if (setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)) == -1 ||
	    set_handler(end_session) == -1) {
		perror(name);
		goto out_sock;
	}
	for (size_t i = 0; i < LEN; i++)
		in[i] = (char)(i * 7);
	src.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_RETRY;
	src.buf[0].fd = sv[0];
	dst.buf[0].mem = out;
	p.fd = sv[1];

	atomic_store(&done, false);
	if (pthread_create(&thread, NULL, sender, &p) != 0)
		goto out_sock;
	res = fuse_buf_copy(&dst, &src, 0);
	atomic_store(&done, true);
	/* After a short copy, the sender may block on a full socket */
	if (res != LEN)
		shutdown(sv[0], SHUT_RDWR);
	pthread_join(thread, NULL);
	if (end_session)
		fuse_session_reset(session);

	if (res != want)
		fprintf(stderr, "FAIL %s: fuse_buf_copy() = %zd, want %zd\n",
			name, res, want);
	else if (p.failed || (!end_session && memcmp(in, out, LEN) != 0))
		fprintf(stderr, "FAIL %s: data mismatch\n", name);
	else
		err = 0;
	if (!err)
		printf("ok %s\n", name);
out_sock:
	close(sv[0]);
	close(sv[1]);
out:
	free(in);
	free(out);
	return err;
}

int main(void)
{
	const struct fuse_lowlevel_ops ops = { 0 };
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	int err = 0;

	/* Not mounted: only fuse_session_exit() and fuse_session_reset() */
	if (fuse_opt_add_arg(&args, "test_buf_eintr") == -1)
		return 1;
	session = fuse_session_new(&args, &ops, sizeof(ops), NULL);
	fuse_opt_free_args(&args);
	if (!session)
		return 1;

	err |= run("read, interrupted", false, LEN / 4);
	err |= run("read, session exited", true, 0);
	err |= run("read, interrupted after fuse_session_reset()", false,
		   LEN / 4);

	fuse_session_destroy(session);
	return err;
}
