/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  ghz <48886505+ghz-max@users.noreply.github.com>
 *
 * Test that fuse_buf_copy() retries a read(), write() or splice() that a
 * signal interrupts when the fd buffer has FUSE_BUF_FD_RETRY.
 *
 * A socket with SO_RCVTIMEO/SO_SNDTIMEO fails an interrupted call with
 * EINTR even when the handler has SA_RESTART (see signal(7)). io_uring
 * task_work interrupts blocking calls of a uring queue thread the same way
 * (TIF_NOTIFY_SIGNAL), so a reply built from such an fd
 * (fuse_reply_data() with FUSE_BUF_IS_FD) used to fail with EINTR, or
 * return a short count once some data had been copied.
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

static atomic_bool done;

static void on_signal(int sig)
{
	(void)sig;
}

struct peer {
	int fd;
	pthread_t victim;
	char *buf;
	size_t first;	/* bytes moved before the victim is interrupted */
	bool failed;
};

/* Interrupt the victim thread while it is blocked in fuse_buf_copy() */
static void interrupt(pthread_t victim)
{
	for (int i = 0; i < 20 && !atomic_load(&done); i++) {
		pthread_kill(victim, SIGUSR1);
		usleep(5000);
	}
}

static int write_all(int fd, const char *buf, size_t len)
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

static int read_all(int fd, char *buf, size_t len)
{
	while (len) {
		ssize_t res = read(fd, buf, len);

		if (res == -1 && errno == EINTR)
			continue;
		if (res <= 0)
			return -1;
		buf += res;
		len -= res;
	}
	return 0;
}

/* Feeds the socket the victim reads from fuse_buf_copy() */
static void *sender(void *arg)
{
	struct peer *p = arg;

	usleep(50000);
	p->failed = write_all(p->fd, p->buf, p->first) == -1;
	if (p->failed)
		return NULL;
	usleep(50000);
	interrupt(p->victim);
	p->failed = write_all(p->fd, p->buf + p->first, LEN - p->first) == -1;
	return NULL;
}

/* Drains the socket the victim writes to from fuse_buf_copy() */
static void *receiver(void *arg)
{
	struct peer *p = arg;

	usleep(50000);
	interrupt(p->victim);
	p->failed = read_all(p->fd, p->buf, LEN) == -1;
	return NULL;
}

/* Drains the pipe the victim splices to from fuse_buf_copy() */
static void *drainer(void *arg)
{
	struct peer *p = arg;

	p->failed = read_all(p->fd, p->buf, LEN) == -1;
	return NULL;
}

static int socket_pair(int sv[2])
{
	struct timeval timeout = { .tv_sec = 10 };
	int sndbuf = 64 * 1024;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
		return -1;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)) == -1 ||
	    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout)) == -1 ||
	    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
		       sizeof(sndbuf)) == -1) {
		perror("setsockopt");
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	return 0;
}

static int start_thread(pthread_t *thread, void *(*fn)(void *), void *arg)
{
	int rc = pthread_create(thread, NULL, fn, arg);

	if (rc != 0)
		fprintf(stderr, "pthread_create: %s\n", strerror(rc));
	return rc;
}

static int run(const char *name, int to_fd, size_t first)
{
	char *mem = malloc(LEN);
	char *peer_buf = malloc(LEN);
	struct fuse_bufvec fd_buf = FUSE_BUFVEC_INIT(LEN);
	struct fuse_bufvec mem_buf = FUSE_BUFVEC_INIT(LEN);
	struct peer p = { .victim = pthread_self(), .first = first };
	pthread_t thread;
	ssize_t res;
	int sv[2];
	int err = 1;

	if (!mem || !peer_buf || socket_pair(sv) == -1)
		goto out;
	for (size_t i = 0; i < LEN; i++)
		(to_fd ? mem : peer_buf)[i] = (char)(i * 7);

	fd_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_RETRY;
	fd_buf.buf[0].fd = sv[0];
	mem_buf.buf[0].mem = mem;
	p.fd = sv[1];
	p.buf = peer_buf;

	atomic_store(&done, false);
	if (start_thread(&thread, to_fd ? receiver : sender, &p) != 0)
		goto out_sock;
	if (to_fd)
		res = fuse_buf_copy(&fd_buf, &mem_buf, 0);
	else
		res = fuse_buf_copy(&mem_buf, &fd_buf, 0);
	atomic_store(&done, true);
	if (res != LEN) {
		/* Let the peer finish; it does not wait for a short copy */
		shutdown(sv[0], SHUT_RDWR);
	}
	pthread_join(thread, NULL);

	if (res != LEN) {
		fprintf(stderr, "FAIL %s: fuse_buf_copy() = %zd (%s), want %d\n",
			name, res, res < 0 ? strerror(-res) : "short", LEN);
	} else if (p.failed || memcmp(mem, peer_buf, LEN) != 0) {
		fprintf(stderr, "FAIL %s: data mismatch\n", name);
	} else {
		printf("ok %s\n", name);
		err = 0;
	}
out_sock:
	close(sv[0]);
	close(sv[1]);
out:
	free(mem);
	free(peer_buf);
	return err;
}

/* fuse_buf_copy() between two fds: splice() from the socket to a pipe */
static int run_splice(const char *name, size_t first)
{
	char *in = malloc(LEN);
	char *out = malloc(LEN);
	struct fuse_bufvec sock_buf = FUSE_BUFVEC_INIT(LEN);
	struct fuse_bufvec pipe_buf = FUSE_BUFVEC_INIT(LEN);
	struct peer snd = { .victim = pthread_self(), .first = first };
	struct peer rcv = { .victim = pthread_self() };
	pthread_t snd_thread, rcv_thread;
	ssize_t res;
	int sv[2];
	int pfd[2];
	int err = 1;

	if (!in || !out || socket_pair(sv) == -1)
		goto out;
	if (pipe(pfd) == -1) {
		perror("pipe");
		goto out_sock;
	}
	for (size_t i = 0; i < LEN; i++)
		in[i] = (char)(i * 7);

	sock_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_RETRY;
	sock_buf.buf[0].fd = sv[0];
	pipe_buf.buf[0].flags = FUSE_BUF_IS_FD;
	pipe_buf.buf[0].fd = pfd[1];
	snd.fd = sv[1];
	snd.buf = in;
	rcv.fd = pfd[0];
	rcv.buf = out;

	atomic_store(&done, false);
	if (start_thread(&snd_thread, sender, &snd) != 0) {
		close(pfd[1]);
		goto out_pipe;
	}
	if (start_thread(&rcv_thread, drainer, &rcv) != 0) {
		/* The sender's writes fail once the socket is shut down */
		atomic_store(&done, true);
		shutdown(sv[0], SHUT_RDWR);
		pthread_join(snd_thread, NULL);
		close(pfd[1]);
		goto out_pipe;
	}
	res = fuse_buf_copy(&pipe_buf, &sock_buf, FUSE_BUF_FORCE_SPLICE);
	atomic_store(&done, true);
	if (res != LEN) {
		/* Let the peers finish; they do not wait for a short copy */
		shutdown(sv[0], SHUT_RDWR);
	}
	close(pfd[1]);
	pthread_join(snd_thread, NULL);
	pthread_join(rcv_thread, NULL);

	if (res != LEN) {
		fprintf(stderr, "FAIL %s: fuse_buf_copy() = %zd (%s), want %d\n",
			name, res, res < 0 ? strerror(-res) : "short", LEN);
	} else if (snd.failed || rcv.failed || memcmp(in, out, LEN) != 0) {
		fprintf(stderr, "FAIL %s: data mismatch\n", name);
	} else {
		printf("ok %s\n", name);
		err = 0;
	}
out_pipe:
	close(pfd[0]);
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
	struct sigaction sa = { .sa_handler = on_signal,
				.sa_flags = SA_RESTART };
	int err = 0;

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		perror("sigaction");
		return 1;
	}

	err |= run("read, interrupted before any data", 0, 0);
	err |= run("read, interrupted after some data", 0, LEN / 4);
	err |= run("write, interrupted", 1, 0);
	err |= run_splice("splice, interrupted before any data", 0);
	err |= run_splice("splice, interrupted after some data", LEN / 4);
	return err;
}
