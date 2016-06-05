/*
  ulockmgr_server: Userspace Lock Manager Server
  Copyright (C) 2006  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/* #define DEBUG 1 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

struct message {
	unsigned intr : 1;
	unsigned nofd : 1;
	pthread_t thr;
	int cmd;
	int fd;
	struct flock lock;
	int error;
};

struct fd_store {
	struct fd_store *next;
	int fd;
	int origfd;
	int inuse;
};

struct owner {
	struct fd_store *fds;
	pthread_mutex_t lock;
};

struct req_data {
	struct owner *o;
	int cfd;
	struct fd_store *f;
	struct message msg;
};

#define MAX_SEND_FDS 2

static int receive_message(int sock, void *buf, size_t buflen, int *fdp,
			   int *numfds)
{
	struct msghdr msg;
	struct iovec iov;
	size_t ccmsg[CMSG_SPACE(sizeof(int) * MAX_SEND_FDS) / sizeof(size_t)];
	struct cmsghdr *cmsg;
	int res;
	int i;

	assert(*numfds <= MAX_SEND_FDS);
	iov.iov_base = buf;
	iov.iov_len = buflen;

	memset(&msg, 0, sizeof(msg));
	memset(ccmsg, -1, sizeof(ccmsg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	res = recvmsg(sock, &msg, MSG_WAITALL);
	if (!res) {
		/* retry on zero return, see do_recv() in ulockmgr.c */
		res = recvmsg(sock, &msg, MSG_WAITALL);
		if (!res)
			return 0;
	}
	if (res == -1) {
		perror("ulockmgr_server: recvmsg");
		return -1;
	}
	if ((size_t) res != buflen) {
		fprintf(stderr, "ulockmgr_server: short message received\n");
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg) {
		if (cmsg->cmsg_type != SCM_RIGHTS) {
			fprintf(stderr,
				"ulockmgr_server: unknown control message %d\n",
				cmsg->cmsg_type);
			return -1;
		}
		memcpy(fdp, CMSG_DATA(cmsg), sizeof(int) * *numfds);
		if (msg.msg_flags & MSG_CTRUNC) {
			fprintf(stderr,
				"ulockmgr_server: control message truncated\n");
			for (i = 0; i < *numfds; i++)
				close(fdp[i]);
			*numfds = 0;
		}
	} else {
		if (msg.msg_flags & MSG_CTRUNC) {
			fprintf(stderr,
				"ulockmgr_server: control message truncated(*)\n");

			/* There's a bug in the Linux kernel, that if
			   not all file descriptors were allocated,
			   then the cmsg header is not filled in */
			cmsg = (struct cmsghdr *) ccmsg;
			memcpy(fdp, CMSG_DATA(cmsg), sizeof(int) * *numfds);
			for (i = 0; i < *numfds; i++)
				close(fdp[i]);
		}
		*numfds = 0;
	}
	return res;
}

static int closefrom(int minfd)
{
	DIR *dir = opendir("/proc/self/fd");
	if (dir) {
		int dfd = dirfd(dir);
		struct dirent *ent;
		while ((ent = readdir(dir))) {
			char *end;
			int fd = strtol(ent->d_name, &end, 10);
			if (ent->d_name[0] && !end[0] && fd >= minfd &&
			    fd != dfd)
				close(fd);
		}
		closedir(dir);
	}
	return 0;
}

static void send_reply(int cfd, struct message *msg)
{
	int res = send(cfd, msg, sizeof(struct message), MSG_NOSIGNAL);
	if (res == -1)
		perror("ulockmgr_server: sending reply");
#ifdef DEBUG
	fprintf(stderr, "ulockmgr_server: error: %i\n", msg->error);
#endif
}

static void *process_request(void *d_)
{
	struct req_data *d = d_;
	int res;

	assert(d->msg.cmd == F_SETLKW);
	res = fcntl(d->f->fd, F_SETLK, &d->msg.lock);
	if (res == -1 && errno == EAGAIN) {
		d->msg.error = EAGAIN;
		d->msg.thr = pthread_self();
		send_reply(d->cfd, &d->msg);
		res = fcntl(d->f->fd, F_SETLKW, &d->msg.lock);
	}
	d->msg.error = (res == -1) ? errno : 0;
	pthread_mutex_lock(&d->o->lock);
	d->f->inuse--;
	pthread_mutex_unlock(&d->o->lock);
	send_reply(d->cfd, &d->msg);
	close(d->cfd);
	free(d);

	return NULL;
}

static void process_message(struct owner *o, struct message *msg, int cfd,
			    int fd)
{
	struct fd_store *f = NULL;
	struct fd_store *newf = NULL;
	struct fd_store **fp;
	struct req_data *d;
	pthread_t tid;
	int res;

#ifdef DEBUG
	fprintf(stderr, "ulockmgr_server: %i %i %i %lli %lli\n",
		msg->cmd, msg->lock.l_type, msg->lock.l_whence,
		msg->lock.l_start, msg->lock.l_len);
#endif

	if (msg->cmd == F_SETLK	 && msg->lock.l_type == F_UNLCK &&
	    msg->lock.l_start == 0 && msg->lock.l_len == 0) {
		for (fp = &o->fds; *fp;) {
			f = *fp;
			if (f->origfd == msg->fd && !f->inuse) {
				close(f->fd);
				*fp = f->next;
				free(f);
			} else
				fp = &f->next;
		}
		if (!msg->nofd)
			close(fd);

		msg->error = 0;
		send_reply(cfd, msg);
		close(cfd);
		return;
	}

	if (msg->nofd) {
		for (fp = &o->fds; *fp; fp = &(*fp)->next) {
			f = *fp;
			if (f->origfd == msg->fd)
				break;
		}
		if (!*fp) {
			fprintf(stderr, "ulockmgr_server: fd %i not found\n",
				msg->fd);
			msg->error = EIO;
			send_reply(cfd, msg);
			close(cfd);
			return;
		}
	} else {
		newf = f = malloc(sizeof(struct fd_store));
		if (!f) {
			msg->error = ENOLCK;
			send_reply(cfd, msg);
			close(cfd);
			return;
		}

		f->fd = fd;
		f->origfd = msg->fd;
		f->inuse = 0;
	}

	if (msg->cmd == F_GETLK || msg->cmd == F_SETLK ||
	    msg->lock.l_type == F_UNLCK) {
		res = fcntl(f->fd, msg->cmd, &msg->lock);
		msg->error = (res == -1) ? errno : 0;
		send_reply(cfd, msg);
		close(cfd);
		if (newf) {
			newf->next = o->fds;
			o->fds = newf;
		}
		return;
	}

	d = malloc(sizeof(struct req_data));
	if (!d) {
		msg->error = ENOLCK;
		send_reply(cfd, msg);
		close(cfd);
		free(newf);
		return;
	}

	f->inuse++;
	d->o = o;
	d->cfd = cfd;
	d->f = f;
	d->msg = *msg;
	res = pthread_create(&tid, NULL, process_request, d);
	if (res) {
		msg->error = ENOLCK;
		send_reply(cfd, msg);
		close(cfd);
		free(d);
		f->inuse--;
		free(newf);
		return;
	}

	if (newf) {
		newf->next = o->fds;
		o->fds = newf;
	}
	pthread_detach(tid);
}

static void sigusr1_handler(int sig)
{
	(void) sig;
	/* Nothing to do */
}

static void process_owner(int cfd)
{
	struct owner o;
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		perror("ulockmgr_server: cannot set sigusr1 signal handler");
		exit(1);
	}

	memset(&o, 0, sizeof(struct owner));
	pthread_mutex_init(&o.lock, NULL);
	while (1) {
		struct message msg;
		int rfds[2];
		int res;
		int numfds = 2;

		res  = receive_message(cfd, &msg, sizeof(msg), rfds, &numfds);
		if (!res)
			break;
		if (res == -1)
			exit(1);

		if (msg.intr) {
			if (numfds != 0)
				fprintf(stderr,
					"ulockmgr_server: too many fds for intr\n");
			pthread_kill(msg.thr, SIGUSR1);
		} else {
			if (numfds != 2)
				continue;

			pthread_mutex_lock(&o.lock);
			process_message(&o, &msg, rfds[0], rfds[1]);
			pthread_mutex_unlock(&o.lock);
		}
	}
	if (o.fds)
		fprintf(stderr,
			"ulockmgr_server: open file descriptors on exit\n");
}

int main(int argc, char *argv[])
{
	int nullfd;
	char *end;
	int cfd;
	sigset_t empty;

	if (argc != 2 || !argv[1][0])
		goto out_inval;

	cfd = strtol(argv[1], &end, 10);
	if (*end)
		goto out_inval;

	/* demonize current process */
	switch(fork()) {
	case -1:
		perror("ulockmgr_server: fork");
		exit(1);
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() == -1) {
		perror("ulockmgr_server: setsid");
		exit(1);
	}

	(void) chdir("/");

	sigemptyset(&empty);
	sigprocmask(SIG_SETMASK, &empty, NULL);

	if (dup2(cfd, 4) == -1) {
		perror("ulockmgr_server: dup2");
		exit(1);
	}
	cfd = 4;
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd >= 0) {
		dup2(nullfd, 0);
		dup2(nullfd, 1);
	}
	close(3);
	closefrom(5);
	while (1) {
		char c;
		int sock;
		int pid;
		int numfds = 1;
		int res = receive_message(cfd, &c, sizeof(c), &sock, &numfds);
		if (!res)
			break;
		if (res == -1)
			exit(1);
		assert(numfds == 1);

		pid = fork();
		if (pid == -1) {
			perror("ulockmgr_server: fork");
			close(sock);
			continue;
		}
		if (pid == 0) {
			close(cfd);
			pid = fork();
			if (pid == -1) {
				perror("ulockmgr_server: fork");
				_exit(1);
			}
			if (pid == 0)
				process_owner(sock);
			_exit(0);
		}
		waitpid(pid, NULL, 0);
		close(sock);
	}
	return 0;

out_inval:
	fprintf(stderr, "%s should be started by libulockmgr\n", argv[0]);
	return 1;
}
