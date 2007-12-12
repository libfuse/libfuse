/*
  libulockmgr: Userspace Lock Manager Library
  Copyright (C) 2006  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

/* #define DEBUG 1 */

#include "ulockmgr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/stat.h>
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
	int inuse;
};

struct owner {
	struct owner *next;
	struct owner *prev;
	struct fd_store *fds;
	void *id;
	size_t id_len;
	int cfd;
};

static pthread_mutex_t ulockmgr_lock;
static int ulockmgr_cfd = -1;
static struct owner owner_list = { .next = &owner_list, .prev = &owner_list };

#define MAX_SEND_FDS 2

static void list_del_owner(struct owner *owner)
{
	struct owner *prev = owner->prev;
	struct owner *next = owner->next;
	prev->next = next;
	next->prev = prev;
}

static void list_add_owner(struct owner *owner, struct owner *next)
{
	struct owner *prev = next->prev;
	owner->next = next;
	owner->prev = prev;
	prev->next = owner;
	next->prev = owner;
}

/*
 * There's a bug in the linux kernel (< 2.6.22) recv() implementation
 * on AF_UNIX, SOCK_STREAM sockets, that could cause it to return
 * zero, even if data was available.  Retrying the recv will return
 * the data in this case.
 */
static int do_recv(int sock, void *buf, size_t len, int flags)
{
	int res = recv(sock, buf, len, flags);
	if (res == 0)
		res = recv(sock, buf, len, flags);

	return res;
}

static int ulockmgr_send_message(int sock, void *buf, size_t buflen,
				 int *fdp, int numfds)
{
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	size_t cmsgbuf[CMSG_SPACE(sizeof(int) * MAX_SEND_FDS) / sizeof(size_t)];
	int res;

	assert(numfds <= MAX_SEND_FDS);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(int) * numfds);
	memcpy(CMSG_DATA(p_cmsg), fdp, sizeof(int) * numfds);
	msg.msg_controllen = p_cmsg->cmsg_len;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	vec.iov_base = buf;
	vec.iov_len = buflen;
	res = sendmsg(sock, &msg, MSG_NOSIGNAL);
	if (res == -1) {
		perror("libulockmgr: sendmsg");
		return -1;
	}
	if ((size_t) res != buflen) {
		fprintf(stderr, "libulockmgr: sendmsg short\n");
		return -1;
	}
	return 0;
}

static int ulockmgr_start_daemon(void)
{
	int sv[2];
	int res;
	char tmp[64];

	res = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	if (res == -1) {
		perror("libulockmgr: socketpair");
		return -1;
	}
	snprintf(tmp, sizeof(tmp), "exec ulockmgr_server %i", sv[0]);
	res = system(tmp);
	close(sv[0]);
	if (res == -1 || !WIFEXITED(res) || WEXITSTATUS(res) != 0) {
		close(sv[1]);
		return -1;
	}
	ulockmgr_cfd = sv[1];
	return 0;
}

static struct owner *ulockmgr_new_owner(const void *id, size_t id_len)
{
	int sv[2];
	int res;
	char c = 'm';
	struct owner *o;

	if (ulockmgr_cfd == -1 && ulockmgr_start_daemon() == -1)
		return NULL;

	o = calloc(1, sizeof(struct owner) + id_len);
	if (!o) {
		fprintf(stderr, "libulockmgr: failed to allocate memory\n");
		return NULL;
	}
	o->id = o + 1;
	o->id_len = id_len;
	res = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	if (res == -1) {
		perror("libulockmgr: socketpair");
		goto out_free;
	}
	res = ulockmgr_send_message(ulockmgr_cfd, &c, sizeof(c), &sv[0], 1);
	close(sv[0]);
	if (res == -1) {
		close(ulockmgr_cfd);
		ulockmgr_cfd = -1;
		goto out_close;
	}

	o->cfd = sv[1];
	memcpy(o->id, id, id_len);
	list_add_owner(o, &owner_list);

	return o;

out_close:
	close(sv[1]);
out_free:
	free(o);
	return NULL;
}

static int ulockmgr_send_request(struct message *msg, const void *id,
				 size_t id_len)
{
	int sv[2];
	int cfd;
	struct owner *o;
	struct fd_store *f = NULL;
	struct fd_store *newf = NULL;
	struct fd_store **fp;
	int fd = msg->fd;
	int cmd = msg->cmd;
	int res;
	int unlockall = (cmd == F_SETLK && msg->lock.l_type == F_UNLCK &&
			 msg->lock.l_start == 0 && msg->lock.l_len == 0);

	for (o = owner_list.next; o != &owner_list; o = o->next)
		if (o->id_len == id_len && memcmp(o->id, id, id_len) == 0)
			break;

	if (o == &owner_list)
		o = NULL;

	if (!o && cmd != F_GETLK && msg->lock.l_type != F_UNLCK)
		o = ulockmgr_new_owner(id, id_len);

	if (!o) {
		if (cmd == F_GETLK) {
			res = fcntl(msg->fd, F_GETLK, &msg->lock);
			return (res == -1) ? -errno : 0;
		} else if (msg->lock.l_type == F_UNLCK)
			return 0;
		else
			return -ENOLCK;
	}

	if (unlockall)
		msg->nofd = 1;
	else {
		for (fp = &o->fds; *fp; fp = &(*fp)->next) {
			f = *fp;
			if (f->fd == fd) {
				msg->nofd = 1;
				break;
			}
		}
	}

	if (!msg->nofd) {
		newf = f = calloc(1, sizeof(struct fd_store));
		if (!f) {
			fprintf(stderr, "libulockmgr: failed to allocate memory\n");
			return -ENOLCK;
		}
	}

	res = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	if (res == -1) {
		perror("libulockmgr: socketpair");
		free(newf);
		return -ENOLCK;
	}

	cfd = sv[1];
	sv[1] = msg->fd;
	res = ulockmgr_send_message(o->cfd, msg, sizeof(struct message), sv,
				    msg->nofd ? 1 : 2);
	close(sv[0]);
	if (res == -1) {
		free(newf);
		close(cfd);
		return -EIO;
	}

	if (newf) {
		newf->fd = msg->fd;
		newf->next = o->fds;
		o->fds = newf;
	}
	if (f)
		f->inuse++;

	res = do_recv(cfd, msg, sizeof(struct message), MSG_WAITALL);
	if (res == -1) {
		perror("libulockmgr: recv");
		msg->error = EIO;
	} else if (res != sizeof(struct message)) {
		fprintf(stderr, "libulockmgr: recv short\n");
		msg->error = EIO;
	} else if (cmd == F_SETLKW && msg->error == EAGAIN) {
		pthread_mutex_unlock(&ulockmgr_lock);
		while (1) {
			sigset_t old;
			sigset_t unblock;
			int errno_save;

			sigemptyset(&unblock);
			sigaddset(&unblock, SIGUSR1);
			pthread_sigmask(SIG_UNBLOCK, &unblock, &old);
			res = do_recv(cfd, msg, sizeof(struct message),
				      MSG_WAITALL);
			errno_save = errno;
			pthread_sigmask(SIG_SETMASK, &old, NULL);
			if (res == sizeof(struct message))
				break;
			else if (res >= 0) {
				fprintf(stderr, "libulockmgr: recv short\n");
				msg->error = EIO;
				break;
			} else if (errno_save != EINTR) {
				errno = errno_save;
				perror("libulockmgr: recv");
				msg->error = EIO;
				break;
			}
			msg->intr = 1;
			res = send(o->cfd, msg, sizeof(struct message),
				   MSG_NOSIGNAL);
			if (res == -1) {
				perror("libulockmgr: send");
				msg->error = EIO;
				break;
			}
			if (res != sizeof(struct message)) {
				fprintf(stderr, "libulockmgr: send short\n");
				msg->error = EIO;
				break;
			}
		}
		pthread_mutex_lock(&ulockmgr_lock);

	}
	if (f)
		f->inuse--;
	close(cfd);
	if (unlockall) {
		for (fp = &o->fds; *fp;) {
			f = *fp;
			if (f->fd == fd && !f->inuse) {
				*fp = f->next;
				free(f);
			} else
				fp = &f->next;
		}
		if (!o->fds) {
			list_del_owner(o);
			close(o->cfd);
			free(o);
		}
		/* Force OK on unlock-all, since it _will_ succeed once the
		   owner is deleted */
		msg->error = 0;
	}

	return -msg->error;
}

#ifdef DEBUG
static uint32_t owner_hash(const unsigned char *id, size_t id_len)
{
	uint32_t h = 0;
	size_t i;
	for (i = 0; i < id_len; i++)
		h = ((h << 8) | (h >> 24)) ^ id[i];

	return h;
}
#endif

static int ulockmgr_canonicalize(int fd, struct flock *lock)
{
	off_t offset;
	if (lock->l_whence == SEEK_CUR) {
		offset = lseek(fd, 0, SEEK_CUR);
		if (offset == (off_t) -1)
			return -errno;
	} else if (lock->l_whence == SEEK_END) {
		struct stat stbuf;
		int res = fstat(fd, &stbuf);
		if (res == -1)
			return -errno;

		offset = stbuf.st_size;
	} else
		offset = 0;

	lock->l_whence = SEEK_SET;
	lock->l_start += offset;

	if (lock->l_start < 0)
		return -EINVAL;

	if (lock->l_len < 0) {
		lock->l_start += lock->l_len;
		if (lock->l_start < 0)
			return -EINVAL;
		lock->l_len = -lock->l_len;
	}
	if (lock->l_len && lock->l_start + lock->l_len - 1 < 0)
		return -EINVAL;

	return 0;
}

int ulockmgr_op(int fd, int cmd, struct flock *lock, const void *owner,
		size_t owner_len)
{
	int err;
	struct message msg;
	sigset_t old;
	sigset_t block;

	if (cmd != F_GETLK && cmd != F_SETLK && cmd != F_SETLKW)
		return -EINVAL;

	if (lock->l_whence != SEEK_SET && lock->l_whence != SEEK_CUR &&
	    lock->l_whence != SEEK_END)
		return -EINVAL;

#ifdef DEBUG
	fprintf(stderr, "libulockmgr: %i %i %i %lli %lli own: 0x%08x\n",
		cmd, lock->l_type, lock->l_whence, lock->l_start, lock->l_len,
		owner_hash(owner, owner_len));
#endif

	/* Unlock should never block anyway */
	if (cmd == F_SETLKW && lock->l_type == F_UNLCK)
		cmd = F_SETLK;

	memset(&msg, 0, sizeof(struct message));
	msg.cmd = cmd;
	msg.fd = fd;
	msg.lock = *lock;
	err = ulockmgr_canonicalize(fd, &msg.lock);
	if (err)
		return err;

	sigemptyset(&block);
	sigaddset(&block, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &block, &old);
	pthread_mutex_lock(&ulockmgr_lock);
	err = ulockmgr_send_request(&msg, owner, owner_len);
	pthread_mutex_unlock(&ulockmgr_lock);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	if (!err && cmd == F_GETLK) {
		if (msg.lock.l_type == F_UNLCK)
			lock->l_type = F_UNLCK;
		else
			*lock = msg.lock;
	}

	return err;
}
