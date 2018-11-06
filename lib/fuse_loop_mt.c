/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Implementation of the multi-threaded FUSE session loop.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "config.h"
#include "fuse_lowlevel.h"
#include "fuse_misc.h"
#include "fuse_kernel.h"
#include "fuse_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <assert.h>

/* Environment var controlling the thread stack size */
#define ENVNAME_THREAD_STACK "FUSE_THREAD_STACK"

struct fuse_worker {
	struct fuse_worker *prev;
	struct fuse_worker *next;
	pthread_t thread_id;
	size_t bufsize;

	// We need to include fuse_buf so that we can properly free
	// it when a thread is terminated by pthread_cancel().
	struct fuse_buf fbuf;
	struct fuse_chan *ch;
	struct fuse_mt *mt;
};

struct fuse_mt {
	pthread_mutex_t lock;
	int numworker;
	int numavail;
	struct fuse_session *se;
	struct fuse_worker main;
	sem_t finish;
	int exit;
	int error;
	int clone_fd;
	int max_idle;
};

static struct fuse_chan *fuse_chan_new(int fd)
{
	struct fuse_chan *ch = (struct fuse_chan *) malloc(sizeof(*ch));
	if (ch == NULL) {
		fprintf(stderr, "fuse: failed to allocate channel\n");
		return NULL;
	}

	memset(ch, 0, sizeof(*ch));
	ch->fd = fd;
	ch->ctr = 1;
	fuse_mutex_init(&ch->lock);

	return ch;
}

struct fuse_chan *fuse_chan_get(struct fuse_chan *ch)
{
	assert(ch->ctr > 0);
	pthread_mutex_lock(&ch->lock);
	ch->ctr++;
	pthread_mutex_unlock(&ch->lock);

	return ch;
}

void fuse_chan_put(struct fuse_chan *ch)
{
	if (ch == NULL)
		return;
	pthread_mutex_lock(&ch->lock);
	ch->ctr--;
	if (!ch->ctr) {
		pthread_mutex_unlock(&ch->lock);
		close(ch->fd);
		pthread_mutex_destroy(&ch->lock);
		free(ch);
	} else
		pthread_mutex_unlock(&ch->lock);
}

static void list_add_worker(struct fuse_worker *w, struct fuse_worker *next)
{
	struct fuse_worker *prev = next->prev;
	w->next = next;
	w->prev = prev;
	prev->next = w;
	next->prev = w;
}

static void list_del_worker(struct fuse_worker *w)
{
	struct fuse_worker *prev = w->prev;
	struct fuse_worker *next = w->next;
	prev->next = next;
	next->prev = prev;
}

static int fuse_loop_start_thread(struct fuse_mt *mt);

static void *fuse_do_work(void *data)
{
	struct fuse_worker *w = (struct fuse_worker *) data;
	struct fuse_mt *mt = w->mt;

	while (!fuse_session_exited(mt->se)) {
		int isforget = 0;
		int res;

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		res = fuse_session_receive_buf_int(mt->se, &w->fbuf, w->ch);
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (res == -EINTR)
			continue;
		if (res <= 0) {
			if (res < 0) {
				fuse_session_exit(mt->se);
				mt->error = res;
			}
			break;
		}

		pthread_mutex_lock(&mt->lock);
		if (mt->exit) {
			pthread_mutex_unlock(&mt->lock);
			return NULL;
		}

		/*
		 * This disgusting hack is needed so that zillions of threads
		 * are not created on a burst of FORGET messages
		 */
		if (!(w->fbuf.flags & FUSE_BUF_IS_FD)) {
			struct fuse_in_header *in = w->fbuf.mem;

			if (in->opcode == FUSE_FORGET ||
			    in->opcode == FUSE_BATCH_FORGET)
				isforget = 1;
		}

		if (!isforget)
			mt->numavail--;
		if (mt->numavail == 0)
			fuse_loop_start_thread(mt);
		pthread_mutex_unlock(&mt->lock);

		fuse_session_process_buf_int(mt->se, &w->fbuf, w->ch);

		pthread_mutex_lock(&mt->lock);
		if (!isforget)
			mt->numavail++;
		if (mt->numavail > mt->max_idle) {
			if (mt->exit) {
				pthread_mutex_unlock(&mt->lock);
				return NULL;
			}
			list_del_worker(w);
			mt->numavail--;
			mt->numworker--;
			pthread_mutex_unlock(&mt->lock);

			pthread_detach(w->thread_id);
			free(w->fbuf.mem);
			fuse_chan_put(w->ch);
			free(w);
			return NULL;
		}
		pthread_mutex_unlock(&mt->lock);
	}

	sem_post(&mt->finish);

	return NULL;
}

int fuse_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg)
{
	sigset_t oldset;
	sigset_t newset;
	int res;
	pthread_attr_t attr;
	char *stack_size;

	/* Override default stack size */
	pthread_attr_init(&attr);
	stack_size = getenv(ENVNAME_THREAD_STACK);
	if (stack_size && pthread_attr_setstacksize(&attr, atoi(stack_size)))
		fprintf(stderr, "fuse: invalid stack size: %s\n", stack_size);

	/* Disallow signal reception in worker threads */
	sigemptyset(&newset);
	sigaddset(&newset, SIGTERM);
	sigaddset(&newset, SIGINT);
	sigaddset(&newset, SIGHUP);
	sigaddset(&newset, SIGQUIT);
	pthread_sigmask(SIG_BLOCK, &newset, &oldset);
	res = pthread_create(thread_id, &attr, func, arg);
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	pthread_attr_destroy(&attr);
	if (res != 0) {
		fprintf(stderr, "fuse: error creating thread: %s\n",
			strerror(res));
		return -1;
	}

	return 0;
}

static struct fuse_chan *fuse_clone_chan(struct fuse_mt *mt)
{
	int res;
	int clonefd;
	uint32_t masterfd;
	struct fuse_chan *newch;
	const char *devname = "/dev/fuse";

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
	clonefd = open(devname, O_RDWR | O_CLOEXEC);
	if (clonefd == -1) {
		fprintf(stderr, "fuse: failed to open %s: %s\n", devname,
			strerror(errno));
		return NULL;
	}
	fcntl(clonefd, F_SETFD, FD_CLOEXEC);

	masterfd = mt->se->fd;
	res = ioctl(clonefd, FUSE_DEV_IOC_CLONE, &masterfd);
	if (res == -1) {
		fprintf(stderr, "fuse: failed to clone device fd: %s\n",
			strerror(errno));
		close(clonefd);
		return NULL;
	}
	newch = fuse_chan_new(clonefd);
	if (newch == NULL)
		close(clonefd);

	return newch;
}

static int fuse_loop_start_thread(struct fuse_mt *mt)
{
	int res;

	struct fuse_worker *w = malloc(sizeof(struct fuse_worker));
	if (!w) {
		fprintf(stderr, "fuse: failed to allocate worker structure\n");
		return -1;
	}
	memset(w, 0, sizeof(struct fuse_worker));
	w->fbuf.mem = NULL;
	w->mt = mt;

	w->ch = NULL;
	if (mt->clone_fd) {
		w->ch = fuse_clone_chan(mt);
		if(!w->ch) {
			/* Don't attempt this again */
			fprintf(stderr, "fuse: trying to continue "
				"without -o clone_fd.\n");
			mt->clone_fd = 0;
		}
	}

	res = fuse_start_thread(&w->thread_id, fuse_do_work, w);
	if (res == -1) {
		fuse_chan_put(w->ch);
		free(w);
		return -1;
	}
	list_add_worker(w, &mt->main);
	mt->numavail ++;
	mt->numworker ++;

	return 0;
}

static void fuse_join_worker(struct fuse_mt *mt, struct fuse_worker *w)
{
	pthread_join(w->thread_id, NULL);
	pthread_mutex_lock(&mt->lock);
	list_del_worker(w);
	pthread_mutex_unlock(&mt->lock);
	free(w->fbuf.mem);
	fuse_chan_put(w->ch);
	free(w);
}

FUSE_SYMVER(".symver fuse_session_loop_mt_32,fuse_session_loop_mt@@FUSE_3.2");
int fuse_session_loop_mt_32(struct fuse_session *se, struct fuse_loop_config *config)
{
	int err;
	struct fuse_mt mt;
	struct fuse_worker *w;

	memset(&mt, 0, sizeof(struct fuse_mt));
	mt.se = se;
	mt.clone_fd = config->clone_fd;
	mt.error = 0;
	mt.numworker = 0;
	mt.numavail = 0;
	mt.max_idle = config->max_idle_threads;
	mt.main.thread_id = pthread_self();
	mt.main.prev = mt.main.next = &mt.main;
	sem_init(&mt.finish, 0, 0);
	fuse_mutex_init(&mt.lock);

	pthread_mutex_lock(&mt.lock);
	err = fuse_loop_start_thread(&mt);
	pthread_mutex_unlock(&mt.lock);
	if (!err) {
		/* sem_wait() is interruptible */
		while (!fuse_session_exited(se))
			sem_wait(&mt.finish);

		pthread_mutex_lock(&mt.lock);
		for (w = mt.main.next; w != &mt.main; w = w->next)
			pthread_cancel(w->thread_id);
		mt.exit = 1;
		pthread_mutex_unlock(&mt.lock);

		while (mt.main.next != &mt.main)
			fuse_join_worker(&mt, mt.main.next);

		err = mt.error;
	}

	pthread_mutex_destroy(&mt.lock);
	sem_destroy(&mt.finish);
	if(se->error != 0)
		err = se->error;
	fuse_session_reset(se);
	return err;
}

int fuse_session_loop_mt_31(struct fuse_session *se, int clone_fd);
FUSE_SYMVER(".symver fuse_session_loop_mt_31,fuse_session_loop_mt@FUSE_3.0");
int fuse_session_loop_mt_31(struct fuse_session *se, int clone_fd)
{
	struct fuse_loop_config config;
	config.clone_fd = clone_fd;
	config.max_idle_threads = 10;
	return fuse_session_loop_mt_32(se, &config);
}
