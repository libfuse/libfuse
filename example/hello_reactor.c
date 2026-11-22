/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  Bernd Schubert <bernd@bsbernd.com>
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

/** @file
 *
 * hello filesystem on one app-owned io_uring for FUSE and backing file IO
 *
 * Compile with:
 *
 *     gcc -Wall hello_reactor.c `pkg-config fuse3 liburing --cflags --libs` -o hello_reactor
 *
 * ## Source code ##
 * \include hello_reactor.c
 */

#define _GNU_SOURCE
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse_lowlevel.h>
#include <fuse_uring.h>
#include <liburing.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <sys/stat.h>

#define HELLO_INO 2

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

/* Index of fuse_session_fd() in the reactor's registered file table */
#define FUSE_FD_INDEX 0

/* How long reactor_sqe_get() waits for a free SQE on a full SQ */
#define GET_SQE_TIMEOUT_MS 1000

static const char hello_name[] = "hello";

struct backend_io {
	/* io_uring user_data of the backend SQE */
	struct fuse_uring_completion comp;

	/* replies to req with the CQE result */
	void (*done)(struct backend_io *io, int res);

	fuse_req_t req;
	char *payload;
	fuse_ino_t ino;
	struct backend_io *next_free;
};

struct hello_reactor {
	struct fuse_session *se;
	int backing_fd;

	/* only the reactor thread touches the fields below */
	struct io_uring ring;

	/* one per FUSE entry, which carries at most one request at a time */
	struct backend_io *backend_ios;
	struct backend_io *backend_free;

	/* SQEs taken from the ring whose CQE is not reaped yet */
	unsigned int sqes_inflight;
};

struct hello_opts {
	char *backing;
};

static const struct fuse_opt hello_opt_specs[] = {
	{ "--backing=%s", offsetof(struct hello_opts, backing), 0 },
	FUSE_OPT_END
};

static int hello_stat(const struct hello_reactor *reactor, fuse_ino_t ino,
		      struct stat *stbuf)
{
	struct stat backing_stat;
	int ret;

	stbuf->st_ino = ino;
	switch (ino) {
	case FUSE_ROOT_ID:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;

	case HELLO_INO:
		ret = fstat(reactor->backing_fd, &backing_stat);
		if (ret == -1)
			return -errno;
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = backing_stat.st_size;
		return 0;

	default:
		return -ENOENT;
	}
}

static void reply_attr(fuse_req_t req, fuse_ino_t ino)
{
	const struct hello_reactor *reactor = fuse_req_userdata(req);
	struct stat stbuf = { 0 };
	int ret;

	ret = hello_stat(reactor, ino, &stbuf);
	if (ret != 0)
		fuse_reply_err(req, -ret);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

static void hello_getattr(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	(void)fi;

	reply_attr(req, ino);
}

static void hello_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	const struct hello_reactor *reactor = fuse_req_userdata(req);
	struct fuse_entry_param entry = { 0 };
	int ret;

	if (parent != FUSE_ROOT_ID || strcmp(name, hello_name) != 0) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	entry.ino = HELLO_INO;
	entry.attr_timeout = 1.0;
	entry.entry_timeout = 1.0;
	ret = hello_stat(reactor, entry.ino, &entry.attr);
	if (ret != 0)
		fuse_reply_err(req, -ret);
	else
		fuse_reply_entry(req, &entry);
}

static void hello_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	static const struct {
		const char *name;
		fuse_ino_t ino;
	} root_entries[] = {
		{ ".", FUSE_ROOT_ID },
		{ "..", FUSE_ROOT_ID },
		{ hello_name, HELLO_INO },
	};
	const size_t entry_count = ARRAY_SIZE(root_entries);

	/* room for all of root_entries */
	char dirents[256];
	const size_t room = size < sizeof(dirents) ? size : sizeof(dirents);
	size_t used = 0;

	(void)fi;

	if (ino != FUSE_ROOT_ID) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	for (size_t entry_idx = off; entry_idx < entry_count; entry_idx++) {
		struct stat stbuf = { .st_ino = root_entries[entry_idx].ino };
		size_t entry_size;

		entry_size = fuse_add_direntry(req, dirents + used, room - used,
					       root_entries[entry_idx].name,
					       &stbuf, entry_idx + 1);
		if (entry_size > room - used)
			break;
		used += entry_size;
	}

	fuse_reply_buf(req, dirents, used);
}

static void hello_open(fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi)
{
	if (ino != HELLO_INO)
		fuse_reply_err(req, EISDIR);
	else
		fuse_reply_open(req, fi);
}

/* Payload buffer of a request that came over the reactor's ring */
static char *ring_payload(fuse_req_t req)
{
	char *payload;
	size_t payload_size;
	int ret;

	ret = fuse_req_get_payload(req, &payload, &payload_size, NULL);

	/* Once io-uring is up the kernel sends reads and writes only on the ring */
	if (ret != 0) {
		fuse_log(FUSE_LOG_ERR, "hello_reactor: fuse_req_get_payload(): %s\n",
			 strerror(-ret));
		abort();
	}

	return payload;
}

static long long monotonic_ms(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * 1000LL + now.tv_nsec / 1000000;
}

/* An SQE on the reactor's ring, submitting the SQ when it is full */
static struct io_uring_sqe *reactor_sqe_get(struct hello_reactor *reactor)
{
	const struct timespec pause = { .tv_nsec = 1000000 };
	struct io_uring_sqe *sqe = io_uring_get_sqe(&reactor->ring);
	long long deadline_ms = 0;
	int ret;

	if (sqe == NULL)
		deadline_ms = monotonic_ms() + GET_SQE_TIMEOUT_MS;

	while (sqe == NULL) {
		ret = io_uring_submit(&reactor->ring);
		sqe = io_uring_get_sqe(&reactor->ring);
		if (sqe != NULL)
			break;

		if (monotonic_ms() >= deadline_ms) {
			fuse_log(FUSE_LOG_ERR,
				 "hello_reactor: io_uring_get_sqe(): SQ full for %d ms, last io_uring_submit() returned %d\n",
				 GET_SQE_TIMEOUT_MS, ret);
			abort();
		}
		nanosleep(&pause, NULL);
	}

	reactor->sqes_inflight++;
	return sqe;
}

/* The get_sqe hook: an SQE for a FUSE command of libfuse */
static struct io_uring_sqe *fuse_sqe_get(void *userdata)
{
	return reactor_sqe_get(userdata);
}

/* Tie a prepared backend SQE to @req, so that its CQE calls @done */
static void backend_io_bind(struct hello_reactor *reactor,
			    struct io_uring_sqe *sqe, fuse_req_t req,
			    char *payload, fuse_ino_t ino,
			    void (*done)(struct backend_io *io, int res))
{
	struct backend_io *io = reactor->backend_free;

	reactor->backend_free = io->next_free;
	io->done = done;
	io->req = req;
	io->payload = payload;
	io->ino = ino;
	io_uring_sqe_set_data(sqe, &io->comp);
}

static void read_done(struct backend_io *io, int res)
{
	if (res < 0)
		fuse_reply_err(io->req, -res);
	else
		fuse_reply_buf(io->req, io->payload, res);
}

static void write_done(struct backend_io *io, int res)
{
	if (res < 0)
		fuse_reply_err(io->req, -res);
	else
		fuse_reply_write(io->req, res);
}

static void truncate_done(struct backend_io *io, int res)
{
	if (res < 0)
		fuse_reply_err(io->req, -res);
	else
		reply_attr(io->req, io->ino);
}

static void hello_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t off, struct fuse_file_info *fi)
{
	struct hello_reactor *reactor = fuse_req_userdata(req);
	char *payload = ring_payload(req);
	struct io_uring_sqe *sqe = reactor_sqe_get(reactor);

	(void)fi;

	io_uring_prep_read(sqe, reactor->backing_fd, payload, size, off);
	backend_io_bind(reactor, sqe, req, payload, ino, read_done);
}

static void hello_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			size_t size, off_t off, struct fuse_file_info *fi)
{
	struct hello_reactor *reactor = fuse_req_userdata(req);
	char *payload = ring_payload(req);
	struct io_uring_sqe *sqe = reactor_sqe_get(reactor);

	(void)buf;
	(void)fi;

	io_uring_prep_write(sqe, reactor->backing_fd, payload, size, off);
	backend_io_bind(reactor, sqe, req, payload, ino, write_done);
}

static void hello_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			  int to_set, struct fuse_file_info *fi)
{
	struct hello_reactor *reactor = fuse_req_userdata(req);
	struct io_uring_sqe *sqe;

	(void)fi;

	if (!(to_set & FUSE_SET_ATTR_SIZE)) {
		reply_attr(req, ino);
		return;
	}

	sqe = reactor_sqe_get(reactor);
	io_uring_prep_ftruncate(sqe, reactor->backing_fd, attr->st_size);
	backend_io_bind(reactor, sqe, req, NULL, ino, truncate_done);
}

static const struct fuse_lowlevel_ops hello_oper = {
	.lookup = hello_lookup,
	.getattr = hello_getattr,
	.setattr = hello_setattr,
	.readdir = hello_readdir,
	.open = hello_open,
	.read = hello_read,
	.write = hello_write,
};

static const struct fuse_uring_app_ops hello_app_ops = {
	.get_sqe = fuse_sqe_get,
};

static void backend_cqe_cb(struct fuse_uring_completion *comp,
			   const struct io_uring_cqe *cqe)
{
	struct backend_io *io = container_of(comp, struct backend_io, comp);
	struct hello_reactor *reactor = fuse_req_userdata(io->req);

	io->done(io, cqe->res);
	io->next_free = reactor->backend_free;
	reactor->backend_free = io;
}

static void reactor_cqes_handle(struct hello_reactor *reactor)
{
	struct io_uring_cqe *cqe;
	unsigned int head;
	unsigned int reaped = 0;

	io_uring_for_each_cqe(&reactor->ring, head, cqe) {
		struct fuse_uring_completion *comp = io_uring_cqe_get_data(cqe);

		comp->cqe_cb(comp, cqe);
		reaped++;
	}
	io_uring_cq_advance(&reactor->ring, reaped);
	reactor->sqes_inflight -= reaped;
}

/* Create the ring that carries every FUSE queue and every backend IO */
static int reactor_setup(struct hello_reactor *reactor)
{
	struct fuse_session *se = reactor->se;
	const unsigned int queue_count = fuse_uring_queue_count(se);
	const unsigned int entry_count = queue_count * fuse_uring_queue_depth(se);
	const unsigned int cqe_count = entry_count * 2;
	struct io_uring_params params = {
		.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQSIZE |
			 IORING_SETUP_SINGLE_ISSUER |
			 IORING_SETUP_DEFER_TASKRUN,
		.cq_entries = cqe_count,
	};
	const int fuse_fd = fuse_session_fd(se);
	struct backend_io *backend_ios;
	bool ring_ready = false;
	int ret = -ENOMEM;

	backend_ios = calloc(entry_count, sizeof(*backend_ios));
	if (backend_ios == NULL) {
		fuse_log(FUSE_LOG_ERR,
			 "hello_reactor: no memory for %u backend IOs\n",
			 entry_count);
		goto out;
	}

	ret = io_uring_queue_init_params(cqe_count, &reactor->ring, &params);
	if (ret != 0) {
		fuse_log(FUSE_LOG_ERR,
			 "hello_reactor: io_uring_queue_init_params(): %s\n",
			 strerror(-ret));
		goto out;
	}
	ring_ready = true;

	ret = io_uring_register_files(&reactor->ring, &fuse_fd, 1);
	if (ret != 0) {
		fuse_log(FUSE_LOG_ERR,
			 "hello_reactor: io_uring_register_files(): %s\n",
			 strerror(-ret));
		goto out;
	}

	for (unsigned int io_idx = 0; io_idx < entry_count; io_idx++) {
		struct backend_io *io = &backend_ios[io_idx];

		io->comp.cqe_cb = backend_cqe_cb;
		io->next_free = reactor->backend_free;
		reactor->backend_free = io;
	}

	reactor->backend_ios = backend_ios;
	backend_ios = NULL;
	ring_ready = false;
	ret = 0;

out:
	if (ring_ready)
		io_uring_queue_exit(&reactor->ring);
	free(backend_ios);
	return ret;
}

static void reactor_run(struct hello_reactor *reactor)
{
	for (;;) {
		int ret;

		/* The kernel answers every entry with -ENOTCONN at umount */
		if (reactor->sqes_inflight == 0)
			break;

		ret = io_uring_submit_and_wait(&reactor->ring, 1);
		if (ret == -EINTR)
			continue;
		if (ret < 0) {
			fuse_log(FUSE_LOG_ERR,
				 "hello_reactor: io_uring_submit_and_wait(): %s\n",
				 strerror(-ret));
			abort();
		}

		reactor_cqes_handle(reactor);
	}
}

static void *reactor_thread(void *arg)
{
	struct hello_reactor *reactor = arg;
	int ret;

	/* fuse_uring_app_wait_submit() fills the REGISTER SQEs on the ring */
	ret = reactor_setup(reactor);
	if (ret != 0) {
		fuse_session_exit(reactor->se);
		return NULL;
	}

	ret = fuse_uring_app_wait_submit(reactor->se);
	if (ret != 0) {
		fuse_log(FUSE_LOG_ERR,
			 "hello_reactor: io-uring did not come up: %s\n",
			 strerror(-ret));
		fuse_session_exit(reactor->se);
	} else {
		reactor_run(reactor);
	}

	io_uring_queue_exit(&reactor->ring);
	free(reactor->backend_ios);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct hello_opts hello_opts = { 0 };
	struct hello_reactor reactor = { .backing_fd = -1 };
	struct fuse_cmdline_opts opts = { 0 };
	struct fuse_session *se = NULL;
	pthread_t reactor_tid;
	bool signals_set = false;
	bool mounted = false;
	int exit_code = 1;
	int ret;

	ret = fuse_opt_parse(&args, &hello_opts, hello_opt_specs, NULL);
	if (ret != 0)
		goto out;

	ret = fuse_parse_cmdline(&args, &opts);
	if (ret != 0)
		goto out;

	if (opts.show_help) {
		printf("usage: %s [options] --backing=<file> <mountpoint>\n\n",
		       argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		exit_code = 0;
		goto out;
	}

	if (opts.mountpoint == NULL || hello_opts.backing == NULL) {
		printf("usage: %s [options] --backing=<file> <mountpoint>\n",
		       argv[0]);
		printf("       %s --help\n", argv[0]);
		goto out;
	}

	reactor.backing_fd = open(hello_opts.backing, O_RDWR);
	if (reactor.backing_fd == -1) {
		fprintf(stderr, "open(%s): %s\n", hello_opts.backing,
			strerror(errno));
		goto out;
	}

	se = fuse_session_new(&args, &hello_oper, sizeof(hello_oper), &reactor);
	if (se == NULL)
		goto out;
	reactor.se = se;

	ret = fuse_uring_set_app_owned(se, 0, FUSE_FD_INDEX);
	assert(ret == 0);

	ret = fuse_uring_set_app_ops(se, &hello_app_ops, sizeof(hello_app_ops),
				     &reactor);
	assert(ret == 0);

	ret = fuse_set_signal_handlers(se);
	if (ret != 0)
		goto out;
	signals_set = true;

	ret = fuse_session_mount(se, opts.mountpoint);
	if (ret != 0)
		goto out;
	mounted = true;

	/* fuse_session_fd() is valid only after the mount */
	ret = pthread_create(&reactor_tid, NULL, reactor_thread, &reactor);
	if (ret != 0) {
		fprintf(stderr, "pthread_create(): %s\n", strerror(ret));
		goto out;
	}

	ret = fuse_session_loop_mt(se, NULL);

	/* After ctrl+c only the umount ends the reactor's FUSE entries */
	fuse_session_unmount(se);
	mounted = false;

	exit_code = ret ? 1 : 0;
	ret = pthread_join(reactor_tid, NULL);
	assert(ret == 0);

out:
	if (mounted)
		fuse_session_unmount(se);
	if (signals_set)
		fuse_remove_signal_handlers(se);
	if (se != NULL)
		fuse_session_destroy(se);
	if (reactor.backing_fd >= 0)
		close(reactor.backing_fd);
	free(opts.mountpoint);
	free(hello_opts.backing);
	fuse_opt_free_args(&args);
	return exit_code;
}
