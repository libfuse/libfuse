/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  Bernd Schubert <bernd@bsbernd.com>
 *
 * A write to a file with 'fuse_file_info::stream' set, while a read on
 * the same fd waits in the filesystem for that write's data.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

/* The asserts are the checks of this test */
#undef NDEBUG

#include <fuse_lowlevel.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define FILE_INO 2
#define FILE_NAME "stream"

/* From the second round on, a kernel file position would be non-zero */
#define ROUNDS 2

/* A working write returns at once; stay below the runner's timeout */
#define WRITE_DEADLINE_SEC 10

static const char stream_msg[] = "ping";

struct stream_state {
	pthread_mutex_t ss_lock;
	pthread_cond_t ss_cond;
	fuse_req_t ss_read_req;
	size_t ss_read_size;
};

static struct stream_state stream_state = {
	.ss_lock = PTHREAD_MUTEX_INITIALIZER,
	.ss_cond = PTHREAD_COND_INITIALIZER,
};

struct read_job {
	int rj_fd;
	ssize_t rj_res;
	char rj_buf[16];
};

struct write_job {
	int wj_fd;
	ssize_t wj_res;
	bool wj_done;
};

static void tfs_stat(fuse_ino_t ino, struct stat *stbuf)
{
	memset(stbuf, 0, sizeof(*stbuf));
	stbuf->st_ino = ino;
	stbuf->st_nlink = 1;
	if (ino == FUSE_ROOT_ID)
		stbuf->st_mode = S_IFDIR | 0755;
	else
		stbuf->st_mode = S_IFREG | 0666;
}

static void tfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e = { .ino = FILE_INO };

	if (parent != FUSE_ROOT_ID || strcmp(name, FILE_NAME) != 0) {
		fuse_reply_err(req, ENOENT);
		return;
	}
	tfs_stat(e.ino, &e.attr);
	fuse_reply_entry(req, &e);
}

static void tfs_getattr(fuse_req_t req, fuse_ino_t ino,
			struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void)fi;

	tfs_stat(ino, &stbuf);
	fuse_reply_attr(req, &stbuf, 5);
}

static void tfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	if (ino == FUSE_ROOT_ID) {
		fuse_reply_err(req, EISDIR);
		return;
	}
	fi->direct_io = 1;
	fi->stream = 1;
	fuse_reply_open(req, fi);
}

/* No reply here: the next write answers the read with its data */
static void tfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		     struct fuse_file_info *fi)
{
	(void)ino;
	(void)fi;

	if (off != 0) {
		fprintf(stderr, "ERROR: read at offset %lld\n", (long long)off);
		fuse_reply_err(req, EINVAL);
		return;
	}

	pthread_mutex_lock(&stream_state.ss_lock);
	stream_state.ss_read_req = req;
	stream_state.ss_read_size = size;
	pthread_cond_broadcast(&stream_state.ss_cond);
	pthread_mutex_unlock(&stream_state.ss_lock);
}

static void tfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
		      size_t size, off_t off, struct fuse_file_info *fi)
{
	fuse_req_t read_req;
	size_t read_size;

	(void)ino;
	(void)fi;

	if (off != 0) {
		fprintf(stderr, "ERROR: write at offset %lld\n", (long long)off);
		fuse_reply_err(req, EINVAL);
		return;
	}

	pthread_mutex_lock(&stream_state.ss_lock);
	read_req = stream_state.ss_read_req;
	read_size = stream_state.ss_read_size;
	stream_state.ss_read_req = NULL;
	pthread_mutex_unlock(&stream_state.ss_lock);

	if (read_req == NULL) {
		fprintf(stderr, "ERROR: write without a pending read\n");
		fuse_reply_err(req, EIO);
		return;
	}

	fuse_reply_buf(read_req, buf, size < read_size ? size : read_size);
	fuse_reply_write(req, size);
}

static const struct fuse_lowlevel_ops tfs_oper = {
	.lookup = tfs_lookup,
	.getattr = tfs_getattr,
	.open = tfs_open,
	.read = tfs_read,
	.write = tfs_write,
};

static void *read_stream(void *data)
{
	struct read_job *job = data;

	job->rj_res = read(job->rj_fd, job->rj_buf, sizeof(job->rj_buf));
	return NULL;
}

static void *write_stream(void *data)
{
	struct write_job *job = data;
	ssize_t res = write(job->wj_fd, stream_msg, sizeof(stream_msg));

	pthread_mutex_lock(&stream_state.ss_lock);
	job->wj_res = res;
	job->wj_done = true;
	pthread_cond_broadcast(&stream_state.ss_cond);
	pthread_mutex_unlock(&stream_state.ss_lock);
	return NULL;
}

static void wait_for_pending_read(void)
{
	pthread_mutex_lock(&stream_state.ss_lock);
	while (stream_state.ss_read_req == NULL)
		pthread_cond_wait(&stream_state.ss_cond, &stream_state.ss_lock);
	pthread_mutex_unlock(&stream_state.ss_lock);
}

/* @return true if the write returned before the deadline */
static bool write_returned(const struct write_job *job)
{
	struct timespec deadline;
	bool done;
	int err = 0;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += WRITE_DEADLINE_SEC;

	pthread_mutex_lock(&stream_state.ss_lock);
	while (!job->wj_done && err != ETIMEDOUT)
		err = pthread_cond_timedwait(&stream_state.ss_cond,
					     &stream_state.ss_lock, &deadline);
	done = job->wj_done;
	pthread_mutex_unlock(&stream_state.ss_lock);
	return done;
}

/*
 * Ends the read with EIO, so the kernel lets the blocked write through.
 * Without this the process cannot exit: the write waits in the kernel
 * for a read that only this process can answer.
 */
static void fail_pending_read(void)
{
	fuse_req_t read_req;

	pthread_mutex_lock(&stream_state.ss_lock);
	read_req = stream_state.ss_read_req;
	stream_state.ss_read_req = NULL;
	pthread_mutex_unlock(&stream_state.ss_lock);

	if (read_req != NULL)
		fuse_reply_err(read_req, EIO);
}

static void *run_fs(void *data)
{
	struct fuse_session *se = data;
	int ret;

	ret = fuse_session_loop(se);
	assert(ret == 0);
	return NULL;
}

/* @return true if every write got through while its read was pending */
static bool test_fs(const char *mountpoint)
{
	char fname[PATH_MAX];
	bool passed = true;
	int fd, ret;

	ret = snprintf(fname, sizeof(fname), "%s/" FILE_NAME, mountpoint);
	assert(ret > 0);
	fd = open(fname, O_RDWR);
	if (fd == -1) {
		perror(fname);
		assert(0);
	}

	for (int round = 0; round < ROUNDS && passed; round++) {
		struct read_job rjob = { .rj_fd = fd };
		struct write_job wjob = { .wj_fd = fd };
		pthread_t reader, writer;

		ret = pthread_create(&reader, NULL, read_stream, &rjob);
		assert(ret == 0);
		wait_for_pending_read();

		/* Without FOPEN_STREAM the write waits for the read to return */
		ret = pthread_create(&writer, NULL, write_stream, &wjob);
		assert(ret == 0);
		if (!write_returned(&wjob)) {
			fprintf(stderr,
				"ERROR: write blocked behind the pending read\n");
			fail_pending_read();
			passed = false;
		}

		ret = pthread_join(writer, NULL);
		assert(ret == 0);
		ret = pthread_join(reader, NULL);
		assert(ret == 0);
		if (passed) {
			assert(wjob.wj_res == sizeof(stream_msg));
			assert(rjob.rj_res == sizeof(stream_msg));
			ret = memcmp(rjob.rj_buf, stream_msg, sizeof(stream_msg));
			assert(ret == 0);
		}
	}
	close(fd);
	return passed;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts fuse_opts;
	struct fuse_session *se;
	pthread_t fs_thread;
	bool passed;
	int ret;

	ret = fuse_parse_cmdline(&args, &fuse_opts);
	assert(ret == 0);
	ret = fuse_opt_add_arg(&args, "-oauto_unmount");
	assert(ret == 0);
	se = fuse_session_new(&args, &tfs_oper, sizeof(tfs_oper), NULL);
	fuse_opt_free_args(&args);
	assert(se != NULL);
	ret = fuse_set_signal_handlers(se);
	assert(ret == 0);
	ret = fuse_session_mount(se, fuse_opts.mountpoint);
	assert(ret == 0);

	ret = pthread_create(&fs_thread, NULL, run_fs, se);
	assert(ret == 0);

	passed = test_fs(fuse_opts.mountpoint);
	free(fuse_opts.mountpoint);

	fuse_session_exit(se);
	ret = pthread_join(fs_thread, NULL);
	assert(ret == 0);
	fuse_session_unmount(se);
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);

	if (!passed)
		return 1;
	printf("Test completed successfully.\n");
	return 0;
}
