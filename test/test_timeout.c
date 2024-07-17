/*
 *	This program can be distributed under the terms of the GNU GPLv2.
 * See the file COPYING.
 */

/** @file
 *
 * This "filesystem" does nothing. It is used for exercising the timeout paths
 * by inserting sleeps before request replies or skipping replies altogether.
 *
 * Ways to run this test:
 *	 ./test/test_timeout ~/test_mount1 --timeout_open
 *			tests open request timeout (reply is sent after timeout
 *			elapses)
 *	 ./test/test_timeout ~/test_mount1 --timeout_open --no_reply
 *			tests open request timeout (no reply ever sent)
 *	 ./test/test_timeout ~/test_mount1 --timeout_write
 *			tests write request timeout (reply is sent after timeout
 *			elapses)
 *	 ./test/test_timeout ~/test_mount1 --timeout_write --no_reply
 *			tests write request timeout (no reply ever sent)
 *	 ./test/test_timeout ~/test_mount1 --successful_request
 *			tests case where all requests succeed before timeout elapses
 */

#define FUSE_USE_VERSION 34

#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#ifndef __linux__
#include <limits.h>
#else
#include <linux/limits.h>
#endif

#define FILE_INO 2
#define FILE_NAME "test_timeout"

/* Command line parsing */
struct options {
	bool timeout_open;
	bool timeout_write;
	bool successful_request;
	bool no_reply;
	int sleep;
} options = {};

static const size_t data_size = 4096;

#define OPTION(t, p)						   \
	{ t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	/* test request timeout for open */
	OPTION("--timeout_open", timeout_open),
	/* test request timeout for write */
	OPTION("--timeout_write", timeout_write),
	/* test path where request succeeds before timeout elapses */
	OPTION("--successful_request", successful_request),
	/* test path where no reply is sent */
	OPTION("--no_reply", no_reply),
	FUSE_OPT_END
};

static int timeout_stat(fuse_ino_t ino, struct stat *stbuf) {
	stbuf->st_ino = ino;
	if (ino == FUSE_ROOT_ID) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
	} else if (ino == FILE_INO) {
		stbuf->st_mode = S_IFREG | 0222;
		stbuf->st_nlink = 1;
		stbuf->st_size = 0;
	} else {
		return -1;
	}

	return 0;
}

static void timeout_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));

	if (parent != FUSE_ROOT_ID)
		goto err_out;
	else if (strcmp(name, FILE_NAME) == 0)
		e.ino = FILE_INO;
	else
		goto err_out;

	if (timeout_stat(e.ino, &e.attr) != 0)
		goto err_out;
	fuse_reply_entry(req, &e);
	return;

err_out:
	fuse_reply_err(req, ENOENT);
}

static void timeout_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {

	if (options.timeout_open) {
		if (options.no_reply)
			return;

		sleep(options.sleep);
	}

	if (ino == FUSE_ROOT_ID)
		fuse_reply_err(req, EISDIR);
	else {
		assert(ino == FILE_INO);
		fuse_reply_open(req, fi);
	}
}

static void timeout_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
							size_t size, off_t off, struct fuse_file_info *fi) {
	(void) fi; (void) buf; (void) off; (void) ino;

	if (options.timeout_write) {
	if (options.no_reply)
		return;
	sleep(options.sleep);
	}

	fuse_reply_write(req, size);
}


static const struct fuse_lowlevel_ops timeout_oper = {
	.open = timeout_open,
	.write = timeout_write,
	.lookup	= timeout_lookup,
};

static void* run_fs(void *data) {
	struct fuse_session *se = (struct fuse_session*) data;

	assert(fuse_session_loop(se) == 0);
	return NULL;
}

static void test_fs(char *mountpoint) {
	const size_t iosize = data_size;
	char fname[PATH_MAX];
	off_t off = 0;
	char *buf;
	int fd;

	assert(snprintf(fname, PATH_MAX, "%s/" FILE_NAME,
					 mountpoint) > 0);

	if (options.timeout_open && !options.successful_request) {
		assert(open(fname, O_WRONLY) == -1);
		assert(errno == ETIME);
		return;
	}

	fd = open(fname, O_WRONLY);
	if (fd == -1) {
		perror(fname);
		assert(0);
	}

	buf = malloc(data_size);
	assert(buf != NULL);

	if (options.timeout_write && !options.successful_request) {
		assert(pwrite(fd, buf + off, iosize, off) == -1);
		assert(errno == ETIME);
		goto done;
	}
	assert(pwrite(fd, buf + off, iosize, off) == iosize);
	off += iosize;
	assert(off <= data_size);

done:
	free(buf);
	close(fd);
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts fuse_opts;
	pthread_t fs_thread;
	int request_timeout;
	int long_interval = 3, short_interval = 1;
	char buf[32];

	assert(fuse_opt_parse(&args, &options, option_spec, NULL) == 0);
	assert(fuse_parse_cmdline(&args, &fuse_opts) == 0);

	if (options.successful_request) {
		options.timeout_open = true;
		options.timeout_write = true;
		request_timeout = long_interval;
		options.sleep = short_interval;
	} else {
		request_timeout = short_interval;
		options.sleep = long_interval;
	}

	/* Set daemon timeout */
	assert(snprintf(buf, sizeof(buf), "-orequest_timeout=%u", request_timeout) == strlen(buf));
	assert(fuse_opt_add_arg(&args, buf) == 0);

	se = fuse_session_new(&args, &timeout_oper,
						  sizeof(timeout_oper), NULL);
	fuse_opt_free_args(&args);
	assert (se != NULL);
	assert(fuse_set_signal_handlers(se) == 0);
	assert(fuse_session_mount(se, fuse_opts.mountpoint) == 0);

	/* Start file-system thread */
	assert(pthread_create(&fs_thread, NULL, run_fs, (void *)se) == 0);

	/* Write test data */
	test_fs(fuse_opts.mountpoint);
	free(fuse_opts.mountpoint);

	/* Stop file system */
	fuse_session_exit(se);
	fuse_session_unmount(se);
	assert(pthread_join(fs_thread, NULL) == 0);

	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);

	printf("Test completed successfully.\n");
	return 0;
}
