/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  Bernd Schubert <bernd@bsbernd.com>
 *
 * A request that carries an extension and is too large for the fixed header
 * the splice path copies out of the pipe first: FUSE_SYMLINK with a long
 * target, with FUSE_CAP_SECURITY_CTX negotiated so the kernel appends a
 * security context. Under valgrind or ASan this catches an extension parse
 * that walks past the header allocation.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file GPL2.txt
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse_lowlevel.h>

#include "fuse_i.h"
#include "fuse_kernel.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef __linux__
#include <limits.h>
#else
#include <linux/limits.h>
#endif

#define LINK_INO 2

/*
 * A FUSE_SYMLINK is the header, the name and the target, each NUL terminated.
 * The target is capped at PATH_MAX, so the name carries the rest of the
 * length needed to clear splice_threshold().
 */
#define LINK_NAME \
	"symlink_name_padded_to_push_the_request_over_the_splice_threshold_0123456789"
#define TARGET_LEN (PATH_MAX - 1)

/* Plus the single 8-byte unit the kernel appends for the security context */
#define REQUEST_SIZE                                                   \
	(sizeof(struct fuse_in_header) + sizeof(LINK_NAME) + TARGET_LEN \
	 + 1 + sizeof(uint64_t))

static struct fuse_conn_info *fs_conn;
static unsigned int fs_max_write;
static char link_target[TARGET_LEN + 1];
static int seen_symlink;

/*
 * Below this libfuse copies the request out of the pipe and clears
 * FUSE_BUF_IS_FD, so a smaller request never reaches the path under test.
 */
static size_t splice_threshold(void)
{
	return sizeof(struct fuse_in_header) + sizeof(struct fuse_write_in) +
	       (size_t)getpagesize();
}

/*
 * se->bufsize has to fit the pipe libfuse splices into, and for an
 * unprivileged process the kernel caps both a new pipe and F_SETPIPE_SZ at
 * /proc/sys/fs/pipe-max-size. The default max_write puts bufsize past that,
 * which turns splice read back off.
 *
 * @param[out] max_write  what the filesystem should ask for
 * @return false if the resulting buffer could not hold the test request
 */
static bool splice_max_write(unsigned int *max_write)
{
	long pipe_max = 16L * getpagesize();
	FILE *sysctl;

	sysctl = fopen("/proc/sys/fs/pipe-max-size", "r");
	if (sysctl != NULL) {
		long configured;

		if (fscanf(sysctl, "%ld", &configured) == 1 && configured > 0 &&
		    configured < pipe_max)
			pipe_max = configured;
		fclose(sysctl);
	}

	if (pipe_max < (long)(FUSE_BUFFER_HEADER_SIZE + REQUEST_SIZE))
		return false;

	*max_write = pipe_max - FUSE_BUFFER_HEADER_SIZE;
	return true;
}

static void tfs_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;

	/* The test case gates on both being capable */
	if (!fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_READ) ||
	    !fuse_set_feature_flag(conn, FUSE_CAP_SECURITY_CTX)) {
		fprintf(stderr,
			"ERROR: splice read or security context not capable\n");
		exit(1);
	}

	conn->max_write = fs_max_write;
	fs_conn = conn;
}

/* Only the root is ever looked up or stat'ed; the symlink is never revisited */
static void tfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	(void)parent;
	(void)name;

	fuse_reply_err(req, ENOENT);
}

static void tfs_getattr(fuse_req_t req, fuse_ino_t ino,
			struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void)fi;

	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	stbuf.st_mode = S_IFDIR | 0755;
	stbuf.st_nlink = 2;
	fuse_reply_attr(req, &stbuf, 5);
}

static void tfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
			const char *name)
{
	struct fuse_entry_param e = {
		.ino = LINK_INO,
		.attr.st_ino = LINK_INO,
		.attr.st_mode = S_IFLNK | 0777,
		.attr.st_nlink = 1,
		.attr.st_size = TARGET_LEN,
	};

	(void)parent;
	(void)name;

	if (strcmp(link, link_target) != 0) {
		fprintf(stderr, "ERROR: symlink target did not survive\n");
		fuse_reply_err(req, EINVAL);
		return;
	}

	seen_symlink = 1;
	fuse_reply_entry(req, &e);
}

static struct fuse_lowlevel_ops tfs_oper = {
	.init = tfs_init,
	.lookup = tfs_lookup,
	.getattr = tfs_getattr,
	.symlink = tfs_symlink,
};

static void *run_fs(void *data)
{
	struct fuse_session *se = (struct fuse_session *)data;

	assert(fuse_session_loop(se) == 0);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts fuse_opts;
	struct fuse_session *se;
	pthread_t fs_thread;
	char path[PATH_MAX];

	if (REQUEST_SIZE <= splice_threshold()) {
		fprintf(stderr,
			"SKIP: a %zu-byte page leaves no symlink big enough to splice\n",
			(size_t)getpagesize());
		return 77;
	}

	if (!splice_max_write(&fs_max_write)) {
		fprintf(stderr,
			"SKIP: /proc/sys/fs/pipe-max-size is too small to splice a %zu-byte request\n",
			(size_t)REQUEST_SIZE);
		return 77;
	}

	memset(link_target, 'x', TARGET_LEN);

	assert(fuse_parse_cmdline(&args, &fuse_opts) == 0);

	se = fuse_session_new(&args, &tfs_oper, sizeof(tfs_oper), NULL);
	fuse_opt_free_args(&args);
	assert(se != NULL);
	assert(fuse_session_mount(se, fuse_opts.mountpoint) == 0);

	assert(pthread_create(&fs_thread, NULL, run_fs, (void *)se) == 0);

	assert(snprintf(path, sizeof(path), "%s/" LINK_NAME,
			fuse_opts.mountpoint) > 0);
	if (symlink(link_target, path) != 0) {
		perror(path);
		exit(1);
	}
	free(fuse_opts.mountpoint);

	fuse_session_exit(se);
	fuse_session_unmount(se);
	assert(pthread_join(fs_thread, NULL) == 0);

	if (!seen_symlink) {
		fprintf(stderr, "ERROR: the filesystem never saw the symlink\n");
		return 1;
	}

	if (!(fs_conn->want_ext & FUSE_CAP_SPLICE_READ)) {
		fprintf(stderr, "ERROR: splice read was disabled at runtime\n");
		return 1;
	}

	fuse_session_destroy(se);

	printf("Test completed successfully.\n");
	return 0;
}
