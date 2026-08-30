/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/*
 * Check that a setattr caused by an operation on an open file descriptor
 * reaches the filesystem with the file handle of that descriptor, so that it
 * can tell which open file the request belongs to. ftruncate() is used to
 * trigger it, as chmod_common() in the kernel does not pass the struct file
 * down and fchmod() would therefore never carry a handle.
 *
 * With --kill-suidgid it also checks that the KILLPRIV_V2 request to drop
 * suid/sgid reaches open, create and write as fi->kill_suidgid.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

/* Not really needed - just to test the build with fuse.h included */
#include <fuse.h>

#include <fuse_config.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <pthread.h>

#ifndef __linux__
#include <limits.h>
#else
#include <linux/limits.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#endif

#define FILE_INO 2
#define FILE_NAME "truncate_me"
#define FILE_SIZE 4096
#define NEW_INO 3
#define NEW_NAME "create_me"

struct options {
	int kill_suidgid;
	int no_killpriv;
	int write_buf;
} options;

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--kill-suidgid", kill_suidgid),
	OPTION("--no-killpriv", no_killpriv),
	OPTION("--write-buf", write_buf),
	FUSE_OPT_END
};

static int got_fh;
static off_t file_size;

/*
 * fi->kill_suidgid as each operation saw it, -1 until the operation runs. An
 * operation that never happens must not be mistaken for one that reported a
 * cleared flag, which is what the --no-killpriv run expects to see.
 */
static int seen_create = -1;
static int seen_open = -1;
static int seen_write = -1;

/*
 * The kernel sets FUSE_OPEN_KILL_SUIDGID and FUSE_WRITE_KILL_SUIDGID only for
 * a caller without CAP_FSETID, so a root test process has to give it up.
 */
static void drop_cap_fsetid(void)
{
#ifdef __linux__
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2];

	assert(syscall(SYS_capget, &hdr, data) == 0);
	if (!(data[0].effective & (1U << CAP_FSETID)))
		return;

	data[0].effective &= ~(1U << CAP_FSETID);
	assert(syscall(SYS_capset, &hdr, data) == 0);
#endif
}

static void tfs_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;

	if (!options.kill_suidgid)
		return;

	/* The test case gates on FUSE_CAP_HANDLE_KILLPRIV_V2 before this */
	assert(fuse_get_feature_flag(conn, FUSE_CAP_HANDLE_KILLPRIV_V2));

	if (options.no_killpriv)
		fuse_unset_feature_flag(conn, FUSE_CAP_HANDLE_KILLPRIV_V2);
	else
		fuse_set_feature_flag(conn, FUSE_CAP_HANDLE_KILLPRIV_V2);
}

static int tfs_stat(fuse_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ino = ino;
	if (ino == FUSE_ROOT_ID) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
	}

	else if (ino == FILE_INO || ino == NEW_INO) {
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = ino == FILE_INO ? file_size : 0;
	}

	else
		return -1;

	return 0;
}

static void tfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));

	if (parent != FUSE_ROOT_ID)
		goto err_out;
	else if (strcmp(name, FILE_NAME) == 0)
		e.ino = FILE_INO;
	else
		goto err_out;

	if (tfs_stat(e.ino, &e.attr) != 0)
		goto err_out;
	fuse_reply_entry(req, &e);
	return;

err_out:
	fuse_reply_err(req, ENOENT);
}

static void tfs_getattr(fuse_req_t req, fuse_ino_t ino,
			struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void)fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (tfs_stat(ino, &stbuf) != 0)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, 5);
}

static void tfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	if (ino == FUSE_ROOT_ID)
		fuse_reply_err(req, EISDIR);
	else {
		assert(ino == FILE_INO);
		/* The kernel sets FUSE_OPEN_KILL_SUIDGID only on O_TRUNC */
		if (fi->flags & O_TRUNC)
			seen_open = fi->kill_suidgid;
		fi->fh = FILE_INO;
		fuse_reply_open(req, fi);
	}
}

static void tfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, struct fuse_file_info *fi)
{
	struct fuse_entry_param e;

	(void)mode;

	if (parent != FUSE_ROOT_ID || strcmp(name, NEW_NAME) != 0) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	seen_create = fi->kill_suidgid;
	fi->fh = NEW_INO;

	/*
	 * Puts the write on fuse_direct_io(), which sets
	 * FUSE_WRITE_KILL_SUIDGID without checking handle_killpriv_v2, and
	 * delivers it before write() returns.
	 */
	fi->direct_io = 1;

	memset(&e, 0, sizeof(e));
	e.ino = NEW_INO;
	assert(tfs_stat(e.ino, &e.attr) == 0);
	fuse_reply_create(req, &e, fi);
}

static void tfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
		      size_t size, off_t off, struct fuse_file_info *fi)
{
	(void)ino;
	(void)buf;
	(void)off;

	seen_write = fi->kill_suidgid;
	fuse_reply_write(req, size);
}

static void tfs_write_buf(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_bufvec *bufv, off_t off,
			  struct fuse_file_info *fi)
{
	(void)ino;
	(void)off;

	seen_write = fi->kill_suidgid;
	fuse_reply_write(req, fuse_buf_size(bufv));
}

static void tfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			int to_set, struct fuse_file_info *fi)
{
	if (ino != FILE_INO || !(to_set & FUSE_SET_ATTR_SIZE)) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	if (fi == NULL)
		fprintf(stderr, "setattr with fi == NULL\n");
	else if (fi->fh != FILE_INO)
		fprintf(stderr, "setattr with wrong fi->fh\n");
	else {
		fprintf(stderr, "setattr ok\n");
		got_fh = 1;
		file_size = attr->st_size;
	}

	tfs_getattr(req, ino, fi);
}

static struct fuse_lowlevel_ops tfs_oper = {
	.init = tfs_init,
	.lookup = tfs_lookup,
	.getattr = tfs_getattr,
	.open = tfs_open,
	.create = tfs_create,
	.write = tfs_write,
	.setattr = tfs_setattr,
};

static void *run_fs(void *data)
{
	struct fuse_session *se = (struct fuse_session *)data;
	assert(fuse_session_loop(se) == 0);
	return NULL;
}

static void test_fs(const char *mountpoint)
{
	char fname[PATH_MAX];
	struct stat stbuf;
	int fd;

	assert(snprintf(fname, PATH_MAX, "%s/" FILE_NAME, mountpoint) > 0);
	fd = open(fname, O_WRONLY);
	if (fd == -1) {
		perror(fname);
		assert(0);
	}

	assert(ftruncate(fd, FILE_SIZE) == 0);
	assert(fstat(fd, &stbuf) == 0);
	assert(stbuf.st_size == FILE_SIZE);
	assert(close(fd) == 0);

	if (!options.kill_suidgid)
		return;

	drop_cap_fsetid();

	/* O_TRUNC, no O_EXCL: CREATE carries FUSE_OPEN_KILL_SUIDGID */
	assert(snprintf(fname, PATH_MAX, "%s/" NEW_NAME, mountpoint) > 0);
	fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd == -1) {
		perror(fname);
		assert(0);
	}
	assert(write(fd, "x", 1) == 1);
	assert(close(fd) == 0);

	/* O_TRUNC on an existing file: OPEN carries FUSE_OPEN_KILL_SUIDGID */
	assert(snprintf(fname, PATH_MAX, "%s/" FILE_NAME, mountpoint) > 0);
	fd = open(fname, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		perror(fname);
		assert(0);
	}
	assert(close(fd) == 0);
}

static void check_kill_suidgid(const char *op, int got, int expected)
{
	if (got == expected)
		return;

	fprintf(stderr, "ERROR: %s: kill_suidgid is %d, expected %d\n", op, got,
		expected);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts fuse_opts;
	pthread_t fs_thread;

	assert(fuse_opt_parse(&args, &options, option_spec, NULL) == 0);
	assert(fuse_parse_cmdline(&args, &fuse_opts) == 0);
#ifndef __FreeBSD__
	assert(fuse_opt_add_arg(&args, "-oauto_unmount") == 0);
#endif
	if (options.write_buf) {
		tfs_oper.write = NULL;
		tfs_oper.write_buf = tfs_write_buf;
	}

	se = fuse_session_new(&args, &tfs_oper, sizeof(tfs_oper), NULL);
	fuse_opt_free_args(&args);
	assert(se != NULL);
	assert(fuse_set_signal_handlers(se) == 0);
	assert(fuse_session_mount(se, fuse_opts.mountpoint) == 0);

	/* Start file-system thread */
	assert(pthread_create(&fs_thread, NULL, run_fs, (void *)se) == 0);

	/* Do test */
	test_fs(fuse_opts.mountpoint);
	free(fuse_opts.mountpoint);

	/* Stop file system */
	fuse_session_exit(se);
	fuse_session_unmount(se);
	assert(pthread_join(fs_thread, NULL) == 0);

	assert(got_fh == 1);

	if (options.kill_suidgid) {
		int expected = options.no_killpriv ? 0 : 1;

		check_kill_suidgid("create", seen_create, expected);
		check_kill_suidgid("open", seen_open, expected);
		check_kill_suidgid("write", seen_write, expected);
	}

	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);

	printf("Test completed successfully.\n");
	return 0;
}
