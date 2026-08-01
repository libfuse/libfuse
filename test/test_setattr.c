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
#endif

#define FILE_INO 2
#define FILE_NAME "truncate_me"
#define FILE_SIZE 4096

static int got_fh;
static off_t file_size;

static int tfs_stat(fuse_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ino = ino;
	if (ino == FUSE_ROOT_ID) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
	}

	else if (ino == FILE_INO) {
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = file_size;
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
		fi->fh = FILE_INO;
		fuse_reply_open(req, fi);
	}
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
	.lookup = tfs_lookup,
	.getattr = tfs_getattr,
	.open = tfs_open,
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
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts fuse_opts;
	pthread_t fs_thread;

	assert(fuse_parse_cmdline(&args, &fuse_opts) == 0);
#ifndef __FreeBSD__
	assert(fuse_opt_add_arg(&args, "-oauto_unmount") == 0);
#endif
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
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);

	printf("Test completed successfully.\n");
	return 0;
}
