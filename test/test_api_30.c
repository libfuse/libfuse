/*
 * FUSE: Filesystem in Userspace
 *
 * Minimal low level filesystem built against the FUSE_USE_VERSION 30 API,
 * so that the old API keeps being compiled and exercised.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

#define FUSE_USE_VERSION 30

/* the high level header has to keep building at this version as well */
#include <fuse.h>

#include <fuse_config.h>
#include <fuse_lowlevel.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __linux__
#include <limits.h>
#else
#include <linux/limits.h>
#endif

#define FILE_INO 2

static const char file_name[] = "hello";
static const char file_contents[] = "Hello World!\n";

static int tfs_stat(fuse_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ino = ino;
	switch (ino) {
	case FUSE_ROOT_ID:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		break;

	case FILE_INO:
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(file_contents);
		break;

	default:
		return -1;
	}
	return 0;
}

static void tfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;

	if (parent != FUSE_ROOT_ID || strcmp(name, file_name) != 0) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	memset(&e, 0, sizeof(e));
	e.ino = FILE_INO;
	e.attr_timeout = 1.0;
	e.entry_timeout = 1.0;
	tfs_stat(e.ino, &e.attr);

	fuse_reply_entry(req, &e);
}

static void tfs_getattr(fuse_req_t req, fuse_ino_t ino,
			struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (tfs_stat(ino, &stbuf) == -1)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
		       fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;

	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = realloc(b->p, b->size);
	assert(b->p != NULL);

	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
			  b->size);
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
			     off_t off, size_t maxsize)
{
	size_t offset = (size_t) off;

	if (off < 0 || offset >= bufsize)
		return fuse_reply_buf(req, NULL, 0);

	if (bufsize - offset < maxsize)
		maxsize = bufsize - offset;

	return fuse_reply_buf(req, buf + offset, maxsize);
}

static void tfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			off_t off, struct fuse_file_info *fi)
{
	struct dirbuf b;

	(void) fi;

	if (ino != FUSE_ROOT_ID) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	memset(&b, 0, sizeof(b));
	dirbuf_add(req, &b, ".", FUSE_ROOT_ID);
	dirbuf_add(req, &b, "..", FUSE_ROOT_ID);
	dirbuf_add(req, &b, file_name, FILE_INO);
	reply_buf_limited(req, b.p, b.size, off, size);
	free(b.p);
}

static void tfs_open(fuse_req_t req, fuse_ino_t ino,
		     struct fuse_file_info *fi)
{
	if (ino != FILE_INO)
		fuse_reply_err(req, EISDIR);
	else if ((fi->flags & O_ACCMODE) != O_RDONLY)
		fuse_reply_err(req, EACCES);
	else
		fuse_reply_open(req, fi);
}

static void tfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		     struct fuse_file_info *fi)
{
	(void) fi;

	assert(ino == FILE_INO);
	reply_buf_limited(req, file_contents, strlen(file_contents), off, size);
}

static const struct fuse_lowlevel_ops tfs_oper = {
	.lookup		= tfs_lookup,
	.getattr	= tfs_getattr,
	.readdir	= tfs_readdir,
	.open		= tfs_open,
	.read		= tfs_read,
};

static void *run_fs(void *data)
{
	struct fuse_session *se = (struct fuse_session *)data;

	assert(fuse_session_loop(se) == 0);
	return NULL;
}

static void check_readdir(const char *mountpoint)
{
	DIR *dir = opendir(mountpoint);
	const struct dirent *ent;
	int found = 0;

	assert(dir != NULL);
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, file_name) == 0)
			found = 1;
	}
	assert(closedir(dir) == 0);
	assert(found == 1);
}

static void check_read(const char *mountpoint)
{
	char path[PATH_MAX];
	char buf[sizeof(file_contents)];
	int fd;
	ssize_t len;

	assert(snprintf(path, PATH_MAX, "%s/%s", mountpoint, file_name) > 0);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		perror(path);
		assert(0);
	}

	len = read(fd, buf, sizeof(buf));
	assert(len == (ssize_t) strlen(file_contents));
	assert(memcmp(buf, file_contents, len) == 0);
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
	assert(se != NULL);
	assert(fuse_set_signal_handlers(se) == 0);
	assert(fuse_session_mount(se, fuse_opts.mountpoint) == 0);

	assert(pthread_create(&fs_thread, NULL, run_fs, (void *)se) == 0);

	check_readdir(fuse_opts.mountpoint);
	check_read(fuse_opts.mountpoint);

	/*
	 * fuse_session_exit() does not interrupt read(), so nudge this thread
	 * with the ignored signal to let the loop free its receive buffer.
	 */
	fuse_session_exit(se);
	assert(pthread_kill(fs_thread, SIGPIPE) == 0);
	assert(pthread_join(fs_thread, NULL) == 0);

	fuse_session_unmount(se);
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);
	free(fuse_opts.mountpoint);
	fuse_opt_free_args(&args);

	printf("Test completed successfully.\n");
	return 0;
}
