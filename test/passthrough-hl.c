/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  Bernd Schubert <bernd@bsbernd.com>
 *
 * High-level passthrough without 'fuse_config::nullpath_ok' that prints
 * the path write, flush and release get.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

static void print_path(const char *op, const char *path)
{
	fprintf(stderr, "%s: path=%s\n", op, path != NULL ? path : "NULL");
}

static void *pt_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	(void)conn;

	cfg->nullpath_ok = 0;
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;
	return NULL;
}

static int pt_getattr(const char *path, struct stat *stbuf,
		      struct fuse_file_info *fi)
{
	int res;

	if (fi != NULL)
		res = fstat(fi->fh, stbuf);
	else
		res = lstat(path, stbuf);
	if (res == -1)
		return -errno;
	return 0;
}

static int pt_mkdir(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == -1)
		return -errno;
	return 0;
}

static int pt_rmdir(const char *path)
{
	if (rmdir(path) == -1)
		return -errno;
	return 0;
}

static int pt_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd;

	fd = open(path, fi->flags, mode);
	if (fd == -1)
		return -errno;
	fi->fh = fd;
	return 0;
}

static int pt_write(const char *path, const char *buf, size_t size,
		    off_t off, struct fuse_file_info *fi)
{
	size_t written = 0;

	print_path("write", path);
	/* The writeback cache ignores the count in a short reply */
	while (written < size) {
		ssize_t res = pwrite(fi->fh, buf + written, size - written,
				     off + written);

		if (res == -1)
			return -errno;
		written += res;
	}
	return size;
}

static int pt_flush(const char *path, struct fuse_file_info *fi)
{
	(void)fi;

	print_path("flush", path);
	return 0;
}

static int pt_release(const char *path, struct fuse_file_info *fi)
{
	print_path("release", path);
	close(fi->fh);
	return 0;
}

static const struct fuse_operations pt_oper = {
	.init = pt_init,
	.getattr = pt_getattr,
	.mkdir = pt_mkdir,
	.rmdir = pt_rmdir,
	.create = pt_create,
	.write = pt_write,
	.flush = pt_flush,
	.release = pt_release,
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &pt_oper, NULL);
}
