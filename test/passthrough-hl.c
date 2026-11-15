/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  Bernd Schubert <bernd@bsbernd.com>
 *
 * High-level passthrough without 'fuse_config::nullpath_ok' that prints
 * the path write, flush and release get. Its readdir returns READDIRPLUS
 * entries, with offsets if --readdir-offsets is given.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

static struct pt_options {
	int readdir_offsets;
} options;

static const struct fuse_opt option_spec[] = {
	{ "--readdir-offsets", offsetof(struct pt_options, readdir_offsets), 1 },
	FUSE_OPT_END
};

static void print_path(const char *op, const char *path)
{
	fprintf(stderr, "%s: path=%s\n", op, path != NULL ? path : "NULL");
}

static void *pt_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	/* One-page READDIRPLUS requests, so a directory takes several */
	conn->max_write = 4096;
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

static int pt_opendir(const char *path, struct fuse_file_info *fi)
{
	const DIR *dir = opendir(path);

	if (dir == NULL)
		return -errno;
	fi->fh = (uintptr_t)dir;
	return 0;
}

static int pt_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		      off_t off, struct fuse_file_info *fi,
		      enum fuse_readdir_flags flags)
{
	DIR *dir = (DIR *)(uintptr_t)fi->fh;
	struct dirent *entry;

	(void)path;
	(void)flags;
	/* The offset says where to continue, so no state is kept between calls */
	if (off == 0)
		rewinddir(dir);
	else {
#ifndef __FreeBSD__
		seekdir(dir, off);
#else
		/* Undo the shift telldir() gets below */
		seekdir(dir, off - 1);
#endif
	}
	while ((entry = readdir(dir)) != NULL) {
		struct stat st;
		off_t next_off = 0;

		if (fstatat(dirfd(dir), entry->d_name, &st,
			    AT_SYMLINK_NOFOLLOW) == -1)
			return -errno;
		if (options.readdir_offsets) {
			next_off = telldir(dir);
#ifdef __FreeBSD__
			/* telldir() can return 0, which libfuse reads as no offset */
			next_off++;
#endif
		}
		if (filler(buf, entry->d_name, &st, next_off,
			   FUSE_FILL_DIR_PLUS))
			break;
	}
	return 0;
}

static int pt_releasedir(const char *path, struct fuse_file_info *fi)
{
	(void)path;

	closedir((DIR *)(uintptr_t)fi->fh);
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
	.opendir = pt_opendir,
	.readdir = pt_readdir,
	.releasedir = pt_releasedir,
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int ret;

	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;
	umask(0);
	ret = fuse_main(args.argc, args.argv, &pt_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}
