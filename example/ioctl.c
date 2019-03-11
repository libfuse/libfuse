/*
  FUSE fioc: FUSE ioctl example
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 * @tableofcontents
 *
 * This example illustrates how to write a FUSE file system that can
 * process (a restricted set of) ioctls. It can be tested with the
 * ioctl_client.c program.
 *
 * Compile with:
 *
 *     gcc -Wall ioctl.c `pkg-config fuse3 --cflags --libs` -o ioctl
 *
 * ## Source code ##
 * \include ioctl.c
 */

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "ioctl.h"

#define FIOC_NAME	"fioc"

enum {
	FIOC_NONE,
	FIOC_ROOT,
	FIOC_FILE,
};

static void *fioc_buf;
static size_t fioc_size;

static int fioc_resize(size_t new_size)
{
	void *new_buf;

	if (new_size == fioc_size)
		return 0;

	new_buf = realloc(fioc_buf, new_size);
	if (!new_buf && new_size)
		return -ENOMEM;

	if (new_size > fioc_size)
		memset(new_buf + fioc_size, 0, new_size - fioc_size);

	fioc_buf = new_buf;
	fioc_size = new_size;

	return 0;
}

static int fioc_expand(size_t new_size)
{
	if (new_size > fioc_size)
		return fioc_resize(new_size);
	return 0;
}

static int fioc_file_type(const char *path)
{
	if (strcmp(path, "/") == 0)
		return FIOC_ROOT;
	if (strcmp(path, "/" FIOC_NAME) == 0)
		return FIOC_FILE;
	return FIOC_NONE;
}

static int fioc_getattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
	(void) fi;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_atime = stbuf->st_mtime = time(NULL);

	switch (fioc_file_type(path)) {
	case FIOC_ROOT:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		break;
	case FIOC_FILE:
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = fioc_size;
		break;
	case FIOC_NONE:
		return -ENOENT;
	}

	return 0;
}

static int fioc_open(const char *path, struct fuse_file_info *fi)
{
	(void) fi;

	if (fioc_file_type(path) != FIOC_NONE)
		return 0;
	return -ENOENT;
}

static int fioc_do_read(char *buf, size_t size, off_t offset)
{
	if (offset >= fioc_size)
		return 0;

	if (size > fioc_size - offset)
		size = fioc_size - offset;

	memcpy(buf, fioc_buf + offset, size);

	return size;
}

static int fioc_read(const char *path, char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	(void) fi;

	if (fioc_file_type(path) != FIOC_FILE)
		return -EINVAL;

	return fioc_do_read(buf, size, offset);
}

static int fioc_do_write(const char *buf, size_t size, off_t offset)
{
	if (fioc_expand(offset + size))
		return -ENOMEM;

	memcpy(fioc_buf + offset, buf, size);

	return size;
}

static int fioc_write(const char *path, const char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	(void) fi;

	if (fioc_file_type(path) != FIOC_FILE)
		return -EINVAL;

	return fioc_do_write(buf, size, offset);
}

static int fioc_truncate(const char *path, off_t size,
			 struct fuse_file_info *fi)
{
	(void) fi;
	if (fioc_file_type(path) != FIOC_FILE)
		return -EINVAL;

	return fioc_resize(size);
}

static int fioc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi,
			enum fuse_readdir_flags flags)
{
	(void) fi;
	(void) offset;
	(void) flags;

	if (fioc_file_type(path) != FIOC_ROOT)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	filler(buf, FIOC_NAME, NULL, 0, 0);

	return 0;
}

static int fioc_ioctl(const char *path, unsigned int cmd, void *arg,
		      struct fuse_file_info *fi, unsigned int flags, void *data)
{
	(void) arg;
	(void) fi;
	(void) flags;

	if (fioc_file_type(path) != FIOC_FILE)
		return -EINVAL;

	if (flags & FUSE_IOCTL_COMPAT)
		return -ENOSYS;

	switch (cmd) {
	case FIOC_GET_SIZE:
		*(size_t *)data = fioc_size;
		return 0;

	case FIOC_SET_SIZE:
		fioc_resize(*(size_t *)data);
		return 0;
	}

	return -EINVAL;
}

static struct fuse_operations fioc_oper = {
	.getattr	= fioc_getattr,
	.readdir	= fioc_readdir,
	.truncate	= fioc_truncate,
	.open		= fioc_open,
	.read		= fioc_read,
	.write		= fioc_write,
	.ioctl		= fioc_ioctl,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &fioc_oper, NULL);
}
