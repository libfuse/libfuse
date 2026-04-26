/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/** @file
 *
 * This "filesystem" provides only a single file. The mountpoint
 * needs to be a file rather than a directory. All writes to the
 * file will be discarded, and reading the file always returns
 * \0.
 *
 * Compile with:
 *
 *     gcc -Wall null.c `pkg-config fuse3 --cflags --libs` -o null
 *
 * Change the ExecStart line in nullfile@.service:
 *
 *     ExecStart=/path/to/null
 *
 * to point to the actual path of the null binary.
 *
 * Finally, install the null@.service and null.socket files to the
 * systemd service directory, usually /run/systemd/system.
 *
 * ## Source code ##
 * \include passthrough_fh.c
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse.h>
#include <fuse_lowlevel.h>
#include <fuse_service.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

static mode_t mode = 0644;

static int null_getattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	stbuf->st_mode = S_IFREG | mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = (1ULL << 32); /* 4G */
	stbuf->st_blocks = 0;
	stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

	return 0;
}

static int null_truncate(const char *path, off_t size,
			 struct fuse_file_info *fi)
{
	(void) size;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	return 0;
}

static int null_open(const char *path, struct fuse_file_info *fi)
{
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	return 0;
}

static int null_read(const char *path, char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	(void) buf;
	(void) offset;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	if (offset >= (1ULL << 32))
		return 0;

	memset(buf, 0, size);
	return size;
}

static int null_write(const char *path, const char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	(void) buf;
	(void) offset;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	return size;
}

static const struct fuse_operations null_oper = {
	.getattr	= null_getattr,
	.truncate	= null_truncate,
	.open		= null_open,
	.read		= null_read,
	.write		= null_write,
};

static int null_service(struct fuse_service *service, struct fuse_args *args)
{
	int ret = 1;

	if (fuse_service_append_args(service, args))
		goto err_service;

	if (fuse_service_finish_file_requests(service))
		goto err_service;

	fuse_service_expect_mount_format(service, S_IFREG);

	/*
	 * In non-service mode, we set up the file to be owned and writable
	 * by the same user that starts the fuse server.  When running in a
	 * container as a dynamic user, we just grant world write access.
	 */
	mode = 0666;
	ret = fuse_service_main(service, args, &null_oper, NULL);

err_service:
	fuse_service_send_goodbye(service, ret);
	fuse_service_destroy(&service);
	fuse_opt_free_args(args);
	return fuse_service_exit(ret);
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;
	struct stat stbuf;
	struct fuse_service *service = NULL;

	if (fuse_service_accept(&service) != 0)
		return 1;

	if (fuse_service_accepted(service))
		return null_service(service, &args);

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;
	fuse_opt_free_args(&args);

	if (!opts.mountpoint) {
		fprintf(stderr, "missing mountpoint parameter\n");
		return 1;
	}

	if (stat(opts.mountpoint, &stbuf) == -1) {
		fprintf(stderr ,"failed to access mountpoint %s: %s\n",
			opts.mountpoint, strerror(errno));
		free(opts.mountpoint);
		return 1;
	}
	free(opts.mountpoint);
	if (!S_ISREG(stbuf.st_mode)) {
		fprintf(stderr, "mountpoint is not a regular file\n");
		return 1;
	}

	return fuse_main(argc, argv, &null_oper, NULL);
}
