/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * dirread.c - read(2) on a directory
 *
 * \section section_compile compiling this example
 *
 * gcc -Wall dirread.c `pkg-config fuse3 --cflags --libs` -o dirread
 *
 * \section section_usage usage
 \verbatim
 % mkdir mnt
 % ./hello mnt        # program will vanish into the background
 % ls -la mnt
   total 4
   drwxr-xr-x 2 root root      0 Jan  1  1970 ./
   drwxrwx--- 1 root vboxsf 4096 Jun 16 23:12 ../
   -r--r--r-- 1 root root     13 Jan  1  1970 readable-dir
 % cat mnt/readable-dir
   Hello World!
 % fusermount -u mnt
 \endverbatim
 *
 * \section section_source the complete source
 * \include dirread.c
 */


#define FUSE_USE_VERSION 30

#include <config.h>

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *dirread_str = "Hello World!\n";
static const char *dirread_path = "/readable-dir";

static int dirread_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, dirread_path) == 0) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(dirread_str);
	} else
		res = -ENOENT;

	return res;
}

static int dirread_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi,
			   enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	if (strcmp(path, "/") == 0) {
		filler(buf, ".", NULL, 0, 0);
		filler(buf, "..", NULL, 0, 0);
		filler(buf, dirread_path + 1, NULL, 0, 0);
		return 0;
	}

	if (strcmp(path, dirread_path) == 0) {
		filler(buf, ".", NULL, 0, 0);
		filler(buf, "..", NULL, 0, 0);
		return 0;
	}

	return -ENOENT;
}

static int dirread_dir_read(const char *path, char *buf, size_t size, off_t off,
                            struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;
	if (strcmp(path, dirread_path) != 0)
		return -ENOENT;

	len = strlen(dirread_str);
	if (off < len) {
		if (off + size > len)
			size = len - off;
		memcpy(buf, dirread_str + off, size);
	} else
		size = 0;

	return size;
}

static struct fuse_operations dirread_oper = {
	.getattr	= dirread_getattr,
	.readdir	= dirread_readdir,
	.dir_read	= dirread_dir_read,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &dirread_oper, NULL);
}
