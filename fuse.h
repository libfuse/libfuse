/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <linux/limits.h>

#define FUSE_MOUNT_VERSION 1

struct fuse_mount_data {
	int version;
	int fd;
};

#define FUSE_ROOT_INO 1

struct fuse_attr {
	unsigned short mode;
	unsigned short nlink;
	unsigned short uid;
	unsigned short gid;
	unsigned short rdev;
	unsigned long  size;
	unsigned long  blksize;
	unsigned long  blocks;
	unsigned long  atime;
	unsigned long  mtime;
	unsigned long  ctime;
};

enum fuse_opcode {
	FUSE_LOOKUP,
	FUSE_GETATTR,
	FUSE_READLINK,
	FUSE_OPEN,
	FUSE_RELEASE,
};

/* Conservative buffer size for the client */
#define FUSE_MAX_IN 8192

struct fuse_in_open {
	int flag;
};

struct fuse_out_open {
	int fd;
};

struct fuse_in_lookup {
	char name[NAME_MAX + 1];
};

struct fuse_out_lookup {
	unsigned long ino;
	struct fuse_attr attr;
};

struct fuse_out_getattr {
	struct fuse_attr attr;
};

struct fuse_out_readlink {
	char link[PATH_MAX + 1];
};

struct fuse_in_common {
	int unique;
	enum fuse_opcode opcode;
	unsigned long ino;	
};

struct fuse_out_common {
	int unique;
	int result;
};

struct fuse_in {
	struct fuse_in_common c;
	size_t argsize;
	void *arg;
};

struct fuse_out {
	struct fuse_out_common c;
	size_t argsize;
	void *arg;
};

struct fuse_dirent {
	unsigned long ino;
	unsigned short namelen;
	unsigned char type;
	char name[NAME_MAX + 1];
};

#define FUSE_NAME_OFFSET ((size_t) ((struct fuse_dirent *) 0)->name)
#define FUSE_DIRENT_ALIGN(x) (((x) + sizeof(long) - 1) & ~(sizeof(long) - 1))
#define FUSE_DIRENT_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
