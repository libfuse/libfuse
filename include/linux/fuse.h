/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/* This file defines the kernel interface of FUSE */


#define FUSE_MOUNT_VERSION 1

struct fuse_mount_data {
	int version;
	int fd;
};

#define FUSE_ROOT_INO 1

struct fuse_attr {
	unsigned short      mode;
	unsigned short      nlink;
	unsigned short      uid;
	unsigned short      gid;
	unsigned short      rdev;
	unsigned long long  size;
	unsigned long       blksize;
	unsigned long       blocks;
	unsigned long       atime;
	unsigned long       mtime;
	unsigned long       ctime;
};

enum fuse_opcode {
	FUSE_LOOKUP     = 1,
	FUSE_FORGET,
	FUSE_GETATTR,
	FUSE_READLINK,
	FUSE_GETDIR,
	FUSE_MKNOD,
};

/* Conservative buffer size for the client */
#define FUSE_MAX_IN 8192

struct fuse_lookup_out {
	unsigned long ino;
	struct fuse_attr attr;
};

struct fuse_getattr_out {
	struct fuse_attr attr;
};

struct fuse_getdir_out {
	int fd;
	void *file; /* Used by kernel only */
};

struct fuse_mknod_in {
	unsigned short mode;
	unsigned short rdev;
	char name[1];
};

struct fuse_mknod_out {
	unsigned long ino;
	struct fuse_attr attr;
};

struct fuse_in_header {
	int unique;
	enum fuse_opcode opcode;
	unsigned long ino;	
};

struct fuse_out_header {
	int unique;
	int result;
};

struct fuse_dirent {
	unsigned long ino;
	unsigned short namelen;
	unsigned char type;
	char name[256];
};

#define FUSE_NAME_OFFSET ((unsigned int) ((struct fuse_dirent *) 0)->name)
#define FUSE_DIRENT_ALIGN(x) (((x) + sizeof(long) - 1) & ~(sizeof(long) - 1))
#define FUSE_DIRENT_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
