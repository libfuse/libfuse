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
	unsigned int        mode;
	unsigned int        nlink;
	unsigned int        uid;
	unsigned int        gid;
	unsigned int        rdev;
	unsigned long long  size;
	unsigned long       blksize;
	unsigned long       blocks;
	unsigned long       atime;
	unsigned long       mtime;
	unsigned long       ctime;
};

#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_UTIME	(1 << 4)

enum fuse_opcode {
	FUSE_LOOKUP     = 1,
	FUSE_FORGET,
	FUSE_GETATTR,
	FUSE_SETATTR,
	FUSE_READLINK,
	FUSE_SYMLINK,
	FUSE_GETDIR,
	FUSE_MKNOD,
	FUSE_MKDIR,
	FUSE_UNLINK,
	FUSE_RMDIR,
	FUSE_RENAME,
	FUSE_LINK,
	FUSE_OPEN,
	FUSE_READ,
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

struct fuse_mkdir_in {
	unsigned short mode;
	char name[1];
};

struct fuse_rename_in {
	unsigned long newdir;
	char names[1];
};

struct fuse_link_in {
	unsigned long newdir;
	char name[1];
};

struct fuse_setattr_in {
	struct fuse_attr attr;
	unsigned int valid;
};

struct fuse_open_in {
	unsigned int flags;
};

struct fuse_read_in {
	unsigned long long offset;
	unsigned int size;
};

struct fuse_in_header {
	int unique;
	enum fuse_opcode opcode;
	unsigned long ino;
};

struct fuse_out_header {
	int unique;
	int error;
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
