/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/* This file defines the kernel interface of FUSE */

/** Version number of this interface */
#define FUSE_KERNEL_VERSION 4

/** Minor version number of this interface */
#define FUSE_KERNEL_MINOR_VERSION 2

/** The node ID of the root inode */
#define FUSE_ROOT_ID 1

/** Opening this will yield a new control file */
#define FUSE_DEV "/dev/fuse"

/** The file containing the version in the form MAJOR.MINOR */
#define FUSE_VERSION_FILE "/sys/fs/fuse/version"

struct fuse_attr {
	unsigned long       ino;
	unsigned int        mode;
	unsigned int        nlink;
	unsigned int        uid;
	unsigned int        gid;
	unsigned int        rdev;
	unsigned long long  size;
	unsigned long       blocks;
	unsigned long       atime;
	unsigned long       atimensec;
	unsigned long       mtime;
	unsigned long       mtimensec;
	unsigned long       ctime;
	unsigned long       ctimensec;
};

struct fuse_kstatfs {
	unsigned int        bsize;
	unsigned long long  blocks;
	unsigned long long  bfree;
	unsigned long long  bavail;
	unsigned long long  files;
	unsigned long long  ffree;
	unsigned int        namelen;
};

#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_ATIME	(1 << 4)
#define FATTR_MTIME	(1 << 5)
#define FATTR_CTIME	(1 << 6)

enum fuse_opcode {
	FUSE_LOOKUP	   = 1,
	FUSE_FORGET	   = 2,  /* no reply */
	FUSE_GETATTR	   = 3,
	FUSE_SETATTR	   = 4,
	FUSE_READLINK	   = 5,
	FUSE_SYMLINK	   = 6,
	FUSE_GETDIR	   = 7,
	FUSE_MKNOD	   = 8,
	FUSE_MKDIR	   = 9,
	FUSE_UNLINK	   = 10,
	FUSE_RMDIR	   = 11,
	FUSE_RENAME	   = 12,
	FUSE_LINK	   = 13,
	FUSE_OPEN	   = 14,
	FUSE_READ	   = 15,
	FUSE_WRITE	   = 16,
	FUSE_STATFS	   = 17,
	FUSE_RELEASE       = 18, /* no reply */
	FUSE_INVALIDATE    = 19, /* user initiated */
	FUSE_FSYNC         = 20,
	FUSE_SETXATTR      = 21,
	FUSE_GETXATTR      = 22,
	FUSE_LISTXATTR     = 23,
	FUSE_REMOVEXATTR   = 24,
	FUSE_FLUSH         = 25,
};

/* Conservative buffer size for the client */
#define FUSE_MAX_IN 8192

#define FUSE_NAME_MAX 1024
#define FUSE_SYMLINK_MAX 4096
#define FUSE_XATTR_SIZE_MAX 4096

struct fuse_entry_out {
	unsigned long nodeid;      /* Inode ID */
	unsigned long generation;  /* Inode generation: nodeid:gen must
                                      be unique for the fs's lifetime */
	unsigned long entry_valid; /* Cache timeout for the name */
	unsigned long entry_valid_nsec;
	unsigned long attr_valid;  /* Cache timeout for the attributes */
	unsigned long attr_valid_nsec;
	struct fuse_attr attr;
};

struct fuse_forget_in {
	int version;
};

struct fuse_attr_out {
	unsigned long attr_valid;  /* Cache timeout for the attributes */
	unsigned long attr_valid_nsec;
	struct fuse_attr attr;
};

struct fuse_getdir_out {
	int fd;
};

struct fuse_mknod_in {
	unsigned int mode;
	unsigned int rdev;
};

struct fuse_mkdir_in {
	unsigned int mode;
};

struct fuse_rename_in {
	unsigned long newdir;
};

struct fuse_link_in {
	unsigned long newdir;
};

struct fuse_setattr_in {
	struct fuse_attr attr;
	unsigned int valid;
};

struct fuse_open_in {
	unsigned int flags;
};

struct fuse_open_out {
	unsigned long fh;
	unsigned int _open_flags;
};

struct fuse_release_in {
	unsigned long fh;
	unsigned int flags;
};

struct fuse_flush_in {
	unsigned long fh;
	unsigned int _nref;
};

struct fuse_read_in {
	unsigned long fh;
	unsigned long long offset;
	unsigned int size;
};

struct fuse_write_in {
	int writepage;
	unsigned long fh;
	unsigned long long offset;
	unsigned int size;
};

struct fuse_write_out {
	unsigned int size;
};

struct fuse_statfs_out {
	struct fuse_kstatfs st;
};

struct fuse_fsync_in {
	unsigned long fh;
	int datasync;
};

struct fuse_setxattr_in {
	unsigned int size;
	unsigned int flags;
};

struct fuse_getxattr_in {
	unsigned int size;
};

struct fuse_getxattr_out {
	unsigned int size;
};

struct fuse_in_header {
	int unique;
	enum fuse_opcode opcode;
	unsigned long nodeid;
	unsigned int uid;
	unsigned int gid;
	unsigned int pid;
};

struct fuse_out_header {
	int unique;
	int error;
};

struct fuse_user_header {
	int unique; /* zero */
	enum fuse_opcode opcode;
	unsigned long nodeid;
	unsigned long ino;  /* Needed only on 2.4.x where ino is also
			       used for inode lookup */
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
