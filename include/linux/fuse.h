/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/* This file defines the kernel interface of FUSE */

/** Version number of this interface */
#define FUSE_KERNEL_VERSION 2

/** Minor version number of this interface */
#define FUSE_KERNEL_MINOR_VERSION 2

/** The inode number of the root indode */
#define FUSE_ROOT_INO 1

/** Opening this will yield a new control file */
#define FUSE_DEV "/proc/fs/fuse/dev"

/** Data passed to mount */
struct fuse_mount_data {
	/** Must be set to FUSE_KERNEL_VERSION */
	int version;
	
	/** The control file descriptor */
	int fd;
	
	/** The file type of the root inode */
	unsigned int rootmode;

	/** The user ID of the user initiating this mount */
	unsigned int uid;
	
	/** FUSE specific mount flags */
	unsigned int flags;
};

/* FUSE mount flags: */

/** If the FUSE_DEFAULT_PERMISSIONS flag is given, the filesystem
module will check permissions based on the file mode.  Otherwise no
permission checking is done in the kernel */
#define FUSE_DEFAULT_PERMISSIONS (1 << 0)

/** If the FUSE_ALLOW_OTHER flag is given, then not only the user
    doing the mount will be allowed to access the filesystem */
#define FUSE_ALLOW_OTHER         (1 << 1)

/** If the FUSE_KERNEL_CACHE flag is given, then files will be cached
    until the INVALIDATE operation is invoked */
#define FUSE_KERNEL_CACHE        (1 << 2)

/** Allow FUSE to combine reads into 64k chunks.  This is useful if
    the filesystem is better at handling large chunks.  NOTE: in
    current implementation the raw throughput is worse for large reads
    than for small. */
#define FUSE_LARGE_READ          (1 << 3)

struct fuse_attr {
	unsigned int        mode;
	unsigned int        nlink;
	unsigned int        uid;
	unsigned int        gid;
	unsigned int        rdev;
	unsigned long long  size;
	unsigned long       _dummy;
	unsigned long       blocks;
	unsigned long       atime;
	unsigned long       mtime;
	unsigned long       ctime;
};

struct fuse_kstatfs {
    long block_size;
    long blocks;
    long blocks_free;
    long files;
    long files_free;
    long namelen;
};

#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_UTIME	(1 << 4)

enum fuse_opcode {
	FUSE_LOOKUP	= 1,
	FUSE_FORGET	= 2,  /* no reply */
	FUSE_GETATTR	= 3,
	FUSE_SETATTR	= 4,
	FUSE_READLINK	= 5,
	FUSE_SYMLINK	= 6,
	FUSE_GETDIR	= 7,
	FUSE_MKNOD	= 8,
	FUSE_MKDIR	= 9,
	FUSE_UNLINK	= 10,
	FUSE_RMDIR	= 11,
	FUSE_RENAME	= 12,
	FUSE_LINK	= 13,
	FUSE_OPEN	= 14,
	FUSE_READ	= 15,
	FUSE_WRITE	= 16,
	FUSE_STATFS	= 17,
	FUSE_RELEASE    = 18, /* no reply */
	FUSE_INVALIDATE = 19, /* user initiated */
	FUSE_FSYNC      = 20
};

/* Conservative buffer size for the client */
#define FUSE_MAX_IN 8192

struct fuse_lookup_out {
	unsigned long ino;
	struct fuse_attr attr;
};

struct fuse_forget_in {
	int version;
};

struct fuse_getattr_out {
	struct fuse_attr attr;
};

struct fuse_getdir_out {
	int fd;
	void *file; /* Used by kernel only */
};

/* FIXME: 2.6 needs 32 bit rdev */
struct fuse_mknod_in {
	unsigned short mode;
	unsigned short rdev;
};

struct fuse_mknod_out {
	unsigned long ino;
	struct fuse_attr attr;
};

struct fuse_mkdir_in {
	unsigned short mode;
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

struct fuse_setattr_out {
	struct fuse_attr attr;
};

struct fuse_open_in {
	unsigned int flags;
};

struct fuse_read_in {
	unsigned long long offset;
	unsigned int size;
};

struct fuse_write_in {
	unsigned long long offset;
	unsigned int size;
};

struct fuse_statfs_out {
	struct fuse_kstatfs st;
};

struct fuse_fsync_in {
	int datasync;
};

struct fuse_in_header {
	int unique;
	enum fuse_opcode opcode;
	unsigned long ino;
	unsigned int uid;
	unsigned int gid;
};

struct fuse_out_header {
	int unique;
	int error;
};

struct fuse_user_header {
	int unique; /* zero */
	enum fuse_opcode opcode;
	unsigned long ino;
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
