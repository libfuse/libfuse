/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/


#define FUSE_MOUNT_VERSION 1

struct fuse_mount_data {
	int version;
	int fd;
};

enum fuse_opcode {
	FUSE_OPEN,
	FUSE_RELEASE,
};

struct fuse_inparam {
	enum fuse_opcode opcode;
	union {
		struct {
			unsigned int ino;
			int flags;
		} open;
	} u;
};

struct fuse_outparam {
	int result;
	union {
		struct {
			int fd;
		} open;
	} u;
};

struct fuse_param {
	int unique;
	int result;
	union {
		struct fuse_inparam i;
		struct fuse_outparam o;
	} u;
};


/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
