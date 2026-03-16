/*
 *  FUSE: Filesystem in Userspace
 *  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *                2026 Bernd Schubert <bernd@bsbernd.com>
 *
 *  This program can be distributed under the terms of the GNU LGPLv2.
 *  See the file LGPL2.txt
 */

#ifndef FUSE_MOUNT_I_LINUX_H_
#define FUSE_MOUNT_I_LINUX_H_

/* Forward declaration for fuse_args */
struct fuse_args;

/* Mount options structure */
struct mount_opts {
	int allow_other;
	int flags;
	int auto_unmount;
	int blkdev;
	char *fsname;
	char *subtype;
	char *subtype_opt;
	char *mtab_opts;
	char *fusermount_opts;
	char *kernel_opts;
	unsigned int max_read;
};


#endif /* FUSE_MOUNT_I_LINUX_H_ */
