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

#include <sys/mount.h>

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

int fuse_kern_mount_prepare(const char *mnt, struct mount_opts *mo);

int fuse_kern_mount_get_base_mnt_opts(const struct mount_opts *mo, char **mnt_optsp);

/**
 * Mount using the new Linux mount API (fsopen/fsconfig/fsmount/move_mount)
 * @mnt: mountpoint
 * @flags: mount flags (MS_NOSUID, MS_NODEV, etc.)
 * @blkdev: 1 for fuseblk, 0 for fuse
 * @fsname: filesystem name (or NULL)
 * @subtype: filesystem subtype (or NULL)
 * @source_dev: device name for building source string
 * @kernel_opts: kernel mount options string
 * @mnt_opts: additional mount options to pass to the kernel
 *
 * Returns: 0 on success, -1 on failure with errno set
 */
int fuse_kern_fsmount(const char *mnt, unsigned long flags, int blkdev,
		      const char *fsname, const char *subtype,
		      const char *source_dev, const char *kernel_opts,
		      const char *mnt_opts);

int fuse_kern_fsmount_mo(const char *mnt, const struct mount_opts *mo,
			 const char *mnt_opts);
int mount_fusermount_obtain_fd(const char *mountpoint,
			       struct mount_opts *mo,
			       const char *opts, int *sock_fd_out,
			       pid_t *pid_out);

int fuse_fusermount_proceed_mnt(int sock_fd);

#endif /* FUSE_MOUNT_I_LINUX_H_ */
