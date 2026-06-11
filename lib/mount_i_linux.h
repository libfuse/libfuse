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
#include <linux/mount.h>

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

int fuse_kern_mount_get_base_mtab_opts(const struct mount_opts *mo,
				       char **mtab_optsp);

/**
 * Mount using the new Linux mount API (fsopen/fsconfig/fsmount/move_mount)
 * @mnt: mountpoint, used for the /etc/mtab record (and as the move_mount
 *       target when @mnt_fd is -1)
 * @dest_mnt_fd: pre-resolved mountpoint fd to mount
 *          or -1 to resolve @mnt by path. A pinned fd closes the suid
 *          fusermount sync-init TOCTOU; in-process direct-mount callers pass -1.
 * @flags: mount flags (MS_NOSUID, MS_NODEV, etc.)
 * @blkdev: 1 for fuseblk, 0 for fuse
 * @fsname: filesystem name (or NULL)
 * @subtype: filesystem subtype (or NULL)
 * @source_dev: device name for building source string
 * @kernel_opts: kernel mount options applied via fsconfig()
 * @mtab_opts:  options recorded in /etc/mtab (or /run/mount/utab) via
 *              fuse_mnt_add_mount_helper(). May overlap with @kernel_opts
 *              because /etc/mtab is expected to display kernel-visible
 *              options; the overlap is filtered before fsconfig where
 *              needed and is idempotent at the kernel.
 *
 * Returns: 0 on success, -1 on failure with errno set
 */
int fuse_kern_fsmount(const char *mnt, int mnt_fd, unsigned long flags,
		      int blkdev, const char *fsname, const char *subtype,
		      const char *source_dev, const char *kernel_opts,
		      const char *mtab_opts);

int fuse_kern_fsmount_mo(const char *mnt, const struct mount_opts *mo,
			 const char *mtab_opts);
int mount_fusermount_obtain_fd(const char *mountpoint,
			       struct mount_opts *mo,
			       const char *opts, int *sock_fd_out,
			       pid_t *pid_out);

int fuse_fusermount_proceed_mnt(int sock_fd);

/**
 * Convert MS_* mount flags to MOUNT_ATTR_* mount attributes.
 * These flags are passed to fsmount(), not fsconfig().
 * Mount attributes control mount-point level behavior.
 * To called after set_ms_flags() which consumes the fsconfig flags.
 *
 * @mount_attrs MOUNT_ATTR flags, built from MS_ flags
 * @return remaining MS_* flags
 */
unsigned long ms_flags_to_mount_attrs(unsigned long ms_flags,
				      unsigned int *mount_attrs);

/**
 * Read and print kernel error messages from fsopen fd.
 * The kernel can provide detailed error/warning/info messages via the
 * filesystem context fd that are more informative than strerror(errno).
 *
 * @fd fsopen fd
 */
void log_fsconfig_kmsg(int fd);

/**
 * Apply VFS superblock (fsconfig) flags to the filesystem context.
 * Handles the fsconfig leg of every entry whose is_fsconfig is set
 * (ro, rw, sync, async, dirsync). Mount attributes (nosuid, nodev, etc.)
 * are handled separately via fsmount().
 *
 * Entries that have *both* legs (ro/rw) leave the MS_ bit in *ms_flags
 * so that ms_flags_to_mount_attrs() can also pick them up.
 *
 * @fsfd fsopen fd
 * @ms_flags flags to set, outvalue are the remaining flags
 * @return 0 on success, negative error code on failure
 */
int set_fsconfig_ms_flags(int fsfd, unsigned long *ms_flags);

/**
 * Apply the "fd" parameter via fsconfig
 *
 * Special handler for the "fd" mount option. Note that despite the name,
 * the fd parameter is passed as a u32 string value, not as a file descriptor
 * to pass to the kernel. Uses FSCONFIG_SET_STRING rather than FSCONFIG_SET_FD.
 *
 * @fsfd fsopen fd
 * @value fd number of /dev/fuse, as a string
 * Returns 0 on success, negative error code on failure.
 */
int apply_fsconfig_opt_fd(int fsfd, const char *value);

/**
 * Apply a key=value string option via fsconfig
 *
 * Applies a mount option that consists of a key-value pair (e.g., "rootmode=40000").
 * Uses FSCONFIG_SET_STRING to pass the key and value to the filesystem configuration.
 *
 * @fsfd fsopen fd
 * @key name of filesystem mount option
 * @value value of mount option
 * Returns 0 on success, negative error code on failure.
 */
int apply_fsconfig_opt_string(int fsfd, const char *key, const char *value);

/**
 * Parse kernel options string and apply via fsconfig
 * Options are comma-separated key=value pairs
 *
 * @fsfd fsopen fd
 * @opt filesystem mount option string
 * Returns 0 on success, negative error code on failure.
 */
int apply_fsconfig_mount_opts(int fsfd, const char *opts);

#endif /* FUSE_MOUNT_I_LINUX_H_ */
