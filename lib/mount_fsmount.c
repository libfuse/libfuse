/*
 *  FUSE: Filesystem in Userspace
 *  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *                2026 Bernd Schubert <bernd@bsbernd.com>
 *
 * New Linux mount API (fsopen/fsconfig/fsmount/move_mount) support.
 *
 *  This program can be distributed under the terms of the GNU LGPLv2.
 *  See the file LGPL2.txt.
 */

#define _GNU_SOURCE

#include "fuse_config.h"
#include "fuse_misc.h"
#include "mount_util.h"
#include "mount_i_linux.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/syscall.h>

/*
 * Mount attribute flags for fsmount() - from linux/mount.h
 * This file is only compiled conditionally when support for the new
 * mount API is detected - only flags that were not in the initial linux
 * commit introducing that API are defined here.
 */
#ifndef MOUNT_ATTR_NOSYMFOLLOW
#define MOUNT_ATTR_NOSYMFOLLOW  0x00200000
#endif

/*
 * Convert MS_* mount flags to MOUNT_ATTR_* mount attributes.
 * These flags are passed to fsmount(), not fsconfig().
 * Mount attributes control mount-point level behavior.
 *
 * @attrs MOUNT_ATTR flags, built from MS_ flags
 * @return remaining flags
 */
static int ms_flags_to_mount_attrs(unsigned long flags,
				   unsigned long *attrs)
{
	int i;

	*attrs = 0;

	for (i = 0; mount_flags[i].opt != NULL && flags != 0; i++) {
		/* Only process mount attributes (mount_attr != 0) with on==1 */
		if (!mount_flags[i].mount_attr || !mount_flags[i].on)
			continue;

		if (flags & mount_flags[i].flag) {
			*attrs |= mount_flags[i].mount_attr;
			flags &= ~mount_flags[i].flag;
		}
	}

	return flags;
}

/*
 * Read and print kernel error messages from fsopen fd.
 * The kernel can provide detailed error/warning/info messages via the
 * filesystem context fd that are more informative than strerror(errno).
 */
static void log_fsconfig_kmsg(int fd)
{
	char buf[4096];
	int err, sz = 0;

	err = errno;

	while ((sz = read(fd, buf, sizeof(buf) - 1)) != -1) {
		if (sz <= 0)
			continue;
		if (buf[sz - 1] == '\n')
			buf[--sz] = '\0';
		else
			buf[sz] = '\0';

		if (!*buf)
			continue;

		switch (buf[0]) {
		case 'e':
			fprintf(stderr, " Error: %s\n", buf + 2);
			break;
		case 'w':
			fprintf(stderr, " Warning: %s\n", buf + 2);
			break;
		case 'i':
			fprintf(stderr, " Info: %s\n", buf + 2);
			break;
		default:
			fprintf(stderr, " %s\n", buf);
			break;
		}
	}

	errno = err;
}

/*
 * Apply VFS superblock (fsconfig) flags to the filesystem context.
 * Only handles flags that are filesystem parameters (ro, sync, dirsync).
 * Mount attributes (nosuid, nodev, etc.) are handled separately via fsmount().
 *
 * @ms_flags flags to set, outvalue are the remaining flags
 * @return 0 on success, negative error code on failure
 */
static int set_ms_flags(int fsfd, unsigned long *ms_flags)
{
	int ret, flags = *ms_flags;
	int i;

	for (i = 0; mount_flags[i].opt != NULL && flags != 0; i++) {
		/* Only process fsconfig flags (mount_attr == 0) with on==1 */
		if (mount_flags[i].mount_attr || !mount_flags[i].on)
			continue;

		if (!(flags & mount_flags[i].flag))
			continue;

		ret = fsconfig(fsfd, FSCONFIG_SET_FLAG, mount_flags[i].opt, NULL, 0);
		if (ret) {
			int save_errno = errno;

			fprintf(stderr, "fuse: set fsconfig %s option failed: %s\n",
				mount_flags[i].opt, strerror(save_errno));
			log_fsconfig_kmsg(fsfd);

			return -save_errno;
		}
		flags &= ~mount_flags[i].flag;
	}

	*ms_flags = flags;
	return 0;
}

/*
 * Apply the "fd" parameter via fsconfig
 *
 * Special handler for the "fd" mount option. Note that despite the name,
 * the fd parameter is passed as a u32 string value, not as a file descriptor
 * to pass to the kernel. Uses FSCONFIG_SET_STRING rather than FSCONFIG_SET_FD.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int apply_opt_fd(int fsfd, const char *value)
{
	int res;

	/* The fd parameter is a u32 value, not a file descriptor to pass */
	res = fsconfig(fsfd, FSCONFIG_SET_STRING, "fd", value, 0);
	if (res == -1) {
		int save_errno = errno;

		fprintf(stderr, "fuse: fsconfig SET_STRING fd=%s failed:",
			value);
		log_fsconfig_kmsg(fsfd);
		return -save_errno;
	}
	return 0;
}

/*
 * Apply a key=value string option via fsconfig
 *
 * Applies a mount option that consists of a key-value pair (e.g., "rootmode=40000").
 * Uses FSCONFIG_SET_STRING to pass the key and value to the filesystem configuration.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int apply_opt_string(int fsfd, const char *key, const char *value)
{
	int res, save_errno;

	res = fsconfig(fsfd, FSCONFIG_SET_STRING, key, value, 0);
	save_errno = errno;
	if (res == -1) {
		fprintf(stderr, "fuse: fsconfig SET_STRING %s=%s failed: ",
			key, value);
		log_fsconfig_kmsg(fsfd);
		return -save_errno;
	}
	return 0;
}

/*
 * Apply a boolean flag option via fsconfig
 *
 * Applies a mount option that is a simple flag without a value (e.g., "rw").
 * Uses FSCONFIG_SET_FLAG to set the flag in the filesystem configuration.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int apply_opt_flag(int fsfd, const char *opt)
{
	int res;

	res = fsconfig(fsfd, FSCONFIG_SET_FLAG, opt, NULL, 0);
	if (res == -1) {
		int save_errno = errno;

		fprintf(stderr, "fuse: fsconfig SET_FLAG %s failed:", opt);
		log_fsconfig_kmsg(fsfd);
		return -save_errno;
	}
	return 0;
}


/*
 * Parse and apply a single mount option via fsconfig
 *
 * Parses a mount option which can be either:
 * - A key=value pair (e.g., "rootmode=40000")
 * - A flag without a value (e.g., "rw")
 *
 * Special handling for the "fd" parameter which is treated as a string
 * value rather than a file descriptor to pass.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int apply_opt_key_value(int fsfd, char *opt)
{
	char *eq;
	const char *key;
	const char *value;

	eq = strchr(opt, '=');
	if (!eq)
		return apply_opt_flag(fsfd, opt);

	*eq = '\0';
	key = opt;
	value = eq + 1;

	if (strcmp(key, "fd") == 0)
		return apply_opt_fd(fsfd, value);

	return apply_opt_string(fsfd, key, value);
}

/*
 * Check if an option is a mount attribute (handled by fsmount, not fsconfig)
 * Uses the mount_flags table to determine if an option is a mount attribute.
 */
static int is_mount_attr_opt(const char *opt)
{
	int i;

	for (i = 0; mount_flags[i].opt != NULL; i++) {
		if (strcmp(mount_flags[i].opt, opt) == 0)
			return mount_flags[i].mount_attr != 0;
	}

	/* Unknown option, assume it's not a mount attribute */
	return 0;
}

/**
 * Check if an option is a mount table option (not passed to fsconfig)
 */
static int is_mtab_only_opt(const char *opt)
{
	/* These options are for /run/mount/utab only, not for the kernel */
	return strncmp(opt, "user=", 5) == 0 ||
	       strcmp(opt, "rw") == 0;
}

/*
 * Parse kernel options string and apply via fsconfig
 * Options are comma-separated key=value pairs
 */
static int apply_mount_opts(int fsfd, const char *opts)
{
	char *opts_copy;
	char *opt;
	char *saveptr;
	int res;

	if (!opts || !*opts)
		return 0;

	opts_copy = strdup(opts);
	if (!opts_copy) {
		fprintf(stderr, "fuse: failed to allocate memory\n");
		return -ENOMEM;
	}

	opt = strtok_r(opts_copy, ",", &saveptr);
	while (opt) {
		/*
		 * Skip mount attributes, they're handled by fsmount()
		 * not fsconfig().
		 *
		 * These string options (nosuid, nodev, etc.) are reconstructed
		 * Skip mtab-only options - they're for /run/mount/utab, not kernel
		 * from MS_* flags by get_mnt_flag_opts() in lib/mount.c and
		 * get_mnt_opts() in util/fusermount.c. Both the library path
		 * (via fuse_kern_mount_get_base_mnt_opts) and fusermount3 path
		 * rebuild these strings from the flags bitmask and pass them in
		 * mnt_opts. They must be filtered here because they are mount
		 * attributes (passed to fsmount via MOUNT_ATTR_*), not
		 * filesystem parameters (which would be passed to fsconfig).
		 *
		 * Also skip mtab-only options - they're for /run/mount/utab, not kernel
		 */
		if (!is_mount_attr_opt(opt) && !is_mtab_only_opt(opt)) {
			res = apply_opt_key_value(fsfd, opt);
			if (res < 0) {
				free(opts_copy);
				return res;
			}
		}
		opt = strtok_r(NULL, ",", &saveptr);
	}

	free(opts_copy);
	return 0;
}


int fuse_kern_fsmount(const char *mnt, unsigned long flags, int blkdev,
		      const char *fsname, const char *subtype,
		      const char *source_dev, const char *kernel_opts,
		      const char *mnt_opts)
{
	char *type = NULL;
	char *source = NULL;
	int fsfd = -1;
	int mntfd = -1;
	int err, res;
	unsigned long mount_attrs;

	/* Build type and source strings */
	type = fuse_mnt_build_type(blkdev, subtype);
	source = fuse_mnt_build_source(fsname, subtype, source_dev);
	err = -ENOMEM;
	if (!type || !source) {
		fprintf(stderr, "fuse: failed to allocate memory\n");
		goto out_free;
	}

	/* Try to open filesystem context */
	fsfd = fsopen(type, FSOPEN_CLOEXEC);
	if (fsfd == -1) {
		if (errno != EPERM)
			fprintf(stderr, "fuse: fsopen(%s) failed: %s\n", type,
				strerror(errno));
		goto out_free;
	}

	/* Configure subtype */
	if (subtype) {
		res = fsconfig(fsfd, FSCONFIG_SET_STRING, "subtype",
			       subtype, 0);
		if (res) {
			err = -errno;
			log_fsconfig_kmsg(fsfd);
			fprintf(stderr, "fuse: fsconfig subtype failed: %s\n",
				strerror(-err));
			goto out_free;
		}
	}

	/* Configure source */
	res = fsconfig(fsfd, FSCONFIG_SET_STRING, "source", source, 0);
	if (res == -1) {
		err = -errno;
		log_fsconfig_kmsg(fsfd);
		fprintf(stderr, "fuse: fsconfig source failed: %s\n",
			strerror(errno));
		goto out_free;
	}

	/* Apply VFS superblock (fsconfig) flags (ro, sync, dirsync) */
	res = set_ms_flags(fsfd, &flags);
	if (res != 0)
		goto out_free;

	/* Apply kernel options */
	err = apply_mount_opts(fsfd, kernel_opts);
	if (err < 0) {
		log_fsconfig_kmsg(fsfd);
		fprintf(stderr,
			"fuse: failed to apply kernel options '%s'\n",
			kernel_opts);
		goto out_free;
	}

	/* Apply additional mount options */
	err = apply_mount_opts(fsfd, mnt_opts);
	if (err < 0) {
		log_fsconfig_kmsg(fsfd);
		fprintf(stderr,
			"fuse: failed to apply additional mount options '%s'\n",
			mnt_opts);
		goto out_free;
	}

	/* Create the filesystem instance */
	res = fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (res == -1) {
		err = -errno;
		log_fsconfig_kmsg(fsfd);
		fprintf(stderr, "fuse: fsconfig CREATE failed: %s\n",
			strerror(errno));
		goto out_free;
	}

	/* Convert MS_* flags to MOUNT_ATTR_* for fsmount() */
	flags = ms_flags_to_mount_attrs(flags, &mount_attrs);
	if (flags != 0) {
		/* unsupported flags found, either fsconfig or mount attr flags  */
		//fuse_log(FUSE_LOG_ERR, "Unsupported mount flags found: %d", flags);
		errno = -ENOTSUP;
		return -1;
	}

	/* Create mount object with mount attributes */
	mntfd = fsmount(fsfd, FSMOUNT_CLOEXEC, mount_attrs);
	if (mntfd == -1) {
		err = -errno;
		log_fsconfig_kmsg(fsfd);
		fprintf(stderr, "fuse: fsmount failed: %s\n",
			strerror(errno));
		goto out_free;
	}

	close(fsfd);
	fsfd = -1;

	/* Attach to mount point */
	if (move_mount(mntfd, "", AT_FDCWD, mnt, MOVE_MOUNT_F_EMPTY_PATH) ==
	    -1) {
		err = -errno;
		fprintf(stderr, "fuse: move_mount failed: %s\n",
			strerror(errno));
		goto out_close_mntfd;
	}

	err = fuse_mnt_add_mount_helper(mnt, source, type, mnt_opts);
	if (err == -1)
		goto out_umount;

	close(mntfd);
	free(source);
	free(type);
	return 0;

out_umount:
	{
		/* race free umount */
		char fd_path[64];

		snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mntfd);
		if (umount2(fd_path, MNT_DETACH) == -1 && errno != EINVAL) {
			fprintf(stderr,
				"fuse: cleanup umount failed: %s\n",
				strerror(errno));
		}
	}
out_close_mntfd:
	if (mntfd != -1)
		close(mntfd);
out_free:
	free(source);
	free(type);
	if (fsfd != -1)
		close(fsfd);
	errno = -err;
	return -1;
}

