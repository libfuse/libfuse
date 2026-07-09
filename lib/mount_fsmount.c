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
 *
 * Syscall number definitions and wrapper functions for new mount API.
 * glibc < 2.36 (e.g., Rocky 9's glibc 2.34) lacks these wrappers, so we
 * provide our own using direct syscall() invocations to access the kernel APIs.
 */
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif
#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif
#if !__GLIBC_PREREQ(2, 36)
static inline int fsopen(const char *fsname, unsigned int flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}

static inline int fsconfig(int fd, unsigned int cmd, const char *key,
			   const void *value, int aux)
{
	return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

static inline int fsmount(int fd, unsigned int flags, unsigned int ms_flags)
{
	return syscall(__NR_fsmount, fd, flags, ms_flags);
}

static inline int move_mount(int from_dfd, const char *from_pathname,
			     int to_dfd, const char *to_pathname,
			     unsigned int flags)
{
	return syscall(__NR_move_mount, from_dfd, from_pathname,
		       to_dfd, to_pathname, flags);
}
#endif /* glibc < 2.36 */

/*
 * Mount attribute flags and fsconfig commands - from linux/mount.h
 * Define missing constants for Rocky 9 compatibility
 */
#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x00000001
#endif

#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC 0x00000001
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1
#endif

#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6
#endif

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002
#endif

#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV 0x00000004
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010
#endif

#ifndef MOUNT_ATTR_NOSYMFOLLOW
#define MOUNT_ATTR_NOSYMFOLLOW  0x00200000
#endif

/* Must be called after set_fsconfig_ms_flags */
unsigned long ms_flags_to_mount_attrs(unsigned long ms_flags,
				      unsigned int *mount_attrs)
{
	int i;

	*mount_attrs = 0;

	for (i = 0; mount_flags[i].opt != NULL && ms_flags != 0; i++) {
		/* Only process mount attributes (mount_attr != 0) with on==1 */
		if (!mount_flags[i].mount_attr || !mount_flags[i].on)
			continue;

		if (ms_flags & mount_flags[i].flag) {
			*mount_attrs |= mount_flags[i].mount_attr;
			ms_flags &= ~mount_flags[i].flag;
		}
	}

	return ms_flags;
}

void log_fsconfig_kmsg(int fd)
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

/* Must be called before ms_flags_to_mount_attrs */
int set_fsconfig_ms_flags(int fsfd, unsigned long *ms_flags)
{
	unsigned long flags = *ms_flags;
	int ret;
	int i;

	for (i = 0; mount_flags[i].opt != NULL && flags != 0; i++) {
		if (!mount_flags[i].is_fsconfig || !mount_flags[i].on)
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

		/*
		 * Only consume the bit if no fsmount mount-attr leg is
		 * also pending for this option. Otherwise leave it for
		 * ms_flags_to_mount_attrs() to apply via fsmount().
		 */
		if (!mount_flags[i].mount_attr)
			flags &= ~mount_flags[i].flag;
	}

	*ms_flags = flags;
	return 0;
}

int apply_fsconfig_opt_fd(int fsfd, const char *value)
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

int apply_fsconfig_opt_string(int fsfd, const char *key, const char *value)
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
 * @fsfd fsopen fd
 * @opt name of filesystem mount flag option
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
 * @fsfd fsopen fd
 * @opt filesystem mount option, may be modified
 * Returns 0 on success, negative error code on failure.
 */
static int apply_opt_key_value(int fsfd, char *opt)
{
	char *eq;
	const char *key;
	char *value;
	size_t len;

	eq = strchr(opt, '=');
	if (!eq)
		return apply_opt_flag(fsfd, opt);

	*eq = '\0';
	key = opt;
	value = eq + 1;

	/*
	 * Strip enclosing double quotes from the value, e.g.
	 * context="system_u:object_r:root_t:s0". The old mount(2) path relied
	 * on the kernel (selinux_sb_eat_lsm_opts) to strip these, but
	 * fsconfig() passes the value through as-is.
	 */
	len = strlen(value);
	if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
		value[len - 1] = '\0';
		value++;
	}

	if (strcmp(key, "fd") == 0)
		return apply_fsconfig_opt_fd(fsfd, value);

	return apply_fsconfig_opt_string(fsfd, key, value);
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
 * Example: parsing  rw,fd=7,context="u:r:t,s0"
 *
 *   call 3 -> "context=\"u:r:t,s0\""   (comma inside quotes kept, not split)
 *   call 4 -> NULL
 */
static char *next_mount_opt(char **cursor)
{
	char *opt_start;
	char *scan;
	int in_quote = 0;

	if (!*cursor || !**cursor)
		return NULL;

	opt_start = *cursor;
	for (scan = opt_start; *scan; scan++) {
		if (*scan == '"')
			in_quote = !in_quote;
		else if (*scan == ',' && !in_quote)
			break;
	}

	if (*scan == ',') {
		*scan = '\0';
		*cursor = scan + 1;
	} else {
		*cursor = scan;
	}

	return opt_start;
}

int apply_fsconfig_mount_opts(int fsfd, const char *opts)
{
	char *opts_copy;
	char *pos;
	char *opt;
	int res;

	if (!opts || !*opts)
		return 0;

	opts_copy = strdup(opts);
	if (!opts_copy) {
		fprintf(stderr, "fuse: failed to allocate memory\n");
		return -ENOMEM;
	}

	pos = opts_copy;
	while ((opt = next_mount_opt(&pos)) != NULL) {
		if (!*opt)
			continue;
		/*
		 * Skip mount attributes, they're handled by fsmount()
		 * not fsconfig().
		 *
		 * These string options (nosuid, nodev, etc.) are reconstructed
		 * from MS_* flags by get_mtab_flag_opts() in lib/mount.c and
		 * get_mtab_opts() in util/fusermount.c. Both the library path
		 * (via fuse_kern_mount_get_base_mtab_opts) and fusermount3 path
		 * rebuild these strings from the flags bitmask and pass them in
		 * mtab_opts. They must be filtered here because they are mount
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
	}

	free(opts_copy);
	return 0;
}

int fuse_kern_fsmount(const char *mnt, int dest_mnt_fd, unsigned long flags,
		      int blkdev, const char *fsname, const char *subtype,
		      const char *source_dev, const char *kernel_opts,
		      const char *mtab_opts)
{
	char *type = NULL;
	char *source = NULL;
	int fsfd = -1;
	int mountfd = -1;
	int err, res;
	unsigned int mount_attrs;

	/* Build type and source strings */
	type = fuse_mnt_build_type(blkdev, subtype);
	source = fuse_mnt_build_source(fsname, subtype, source_dev, 0);
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
	res = set_fsconfig_ms_flags(fsfd, &flags);
	if (res != 0)
		goto out_free;

	/* Apply kernel options */
	err = apply_fsconfig_mount_opts(fsfd, kernel_opts);
	if (err < 0) {
		log_fsconfig_kmsg(fsfd);
		fprintf(stderr,
			"fuse: failed to apply kernel options '%s'\n",
			kernel_opts);
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
		errno = ENOTSUP;
		goto out_free;
	}

	/* Create mount object with mount attributes */
	mountfd = fsmount(fsfd, FSMOUNT_CLOEXEC, mount_attrs);
	if (mountfd == -1) {
		err = -errno;
		log_fsconfig_kmsg(fsfd);
		fprintf(stderr, "fuse: fsmount failed: %s\n",
			strerror(errno));
		goto out_free;
	}

	close(fsfd);
	fsfd = -1;

	if (dest_mnt_fd >= 0)
		res = move_mount(mountfd, "", dest_mnt_fd, "",
				 MOVE_MOUNT_F_EMPTY_PATH |
					 MOVE_MOUNT_T_EMPTY_PATH);
	else
		res = move_mount(mountfd, "", AT_FDCWD, mnt,
				 MOVE_MOUNT_F_EMPTY_PATH);
	if (res == -1) {
		err = -errno;
		fprintf(stderr, "fuse: move_mount failed: %s\n",
			strerror(errno));
		goto out_close_mntfd;
	}

	err = fuse_mnt_add_mount_helper(mnt, source, type, mtab_opts);
	if (err == -1)
		goto out_umount;

	close(mountfd);
	free(source);
	free(type);
	return 0;

out_umount:
	{
		/* race free umount */
		char fd_path[64];

		snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mountfd);
		if (umount2(fd_path, MNT_DETACH) == -1 && errno != EINVAL) {
			fprintf(stderr,
				"fuse: cleanup umount failed: %s\n",
				strerror(errno));
		}
	}
out_close_mntfd:
	if (mountfd != -1)
		close(mountfd);
out_free:
	free(source);
	free(type);
	if (fsfd != -1)
		close(fsfd);
	errno = -err;
	return -1;
}

