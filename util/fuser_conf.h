/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt.
 */
#ifndef FUSER_CONF_H_
#define FUSER_CONF_H_

#include <sys/vfs.h>
#include <sys/stat.h>

extern int user_allow_other;
extern int mount_max;

void unescape(char *buf);

#ifdef GETMNTENT_NEEDS_UNESCAPING
#include <stdio.h>
#include <mntent.h>

static inline struct mntent *GETMNTENT(FILE *stream)
{
	struct mntent *entp = getmntent(stream);

	if (entp != NULL) {
		unescape(entp->mnt_fsname);
		unescape(entp->mnt_dir);
		unescape(entp->mnt_type);
		unescape(entp->mnt_opts);
	}
	return entp;
}
#else
#define GETMNTENT getmntent
#endif // GETMNTENT_NEEDS_UNESCAPING

int count_fuse_fs(const char *progname);

void read_conf(const char *progname);

void drop_privs(void);
void restore_privs(void);

int check_nonroot_mount_count(const char *progname);

int check_nonroot_dir_access(const char *progname, const char *origmnt,
			     const char *mnt, const struct stat *stbuf);

int check_nonroot_fstype(const char *progname, const struct statfs *fs_buf);

struct mount_flags {
	const char *opt;
	unsigned long flag;
	int on;
	int safe;
};

extern const struct mount_flags mount_flags[];

#endif /* FUSER_CONF_H_ */
