/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt.
*/

#ifndef FUSE_MOUNT_UTIL_H_
#define FUSE_MOUNT_UTIL_H_

#include <sys/types.h>
#include "mount_common_i.h" // IWYU pragma: keep

/* Mount flags mapping structure */
struct mount_flags {
	const char *opt;
	unsigned long flag;
	int on;
	int safe; /* used by fusermount */
	int is_mount_attr; /* 1 = mount attribute (fsmount), 0 = filesystem parameter (fsconfig) */
};
extern const struct mount_flags mount_flags[];

int fuse_mnt_add_mount(const char *progname, const char *fsname,
		       const char *mnt, const char *type, const char *opts);
int fuse_mnt_remove_mount(const char *progname, const char *mnt);
int fuse_mnt_umount(const char *progname, const char *abs_mnt,
		    const char *rel_mnt, int lazy);
char *fuse_mnt_resolve_path(const char *progname, const char *orig);
int fuse_mnt_check_fuseblk(void);
int fuse_mnt_parse_fuse_fd(const char *mountpoint);

/* Helper functions for mount operations */
const char *fuse_mnt_get_devname(void);
int fuse_mnt_add_mount_helper(const char *mnt, const char *source,
			       const char *type, const char *mnt_opts);

#endif /* FUSE_MOUNT_UTIL_H_ */
