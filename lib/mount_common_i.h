/*
 *  FUSE: Filesystem in Userspace
 *  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *                2026 Bernd Schubert <bernd@bsbernd.com>
 *
 *  This program can be distributed under the terms of the GNU LGPLv2.
 *  See the file LGPL2.txt
 */

#ifndef FUSE_MOUNT_COMMON_I_H_
#define FUSE_MOUNT_COMMON_I_H_

struct mount_opts;

char *fuse_mnt_build_source(const struct mount_opts *mo);
char *fuse_mnt_build_type(const struct mount_opts *mo);
char *fuse_mnt_kernel_opts(const struct mount_opts *mo);
unsigned int fuse_mnt_flags(const struct mount_opts *mo);


#endif /* FUSE_MOUNT_COMMON_I_H_ */
