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

/* Forward declaration for fuse_args */
struct fuse_args;
struct mount_opts;

/* Special return value for mount functions to indicate fallback to fusermount3 is needed */
#define FUSE_MOUNT_FALLBACK_NEEDED (-2)

/* Mount options management functions */
struct mount_opts *parse_mount_opts(struct fuse_args *args);
void destroy_mount_opts(struct mount_opts *mo);
unsigned int get_max_read(const struct mount_opts *o);


#endif /* FUSE_MOUNT_COMMON_I_H_ */
