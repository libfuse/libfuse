/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2019 Bill Zissimopoulos <billziss at navimatics.com>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB
 */

#ifndef FUSE_TYPES_H_
#define FUSE_TYPES_H_

#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef uint64_t fuse_ino_t;

#define fuse_uid_t                      uid_t
#define fuse_gid_t                      gid_t
#define fuse_pid_t                      pid_t

#define fuse_dev_t                      dev_t
#define fuse_mode_t                     mode_t
#define fuse_nlink_t                    nlink_t
#define fuse_off_t                      off_t

#define fuse_fsblkcnt_t                 fsblkcnt_t
#define fuse_fsfilcnt_t                 fsfilcnt_t
#define fuse_blksize_t                  blksize_t
#define fuse_blkcnt_t                   blkcnt_t

#define fuse_timespec                   timespec

#define fuse_stat                       stat

#define fuse_statvfs                    statvfs

#define fuse_flock                      flock

#define fuse_iovec                      iovec

#endif /* FUSE_TYPES_H_ */
