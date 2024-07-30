/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2023 Giulio Benetti <giulio.benetti@benettiengineering.com>

  Logging API.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LICENSE
*/

#ifndef FUSE_MOUNT_COMPAT_H_
#define FUSE_MOUNT_COMPAT_H_

#include <sys/mount.h>

/* Some libc don't define MS_*, so define them manually
 * (values taken from https://elixir.bootlin.com/linux/v6.10/source/include/uapi/linux/mount.h#L13 on)
 */
#ifndef MS_DIRSYNC
#define MS_DIRSYNC	128
#endif

#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW 256
#endif

#ifndef MS_REC
#define MS_REC		16384
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE	(1<<18)
#endif

#ifndef MS_LAZYTIME
#define MS_LAZYTIME	(1<<25)
#endif

#ifndef UMOUNT_DETACH
#define UMOUNT_DETACH	0x00000002	/* Just detach from the tree */
#endif
#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW	0x00000008	/* Don't follow symlink on umount */
#endif
#ifndef UMOUNT_UNUSED
#define UMOUNT_UNUSED	0x80000000	/* Flag guaranteed to be unused */
#endif

#endif /* FUSE_MOUNT_COMPAT_H_ */
