/*
  libulockmgr: Userspace Lock Manager Library
  Copyright (C) 2006  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>

/**
 * Perform POSIX locking operation
 *
 * @param fd the file descriptor
 * @param cmd the locking command (F_GETFL, F_SETLK or F_SETLKW)
 * @param lock the lock parameters
 * @param owner the lock owner ID cookie
 * @param owner_len length of the lock owner ID cookie
 * @return 0 on success -errno on error
 */
int ulockmgr_op(int fd, int cmd, struct flock *lock, const void *owner,
		size_t owner_len);
