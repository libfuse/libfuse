/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/
#ifndef MOUNT_SERVICE_H_
#define MOUNT_SERVICE_H_

/**
 * Connect to a fuse service socket and try to mount the filesystem as
 * specified with the CLI arguments.
 *
 * @argc argument count
 * @argv vector of argument strings
 * @return EXIT_SUCCESS for success, EXIT_FAILURE if mount fails
 */
int mount_service_main(int argc, char *argv[]);

/**
 * Return the fuse filesystem subtype from a full fuse filesystem type
 * specification.  IOWs, fuse.Y -> Y; fuseblk.Z -> Z; or A -> A.  The returned
 * pointer is within the caller's string.
 *
 * @param fstype full fuse filesystem type
 * @return fuse subtype
 */
const char *mount_service_subtype(const char *fstype);

#endif /* MOUNT_SERVICE_H_ */
