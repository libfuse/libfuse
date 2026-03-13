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

/**
 * Discover if there is a fuse service socket for the given fuse subtype.
 *
 * @param subtype subtype of a fuse filesystem type (e.g. Y from
 *                mount_service_subtype)
 * @return true if available, false if not
 */
bool mount_service_present(const char *subtype);

#endif /* MOUNT_SERVICE_H_ */
