/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/
/* This program does the mounting of FUSE filesystems that run in systemd */

#define _GNU_SOURCE
#include "fuse_config.h"
#include "mount_service.h"

int main(int argc, char *argv[])
{
	return mount_service_main(argc, argv);
}
