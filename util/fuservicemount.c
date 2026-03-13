/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/
/* This program does the mounting of FUSE filesystems that run in systemd */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fuse_config.h"
#include "mount_service.h"

static int check_service(const char *fstype)
{
	const char *subtype;

	if (!fstype) {
		fprintf(stderr,
			"fuservicemount: expected fs type for --check\n");
		return EXIT_FAILURE;
	}

	subtype = mount_service_subtype(fstype);
	return mount_service_present(subtype) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
	char *fstype = NULL;
	bool check = false;
	int i;

	/*
	 * If the user passes us exactly the args -t FSTYPE --check then
	 * we'll just check if there's a service for the FSTYPE fuse server.
	 */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--check")) {
			if (check) {
				check = false;
				break;
			}
			check = true;
		} else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
			if (fstype) {
				check = false;
				break;
			}
			fstype = argv[i + 1];
			i++;
		} else {
			check = false;
			break;
		}
	}
	if (check)
		return check_service(fstype);

	return mount_service_main(argc, argv);
}
