/*
  FUSE fioclient: FUSE ioctl example client
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program tests the ioctl.c example file systsem.

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This program tests the ioctl.c example file systsem.
 *
 * Compile with:
 *
 *     gcc -Wall ioctl_client.c -o ioctl_client
 *
 * ## Source code ##
 * \include ioctl_client.c
 */

#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "ioctl.h"

const char *usage =
"Usage: fioclient FIOC_FILE [size]\n"
"\n"
"Get size if <size> is omitted, set size otherwise\n"
"\n";

int main(int argc, char **argv)
{
	size_t size;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "%s", usage);
		return 1;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (argc == 2) {
		if (ioctl(fd, FIOC_GET_SIZE, &size)) {
			perror("ioctl");
			return 1;
		}
		printf("%zu\n", size);
	} else {
		size = strtoul(argv[2], NULL, 0);
		if (ioctl(fd, FIOC_SET_SIZE, &size)) {
			perror("ioctl");
			return 1;
		}
	}
	return 0;
}
