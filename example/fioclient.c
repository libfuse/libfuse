/*
  FUSE fioclient: FUSE ioctl example client
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall fioclient.c -o fioclient
*/

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "fioc.h"

const char *usage =
"Usage: fioclient FIOC_FILE [SIZE]\n"
"\n"
"       get size if SIZE is omitted, set size otherwise\n"
"\n";

int main(int argc, char **argv)
{
	size_t size;
	int fd;

	if (argc < 2) {
		goto usage;
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
		char *endp;

		size = strtoul(argv[2], &endp, 0);
		if (endp == argv[2] || *endp != '\0')
			goto usage;

		if (ioctl(fd, FIOC_SET_SIZE, &size)) {
			perror("ioctl");
			return 1;
		}
	}
	return 0;

usage:
	fprintf(stderr, usage);
	return 1;
}
