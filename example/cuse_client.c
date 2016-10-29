/*
  FUSE fioclient: FUSE ioctl example client
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This program tests the cuse.c example file system.
 *
 * Example usage (assuming that /dev/foobar is a CUSE device provided
 * by the cuse.c example file system):
 *
 *     $ cuse_client /dev/foobar s
 *     0
 *
 *     $ echo "hello" | cuse_client /dev/foobar w 6
 *     Writing 6 bytes
 *     transferred 6 bytes (0 -> 6)
 *
 *     $ cuse_client /dev/foobar s
 *     6
 *
 *     $ cuse_client /dev/foobar r 10
 *     hello
 *     transferred 6 bytes (6 -> 6)
 *
 * Compiling this example
 *
 *     gcc -Wall cuse_client.c -o cuse_client
 *
 * ## Source Code ##
 * \include cuse_client.c
 */


#include <config.h>

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "ioctl.h"

const char *usage =
"Usage: cuse_client FIOC_FILE COMMAND\n"
"\n"
"COMMANDS\n"
"  s [SIZE]     : get size if SIZE is omitted, set size otherwise\n"
"  r SIZE [OFF] : read SIZE bytes @ OFF (dfl 0) and output to stdout\n"
"  w SIZE [OFF] : write SIZE bytes @ OFF (dfl 0) from stdin\n"
"\n";

static int do_rw(int fd, int is_read, size_t size, off_t offset,
		 size_t *prev_size, size_t *new_size)
{
	struct fioc_rw_arg arg = { .offset = offset };
	ssize_t ret;

	arg.buf = calloc(1, size);
	if (!arg.buf) {
		fprintf(stderr, "failed to allocated %zu bytes\n", size);
		return -1;
	}

	if (is_read) {
		arg.size = size;
		ret = ioctl(fd, FIOC_READ, &arg);
		if (ret >= 0)
			fwrite(arg.buf, 1, ret, stdout);
	} else {
		arg.size = fread(arg.buf, 1, size, stdin);
		fprintf(stderr, "Writing %zu bytes\n", arg.size);
		ret = ioctl(fd, FIOC_WRITE, &arg);
	}

	if (ret >= 0) {
		*prev_size = arg.prev_size;
		*new_size = arg.new_size;
	} else
		perror("ioctl");

	free(arg.buf);
	return ret;
}

int main(int argc, char **argv)
{
	size_t param[2] = { };
	size_t size, prev_size = 0, new_size = 0;
	char cmd;
	int fd, i, rc;

	if (argc < 3)
		goto usage;

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	cmd = tolower(argv[2][0]);
	argc -= 3;
	argv += 3;

	for (i = 0; i < argc; i++) {
		char *endp;
		param[i] = strtoul(argv[i], &endp, 0);
		if (endp == argv[i] || *endp != '\0')
			goto usage;
	}

	switch (cmd) {
	case 's':
		if (!argc) {
			if (ioctl(fd, FIOC_GET_SIZE, &size)) {
				perror("ioctl");
				return 1;
			}
			printf("%zu\n", size);
		} else {
			size = param[0];
			if (ioctl(fd, FIOC_SET_SIZE, &size)) {
				perror("ioctl");
				return 1;
			}
		}
		return 0;

	case 'r':
	case 'w':
		rc = do_rw(fd, cmd == 'r', param[0], param[1],
			   &prev_size, &new_size);
		if (rc < 0)
			return 1;
		fprintf(stderr, "transferred %d bytes (%zu -> %zu)\n",
			rc, prev_size, new_size);
		return 0;
	}

 usage:
	fprintf(stderr, "%s", usage);
	return 1;
}
