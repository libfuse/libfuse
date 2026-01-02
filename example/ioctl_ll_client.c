/*
 * FUSE fioc_ll_client: FUSE ioctl example client for low-level API
 * Copyright (C) 2008       SUSE Linux Products GmbH
 * Copyright (C) 2008       Tejun Heo <teheo@suse.de>
 * Copyright (C) 2024       libfuse maintainers
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

/** @file
 *
 * This program tests the ioctl_ll.c example file system.
 * It tests both restricted ioctls (FIOC_GET_SIZE, FIOC_SET_SIZE) and
 * unrestricted ioctls (FIOC_READ, FIOC_WRITE).
 *
 * Compile with:
 *
 *     gcc -Wall ioctl_ll_client.c -o ioctl_ll_client
 *
 * ## Source code ##
 * \include ioctl_ll_client.c
 */

#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ioctl.h"

static const char *usage =
"Usage: ioctl_ll_client <command> <fioc_file> [args]\n"
"\n"
"Commands:\n"
"    get_size                 Get the current size (restricted ioctl)\n"
"    set_size <size>          Set the size (restricted ioctl)\n"
"    read <offset> <size>     Read data via ioctl (unrestricted)\n"
"    write <offset> <data>    Write data via ioctl (unrestricted)\n"
"\n"
"Examples:\n"
"    ioctl_ll_client get_size /mnt/fioc\n"
"    ioctl_ll_client set_size /mnt/fioc 100\n"
"    ioctl_ll_client read /mnt/fioc 0 10\n"
"    ioctl_ll_client write /mnt/fioc 0 hello\n"
"\n";

static int do_get_size(int fd)
{
	size_t size;

	if (ioctl(fd, FIOC_GET_SIZE, &size)) {
		perror("ioctl(FIOC_GET_SIZE)");
		return 1;
	}
	printf("%zu\n", size);
	return 0;
}

static int do_set_size(int fd, const char *size_str)
{
	size_t size = strtoul(size_str, NULL, 0);

	if (ioctl(fd, FIOC_SET_SIZE, &size)) {
		perror("ioctl(FIOC_SET_SIZE)");
		return 1;
	}
	printf("Size set to %zu\n", size);
	return 0;
}

static int do_read(int fd, const char *offset_str, const char *size_str)
{
	struct fioc_rw_arg arg;
	char *buf;
	ssize_t ret;
	size_t sz = strtoul(size_str, NULL, 0);

	buf = malloc(sz + 1);
	if (!buf) {
		perror("malloc");
		return 1;
	}

	memset(&arg, 0, sizeof(arg));
	arg.offset = strtol(offset_str, NULL, 0);
	arg.buf = buf;
	arg.size = sz;

	ret = ioctl(fd, FIOC_READ, &arg);
	if (ret < 0) {
		perror("ioctl(FIOC_READ)");
		free(buf);
		return 1;
	}

	buf[ret] = '\0';
	printf("Read %zd bytes (prev_size=%zu, new_size=%zu): %s\n",
	       ret, arg.prev_size, arg.new_size, buf);
	free(buf);
	return 0;
}

static int do_write(int fd, const char *offset_str, const char *data)
{
	struct fioc_rw_arg arg;
	ssize_t ret;

	memset(&arg, 0, sizeof(arg));
	arg.offset = strtol(offset_str, NULL, 0);
	arg.buf = (void *)data;
	arg.size = strlen(data);

	ret = ioctl(fd, FIOC_WRITE, &arg);
	if (ret < 0) {
		perror("ioctl(FIOC_WRITE)");
		return 1;
	}

	printf("Wrote %zd bytes (prev_size=%zu, new_size=%zu)\n",
	       ret, arg.prev_size, arg.new_size);
	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	int ret = 0;

	if (argc < 3) {
		fprintf(stderr, "%s", usage);
		return 1;
	}

	fd = open(argv[2], O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (strcmp(argv[1], "get_size") == 0) {
		ret = do_get_size(fd);
	} else if (strcmp(argv[1], "set_size") == 0) {
		if (argc < 4) {
			fprintf(stderr, "set_size requires a size argument\n");
			ret = 1;
		} else {
			ret = do_set_size(fd, argv[3]);
		}
	} else if (strcmp(argv[1], "read") == 0) {
		if (argc < 5) {
			fprintf(stderr, "read requires offset and size\n");
			ret = 1;
		} else {
			ret = do_read(fd, argv[3], argv[4]);
		}
	} else if (strcmp(argv[1], "write") == 0) {
		if (argc < 5) {
			fprintf(stderr, "write requires offset and data\n");
			ret = 1;
		} else {
			ret = do_write(fd, argv[3], argv[4]);
		}
	} else {
		fprintf(stderr, "Unknown command: %s\n", argv[1]);
		fprintf(stderr, "%s", usage);
		ret = 1;
	}

	close(fd);
	return ret;
}

