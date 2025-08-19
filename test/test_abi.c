#define FUSE_USE_VERSION 30

#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	if (sizeof(struct fuse_file_info) != 64) {
		fprintf(stderr, "struct fuse_file_info size mismatch\n");
		exit(1);
	}
	if (sizeof(struct fuse_conn_info) != 128) {
		fprintf(stderr, "struct fuse_conn_info size mismatch\n");
		exit(1);
	}
}
