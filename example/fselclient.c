/*
  FUSE fselclient: FUSE select example client
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall fselclient.c -o fselclient
*/

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define FSEL_FILES	16

int main(void)
{
	static const char hex_map[FSEL_FILES] = "0123456789ABCDEF";
	int fds[FSEL_FILES];
	int i, nfds;

	for (i = 0; i < FSEL_FILES; i++) {
		char name[] = { hex_map[i], '\0' };
		fds[i] = open(name, O_RDONLY);
		if (fds[i] < 0) {
			perror("open");
			return 1;
		}
	}
	nfds = fds[FSEL_FILES - 1] + 1;

	while (1) {
		static char buf[4096];
		fd_set rfds;
		int rc;

		FD_ZERO(&rfds);
		for (i = 0; i < FSEL_FILES; i++)
			FD_SET(fds[i], &rfds);

		rc = select(nfds, &rfds, NULL, NULL, NULL);

		if (rc < 0) {
			perror("select");
			return 1;
		}

		for (i = 0; i < FSEL_FILES; i++) {
			if (!FD_ISSET(fds[i], &rfds)) {
				printf("_:   ");
				continue;
			}
			printf("%X:", i);
			rc = read(fds[i], buf, sizeof(buf));
			if (rc < 0) {
				perror("read");
				return 1;
			}
			printf("%02d ", rc);
		}
		printf("\n");
	}
}
