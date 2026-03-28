/*
  FUSE fselclient: FUSE select example client
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/** @file
 *
 * This program tests the poll.c example file systsem.
 *
 * Compile with:
 *
 *      gcc -Wall poll_client.c -o poll_client
 *
 * ## Source code ##
 * \include poll_client.c
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

int main(void)
{
	static const char hex_map[] = "0123456789ABCDEF";
	const size_t fsel_files = sizeof(hex_map) - 1;
	int fds[sizeof(hex_map) - 1];
	size_t i, tries;
	int nfds;

	for (i = 0; i < fsel_files; i++) {
		char name[] = { hex_map[i], '\0' };
		fds[i] = open(name, O_RDONLY);
		if (fds[i] < 0) {
			perror("open");
			return 1;
		}
	}
	nfds = fds[fsel_files - 1] + 1;

	for (tries = 0; tries < fsel_files; tries++) {
		static char buf[4096];
		fd_set rfds;
		int rc;

		FD_ZERO(&rfds);
		for (i = 0; i < fsel_files; i++)
			FD_SET(fds[i], &rfds);

		rc = select(nfds, &rfds, NULL, NULL, NULL);

		if (rc < 0) {
			perror("select");
			return 1;
		}

		for (i = 0; i < fsel_files; i++) {
			if (!FD_ISSET(fds[i], &rfds)) {
				printf("_:   ");
				continue;
			}
			printf("%zX:", i);
			rc = read(fds[i], buf, sizeof(buf));
			if (rc < 0) {
				perror("read");
				return 1;
			}
			printf("%02d ", rc);
		}
		printf("\n");
	}
	return 0;
}
