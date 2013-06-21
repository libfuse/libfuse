/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse_i.h"
#include "fuse_misc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>


struct fuse_session *fuse_session_new(void)
{
	struct fuse_session *se = (struct fuse_session *) malloc(sizeof(*se));
	if (se == NULL) {
		fprintf(stderr, "fuse: failed to allocate session\n");
		return NULL;
	}
	memset(se, 0, sizeof(*se));

	return se;
}

void fuse_session_add_chan(struct fuse_session *se, struct fuse_chan *ch)
{
	assert(se->ch == NULL);
	assert(ch->se == NULL);
	se->ch = ch;
	ch->se = se;
}

void fuse_session_remove_chan(struct fuse_chan *ch)
{
	struct fuse_session *se = ch->se;
	if (se) {
		assert(se->ch == ch);
		se->ch = NULL;
		ch->se = NULL;
	}
}

struct fuse_chan *fuse_session_chan(struct fuse_session *se)
{
	return se->ch;
}

int fuse_chan_clearfd(struct fuse_chan *ch)
{
	int fd = ch->fd;
	ch->fd = -1;
	return fd;
}

void fuse_session_exit(struct fuse_session *se)
{
	se->exited = 1;
}

void fuse_session_reset(struct fuse_session *se)
{
	se->exited = 0;
}

int fuse_session_exited(struct fuse_session *se)
{
	return se->exited;
}

struct fuse_chan *fuse_chan_new(int fd)
{
	struct fuse_chan *ch = (struct fuse_chan *) malloc(sizeof(*ch));
	if (ch == NULL) {
		fprintf(stderr, "fuse: failed to allocate channel\n");
		return NULL;
	}

	memset(ch, 0, sizeof(*ch));
	ch->fd = fd;

	return ch;
}

int fuse_chan_fd(struct fuse_chan *ch)
{
	return ch->fd;
}

struct fuse_session *fuse_chan_session(struct fuse_chan *ch)
{
	return ch->se;
}

void fuse_chan_destroy(struct fuse_chan *ch)
{
	fuse_session_remove_chan(ch);
	fuse_chan_close(ch);
	free(ch);
}
