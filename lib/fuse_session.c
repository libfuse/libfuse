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

struct fuse_chan {
	struct fuse_chan_ops op;

	struct fuse_session *se;

	int fd;

	size_t bufsize;
};

struct fuse_session *fuse_session_new(void *data)
{
	struct fuse_session *se = (struct fuse_session *) malloc(sizeof(*se));
	if (se == NULL) {
		fprintf(stderr, "fuse: failed to allocate session\n");
		return NULL;
	}

	memset(se, 0, sizeof(*se));
	se->data = data;

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

void fuse_session_process_buf(struct fuse_session *se,
			      const struct fuse_buf *buf, struct fuse_chan *ch)
{
	se->process_buf(se->data, buf, ch);
}

int fuse_session_receive_buf(struct fuse_session *se, struct fuse_buf *buf,
			     struct fuse_chan *ch)
{
	return se->receive_buf(se, buf, ch);
}

int fuse_chan_clearfd(struct fuse_chan *ch)
{
	int fd = ch->fd;
	ch->fd = -1;
	return fd;
}

void fuse_session_destroy(struct fuse_session *se)
{
	se->destroy(se->data);
	if (se->ch != NULL)
		fuse_chan_destroy(se->ch);
	free(se);
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

void *fuse_session_data(struct fuse_session *se)
{
	return se->data;
}

struct fuse_chan *fuse_chan_new(struct fuse_chan_ops *op, int fd,
				size_t bufsize)
{
	struct fuse_chan *ch = (struct fuse_chan *) malloc(sizeof(*ch));
	if (ch == NULL) {
		fprintf(stderr, "fuse: failed to allocate channel\n");
		return NULL;
	}

	memset(ch, 0, sizeof(*ch));
	ch->op = *op;
	ch->fd = fd;
	ch->bufsize = bufsize;

	return ch;
}

int fuse_chan_fd(struct fuse_chan *ch)
{
	return ch->fd;
}

size_t fuse_chan_bufsize(struct fuse_chan *ch)
{
	return ch->bufsize;
}

struct fuse_session *fuse_chan_session(struct fuse_chan *ch)
{
	return ch->se;
}

void fuse_chan_destroy(struct fuse_chan *ch)
{
	fuse_session_remove_chan(ch);
	if (ch->op.destroy)
		ch->op.destroy(ch);
	free(ch);
}
