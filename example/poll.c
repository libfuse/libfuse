/*
  FUSE fsel: FUSE select example
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This example illustrates how to write a FUSE file system that
 * supports polling for changes that don't come through the kernel. It
 * can be tested with the poll_client.c program.
 *
 * Compile with:
 *
 *     gcc -Wall poll.c `pkg-config fuse3 --cflags --libs` -o poll
 *
 * ## Source code ##
 * \include poll.c
 */

#define FUSE_USE_VERSION 31

#include <config.h>

#include <fuse.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>

/*
 * fsel_open_mask is used to limit the number of opens to 1 per file.
 * This is to use file index (0-F) as fh as poll support requires
 * unique fh per open file.  Lifting this would require proper open
 * file management.
 */
static unsigned fsel_open_mask;
static const char fsel_hex_map[] = "0123456789ABCDEF";
static struct fuse *fsel_fuse;	/* needed for poll notification */

#define FSEL_CNT_MAX	10	/* each file can store upto 10 chars */
#define FSEL_FILES	16

static pthread_mutex_t fsel_mutex;	/* protects notify_mask and cnt array */
static unsigned fsel_poll_notify_mask;	/* poll notification scheduled? */
static struct fuse_pollhandle *fsel_poll_handle[FSEL_FILES]; /* poll notify handles */
static unsigned fsel_cnt[FSEL_FILES];	/* nbytes stored in each file */

static int fsel_path_index(const char *path)
{
	char ch = path[1];

	if (strlen(path) != 2 || path[0] != '/' || !isxdigit(ch) || islower(ch))
		return -1;
	return ch <= '9' ? ch - '0' : ch - 'A' + 10;
}

static int fsel_getattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
	(void) fi;
	int idx;

	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		return 0;
	}

	idx = fsel_path_index(path);
	if (idx < 0)
		return -ENOENT;

	stbuf->st_mode = S_IFREG | 0444;
	stbuf->st_nlink = 1;
	stbuf->st_size = fsel_cnt[idx];
	return 0;
}

static int fsel_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi,
			enum fuse_readdir_flags flags)
{
	char name[2] = { };
	int i;

	(void) offset;
	(void) fi;
	(void) flags;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	for (i = 0; i < FSEL_FILES; i++) {
		name[0] = fsel_hex_map[i];
		filler(buf, name, NULL, 0, 0);
	}

	return 0;
}

static int fsel_open(const char *path, struct fuse_file_info *fi)
{
	int idx = fsel_path_index(path);

	if (idx < 0)
		return -ENOENT;
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;
	if (fsel_open_mask & (1 << idx))
		return -EBUSY;
	fsel_open_mask |= (1 << idx);

	/*
	 * fsel files are nonseekable somewhat pipe-like files which
	 * gets filled up periodically by producer thread and consumed
	 * on read.  Tell FUSE as such.
	 */
	fi->fh = idx;
	fi->direct_io = 1;
	fi->nonseekable = 1;

	return 0;
}

static int fsel_release(const char *path, struct fuse_file_info *fi)
{
	int idx = fi->fh;

	(void) path;

	fsel_open_mask &= ~(1 << idx);
	return 0;
}

static int fsel_read(const char *path, char *buf, size_t size, off_t offset,
		     struct fuse_file_info *fi)
{
	int idx = fi->fh;

	(void) path;
	(void) offset;

	pthread_mutex_lock(&fsel_mutex);
	if (fsel_cnt[idx] < size)
		size = fsel_cnt[idx];
	printf("READ   %X transferred=%zu cnt=%u\n", idx, size, fsel_cnt[idx]);
	fsel_cnt[idx] -= size;
	pthread_mutex_unlock(&fsel_mutex);

	memset(buf, fsel_hex_map[idx], size);
	return size;
}

static int fsel_poll(const char *path, struct fuse_file_info *fi,
		     struct fuse_pollhandle *ph, unsigned *reventsp)
{
	static unsigned polled_zero;
	int idx = fi->fh;

	(void) path;

	/*
	 * Poll notification requires pointer to struct fuse which
	 * can't be obtained when using fuse_main().  As notification
	 * happens only after poll is called, fill it here from
	 * fuse_context.
	 */
	if (!fsel_fuse) {
		struct fuse_context *cxt = fuse_get_context();
		if (cxt)
			fsel_fuse = cxt->fuse;
	}

	pthread_mutex_lock(&fsel_mutex);

	if (ph != NULL) {
		struct fuse_pollhandle *oldph = fsel_poll_handle[idx];

		if (oldph)
			fuse_pollhandle_destroy(oldph);

		fsel_poll_notify_mask |= (1 << idx);
		fsel_poll_handle[idx] = ph;
	}

	if (fsel_cnt[idx]) {
		*reventsp |= POLLIN;
		printf("POLL   %X cnt=%u polled_zero=%u\n",
		       idx, fsel_cnt[idx], polled_zero);
		polled_zero = 0;
	} else
		polled_zero++;

	pthread_mutex_unlock(&fsel_mutex);
	return 0;
}

static struct fuse_operations fsel_oper = {
	.getattr	= fsel_getattr,
	.readdir	= fsel_readdir,
	.open		= fsel_open,
	.release	= fsel_release,
	.read		= fsel_read,
	.poll		= fsel_poll,
};

static void *fsel_producer(void *data)
{
	const struct timespec interval = { 0, 250000000 };
	unsigned idx = 0, nr = 1;

	(void) data;

	while (1) {
		int i, t;

		pthread_mutex_lock(&fsel_mutex);

		/*
		 * This is the main producer loop which is executed
		 * ever 500ms.  On each iteration, it fills one byte
		 * to 1, 2 or 4 files and sends poll notification if
		 * requested.
		 */
		for (i = 0, t = idx; i < nr;
		     i++, t = (t + FSEL_FILES / nr) % FSEL_FILES) {
			if (fsel_cnt[t] == FSEL_CNT_MAX)
				continue;

			fsel_cnt[t]++;
			if (fsel_fuse && (fsel_poll_notify_mask & (1 << t))) {
				struct fuse_pollhandle *ph;

				printf("NOTIFY %X\n", t);
				ph = fsel_poll_handle[t];
				fuse_notify_poll(ph);
				fuse_pollhandle_destroy(ph);
				fsel_poll_notify_mask &= ~(1 << t);
				fsel_poll_handle[t] = NULL;
			}
		}

		idx = (idx + 1) % FSEL_FILES;
		if (idx == 0)
			nr = (nr * 2) % 7;	/* cycle through 1, 2 and 4 */

		pthread_mutex_unlock(&fsel_mutex);

		nanosleep(&interval, NULL);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t producer;
	pthread_attr_t attr;
	int ret;

	errno = pthread_mutex_init(&fsel_mutex, NULL);
	if (errno) {
		perror("pthread_mutex_init");
		return 1;
	}

	errno = pthread_attr_init(&attr);
	if (errno) {
		perror("pthread_attr_init");
		return 1;
	}

	errno = pthread_create(&producer, &attr, fsel_producer, NULL);
	if (errno) {
		perror("pthread_create");
		return 1;
	}

	ret = fuse_main(argc, argv, &fsel_oper, NULL);

	pthread_cancel(producer);
	pthread_join(producer, NULL);

	return ret;
}
