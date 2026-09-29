/*
  FUSE fsel: FUSE select example
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
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

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse.h>
#include <fuse_lowlevel.h>  /* for fuse_cmdline_opts */
#include <fuse_daemonize.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>

/*
 * fsel_open_mask is used to limit the number of opens to 1 per file.
 * This is to use file index (0-F) as fh as poll support requires
 * unique fh per open file.  Lifting this would require proper open
 * file management.
 */
static unsigned fsel_open_mask;
static const char fsel_hex_map[] = "0123456789ABCDEF";
static struct fuse *fsel_fuse;	/* needed for poll notification */

#define FSEL_CNT_MAX	10	/* each file can store up to 10 chars */
#define FSEL_FILES	16

static pthread_mutex_t fsel_mutex;	/* protects the masks, cnt array and fsel_fuse */
static unsigned fsel_poll_notify_mask;	/* poll notification scheduled? */
static struct fuse_pollhandle *fsel_poll_handle[FSEL_FILES]; /* poll notify handles */
static unsigned fsel_cnt[FSEL_FILES];	/* nbytes stored in each file */
static _Atomic bool fsel_stop = false;


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
	pthread_mutex_lock(&fsel_mutex);
	stbuf->st_size = fsel_cnt[idx];
	pthread_mutex_unlock(&fsel_mutex);
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
		filler(buf, name, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
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
	pthread_mutex_lock(&fsel_mutex);
	if (fsel_open_mask & (1 << idx)) {
		pthread_mutex_unlock(&fsel_mutex);
		return -EBUSY;
	}
	fsel_open_mask |= (1 << idx);
	pthread_mutex_unlock(&fsel_mutex);

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

	pthread_mutex_lock(&fsel_mutex);
	fsel_open_mask &= ~(1 << idx);
	pthread_mutex_unlock(&fsel_mutex);
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
	pthread_mutex_lock(&fsel_mutex);
	if (!fsel_fuse) {
		struct fuse_context *cxt = fuse_get_context();
		if (cxt)
			fsel_fuse = cxt->fuse;
	}

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

static const struct fuse_operations fsel_oper = {
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

	while (!fsel_stop) {
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
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;
	struct fuse_loop_config *config;
	pthread_t producer;
	struct fuse *fuse;
	int res;

	errno = pthread_mutex_init(&fsel_mutex, NULL);
	if (errno) {
		perror("pthread_mutex_init");
		return 1;
	}

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		res = 0;
		goto out1;
	} else if (opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lib_help(&args);
		res = 0;
		goto out1;
	} else if (!opts.mountpoint) {
		fprintf(stderr, "error: no mountpoint specified\n");
		res = 1;
		goto out1;
	}

	fuse = fuse_new(&args, &fsel_oper, sizeof(fsel_oper), NULL);
	if (fuse == NULL) {
		res = 1;
		goto out1;
	}

	if (fuse_daemonize_early_start(opts.foreground ?
				       FUSE_DAEMONIZE_NO_BACKGROUND : 0) != 0) {
		res = 1;
		goto out2;
	}

	if (fuse_mount(fuse, opts.mountpoint) != 0) {
		res = 1;
		goto out2;
	}

	fuse_daemonize_early_success();

	errno = pthread_create(&producer, NULL, fsel_producer, NULL);
	if (errno) {
		perror("pthread_create");
		res = 1;
		goto out3;
	}

	if (fuse_set_signal_handlers(fuse_get_session(fuse)) != 0) {
		res = 1;
		goto out4;
	}

	if (opts.singlethread)
		res = fuse_loop(fuse);
	else {
		config = fuse_loop_cfg_create();
		if (config == NULL) {
			res = 1;
			goto out5;
		}
		fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
		fuse_loop_cfg_set_idle_threads(config, opts.max_idle_threads);
		res = fuse_loop_mt(fuse, config);
		fuse_loop_cfg_destroy(config);
	}
	if (res)
		res = 1;

out5:
	fuse_remove_signal_handlers(fuse_get_session(fuse));
out4:
	/* the producer sends notifications on the fd that fuse_unmount() closes */
	fsel_stop = true;
	pthread_join(producer, NULL);
out3:
	fuse_unmount(fuse);
out2:
	fuse_destroy(fuse);
out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);
	return res;
}
