/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>
            (C) 2017 EditShare LLC <slawek.rudnicki@editshare.com>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
 */

/** @file
 *
 * This example implements a file system with two files:
 *   * 'current-time', whose contents change dynamically:
 *     it always contains the current time (same as in
 *     notify_inval_inode.c).
 *   * 'growing', whose size changes dynamically, growing
 *     by 1 byte after each update. This aims to check
 *     if cached file metadata is also invalidated.
 *
 * ## Compilation ##
 *
 *     gcc -Wall @file `pkg-config fuse3 --cflags --libs` -o invalidate_path
 *
 * ## Source code ##
 * \include @file
 */

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <fuse_lowlevel.h>  /* for fuse_cmdline_opts */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <pthread.h>

/* We can't actually tell the kernel that there is no
   timeout, so we just send a big value */
#define NO_TIMEOUT 500000

#define MAX_STR_LEN 128
#define TIME_FILE_NAME "current_time"
#define TIME_FILE_INO 2
#define GROW_FILE_NAME "growing"
#define GROW_FILE_INO 3

static char time_file_contents[MAX_STR_LEN];
static size_t grow_file_size;

/* Command line parsing */
struct options {
	int no_notify;
	int update_interval;
};
static struct options options = {
		.no_notify = 0,
		.update_interval = 1,
};

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
		OPTION("--no-notify", no_notify),
		OPTION("--update-interval=%d", update_interval),
		FUSE_OPT_END
};

static void *xmp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	(void) conn;
	cfg->entry_timeout = NO_TIMEOUT;
	cfg->attr_timeout = NO_TIMEOUT;
	cfg->negative_timeout = 0;

	return NULL;
}

static int xmp_getattr(const char *path,
		struct stat *stbuf, struct fuse_file_info* fi) {
	(void) fi;
	if (strcmp(path, "/") == 0) {
		stbuf->st_ino = 1;
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
	} else if (strcmp(path, "/" TIME_FILE_NAME) == 0) {
		stbuf->st_ino = TIME_FILE_INO;
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(time_file_contents);
	} else if (strcmp(path, "/" GROW_FILE_NAME) == 0) {
		stbuf->st_ino = GROW_FILE_INO;
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = grow_file_size;
	} else {
		return -ENOENT;
	}

	return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi,
		enum fuse_readdir_flags flags) {
	(void) fi;
	(void) offset;
	(void) flags;
	if (strcmp(path, "/") != 0) {
		return -ENOTDIR;
	} else {
		(void) filler;
		(void) buf;
		struct stat file_stat;
		xmp_getattr("/" TIME_FILE_NAME, &file_stat, NULL);
		filler(buf, TIME_FILE_NAME, &file_stat, 0, 0);
		xmp_getattr("/" GROW_FILE_NAME, &file_stat, NULL);
		filler(buf, GROW_FILE_NAME, &file_stat, 0, 0);
		return 0;
	}
}

static int xmp_open(const char *path, struct fuse_file_info *fi) {
	(void) path;
	/* Make cache persistent even if file is closed,
       this makes it easier to see the effects */
	fi->keep_cache = 1;
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi) {
	(void) fi;
	(void) offset;
	if (strcmp(path, "/" TIME_FILE_NAME) == 0) {
		int file_length = strlen(time_file_contents);
		int to_copy = offset + size <= file_length
				? size
						: file_length - offset;
		memcpy(buf, time_file_contents, to_copy);
		return to_copy;
	} else {
		assert(strcmp(path, "/" GROW_FILE_NAME) == 0);
		int to_copy = offset + size <= grow_file_size
				? size
						: grow_file_size - offset;
		memset(buf, 'x', to_copy);
		return to_copy;
	}
}

static struct fuse_operations xmp_oper = {
		.init     = xmp_init,
		.getattr  = xmp_getattr,
		.readdir  = xmp_readdir,
		.open     = xmp_open,
		.read     = xmp_read,
};

static void update_fs(void) {
	static int count = 0;
	struct tm *now;
	time_t t;
	t = time(NULL);
	now = localtime(&t);
	assert(now != NULL);

	int time_file_size = strftime(time_file_contents, MAX_STR_LEN,
			"The current time is %H:%M:%S\n", now);
	assert(time_file_size != 0);

	grow_file_size = count++;
}

static int invalidate(struct fuse *fuse, const char *path) {
	int status = fuse_invalidate_path(fuse, path);
	if (status == -ENOENT) {
		return 0;
	} else {
		return status;
	}
}

static void* update_fs_loop(void *data) {
	struct fuse *fuse = (struct fuse*) data;

	while (1) {
		update_fs();
		if (!options.no_notify) {
			assert(invalidate(fuse, "/" TIME_FILE_NAME) == 0);
			assert(invalidate(fuse, "/" GROW_FILE_NAME) == 0);
		}
		sleep(options.update_interval);
	}
	return NULL;
}

static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
			"    --update-interval=<secs>  Update-rate of file system contents\n"
			"    --no-notify            Disable kernel notifications\n"
			"\n");
}

int main(int argc, char *argv[]) {
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse *fuse;
	struct fuse_cmdline_opts opts;
	int res;

	/* Initialize the files */
	update_fs();

	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		res = 0;
		goto out1;
	} else if (opts.show_help) {
		show_help(argv[0]);
		fuse_cmdline_help();
		fuse_lib_help(&args);
		res = 0;
		goto out1;
	} else if (!opts.mountpoint) {
		fprintf(stderr, "error: no mountpoint specified\n");
		res = 1;
		goto out1;
	}

	fuse = fuse_new(&args, &xmp_oper, sizeof(xmp_oper), NULL);
	if (fuse == NULL) {
		res = 1;
		goto out1;
	}

	if (fuse_mount(fuse,opts.mountpoint) != 0) {
		res = 1;
		goto out2;
	}

	if (fuse_daemonize(opts.foreground) != 0) {
		res = 1;
		goto out3;
	}

	pthread_t updater;     /* Start thread to update file contents */
	int ret = pthread_create(&updater, NULL, update_fs_loop, (void *) fuse);
	if (ret != 0) {
		fprintf(stderr, "pthread_create failed with %s\n", strerror(ret));
		return 1;
	};

	struct fuse_session *se = fuse_get_session(fuse);
	if (fuse_set_signal_handlers(se) != 0) {
		res = 1;
		goto out3;
	}

	if (opts.singlethread)
		res = fuse_loop(fuse);
	else
		res = fuse_loop_mt(fuse, opts.clone_fd);
	if (res)
		res = 1;

	fuse_remove_signal_handlers(se);
out3:
	fuse_unmount(fuse);
out2:
	fuse_destroy(fuse);
out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);
	return res;
}
