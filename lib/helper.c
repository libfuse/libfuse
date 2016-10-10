/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Helper functions to create (simple) standalone programs. With the
  aid of these functions it should be possible to create full FUSE
  file system by implementing nothing but the request handlers.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "config.h"
#include "fuse_i.h"
#include "fuse_misc.h"
#include "fuse_opt.h"
#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/param.h>

#define FUSE_HELPER_OPT(t, p) \
	{ t, offsetof(struct fuse_cmdline_opts, p), 1 }

static const struct fuse_opt fuse_helper_opts[] = {
	FUSE_HELPER_OPT("-h",		show_help),
	FUSE_HELPER_OPT("--help",	show_help),
	FUSE_HELPER_OPT("-V",		show_version),
	FUSE_HELPER_OPT("--version",	show_version),
	FUSE_HELPER_OPT("-d",		debug),
	FUSE_HELPER_OPT("debug",	debug),
	FUSE_HELPER_OPT("-d",		foreground),
	FUSE_HELPER_OPT("debug",	foreground),
	FUSE_OPT_KEY("-d",		FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("debug",		FUSE_OPT_KEY_KEEP),
	FUSE_HELPER_OPT("-f",		foreground),
	FUSE_HELPER_OPT("-s",		singlethread),
	FUSE_HELPER_OPT("fsname=",	nodefault_subtype),
	FUSE_HELPER_OPT("subtype=",	nodefault_subtype),
	FUSE_OPT_KEY("fsname=",		FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("subtype=",	FUSE_OPT_KEY_KEEP),
	FUSE_OPT_END
};

void fuse_cmdline_help(void)
{
	printf("General options:\n"
	       "    -h   --help            print help\n"
	       "    -V   --version         print version\n"
	       "    -d   -o debug          enable debug output (implies -f)\n"
	       "    -f                     foreground operation\n"
	       "    -s                     disable multi-threaded operation\n"
	       "\n");
}

static int fuse_helper_opt_proc(void *data, const char *arg, int key,
				struct fuse_args *outargs)
{
	(void) outargs;
	struct fuse_cmdline_opts *opts = data;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		if (!opts->mountpoint) {
			char mountpoint[PATH_MAX];
			if (realpath(arg, mountpoint) == NULL) {
				fprintf(stderr,
					"fuse: bad mount point `%s': %s\n",
					arg, strerror(errno));
				return -1;
			}
			return fuse_opt_add_opt(&opts->mountpoint, mountpoint);
		} else {
			fprintf(stderr, "fuse: invalid argument `%s'\n", arg);
			return -1;
		}

	default:
		/* Pass through unknown options */
		return 1;
	}
}

static int add_default_subtype(const char *progname, struct fuse_args *args)
{
	int res;
	char *subtype_opt;
	const char *basename = strrchr(progname, '/');
	if (basename == NULL)
		basename = progname;
	else if (basename[1] != '\0')
		basename++;

	subtype_opt = (char *) malloc(strlen(basename) + 64);
	if (subtype_opt == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		return -1;
	}
	sprintf(subtype_opt, "-osubtype=%s", basename);
	res = fuse_opt_add_arg(args, subtype_opt);
	free(subtype_opt);
	return res;
}

int fuse_parse_cmdline(struct fuse_args *args,
		       struct fuse_cmdline_opts *opts)
{
	memset(opts, 0, sizeof(struct fuse_cmdline_opts));
	if (fuse_opt_parse(args, opts, fuse_helper_opts,
			   fuse_helper_opt_proc) == -1)
		return -1;

	/* If neither -o subtype nor -o fsname are specified,
	   set subtype to program's basename */
	if (!opts->nodefault_subtype)
		if (add_default_subtype(args->argv[0], args) == -1)
			return -1;

	return 0;
}


int fuse_daemonize(int foreground)
{
	if (!foreground) {
		int nullfd;
		int waiter[2];
		char completed;

		if (pipe(waiter)) {
			perror("fuse_daemonize: pipe");
			return -1;
		}

		/*
		 * demonize current process by forking it and killing the
		 * parent.  This makes current process as a child of 'init'.
		 */
		switch(fork()) {
		case -1:
			perror("fuse_daemonize: fork");
			return -1;
		case 0:
			break;
		default:
			read(waiter[0], &completed, sizeof(completed));
			_exit(0);
		}

		if (setsid() == -1) {
			perror("fuse_daemonize: setsid");
			return -1;
		}

		(void) chdir("/");

		nullfd = open("/dev/null", O_RDWR, 0);
		if (nullfd != -1) {
			(void) dup2(nullfd, 0);
			(void) dup2(nullfd, 1);
			(void) dup2(nullfd, 2);
			if (nullfd > 2)
				close(nullfd);
		}

		/* Propagate completion of daemon initializatation */
		completed = 1;
		write(waiter[1], &completed, sizeof(completed));
		close(waiter[0]);
		close(waiter[1]);
	} else {
		(void) chdir("/");
	}
	return 0;
}

int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		   size_t op_size, void *user_data)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse *fuse;
	struct fuse_cmdline_opts opts;
	int res;

	memset(&opts, 0, sizeof(opts));
	if (fuse_opt_parse(&args, &opts, fuse_helper_opts,
			   fuse_helper_opt_proc) == -1)
		return 1;

	if (opts.show_version) {
		printf("FUSE library version %s\n", PACKAGE_VERSION);
		fuse_lowlevel_version();
		fuse_mount_version();
		res = 0;
		goto out1;
	}

	/* Re-add --help for later processing by fuse_new()
	   (that way we also get help for modules options) */
	if (opts.show_help) {
		fuse_cmdline_help();
		if (fuse_opt_add_arg(&args, "--help") == -1) {
			res = 1;
			goto out1;
		}
	}

	if (!opts.show_help &&
	    !opts.mountpoint) {
		fprintf(stderr, "error: no mountpoint specified\n");
		res = 1;
		goto out1;
	}

	/* If neither -o subtype nor -o fsname are specified,
	   set subtype to program's basename */
	if (!opts.nodefault_subtype) {
		if (add_default_subtype(args.argv[0], &args) == -1) {
			res = 1;
			goto out1;
		}
	}

	/* --help is processed here and will result in NULL */
	fuse = fuse_new(&args, op, op_size, user_data);
	if (fuse == NULL) {
		res = opts.show_help ? 0 : 1;
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

	struct fuse_session *se = fuse_get_session(fuse);
	if (fuse_set_signal_handlers(se) != 0) {
		res = 1;
		goto out3;
	}

	if (opts.singlethread)
		res = fuse_loop(fuse);
	else
		res = fuse_loop_mt(fuse);
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
