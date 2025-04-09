/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2005-2008 Csaba Henk <csaba.henk@creo.hu>

  Architecture specific file system mounting (FreeBSD).

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_misc.h"
#include "fuse_opt.h"
#include "util.h"

#include <sys/param.h>
#include "fuse_mount_compat.h"

#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <spawn.h>

#define FUSERMOUNT_PROG		"mount_fusefs"
#define FUSERMOUNT_PATH		"/sbin/" FUSERMOUNT_PROG
#define FUSE_DEV_TRUNK		"/dev/fuse"

#ifndef HAVE_ENVIRON_DECL
extern char **environ __weak_symbol;
#endif

enum {
	KEY_RO,
	KEY_KERN
};

struct mount_opts {
	int allow_other;
	char *kernel_opts;
	unsigned max_read;
};

#define FUSE_DUAL_OPT_KEY(templ, key)				\
	FUSE_OPT_KEY(templ, key), FUSE_OPT_KEY("no" templ, key)

static const struct fuse_opt fuse_mount_opts[] = {
	{ "allow_other", offsetof(struct mount_opts, allow_other), 1 },
	{ "max_read=%u", offsetof(struct mount_opts, max_read), 1 },
	FUSE_OPT_KEY("-r",			KEY_RO),
	/* standard FreeBSD mount options */
	FUSE_DUAL_OPT_KEY("dev",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("async",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("atime",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("dev",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("exec",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("suid",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("symfollow",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("rdonly",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("sync",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("union",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("userquota",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("groupquota",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("clusterr",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("clusterw",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("suiddir",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("snapshot",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("multilabel",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("acls",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("force",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("update",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("ro",			KEY_KERN),
	FUSE_DUAL_OPT_KEY("rw",			KEY_KERN),
	FUSE_DUAL_OPT_KEY("auto",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("automounted",	KEY_KERN),
	/* options supported under both Linux and FBSD */
	FUSE_DUAL_OPT_KEY("allow_other",	KEY_KERN),
	FUSE_DUAL_OPT_KEY("default_permissions",KEY_KERN),
	FUSE_OPT_KEY("max_read=",		KEY_KERN),
	FUSE_OPT_KEY("subtype=",		KEY_KERN),
	/* FBSD FUSE specific mount options */
	FUSE_DUAL_OPT_KEY("private",		KEY_KERN),
	FUSE_DUAL_OPT_KEY("neglect_shares",	KEY_KERN),
	FUSE_DUAL_OPT_KEY("push_symlinks_in",	KEY_KERN),
#if __FreeBSD_version >= 1200519
	FUSE_DUAL_OPT_KEY("intr",		KEY_KERN),
#endif
	/* stock FBSD mountopt parsing routine lets anything be negated... */
	/*
	 * Linux specific mount options, but let just the mount util
	 * handle them
	 */
	FUSE_OPT_KEY("fsname=",			KEY_KERN),
	FUSE_OPT_END
};

void fuse_mount_version(void)
{
	system(FUSERMOUNT_PROG " --version");
}

unsigned get_max_read(struct mount_opts *o)
{
	return o->max_read;
}

static int fuse_mount_opt_proc(void *data, const char *arg, int key,
			       struct fuse_args *outargs)
{
	(void) outargs;
	struct mount_opts *mo = data;

	switch (key) {
	case KEY_RO:
		arg = "ro";
		/* fall through */

	case KEY_KERN:
		return fuse_opt_add_opt(&mo->kernel_opts, arg);
	}

	/* Pass through unknown options */
	return 1;
}

void fuse_kern_unmount(const char *mountpoint, int fd)
{
	if (close(fd) < 0)
		fuse_log(FUSE_LOG_WARNING, "closing FD %d failed: %s\n", fd, strerror(errno));
	if (unmount(mountpoint, MNT_FORCE) < 0)
		fuse_log(FUSE_LOG_ERR, "unmounting %s failed: %s\n",
			 mountpoint, strerror(errno));
}

static int fuse_mount_core(const char *mountpoint, const char *opts)
{
	long fd;
	char *fdnam, *dev;
	int err;

	fdnam = getenv("FUSE_DEV_FD");

	if (fdnam) {
		err = libfuse_strtol(fdnam, &fd);
		if (err || fd < 0) {
			fuse_log(FUSE_LOG_ERR, "invalid value given in FUSE_DEV_FD\n");
			return -1;
		}

		goto mount;
	}

	dev = getenv("FUSE_DEV_NAME");

	if (! dev)
		dev = (char *)FUSE_DEV_TRUNK;

	if ((fd = open(dev, O_RDWR)) < 0) {
		perror("fuse: failed to open fuse device");
		return -1;
	}

	_Bool fdnam_alloc = 0;
mount:
	if (getenv("FUSE_NO_MOUNT") || ! mountpoint)
		goto out;

	int status;

	if (!fdnam) {
		status = asprintf(&fdnam, "%ld", fd);
		if (status < 0) {
			perror("fuse: failed to assemble mount arguments for " FUSERMOUNT_PROG);
			(void)close(fd);
			return -1;
		}
		fdnam_alloc = 1;
	}

	const char *argv[6];
	unsigned char a = 0;

	argv[a++] = FUSERMOUNT_PROG;
	if (opts) {
		argv[a++] = "-o";
		argv[a++] = opts;
	}
	argv[a++] = fdnam;
	argv[a++] = mountpoint;
	argv[a] = NULL;

	pid_t pid;

	status = posix_spawn(&pid, FUSERMOUNT_PATH, NULL, NULL, (char *const *) argv, environ);
	if (status) {
		fuse_log(FUSE_LOG_CRIT, "spawning " FUSERMOUNT_PROG " failed: %s (%d)\n",
			 strerror(status), status);
		(void)close(fd); fd = -1;
		goto out;
	}

	/* XXX: we only verify here that the process has not already failed. We do not wait for
	 * it to finish nor we guarantee that it won't fail later. It might change in the future.
	 */
	if (waitpid(pid, &status, WNOHANG) < 0) {
		fuse_log(FUSE_LOG_CRIT,
			 "spawning " FUSERMOUNT_PROG " failed: waitpid: %s\n", strerror(errno));
		(void)close(fd); fd = -1;
		goto out;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		fuse_log(FUSE_LOG_ERR, FUSERMOUNT_PROG " exited with code %d\n",
			 WEXITSTATUS(status));
		(void)close(fd); fd = -1;
		goto out;
	}
	if (WIFSIGNALED(status)) {
		fuse_log(FUSE_LOG_ERR, FUSERMOUNT_PROG " was killed by %s\n",
			 strsignal(WTERMSIG(status)));
		(void)close(fd); fd = -1;
	}

out:
	if (fdnam_alloc)
		free(fdnam);

	return fd;
}

struct mount_opts *parse_mount_opts(struct fuse_args *args)
{
	struct mount_opts *mo;

	mo = (struct mount_opts*) malloc(sizeof(struct mount_opts));
	if (mo == NULL)
		return NULL;

	memset(mo, 0, sizeof(struct mount_opts));

	if (args &&
	    fuse_opt_parse(args, mo, fuse_mount_opts, fuse_mount_opt_proc) == -1)
		goto err_out;

	return mo;

err_out:
	destroy_mount_opts(mo);
	return NULL;
}

void destroy_mount_opts(struct mount_opts *mo)
{
	free(mo->kernel_opts);
	free(mo);
}

int fuse_kern_mount(const char *mountpoint, struct mount_opts *mo)
{
	/* mount util should not try to spawn the daemon */
	setenv("MOUNT_FUSEFS_SAFE", "1", 1);
	/* to notify the mount util it's called from lib */
	setenv("MOUNT_FUSEFS_CALL_BY_LIB", "1", 1);

	return fuse_mount_core(mountpoint, mo->kernel_opts);
}
