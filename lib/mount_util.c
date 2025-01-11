/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Architecture-independent mounting code.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#define _GNU_SOURCE

#include "fuse_config.h"
#include "mount_util.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#if !defined( __NetBSD__) && !defined(__FreeBSD__) && !defined(__DragonFly__) && !defined(__ANDROID__)
#include <mntent.h>
#else
#define IGNORE_MTAB
#endif
#include <sys/stat.h>
#include <sys/wait.h>

#include "fuse_mount_compat.h"

#include <sys/param.h>
#include <spawn.h>

#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
#define umount2(mnt, flags) unmount(mnt, ((flags) == 2) ? MNT_FORCE : 0)
#endif

#ifdef IGNORE_MTAB
#define mtab_needs_update(mnt) 0
#else
static int mtab_needs_update(const char *mnt)
{
	int res;
	struct stat stbuf;

	char *env = getenv("FUSE_NO_MTAB_UPDATE");
	if (env != NULL) {
		int value = atoi(env);
		if (value == 1)
			return 0;
	}

	/* If mtab is within new mount, don't touch it */
	if (strncmp(mnt, _PATH_MOUNTED, strlen(mnt)) == 0 &&
	    _PATH_MOUNTED[strlen(mnt)] == '/')
		return 0;

	/*
	 * Skip mtab update if /etc/mtab:
	 *
	 *  - doesn't exist,
	 *  - is on a read-only filesystem.
	 */
	res = lstat(_PATH_MOUNTED, &stbuf);
	if (res == -1) {
		if (errno == ENOENT)
			return 0;
	} else {
		uid_t ruid;
		int err;

		ruid = getuid();
		if (ruid != 0)
			setreuid(0, -1);

		res = access(_PATH_MOUNTED, W_OK);
		err = (res == -1) ? errno : 0;
		if (ruid != 0)
			setreuid(ruid, -1);

		if (err == EROFS)
			return 0;
	}

	return 1;
}
#endif /* IGNORE_MTAB */

static int fuse_mount_posix_spawn_attr(posix_spawnattr_t *attr, const char *cmd,
				       sigset_t mask)
{
	int res;

	posix_spawnattr_init(attr);

	int flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETSIGMASK;
	res = posix_spawnattr_setflags(attr, flags);
	if (res) {
		fprintf(stderr, "Failed to set posix_spawn flags for cmd %s: %s\n",
			cmd, strerror(res));
		return res;
	}

	res = posix_spawnattr_setsigmask(attr, &mask);
	if (res < 0) {
		fprintf(stderr,
			 "Failed to set posix_spawn sigmask for cmd %s: %s\n",
			cmd, strerror(res));
		return res;
	}

	return 0;
}

/*
 * @return caller expects 0 or -1
 */
static int add_mount(const char *progname, const char *fsname,
		       const char *mnt, const char *type, const char *opts)
{
	int res;
	int status;
	pid_t pid;
	sigset_t blockmask;
	sigset_t oldmask;
	posix_spawnattr_t attr;
	const char *cmd = "/bin/mount";

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	res = sigprocmask(SIG_BLOCK, &blockmask, &oldmask);
	if (res == -1) {
		fprintf(stderr, "%s: sigprocmask: %s\n", progname, strerror(errno));
		return -1;
	}

	char const * const argv[] =  {
			cmd, "--no-canonicalize", "-i", "-f", "-t", type, "-o", opts,
		fsname, mnt, NULL
	};

	res = fuse_mount_posix_spawn_attr(&attr, cmd, oldmask);
	if (res)
		goto out_restore;

	res = posix_spawn(&pid, cmd, NULL, &attr,
			  (char * const *) argv, environ);
	posix_spawnattr_destroy(&attr);

	if (res) {
		fprintf(stderr, "%s: failed to execute /bin/mount: %s\n",
			progname, strerror(res));
		res = -1;
		goto out_restore;
	}

	res = waitpid(pid, &status, 0);
	if (res == -1)
		fprintf(stderr, "%s: waitpid of %d: %s\n", progname,
			pid, strerror(errno));

	if (status != 0)
		res = -1;

out_restore:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	return res;
}

int fuse_mnt_add_mount(const char *progname, const char *fsname,
		       const char *mnt, const char *type, const char *opts)
{
	if (!mtab_needs_update(mnt))
		return 0;

	return add_mount(progname, fsname, mnt, type, opts);
}

static int exec_umount(const char *progname, const char *rel_mnt, int lazy)
{
	int res;
	int status;
	pid_t pid;
	sigset_t blockmask;
	sigset_t oldmask;
	posix_spawnattr_t attr;
	const char *cmd = "/bin/umount";

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	res = sigprocmask(SIG_BLOCK, &blockmask, &oldmask);
	if (res == -1) {
		fprintf(stderr, "%s: sigprocmask: %s\n", progname, strerror(errno));
		return -1;
	}

	char const * const argv[] = {
		cmd, "-i", lazy ? "-l" : "", rel_mnt, NULL
	};

	res = fuse_mount_posix_spawn_attr(&attr, cmd, oldmask);
	if (res < 0)
		goto out_restore;

	res = posix_spawn(&pid, cmd, NULL, &attr,
			  (char * const *) argv, environ);

	posix_spawnattr_destroy(&attr);

	if (res < 0) {
		fprintf(stderr, "%s: failed to execute /bin/umount: %s\n",
			progname, strerror(-res));
		goto out_restore;
	}

	res = waitpid(pid, &status, 0);
	if (res == -1)
		fprintf(stderr, "%s: waitpid: %s\n", progname, strerror(errno));

	if (status != 0) {
		res = -1;
	}

 out_restore:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	return res;

}

int fuse_mnt_umount(const char *progname, const char *abs_mnt,
		    const char *rel_mnt, int lazy)
{
	int res;

	if (!mtab_needs_update(abs_mnt)) {
		res = umount2(rel_mnt, lazy ? 2 : 0);
		if (res == -1)
			fprintf(stderr, "%s: failed to unmount %s: %s\n",
				progname, abs_mnt, strerror(errno));
		return res;
	}

	return exec_umount(progname, rel_mnt, lazy);
}

static int remove_mount(const char *progname, const char *mnt)
{
	int res;
	int status;
	pid_t pid;
	sigset_t blockmask;
	sigset_t oldmask;
	posix_spawnattr_t attr;
	const char *cmd = "/bin/umount";

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	res = sigprocmask(SIG_BLOCK, &blockmask, &oldmask);
	if (res == -1) {
		fprintf(stderr, "%s: sigprocmask: %s\n", progname, strerror(errno));
		return -1;
	}

	char const * const argv[] =  {
		cmd, "--no-canonicalize", "-i", "--fake", mnt, NULL
	};

	res = fuse_mount_posix_spawn_attr(&attr, cmd, oldmask);
	if (res < 0)
		goto out_restore;

	res = posix_spawn(&pid, cmd, NULL, &attr, (char * const *) argv, environ);
	posix_spawnattr_destroy(&attr);
	if (res < 0) {
		fprintf(stderr, "%s: failed to execute %s: %s\n",
			 progname, cmd, strerror(-res));
		res = -1;
		goto out_restore;
	}

	res = waitpid(pid, &status, 0);
	if (res == -1)
		fprintf(stderr, "%s: waitpid: %s\n", progname, strerror(errno));

	if (status != 0)
		res = -1;

 out_restore:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	return res;
}

int fuse_mnt_remove_mount(const char *progname, const char *mnt)
{
	if (!mtab_needs_update(mnt))
		return 0;

	return remove_mount(progname, mnt);
}

char *fuse_mnt_resolve_path(const char *progname, const char *orig)
{
	char buf[PATH_MAX];
	char *copy;
	char *dst;
	char *end;
	char *lastcomp;
	const char *toresolv;

	if (!orig[0]) {
		fprintf(stderr, "%s: invalid mountpoint '%s'\n", progname,
			orig);
		return NULL;
	}

	copy = strdup(orig);
	if (copy == NULL) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		return NULL;
	}

	toresolv = copy;
	lastcomp = NULL;
	for (end = copy + strlen(copy) - 1; end > copy && *end == '/'; end --);
	if (end[0] != '/') {
		char *tmp;
		end[1] = '\0';
		tmp = strrchr(copy, '/');
		if (tmp == NULL) {
			lastcomp = copy;
			toresolv = ".";
		} else {
			lastcomp = tmp + 1;
			if (tmp == copy)
				toresolv = "/";
		}
		if (strcmp(lastcomp, ".") == 0 || strcmp(lastcomp, "..") == 0) {
			lastcomp = NULL;
			toresolv = copy;
		}
		else if (tmp)
			tmp[0] = '\0';
	}
	if (realpath(toresolv, buf) == NULL) {
		fprintf(stderr, "%s: bad mount point %s: %s\n", progname, orig,
			strerror(errno));
		free(copy);
		return NULL;
	}
	if (lastcomp == NULL)
		dst = strdup(buf);
	else {
		dst = (char *) malloc(strlen(buf) + 1 + strlen(lastcomp) + 1);
		if (dst) {
			unsigned buflen = strlen(buf);
			if (buflen && buf[buflen-1] == '/')
				sprintf(dst, "%s%s", buf, lastcomp);
			else
				sprintf(dst, "%s/%s", buf, lastcomp);
		}
	}
	free(copy);
	if (dst == NULL)
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
	return dst;
}

int fuse_mnt_check_fuseblk(void)
{
	char buf[256];
	FILE *f = fopen("/proc/filesystems", "r");
	if (!f)
		return 1;

	while (fgets(buf, sizeof(buf), f))
		if (strstr(buf, "fuseblk\n")) {
			fclose(f);
			return 1;
		}

	fclose(f);
	return 0;
}

int fuse_mnt_parse_fuse_fd(const char *mountpoint)
{
	int fd = -1;
	int len = 0;

	if (mountpoint == NULL) {
		fprintf(stderr, "Invalid null-ptr mount-point!\n");
		return -1;
	}

	if (sscanf(mountpoint, "/dev/fd/%u%n", &fd, &len) == 1 &&
	    len == strlen(mountpoint)) {
		return fd;
	}

	return -1;
}
