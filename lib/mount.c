/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Architecture specific file system mounting (Linux).

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "config.h"
#include "fuse_i.h"
#include "fuse_misc.h"
#include "fuse_opt.h"
#include "mount_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/mount.h>

#ifdef __NetBSD__
#include <perfuse.h>

#define MS_RDONLY	MNT_RDONLY
#define MS_NOSUID	MNT_NOSUID
#define MS_NODEV	MNT_NODEV
#define MS_NOEXEC	MNT_NOEXEC
#define MS_SYNCHRONOUS	MNT_SYNCHRONOUS
#define MS_NOATIME	MNT_NOATIME

#define umount2(mnt, flags) unmount(mnt, (flags == 2) ? MNT_FORCE : 0)
#endif

#define FUSERMOUNT_PROG		"fusermount3"
#define FUSE_COMMFD_ENV		"_FUSE_COMMFD"

#ifndef HAVE_FORK
#define fork() vfork()
#endif

#ifndef MS_DIRSYNC
#define MS_DIRSYNC 128
#endif

enum {
	KEY_KERN_FLAG,
	KEY_KERN_OPT,
	KEY_FUSERMOUNT_OPT,
	KEY_SUBTYPE_OPT,
	KEY_MTAB_OPT,
	KEY_ALLOW_OTHER,
	KEY_RO,
};

struct mount_opts {
	int allow_other;
	int flags;
	int auto_unmount;
	int blkdev;
	char *fsname;
	char *subtype;
	char *subtype_opt;
	char *mtab_opts;
	char *fusermount_opts;
	char *kernel_opts;
	unsigned max_read;
};

#define FUSE_MOUNT_OPT(t, p) { t, offsetof(struct mount_opts, p), 1 }

static const struct fuse_opt fuse_mount_opts[] = {
	FUSE_MOUNT_OPT("allow_other",		allow_other),
	FUSE_MOUNT_OPT("blkdev",		blkdev),
	FUSE_MOUNT_OPT("auto_unmount",		auto_unmount),
	FUSE_MOUNT_OPT("fsname=%s",		fsname),
	FUSE_MOUNT_OPT("max_read=%u",		max_read),
	FUSE_MOUNT_OPT("subtype=%s",		subtype),
	FUSE_OPT_KEY("allow_other",		KEY_KERN_OPT),
	FUSE_OPT_KEY("auto_unmount",		KEY_FUSERMOUNT_OPT),
	FUSE_OPT_KEY("blkdev",			KEY_FUSERMOUNT_OPT),
	FUSE_OPT_KEY("fsname=",			KEY_FUSERMOUNT_OPT),
	FUSE_OPT_KEY("subtype=",		KEY_SUBTYPE_OPT),
	FUSE_OPT_KEY("blksize=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("default_permissions",	KEY_KERN_OPT),
	FUSE_OPT_KEY("context=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("fscontext=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("defcontext=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("rootcontext=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("max_read=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("user=",			KEY_MTAB_OPT),
	FUSE_OPT_KEY("-r",			KEY_RO),
	FUSE_OPT_KEY("ro",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("rw",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("suid",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("nosuid",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("dev",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("nodev",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("exec",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("noexec",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("async",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("sync",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("dirsync",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("atime",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("noatime",			KEY_KERN_FLAG),
	FUSE_OPT_END
};

static void exec_fusermount(const char *argv[])
{
	execv(FUSERMOUNT_DIR "/" FUSERMOUNT_PROG, (char **) argv);
	execvp(FUSERMOUNT_PROG, (char **) argv);
}

void fuse_mount_version(void)
{
	int pid = fork();
	if (!pid) {
		const char *argv[] = { FUSERMOUNT_PROG, "--version", NULL };
		exec_fusermount(argv);
		_exit(1);
	} else if (pid != -1)
		waitpid(pid, NULL, 0);
}

struct mount_flags {
	const char *opt;
	unsigned long flag;
	int on;
};

static const struct mount_flags mount_flags[] = {
	{"rw",	    MS_RDONLY,	    0},
	{"ro",	    MS_RDONLY,	    1},
	{"suid",    MS_NOSUID,	    0},
	{"nosuid",  MS_NOSUID,	    1},
	{"dev",	    MS_NODEV,	    0},
	{"nodev",   MS_NODEV,	    1},
	{"exec",    MS_NOEXEC,	    0},
	{"noexec",  MS_NOEXEC,	    1},
	{"async",   MS_SYNCHRONOUS, 0},
	{"sync",    MS_SYNCHRONOUS, 1},
	{"atime",   MS_NOATIME,	    0},
	{"noatime", MS_NOATIME,	    1},
#ifndef __NetBSD__
	{"dirsync", MS_DIRSYNC,	    1},
#endif
	{NULL,	    0,		    0}
};

unsigned get_max_read(struct mount_opts *o)
{
	return o->max_read;
}

static void set_mount_flag(const char *s, int *flags)
{
	int i;

	for (i = 0; mount_flags[i].opt != NULL; i++) {
		const char *opt = mount_flags[i].opt;
		if (strcmp(opt, s) == 0) {
			if (mount_flags[i].on)
				*flags |= mount_flags[i].flag;
			else
				*flags &= ~mount_flags[i].flag;
			return;
		}
	}
	fprintf(stderr, "fuse: internal error, can't find mount flag\n");
	abort();
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
	case KEY_KERN_FLAG:
		set_mount_flag(arg, &mo->flags);
		return 0;

	case KEY_KERN_OPT:
		return fuse_opt_add_opt(&mo->kernel_opts, arg);

	case KEY_FUSERMOUNT_OPT:
		return fuse_opt_add_opt_escaped(&mo->fusermount_opts, arg);

	case KEY_SUBTYPE_OPT:
		return fuse_opt_add_opt(&mo->subtype_opt, arg);

	case KEY_MTAB_OPT:
		return fuse_opt_add_opt(&mo->mtab_opts, arg);
	}

	/* Pass through unknown options */
	return 1;
}

/* return value:
 * >= 0	 => fd
 * -1	 => error
 */
static int receive_fd(int fd)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	int rv;
	size_t ccmsg[CMSG_SPACE(sizeof(int)) / sizeof(size_t)];
	struct cmsghdr *cmsg;

	iov.iov_base = buf;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	/* old BSD implementations should use msg_accrights instead of
	 * msg_control; the interface is different. */
	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	while(((rv = recvmsg(fd, &msg, 0)) == -1) && errno == EINTR);
	if (rv == -1) {
		perror("recvmsg");
		return -1;
	}
	if(!rv) {
		/* EOF */
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "got control message of unknown type %d\n",
			cmsg->cmsg_type);
		return -1;
	}
	return *(int*)CMSG_DATA(cmsg);
}

void fuse_kern_unmount(const char *mountpoint, int fd)
{
	int res;
	int pid;

	if (fd != -1) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = 0;
		res = poll(&pfd, 1, 0);

		/* Need to close file descriptor, otherwise synchronous umount
		   would recurse into filesystem, and deadlock.

		   Caller expects fuse_kern_unmount to close the fd, so close it
		   anyway. */
		close(fd);

		/* If file poll returns POLLERR on the device file descriptor,
		   then the filesystem is already unmounted or the connection
		   was severed via /sys/fs/fuse/connections/NNN/abort */
		if (res == 1 && (pfd.revents & POLLERR))
			return;
	}

	if (geteuid() == 0) {
		fuse_mnt_umount("fuse", mountpoint, mountpoint,  1);
		return;
	}

	res = umount2(mountpoint, 2);
	if (res == 0)
		return;

	pid = fork();
	if(pid == -1)
		return;

	if(pid == 0) {
		const char *argv[] = { FUSERMOUNT_PROG, "-u", "-q", "-z",
				       "--", mountpoint, NULL };

		exec_fusermount(argv);
		_exit(1);
	}
	waitpid(pid, NULL, 0);
}

static int fuse_mount_fusermount(const char *mountpoint, struct mount_opts *mo,
		const char *opts, int quiet)
{
	int fds[2], pid;
	int res;
	int rv;

	if (!mountpoint) {
		fprintf(stderr, "fuse: missing mountpoint parameter\n");
		return -1;
	}

	res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
	if(res == -1) {
		perror("fuse: socketpair() failed");
		return -1;
	}

	pid = fork();
	if(pid == -1) {
		perror("fuse: fork() failed");
		close(fds[0]);
		close(fds[1]);
		return -1;
	}

	if(pid == 0) {
		char env[10];
		const char *argv[32];
		int a = 0;

		if (quiet) {
			int fd = open("/dev/null", O_RDONLY);
			if (fd != -1) {
				dup2(fd, 1);
				dup2(fd, 2);
			}
		}

		argv[a++] = FUSERMOUNT_PROG;
		if (opts) {
			argv[a++] = "-o";
			argv[a++] = opts;
		}
		argv[a++] = "--";
		argv[a++] = mountpoint;
		argv[a++] = NULL;

		close(fds[1]);
		fcntl(fds[0], F_SETFD, 0);
		snprintf(env, sizeof(env), "%i", fds[0]);
		setenv(FUSE_COMMFD_ENV, env, 1);
		exec_fusermount(argv);
		perror("fuse: failed to exec fusermount3");
		_exit(1);
	}

	close(fds[0]);
	rv = receive_fd(fds[1]);

	if (!mo->auto_unmount) {
		/* with auto_unmount option fusermount3 will not exit until
		   this socket is closed */
		close(fds[1]);
		waitpid(pid, NULL, 0); /* bury zombie */
	}

	if (rv >= 0)
		fcntl(rv, F_SETFD, FD_CLOEXEC);

	return rv;
}

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int fuse_mount_sys(const char *mnt, struct mount_opts *mo,
			  const char *mnt_opts)
{
	char tmp[128];
	const char *devname = "/dev/fuse";
	char *source = NULL;
	char *type = NULL;
	struct stat stbuf;
	int fd;
	int res;

	if (!mnt) {
		fprintf(stderr, "fuse: missing mountpoint parameter\n");
		return -1;
	}

	res = stat(mnt, &stbuf);
	if (res == -1) {
		fprintf(stderr ,"fuse: failed to access mountpoint %s: %s\n",
			mnt, strerror(errno));
		return -1;
	}

	if (mo->auto_unmount) {
		/* Tell the caller to fallback to fusermount3 because
		   auto-unmount does not work otherwise. */
		return -2;
	}

	fd = open(devname, O_RDWR | O_CLOEXEC);
	if (fd == -1) {
		if (errno == ENODEV || errno == ENOENT)
			fprintf(stderr, "fuse: device not found, try 'modprobe fuse' first\n");
		else
			fprintf(stderr, "fuse: failed to open %s: %s\n",
				devname, strerror(errno));
		return -1;
	}
	if (!O_CLOEXEC)
		fcntl(fd, F_SETFD, FD_CLOEXEC);

	snprintf(tmp, sizeof(tmp),  "fd=%i,rootmode=%o,user_id=%u,group_id=%u",
		 fd, stbuf.st_mode & S_IFMT, getuid(), getgid());

	res = fuse_opt_add_opt(&mo->kernel_opts, tmp);
	if (res == -1)
		goto out_close;

	source = malloc((mo->fsname ? strlen(mo->fsname) : 0) +
			(mo->subtype ? strlen(mo->subtype) : 0) +
			strlen(devname) + 32);

	type = malloc((mo->subtype ? strlen(mo->subtype) : 0) + 32);
	if (!type || !source) {
		fprintf(stderr, "fuse: failed to allocate memory\n");
		goto out_close;
	}

	strcpy(type, mo->blkdev ? "fuseblk" : "fuse");
	if (mo->subtype) {
		strcat(type, ".");
		strcat(type, mo->subtype);
	}
	strcpy(source,
	       mo->fsname ? mo->fsname : (mo->subtype ? mo->subtype : devname));

	res = mount(source, mnt, type, mo->flags, mo->kernel_opts);
	if (res == -1 && errno == ENODEV && mo->subtype) {
		/* Probably missing subtype support */
		strcpy(type, mo->blkdev ? "fuseblk" : "fuse");
		if (mo->fsname) {
			if (!mo->blkdev)
				sprintf(source, "%s#%s", mo->subtype,
					mo->fsname);
		} else {
			strcpy(source, type);
		}
		res = mount(source, mnt, type, mo->flags, mo->kernel_opts);
	}
	if (res == -1) {
		/*
		 * Maybe kernel doesn't support unprivileged mounts, in this
		 * case try falling back to fusermount3
		 */
		if (errno == EPERM) {
			res = -2;
		} else {
			int errno_save = errno;
			if (mo->blkdev && errno == ENODEV &&
			    !fuse_mnt_check_fuseblk())
				fprintf(stderr,
					"fuse: 'fuseblk' support missing\n");
			else
				fprintf(stderr, "fuse: mount failed: %s\n",
					strerror(errno_save));
		}

		goto out_close;
	}

#ifndef __NetBSD__
#ifndef IGNORE_MTAB
	if (geteuid() == 0) {
		char *newmnt = fuse_mnt_resolve_path("fuse", mnt);
		res = -1;
		if (!newmnt)
			goto out_umount;

		res = fuse_mnt_add_mount("fuse", source, newmnt, type,
					 mnt_opts);
		free(newmnt);
		if (res == -1)
			goto out_umount;
	}
#endif /* IGNORE_MTAB */
#endif /* __NetBSD__ */
	free(type);
	free(source);

	return fd;

out_umount:
	umount2(mnt, 2); /* lazy umount */
out_close:
	free(type);
	free(source);
	close(fd);
	return res;
}

static int get_mnt_flag_opts(char **mnt_optsp, int flags)
{
	int i;

	if (!(flags & MS_RDONLY) && fuse_opt_add_opt(mnt_optsp, "rw") == -1)
		return -1;

	for (i = 0; mount_flags[i].opt != NULL; i++) {
		if (mount_flags[i].on && (flags & mount_flags[i].flag) &&
		    fuse_opt_add_opt(mnt_optsp, mount_flags[i].opt) == -1)
			return -1;
	}
	return 0;
}

struct mount_opts *parse_mount_opts(struct fuse_args *args)
{
	struct mount_opts *mo;

	mo = (struct mount_opts*) malloc(sizeof(struct mount_opts));
	if (mo == NULL)
		return NULL;

	memset(mo, 0, sizeof(struct mount_opts));
	mo->flags = MS_NOSUID | MS_NODEV;

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
	free(mo->fsname);
	free(mo->subtype);
	free(mo->fusermount_opts);
	free(mo->subtype_opt);
	free(mo->kernel_opts);
	free(mo->mtab_opts);
	free(mo);
}


int fuse_kern_mount(const char *mountpoint, struct mount_opts *mo)
{
	int res = -1;
	char *mnt_opts = NULL;

	res = -1;
	if (get_mnt_flag_opts(&mnt_opts, mo->flags) == -1)
		goto out;
	if (mo->kernel_opts && fuse_opt_add_opt(&mnt_opts, mo->kernel_opts) == -1)
		goto out;
	if (mo->mtab_opts &&  fuse_opt_add_opt(&mnt_opts, mo->mtab_opts) == -1)
		goto out;

	res = fuse_mount_sys(mountpoint, mo, mnt_opts);
	if (res == -2) {
		if (mo->fusermount_opts &&
		    fuse_opt_add_opt(&mnt_opts, mo->fusermount_opts) == -1)
			goto out;

		if (mo->subtype) {
			char *tmp_opts = NULL;

			res = -1;
			if (fuse_opt_add_opt(&tmp_opts, mnt_opts) == -1 ||
			    fuse_opt_add_opt(&tmp_opts, mo->subtype_opt) == -1) {
				free(tmp_opts);
				goto out;
			}

			res = fuse_mount_fusermount(mountpoint, mo, tmp_opts, 1);
			free(tmp_opts);
			if (res == -1)
				res = fuse_mount_fusermount(mountpoint, mo,
							    mnt_opts, 0);
		} else {
			res = fuse_mount_fusermount(mountpoint, mo, mnt_opts, 0);
		}
	}
out:
	free(mnt_opts);
	return res;
}
