/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Architecture specific file system mounting (Linux).

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt.
*/

/* For environ */
#define _GNU_SOURCE

#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_misc.h"
#include "fuse_opt.h"
#include "mount_util.h"
#include "mount_i_linux.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "fuse_mount_compat.h"

#define FUSERMOUNT_PROG		"fusermount3"
#define FUSE_COMMFD_ENV		"_FUSE_COMMFD"
#define FUSE_COMMFD2_ENV	"_FUSE_COMMFD2"
#define ARG_FD_ENTRY_SIZE	30

	enum { KEY_KERN_FLAG,
	       KEY_KERN_OPT,
	       KEY_FUSERMOUNT_OPT,
	       KEY_SUBTYPE_OPT,
	       KEY_MTAB_OPT,
	       KEY_ALLOW_OTHER,
	       KEY_RO,
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
	FUSE_OPT_KEY("-n",			KEY_MTAB_OPT),
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
	FUSE_OPT_KEY("noatime",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("nodiratime",		KEY_KERN_FLAG),
	FUSE_OPT_KEY("nostrictatime",		KEY_KERN_FLAG),
	FUSE_OPT_KEY("symfollow",		KEY_KERN_FLAG),
	FUSE_OPT_KEY("nosymfollow",		KEY_KERN_FLAG),
	FUSE_OPT_END
};

/*
 * Running fusermount by calling 'posix_spawn'
 *
 * @param out_pid might be NULL
 */
static int fusermount_posix_spawn(posix_spawn_file_actions_t *action,
				  char const * const argv[], pid_t *out_pid)
{
	const char *full_path = FUSERMOUNT_DIR "/" FUSERMOUNT_PROG;
	pid_t pid;

	/* See man 7 environ for the global environ pointer */

	/* first try the install path */
	int status = posix_spawn(&pid, full_path,  action, NULL,
				 (char * const *) argv, environ);
	if (status != 0) {
		/* if that fails, try a system install */
		status = posix_spawnp(&pid, FUSERMOUNT_PROG, action, NULL,
				      (char * const *) argv, environ);
	}

	if (status != 0) {
		fuse_log(FUSE_LOG_ERR, "Failed to call '%s': %s\n",
			 FUSERMOUNT_PROG, strerror(status));
		return -status;
	}

	if (out_pid)
		*out_pid = pid;
	else
		waitpid(pid, NULL, 0); /* FIXME: check exit code and return error if any */

	return 0;
}

void fuse_mount_version(void)
{
	char const *const argv[] = {FUSERMOUNT_PROG, "--version", NULL};
	int status = fusermount_posix_spawn(NULL, argv, NULL);

	if(status != 0)
		fuse_log(FUSE_LOG_ERR, "Running '%s --version' failed",
			 FUSERMOUNT_PROG);
}

unsigned int get_max_read(const struct mount_opts *o)
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
	fuse_log(FUSE_LOG_ERR, "fuse: internal error, can't find mount flag\n");
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

	/* Third party options like 'x-gvfs-notrash' */
	case FUSE_OPT_KEY_OPT:
		return (strncmp("x-", arg, 2) == 0) ?
			fuse_opt_add_opt(&mo->mtab_opts, arg) :
			1;
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
	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	while(((rv = recvmsg(fd, &msg, 0)) == -1) && errno == EINTR);
	if (rv == -1) {
		fuse_log(FUSE_LOG_ERR, "recvmsg failed: %s", strerror(errno));
		return -1;
	}
	if(!rv) {
		/* EOF */
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fuse_log(FUSE_LOG_ERR, "error retrieving control message header\n");
		return -1;
	}
	if (cmsg->cmsg_type != SCM_RIGHTS) {
		fuse_log(FUSE_LOG_ERR, "got control message of unknown type %d\n",
			cmsg->cmsg_type);
		return -1;
	}
	return *(int*)CMSG_DATA(cmsg);
}

void fuse_kern_unmount(const char *mountpoint, int fd)
{
	int res;

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

	char const * const argv[] =
		{ FUSERMOUNT_PROG, "--unmount", "--quiet", "--lazy",
				"--", mountpoint, NULL };
	int status = fusermount_posix_spawn(NULL, argv, NULL);
	if(status != 0) {
		fuse_log(FUSE_LOG_ERR, "Spawning %s to unmount failed: %s",
			 FUSERMOUNT_PROG, strerror(-status));
		return;
	}
}

static int setup_auto_unmount(const char *mountpoint, int quiet)
{
	int fds[2];
	pid_t pid;
	int res;

	if (!mountpoint) {
		fuse_log(FUSE_LOG_ERR, "fuse: missing mountpoint parameter\n");
		return -1;
	}

	res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
	if(res == -1) {
		fuse_log(FUSE_LOG_ERR, "Setting up auto-unmount socketpair() failed: %s\n",
			 strerror(errno));
		return -1;
	}

	char arg_fd_entry[ARG_FD_ENTRY_SIZE];
	snprintf(arg_fd_entry, sizeof(arg_fd_entry), "%i", fds[0]);
	setenv(FUSE_COMMFD_ENV, arg_fd_entry, 1);
	/*
	 * This helps to identify the FD hold by parent process.
	 * In auto-unmount case, parent process can close this FD explicitly to do unmount.
	 * The FD[1] can be got via getenv(FUSE_COMMFD2_ENV).
	 * One potential use case is to satisfy FD-Leak checks.
	 */
	snprintf(arg_fd_entry, sizeof(arg_fd_entry), "%i", fds[1]);
	setenv(FUSE_COMMFD2_ENV, arg_fd_entry, 1);

	char const *const argv[] = {
		FUSERMOUNT_PROG,
		"--auto-unmount",
		"--",
		mountpoint,
		NULL,
	};

	// TODO: add error handling for all manipulations of action.
	posix_spawn_file_actions_t action;
	posix_spawn_file_actions_init(&action);

	if (quiet) {
		posix_spawn_file_actions_addopen(&action, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
		posix_spawn_file_actions_addopen(&action, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
	}
	posix_spawn_file_actions_addclose(&action, fds[1]);

	/*
	 * auto-umount runs in the background - it is not waiting for the
	 * process
	 */
	int status = fusermount_posix_spawn(&action, argv, &pid);

	posix_spawn_file_actions_destroy(&action);

	if(status != 0) {
		close(fds[0]);
		close(fds[1]);
		fuse_log(FUSE_LOG_ERR, "fuse: Setting up auto-unmount failed (spawn): %s",
			     strerror(-status));
		return -1;
	}
	// passed to child now, so can close here.
	close(fds[0]);

	// Now fusermount3 will only exit when fds[1] closes automatically when our
	// process exits.
	return 0;
	// Note: fds[1] is leakend and doesn't get FD_CLOEXEC
}

static int fuse_mount_fusermount(const char *mountpoint, const struct mount_opts *mo,
		const char *opts, int quiet)
{
	int fds[2];
	pid_t pid;
	int res;

	if (!mountpoint) {
		fuse_log(FUSE_LOG_ERR, "fuse: missing mountpoint parameter\n");
		return -1;
	}

	res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
	if(res == -1) {
		fuse_log(FUSE_LOG_ERR, "Running %s: socketpair() failed: %s\n",
			 FUSERMOUNT_PROG, strerror(errno));
		return -1;
	}

	char arg_fd_entry[ARG_FD_ENTRY_SIZE];
	snprintf(arg_fd_entry, sizeof(arg_fd_entry), "%i", fds[0]);
	setenv(FUSE_COMMFD_ENV, arg_fd_entry, 1);
	/*
	 * This helps to identify the FD hold by parent process.
	 * In auto-unmount case, parent process can close this FD explicitly to do unmount.
	 * The FD[1] can be got via getenv(FUSE_COMMFD2_ENV).
	 * One potential use case is to satisfy FD-Leak checks.
	 */
	snprintf(arg_fd_entry, sizeof(arg_fd_entry), "%i", fds[1]);
	setenv(FUSE_COMMFD2_ENV, arg_fd_entry, 1);

	char const *const argv[] = {
		FUSERMOUNT_PROG,
		"-o", opts ? opts : "",
		"--",
		mountpoint,
		NULL,
	};


	posix_spawn_file_actions_t action;
	posix_spawn_file_actions_init(&action);

	if (quiet) {
		posix_spawn_file_actions_addopen(&action, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
		posix_spawn_file_actions_addopen(&action, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
	}
	posix_spawn_file_actions_addclose(&action, fds[1]);

	int status = fusermount_posix_spawn(&action, argv, &pid);

	posix_spawn_file_actions_destroy(&action);

	if(status != 0) {
		close(fds[0]);
		close(fds[1]);
		fuse_log(FUSE_LOG_ERR, "posix_spawn(p)() for %s failed: %s",
			 FUSERMOUNT_PROG, strerror(-status));
		return -1;
	}

	// passed to child now, so can close here.
	close(fds[0]);

	int fd = receive_fd(fds[1]);

	if (!mo->auto_unmount) {
		/* with auto_unmount option fusermount3 will not exit until
		   this socket is closed */
		close(fds[1]);
		waitpid(pid, NULL, 0); /* bury zombie */
	}

	if (fd >= 0)
		fcntl(fd, F_SETFD, FD_CLOEXEC);

	return fd;
}

/*
 * Mount using fusermount3 with --sync-init flag for bidirectional fd exchange
 * Used by new mount API when privileged mount fails with EPERM
 *
 * Returns: fd of /dev/fuse opened by fusermount on success, -1 on failure
 * On success, *sock_fd_out contains the socket fd for signaling fusermount3
 */
int mount_fusermount_obtain_fd(const char *mountpoint, struct mount_opts *mo,
			       const char *opts, int *sock_fd_out,
			       pid_t *pid_out)
{
	int fds[2];
	pid_t pid;
	int res;
	char arg_fd_entry[ARG_FD_ENTRY_SIZE];
	posix_spawn_file_actions_t action;
	int fd, status;

	(void)mo;

	if (!mountpoint) {
		fuse_log(FUSE_LOG_ERR, "fuse: missing mountpoint parameter\n");
		return -1;
	}

	res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
	if (res == -1) {
		fuse_log(FUSE_LOG_ERR, "Running %s: socketpair() failed: %s\n",
			 FUSERMOUNT_PROG, strerror(errno));
		return -1;
	}

	snprintf(arg_fd_entry, sizeof(arg_fd_entry), "%i", fds[0]);
	setenv(FUSE_COMMFD_ENV, arg_fd_entry, 1);
	snprintf(arg_fd_entry, sizeof(arg_fd_entry), "%i", fds[1]);
	setenv(FUSE_COMMFD2_ENV, arg_fd_entry, 1);

	char const *const argv[] = {
		FUSERMOUNT_PROG,
		"--sync-init",
		"-o", opts ? opts : "",
		"--",
		mountpoint,
		NULL,
	};

	posix_spawn_file_actions_init(&action);
	posix_spawn_file_actions_addclose(&action, fds[1]);
	status = fusermount_posix_spawn(&action, argv, &pid);
	posix_spawn_file_actions_destroy(&action);

	if (status != 0) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}

	close(fds[0]);

	fd = receive_fd(fds[1]);
	if (fd < 0) {
		close(fds[1]);
		waitpid(pid, NULL, 0);
		return -1;
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);

	/* Return socket fd for later signaling */
	*sock_fd_out = fds[1];
	*pid_out = pid;

	return fd;
}

/*
 * Send proceed signal to fusermount3 and wait for mount result
 * Returns: 0 on success, -1 on failure
 */
int fuse_fusermount_proceed_mnt(int sock_fd)
{
	char buf = '\0';
	ssize_t res;

	/* Send proceed signal */
	do {
		res = send(sock_fd, &buf, 1, 0);
	} while (res == -1 && errno == EINTR);

	if (res != 1) {
		fuse_log(FUSE_LOG_ERR, "fuse: failed to send proceed signal: %s\n",
			 strerror(errno));
		return -1;
	}

	/* Wait for mount result from fusermount3 (4-byte error code) */
	int32_t status;

	do {
		res = recv(sock_fd, &status, sizeof(status), 0);
	} while (res == -1 && errno == EINTR);

	if (res != sizeof(status)) {
		if (res == 0)
			fuse_log(FUSE_LOG_ERR, "fuse: fusermount3 closed connection\n");
		else
			fuse_log(FUSE_LOG_ERR, "fuse: failed to receive mount status: %s\n",
				 strerror(errno));
		return -1;
	}

	if (status != 0) {
		if (status != -EPERM)
			fuse_log(FUSE_LOG_ERR, "fuse: fusermount3 mount failed: %s\n",
				 strerror(-status));
		return -1;
	}

	return 0;
}

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int fuse_kern_mount_prepare(const char *mnt,
			    struct mount_opts *mo)
{
	char tmp[128];
	const char *devname = fuse_mnt_get_devname();
	struct stat stbuf;
	int fd;
	int res;

	if (!mnt) {
		fuse_log(FUSE_LOG_ERR, "fuse: missing mountpoint parameter\n");
		return -1;
	}

	res = stat(mnt, &stbuf);
	if (res == -1) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: failed to access mountpoint %s: %s\n", mnt,
			 strerror(errno));
		return -1;
	}

	/* codeql[cpp/path-injection] devname is verified */
	fd = open(devname, O_RDWR | O_CLOEXEC);
	if (fd == -1) {
		if (errno == ENODEV || errno == ENOENT)
			fuse_log(
				FUSE_LOG_ERR,
				"fuse: device %s not found. Kernel module not loaded?\n",
				devname);
		else
			fuse_log(FUSE_LOG_ERR, "fuse: failed to open %s: %s\n",
				 devname, strerror(errno));
		return -1;
	}
	if (!O_CLOEXEC)
		fcntl(fd, F_SETFD, FD_CLOEXEC);

	snprintf(tmp, sizeof(tmp), "fd=%i,rootmode=%o,user_id=%u,group_id=%u",
		 fd, stbuf.st_mode & S_IFMT, getuid(), getgid());

	res = fuse_opt_add_opt(&mo->kernel_opts, tmp);
	if (res == -1)
		goto out_close;

	return fd;

out_close:
	close(fd);
	return -1;
}

#if defined(HAVE_NEW_MOUNT_API)
/**
 * Wrapper for fuse_kern_fsmount that accepts struct mount_opts
 * @mnt: mountpoint
 * @mo: mount options
 * @mnt_opts: mount options to pass to the kernel
 *
 * Returns: 0 on success, -1 on failure with errno set
 */
int fuse_kern_fsmount_mo(const char *mnt, const struct mount_opts *mo,
			 const char *mnt_opts)
{
	/* codeql[cpp/path-injection] verification is in the function */
	const char *devname = fuse_mnt_get_devname();

	return fuse_kern_fsmount(mnt, mo->flags, mo->blkdev, mo->fsname,
				 mo->subtype, devname, mo->kernel_opts,
				 mnt_opts);
}
#endif

/**
 * Complete the mount operation with an already-opened fd
 * @mnt: mountpoint
 * @mo: mount options
 * @mnt_opts: mount options to pass to the kernel
 *
 * Returns: 0 on success, -1 on failure,
 *          FUSE_MOUNT_FALLBACK_NEEDED if fusermount should be used
 */
int fuse_kern_do_mount(const char *mnt, struct mount_opts *mo,
		       const char *mnt_opts)
{
	char *source = NULL;
	char *type = NULL;
	int res;
	const char *devname = fuse_mnt_get_devname();
	res = -ENOMEM;
	source = fuse_mnt_build_source(mo->fsname, mo->subtype, devname);
	type = fuse_mnt_build_type(mo->blkdev, mo->subtype);
	if (!type || !source) {
		fuse_log(FUSE_LOG_ERR, "%s: failed to allocate memory\n",
			 __func__);
		goto out_close;
	}

	res = mount(source, mnt, type, mo->flags, mo->kernel_opts);
	if (res == -1 && errno == ENODEV && mo->subtype) {
		/* Probably missing subtype support */

		/*
		 * The allocated space by fuse_mnt_build_{source,type}
		 * might be too small.
		 */
		free(source);
		free(type);

		type = fuse_mnt_build_type(mo->blkdev, NULL);
		source = fuse_mnt_build_source(mo->fsname, NULL, devname);

		if (!type || !source) {
			fuse_log(FUSE_LOG_ERR,
				 "%s: failed to allocate memory\n",
				 __func__);
			goto out_close;
		}

		res = mount(source, mnt, type, mo->flags, mo->kernel_opts);
	}
	if (res == -1) {
		/*
		 * Maybe kernel doesn't support unprivileged mounts, in this
		 * case try falling back to fusermount3
		 */
		if (errno == EPERM) {
			res = FUSE_MOUNT_FALLBACK_NEEDED;
		} else {
			int errno_save = errno;
			if (mo->blkdev && errno == ENODEV &&
			    !fuse_mnt_check_fuseblk())
				fuse_log(FUSE_LOG_ERR,
					 "fuse: 'fuseblk' support missing\n");
			else
				fuse_log(FUSE_LOG_ERR,
					 "fuse: mount failed: %s\n",
					 strerror(errno_save));
		}

		goto out_close;
	}

	res = fuse_mnt_add_mount_helper(mnt, source, type, mnt_opts);
	if (res == -1)
		goto out_umount;

	free(type);
	free(source);

	return 0;

out_umount:
	umount2(mnt, 2); /* lazy umount */
out_close:
	free(type);
	free(source);
	return res;
}

static int fuse_mount_sys(const char *mnt, struct mount_opts *mo,
				  const char *mnt_opts)
{
	int fd;
	int res;

	fd = fuse_kern_mount_prepare(mnt, mo);
	if (fd == -1)
		return -1;

	res = fuse_kern_do_mount(mnt, mo, mnt_opts);
	if (res) {
		close(fd);
		return res;
	}

	return fd;
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

int fuse_kern_mount_get_base_mnt_opts(const struct mount_opts *mo, char **mnt_optsp)
{
	if (get_mnt_flag_opts(mnt_optsp, mo->flags) == -1)
		return -1;
	if (mo->kernel_opts && fuse_opt_add_opt(mnt_optsp, mo->kernel_opts) == -1)
		return -1;
	if (mo->mtab_opts &&  fuse_opt_add_opt(mnt_optsp, mo->mtab_opts) == -1)
		return -1;
	return 0;
}

int fuse_kern_mount(const char *mountpoint, struct mount_opts *mo)
{
	int res = -1;
	char *mnt_opts = NULL;

	res = -1;
	if (fuse_kern_mount_get_base_mnt_opts(mo, &mnt_opts) == -1)
		goto out;

	res = fuse_mount_sys(mountpoint, mo, mnt_opts);
	if (res >= 0 && mo->auto_unmount) {
		if(0 > setup_auto_unmount(mountpoint, 0)) {
			// Something went wrong, let's umount like in fuse_mount_sys.
			umount2(mountpoint, MNT_DETACH); /* lazy umount */
			res = -1;
		}
	} else if (res == FUSE_MOUNT_FALLBACK_NEEDED) {
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
