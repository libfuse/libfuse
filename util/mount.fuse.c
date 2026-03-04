/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/* For environ */
#define _GNU_SOURCE

#include "fuse_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/wait.h>
#ifdef HAVE_SERVICEMOUNT
#include <spawn.h>
#endif

#ifdef linux
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/securebits.h>
/* for 2.6 kernels */
#if !defined(SECBIT_KEEP_CAPS) && defined(SECURE_KEEP_CAPS)
#define SECBIT_KEEP_CAPS (issecure_mask(SECURE_KEEP_CAPS))
#endif
#if !defined(SECBIT_KEEP_CAPS_LOCKED) && defined(SECURE_KEEP_CAPS_LOCKED)
#define SECBIT_KEEP_CAPS_LOCKED (issecure_mask(SECURE_KEEP_CAPS_LOCKED))
#endif
#if !defined(SECBIT_NO_SETUID_FIXUP) && defined(SECURE_NO_SETUID_FIXUP)
#define SECBIT_NO_SETUID_FIXUP (issecure_mask(SECURE_NO_SETUID_FIXUP))
#endif
#if !defined(SECBIT_NO_SETUID_FIXUP_LOCKED) && defined(SECURE_NO_SETUID_FIXUP_LOCKED)
#define SECBIT_NO_SETUID_FIXUP_LOCKED (issecure_mask(SECURE_NO_SETUID_FIXUP_LOCKED))
#endif
#if !defined(SECBIT_NOROOT) && defined(SECURE_NOROOT)
#define SECBIT_NOROOT (issecure_mask(SECURE_NOROOT))
#endif
#if !defined(SECBIT_NOROOT_LOCKED) && defined(SECURE_NOROOT_LOCKED)
#define SECBIT_NOROOT_LOCKED (issecure_mask(SECURE_NOROOT_LOCKED))
#endif
#endif
/* linux < 3.5 */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#include "fuse.h"
#ifdef HAVE_SERVICEMOUNT
# include "mount_service.h"
#endif

static char *progname;

static char *xstrdup(const char *s)
{
	char *t = strdup(s);
	if (!t) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		exit(1);
	}
	return t;
}

static void *xrealloc(void *oldptr, size_t size)
{
	void *ptr = realloc(oldptr, size);
	if (!ptr) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		exit(1);
	}
	return ptr;
}

static void add_arg(char **cmdp, const char *opt)
{
	size_t optlen = strlen(opt);
	size_t cmdlen = *cmdp ? strlen(*cmdp) : 0;
	if (optlen >= (SIZE_MAX - cmdlen - 4)/4) {
		fprintf(stderr, "%s: argument too long\n", progname);
		exit(1);
	}
	char *cmd = xrealloc(*cmdp, cmdlen + optlen * 4 + 4);
	char *s;
	s = cmd + cmdlen;
	if (*cmdp)
		*s++ = ' ';

	*s++ = '\'';
	for (; *opt; opt++) {
		if (*opt == '\'') {
			*s++ = '\'';
			*s++ = '\\';
			*s++ = '\'';
			*s++ = '\'';
		} else
			*s++ = *opt;
	}
	*s++ = '\'';
	*s = '\0';
	*cmdp = cmd;
}

static char *add_option(const char *opt, char *options)
{
	int oldlen = options ? strlen(options) : 0;

	options = xrealloc(options, oldlen + 1 + strlen(opt) + 1);
	if (!oldlen)
		strcpy(options, opt);
	else {
		strcat(options, ",");
		strcat(options, opt);
	}
	return options;
}

static int prepare_fuse_fd(const char *mountpoint, const char* subtype,
			   const char *options)
{
	int fuse_fd = -1;
	int flags = -1;
	int subtype_len = strlen(subtype) + 9;
	char* options_copy = xrealloc(NULL, subtype_len);

	snprintf(options_copy, subtype_len, "subtype=%s", subtype);
	options_copy = add_option(options, options_copy);
	fuse_fd = fuse_open_channel(mountpoint, options_copy);
	if (fuse_fd == -1) {
		exit(1);
	}

	flags = fcntl(fuse_fd, F_GETFD);
	if (flags == -1 || fcntl(fuse_fd, F_SETFD, flags & ~FD_CLOEXEC) == 1) {
		fprintf(stderr, "%s: Failed to clear CLOEXEC: %s\n",
			progname, strerror(errno));
		exit(1);
	}

	return fuse_fd;
}

#ifdef linux
static uint64_t get_capabilities(void)
{
	/*
	 * This invokes the capset syscall directly to avoid the libcap
	 * dependency, which isn't really justified just for this.
	 */
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2];
	memset(data, 0, sizeof(data));
	if (syscall(SYS_capget, &header, data) == -1) {
		fprintf(stderr, "%s: Failed to get capabilities: %s\n",
			progname, strerror(errno));
		exit(1);
	}

	return data[0].effective | ((uint64_t) data[1].effective << 32);
}

static void set_capabilities(uint64_t caps)
{
	/*
	 * This invokes the capset syscall directly to avoid the libcap
	 * dependency, which isn't really justified just for this.
	 */
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2];
	memset(data, 0, sizeof(data));
	data[0].effective = data[0].permitted = caps;
	data[1].effective = data[1].permitted = caps >> 32;
	if (syscall(SYS_capset, &header, data) == -1) {
		fprintf(stderr, "%s: Failed to set capabilities: %s\n",
			progname, strerror(errno));
		exit(1);
	}
}

static void drop_and_lock_capabilities(void)
{
	/* Set and lock securebits. */
	if (prctl(PR_SET_SECUREBITS,
		  SECBIT_KEEP_CAPS_LOCKED |
		  SECBIT_NO_SETUID_FIXUP |
		  SECBIT_NO_SETUID_FIXUP_LOCKED |
		  SECBIT_NOROOT |
		  SECBIT_NOROOT_LOCKED) == -1) {
		fprintf(stderr, "%s: Failed to set securebits %s\n",
			progname, strerror(errno));
		exit(1);
	}

	/* Clear the capability bounding set. */
	int cap;
	for (cap = 0; ; cap++) {
		int cap_status = prctl(PR_CAPBSET_READ, cap);
		if (cap_status == 0) {
			continue;
		}
		if (cap_status == -1 && errno == EINVAL) {
			break;
		}

		if (cap_status != 1) {
			fprintf(stderr,
				"%s: Failed to get capability %u: %s\n",
				progname, cap, strerror(errno));
			exit(1);
		}
		if (prctl(PR_CAPBSET_DROP, cap) == -1) {
			fprintf(stderr,
				"%s: Failed to drop capability %u: %s\n",
				progname, cap, strerror(errno));
		}
	}

	/* Drop capabilities. */
	set_capabilities(0);

	/* Prevent re-acquisition of privileges. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		fprintf(stderr, "%s: Failed to set no_new_privs: %s\n",
			progname, strerror(errno));
		exit(1);
	}
}
#endif

#ifdef HAVE_SERVICEMOUNT
#define FUSERVICEMOUNT_PROG	"fuservicemount3"

static int mount_service_child(char **argv)
{
	const char *full_path = FUSERVICEMOUNT_DIR "/" FUSERVICEMOUNT_PROG;
	pid_t child_pid;
	int child_status;
	int ret;

	/*
	 * First try the install path, then a system install, just like we do
	 * for fusermount.  See man 7 environ for the global environ pointer.
	 */
	ret = posix_spawn(&child_pid, full_path, NULL, NULL,
			  (char *const *)argv, environ);
	if (ret)
		ret = posix_spawnp(&child_pid, FUSERVICEMOUNT_PROG, NULL, NULL,
				   (char * const *)argv, environ);
	if (ret) {
		fprintf(stderr, "%s: could not start %s helper: %s\n",
			argv[0], FUSERVICEMOUNT_PROG, strerror(ret));
		return MOUNT_SERVICE_FALLBACK_NEEDED;
	}

	ret = waitpid(child_pid, &child_status, 0);
	if (ret < 0) {
		fprintf(stderr, "%s: could not wait for %s helper: %s\n",
			argv[0], FUSERVICEMOUNT_PROG, strerror(errno));
		return MOUNT_SERVICE_FALLBACK_NEEDED;
	}

	if (WIFEXITED(child_status))
		return WEXITSTATUS(child_status);

	/* terminated due to signal or coredump */
	return EXIT_FAILURE;
}

static int try_service_main(char *argv0, char *fstype, char *source,
			    const char *mountpoint, char *options)
{
	char **argv;
	char dash_o[] = "-o";
	char dash_t[] = "-t";
	char *mntpt;
	int argc = 5; /* argv[0], -t type, mountpoint, and trailing NULL */
	int i = 0;
	int ret;

	if (!mount_service_present(fstype))
		return MOUNT_SERVICE_FALLBACK_NEEDED;

	/* This can be an empty string if "mount.fuse3 null# /tmp/a" */
	if (source && source[0] == 0)
		source = NULL;

	mntpt = strdup(mountpoint);
	if (!mntpt) {
		perror("mountpoint allocation");
		return -1;
	}

	if (source)
		argc++;
	if (options)
		argc += 2;

	argv = calloc(argc, sizeof(char *));
	if (!argv) {
		perror("argv allocation");
		free(mntpt);
		return -1;
	}

	argv[i++] = argv0;
	if (source)
		argv[i++] = source;
	argv[i++] = mntpt;
	argv[i++] = dash_t;
	argv[i++] = fstype;
	if (options) {
		argv[i++] = dash_o;
		argv[i++] = options;
	}
	argv[i] = 0;

	if (getuid() != 0) {
		ret = mount_service_child(argv);
	} else {
		/* We're root, just do the mount directly. */
		ret = mount_service_main(argc - 1, argv);
	}
	free(argv);
	free(mntpt);
	return ret;
}
#endif

int main(int argc, char *argv[])
{
	char *type = NULL;
	char *source;
	char *dup_source = NULL;
	const char *mountpoint;
	char *basename;
	char *options = NULL;
	char *command = NULL;
	char *setuid_name = NULL;
	int i;
	int dev = 1;
	int suid = 1;
	int pass_fuse_fd = 0;
	int fuse_fd = 0;
	int drop_privileges = 0;
	char *dev_fd_mountpoint = NULL;

	progname = argv[0];
	basename = strrchr(argv[0], '/');
	if (basename)
		basename++;
	else
		basename = argv[0];

	if (strncmp(basename, "mount.fuse.", 11) == 0)
		type = basename + 11;
	if (strncmp(basename, "mount.fuseblk.", 14) == 0)
		type = basename + 14;

	if (type && !type[0])
		type = NULL;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s %s destination [-t type] [-o opt[,opts...]]\n",
			progname, type ? "source" : "type#[source]");
		exit(1);
	}

	source = argv[1];
	if (!source[0])
		source = NULL;

	mountpoint = argv[2];

	for (i = 3; i < argc; i++) {
		if (strcmp(argv[i], "-t") == 0) {
			i++;

			if (i == argc) {
				fprintf(stderr,
					"%s: missing argument to option '-t'\n",
					progname);
				exit(1);
			}
			type = argv[i];
			if (strncmp(type, "fuse.", 5) == 0)
				type += 5;
			else if (strncmp(type, "fuseblk.", 8) == 0)
				type += 8;

			if (!type[0]) {
				fprintf(stderr,
					"%s: empty type given as argument to option '-t'\n",
					progname);
				exit(1);
			}
		}
	}

	if (!type) {
		if (source) {
			dup_source = xstrdup(source);
			type = dup_source;
			source = strchr(type, '#');
			if (source)
				*source++ = '\0';
			if (!type[0]) {
				fprintf(stderr, "%s: empty filesystem type\n",
					progname);
				exit(1);
			}
		} else {
			fprintf(stderr, "%s: empty source\n", progname);
			exit(1);
		}
	}

	for (i = 3; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			continue;
		} else	if (strcmp(argv[i], "-o") == 0) {
			char *opts;
			const char *opt;
			i++;
			if (i == argc)
				break;

			opts = xstrdup(argv[i]);
			opt = strtok(opts, ",");
			while (opt) {
				int j;
				int ignore = 0;
				const char *ignore_opts[] = { "",
							      "user",
							      "nofail",
							      "nouser",
							      "users",
							      "auto",
							      "noauto",
							      "_netdev",
							      NULL};
				if (strncmp(opt, "setuid=", 7) == 0) {
					setuid_name = xstrdup(opt + 7);
					ignore = 1;
				} else if (strcmp(opt,
						  "drop_privileges") == 0) {
					pass_fuse_fd = 1;
					drop_privileges = 1;
					ignore = 1;
				}
				for (j = 0; ignore_opts[j]; j++)
					if (strcmp(opt, ignore_opts[j]) == 0)
						ignore = 1;

				if (!ignore) {
					if (strcmp(opt, "nodev") == 0)
						dev = 0;
					else if (strcmp(opt, "nosuid") == 0)
						suid = 0;

					options = add_option(opt, options);
				}
				opt = strtok(NULL, ",");
			}
			free(opts);
		}
	}

	if (drop_privileges) {
		uint64_t required_caps = CAP_TO_MASK(CAP_SETPCAP) |
				CAP_TO_MASK(CAP_SYS_ADMIN);
		if ((get_capabilities() & required_caps) != required_caps) {
			fprintf(stderr, "%s: drop_privileges was requested, which launches the FUSE file system fully unprivileged. In order to do so %s must be run with privileges, please invoke with CAP_SYS_ADMIN and CAP_SETPCAP (e.g. as root).\n",
			progname, progname);
			exit(1);
		}
	}

	if (dev)
		options = add_option("dev", options);
	if (suid)
		options = add_option("suid", options);

	if (setuid_name && setuid_name[0]) {
#ifdef linux
		if (drop_privileges) {
			/*
			 * Make securebits more permissive before calling
			 * setuid(). Specifically, if SECBIT_KEEP_CAPS and
			 * SECBIT_NO_SETUID_FIXUP weren't set, setuid() would
			 * have the side effect of dropping all capabilities,
			 * and we need to retain CAP_SETPCAP in order to drop
			 * all privileges before exec().
			 */
			if (prctl(PR_SET_SECUREBITS,
				  SECBIT_KEEP_CAPS |
				  SECBIT_NO_SETUID_FIXUP) == -1) {
				fprintf(stderr,
					"%s: Failed to set securebits %s\n",
					progname, strerror(errno));
				exit(1);
			}
		}
#endif

		struct passwd *pwd = getpwnam(setuid_name);
		if (!pwd || setgid(pwd->pw_gid) == -1 || setuid(pwd->pw_uid) == -1) {
			fprintf(stderr, "%s: Failed to setuid to %s: %s\n",
				progname, setuid_name, strerror(errno));
			exit(1);
		}
	} else if (!getenv("HOME")) {
		/* Hack to make filesystems work in the boot environment */
		setenv("HOME", "/root", 0);
	}

	if (pass_fuse_fd)  {
		fuse_fd = prepare_fuse_fd(mountpoint, type, options);
		dev_fd_mountpoint = xrealloc(NULL, 20);
		snprintf(dev_fd_mountpoint, 20, "/dev/fd/%d", fuse_fd);
		mountpoint = dev_fd_mountpoint;
	}

#ifdef linux
	if (drop_privileges) {
		drop_and_lock_capabilities();
	}
#endif

#ifdef HAVE_SERVICEMOUNT
	/*
	 * Now that we know the desired filesystem type, see if we can find
	 * a socket service implementing that, if we haven't selected any weird
	 * options that would prevent that.
	 */
	if (!pass_fuse_fd && !(setuid_name && setuid_name[0])) {
		int ret = try_service_main(argv[0], type, source, mountpoint,
					   options);
		if (ret != MOUNT_SERVICE_FALLBACK_NEEDED)
			return ret;
	}
#endif

	add_arg(&command, type);
	if (source)
		add_arg(&command, source);
	add_arg(&command, mountpoint);
	if (options) {
		add_arg(&command, "-o");
		add_arg(&command, options);
	}

	free(options);
	free(dev_fd_mountpoint);
	free(dup_source);
	free(setuid_name);

	execl("/bin/sh", "/bin/sh", "-c", command, NULL);
	fprintf(stderr, "%s: failed to execute /bin/sh: %s\n", progname,
		strerror(errno));
	
	if (pass_fuse_fd)
		close(fuse_fd);
	free(command);
	return 1;
}
