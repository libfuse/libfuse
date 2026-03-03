/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/
/* This program does the mounting of FUSE filesystems that run in systemd */

#define _GNU_SOURCE
#include "fuse_config.h"
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "mount_util.h"
#include "util.h"
#include "fuse_i.h"
#include "fuse_service_priv.h"
#include "mount_service.h"

#define FUSE_KERN_DEVICE_ENV	"FUSE_KERN_DEVICE"
#define FUSE_DEV		"/dev/fuse"

struct mount_service {
	/* alleged fuse subtype based on -t cli argument */
	const char *subtype;

	/* full fuse filesystem type we give to mount() */
	char *fstype;

	/* source argument to mount() */
	char *source;

	/* target argument (aka mountpoint) to mount() */
	char *mountpoint;

	/* mount options */
	char *mntopts;

	/* socket fd */
	int sockfd;

	/* /dev/fuse device */
	int fusedevfd;

	/* memfd for cli arguments */
	int argvfd;

	/* fd for fsopen */
	int fsopenfd;
};

/* Filter out the subtype of the filesystem (e.g. fuse.Y -> Y) */
const char *mount_service_subtype(const char *fstype)
{
	char *period = strrchr(fstype, '.');
	if (period)
		return period + 1;

	return fstype;
}

static int mount_service_init(struct mount_service *mo, int argc,
			      char *argv[])
{
	char *fstype = NULL;
	int i;

	mo->sockfd = -1;
	mo->fsopenfd = -1;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-t") && i + 1 < argc) {
			fstype = argv[i + 1];
			break;
		}
	}
	if (!fstype)
		return -1;

	mo->subtype = mount_service_subtype(fstype);
	return 0;
}

static int mount_service_connect(struct mount_service *mo)
{
	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
	};
	int sockfd;
	ssize_t written;
	int ret;

	written = snprintf(name.sun_path, sizeof(name.sun_path),
			FUSE_SERVICE_SOCKET_DIR "/%s", mo->subtype);
	if (written > sizeof(name.sun_path)) {
		fprintf(stderr,
 "mount.service: filesystem type name (\"%s\") is too long.\n",
			mo->subtype);
		return -1;
	}

	sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sockfd < 0) {
		fprintf(stderr,
 "mount.service: opening %s service socket: %s\n", mo->subtype,
			strerror(errno));
		return -1;
	}

	ret = connect(sockfd, (const struct sockaddr *)&name, sizeof(name));
	if (ret) {
		if (errno == ENOENT)
			fprintf(stderr,
 "mount.service: no safe filesystem driver for %s available.\n",
				mo->subtype);
		else
			perror(name.sun_path);
		goto out;
	}

#ifdef SO_PASSRIGHTS
	{
		int zero = 0;

		/* don't let a malicious fuse server send us more fds */
		setsockopt(sockfd, SOL_SOCKET, SO_PASSRIGHTS, &zero,
			   sizeof(zero));
	}
#endif

	mo->sockfd = sockfd;
	return 0;
out:
	close(sockfd);
	return -1;
}

static int mount_service_send_hello(struct mount_service *mo)
{
	struct fuse_service_hello hello = {
		.p.magic = htonl(FUSE_SERVICE_HELLO_CMD),
		.min_version = htons(FUSE_SERVICE_MIN_PROTO),
		.max_version = htons(FUSE_SERVICE_MAX_PROTO),
	};
	struct fuse_service_hello_reply reply = { };
	struct iovec iov = {
		.iov_base = &hello,
		.iov_len = sizeof(hello),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t size;

	size = sendmsg(mo->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
	if (size < 0) {
		perror("mount.service: send hello");
		return -1;
	}

	iov.iov_base = &reply;
	iov.iov_len = sizeof(reply);

	size = recvmsg(mo->sockfd, &msg, MSG_TRUNC);
	if (size < 0) {
		perror("mount.service: hello reply");
		return -1;
	}
	if (size != sizeof(reply)) {
		fprintf(stderr,
 "mount.service: wrong hello reply size %zd, expected %zd\n",
			size, sizeof(reply));
		return -1;
	}

	if (reply.p.magic != ntohl(FUSE_SERVICE_HELLO_REPLY)) {
		fprintf(stderr,
 "mount.service: %s service server did not reply to hello\n",
			mo->subtype);
		return -1;
	}

	if (ntohs(reply.version) < FUSE_SERVICE_MIN_PROTO ||
	    ntohs(reply.version) > FUSE_SERVICE_MAX_PROTO) {
		fprintf(stderr,
 "mount.service: unsupported protocol version %u\n",
			ntohs(reply.version));
		return -1;
	}

	return 0;
}

static int mount_service_capture_arg(struct mount_service *mo,
				     struct fuse_service_memfd_argv *args,
				     const char *string, off_t *array_pos,
				     off_t *string_pos)
{
	const size_t string_len = strlen(string) + 1;
	struct fuse_service_memfd_arg arg = {
		.pos = htonl(*string_pos),
		.len = htonl(string_len),
	};
	ssize_t written;

	written = pwrite(mo->argvfd, string, string_len, *string_pos);
	if (written < 0) {
		perror("mount.service: memfd argv write");
		return -1;
	}
	if (written < string_len) {
		fprintf(stderr, "mount.service: memfd argv[%u] write %zd\n",
			args->argc, written);
		return -1;
	}

	written = pwrite(mo->argvfd, &arg, sizeof(arg), *array_pos);
	if (written < 0) {
		perror("mount.service: memfd arg write");
		return -1;
	}
	if (written < sizeof(arg)) {
		fprintf(stderr, "mount.service: memfd arg[%u] write %zd\n",
			args->argc, written);
		return -1;
	}

	args->argc++;
	*string_pos += string_len;
	*array_pos += sizeof(arg);

	return 0;
}

static int mount_service_capture_args(struct mount_service *mo, int argc,
				      char *argv[])
{
	struct fuse_service_memfd_argv args = {
		.magic = htonl(FUSE_SERVICE_ARGS_MAGIC),
	};
	off_t array_pos = sizeof(struct fuse_service_memfd_argv);
	off_t string_pos = array_pos +
			(argc * sizeof(struct fuse_service_memfd_arg));
	ssize_t written;
	int i;
	int ret;

	if (argc < 0) {
		fprintf(stderr, "mount.service: argc cannot be negative\n");
		return -1;
	}

	/*
	 * Create the memfd in which we'll stash arguments, and set the write
	 * pointer for the names.
	 */
	mo->argvfd = memfd_create("mount.service args", MFD_CLOEXEC);
	if (mo->argvfd < 0) {
		perror("mount.service: argvfd create");
		return -1;
	}

	/*
	 * Write the alleged subtype as if it were argv[0], then write the rest
	 * of the argv arguments.
	 */
	ret = mount_service_capture_arg(mo, &args, mo->subtype, &array_pos,
					&string_pos);
	if (ret)
		return ret;

	for (i = 1; i < argc; i++) {
		/* skip the -t(ype) argument */
		if (!strcmp(argv[i], "-t")) {
			i++;
			continue;
		}

		ret = mount_service_capture_arg(mo, &args, argv[i],
						&array_pos, &string_pos);
		if (ret)
			return ret;
	}

	/* Now write the header */
	args.argc = htonl(args.argc);
	written = pwrite(mo->argvfd, &args, sizeof(args), 0);
	if (written < 0) {
		perror("mount.service: memfd argv write");
		return -1;
	}
	if (written < sizeof(args)) {
		fprintf(stderr, "mount.service: memfd argv wrote %zd\n",
			written);
		return -1;
	}

	return 0;
}

static ssize_t __send_fd(int sockfd, struct fuse_service_requested_file *req,
			 size_t req_sz, int fd)
{
	union {
		struct cmsghdr cmsghdr;
		char control[CMSG_SPACE(sizeof(int))];
	} cmsgu;
	struct iovec iov = {
		.iov_base = req,
		.iov_len = req_sz,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgu.control,
		.msg_controllen = sizeof(cmsgu.control),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	memset(&cmsgu, 0, sizeof(cmsgu));
	cmsg->cmsg_len = CMSG_LEN(sizeof (int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	*((int *)CMSG_DATA(cmsg)) = fd;

	return sendmsg(sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
}

static int mount_service_send_file(struct mount_service *mo,
				   const char *path, int fd)
{
	struct fuse_service_requested_file *req;
	const size_t req_sz =
			sizeof_fuse_service_requested_file(strlen(path));
	ssize_t written;
	int ret = 0;

	req = malloc(req_sz);
	if (!req) {
		perror("mount.service: alloc send file reply");
		return -1;
	}
	req->p.magic = htonl(FUSE_SERVICE_OPEN_REPLY);
	req->error = 0;
	strcpy(req->path, path);

	written = __send_fd(mo->sockfd, req, req_sz, fd);
	if (written < 0) {
		perror("mount.service: send file reply");
		ret = -1;
	}

	free(req);
	return ret;
}

static ssize_t __send_packet(int sockfd, void *buf, ssize_t buflen)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = buflen,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	return sendmsg(sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
}

static int mount_service_send_file_error(struct mount_service *mo, int error,
					 const char *path)
{
	struct fuse_service_requested_file *req;
	const size_t req_sz =
			sizeof_fuse_service_requested_file(strlen(path));
	ssize_t written;
	int ret = 0;

	req = malloc(req_sz);
	if (!req) {
		perror("mount.service: alloc send file error");
		return -1;
	}
	req->p.magic = htonl(FUSE_SERVICE_OPEN_REPLY);
	req->error = htonl(error);
	strcpy(req->path, path);

	written = __send_packet(mo->sockfd, req, req_sz);
	if (written < 0) {
		perror("mount.service: send file error");
		ret = -1;
	}

	free(req);
	return ret;
}

static int mount_service_send_required_files(struct mount_service *mo,
					     const char *fusedev)
{
	int ret;

	mo->fusedevfd = open(fusedev, O_RDWR | O_CLOEXEC);
	if (mo->fusedevfd < 0) {
		perror(fusedev);
		return -1;
	}

	ret = mount_service_send_file(mo, FUSE_SERVICE_ARGV, mo->argvfd);
	close(mo->argvfd);
	mo->argvfd = -1;
	if (ret)
		return ret;

	return mount_service_send_file(mo, FUSE_SERVICE_FUSEDEV,
				       mo->fusedevfd);
}

static int
mount_service_receive_command(struct mount_service *mo,
			      struct fuse_service_packet **commandp)
{
	struct iovec iov = {
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct fuse_service_packet *command;
	ssize_t size;

	size = recvmsg(mo->sockfd, &msg, MSG_PEEK | MSG_TRUNC);
	if (size < 0) {
		perror("mount.service: peek service command");
		return -1;
	}
	if (size == 0) {
		/* fuse server probably exited early */
		return -1;
	}
	if (size < sizeof(struct fuse_service_packet)) {
		fprintf(stderr,
 "mount.service: wrong command packet size %zd, expected at least %zd\n",
			size, sizeof(struct fuse_service_packet));
		return -1;
	}

	command = calloc(1, size + 1);
	if (!command) {
		perror("mount.service: alloc service command");
		return -1;
	}
	iov.iov_base = command;
	iov.iov_len = size;

	size = recvmsg(mo->sockfd, &msg, MSG_TRUNC);
	if (size < 0) {
		perror("mount.service: receive service command");
		return -1;
	}
	if (size != iov.iov_len) {
		fprintf(stderr,
 "mount.service: wrong service command size %zd, expected %zd\n",
			size, iov.iov_len);
		return -1;
	}

	*commandp = command;
	return 0;
}

static int mount_service_send_reply(struct mount_service *mo, int error)
{
	struct fuse_service_simple_reply reply = {
		.p.magic = htonl(FUSE_SERVICE_SIMPLE_REPLY),
		.error = htonl(error),
	};
	struct iovec iov = {
		.iov_base = &reply,
		.iov_len = sizeof(reply),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t size;

	size = sendmsg(mo->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
	if (size < 0) {
		perror("mount.service: send service reply");
		return -1;
	}

	return 0;
}

static int prepare_bdev(struct fuse_service_open_command *oc, int fd)
{
	struct stat statbuf;
	int block_size;
	int ret;

	ret = fstat(fd, &statbuf);
	if (ret) {
		perror(oc->path);
		return errno;
	}

	if (!S_ISBLK(statbuf.st_mode)) {
		fprintf(stderr, "%s: not a block device\n", oc->path);
		return ENOTBLK;
	}

	if (!oc->block_size)
		return 0;
	block_size = ntohl(oc->block_size);

	ret = ioctl(fd, BLKBSZSET, &block_size);
	if (ret) {
		perror(oc->path);
		return errno;
	}

	return 0;
}

static int mount_service_handle_open_path(struct mount_service *mo, mode_t mode,
					  struct fuse_service_packet *p)
{
	struct fuse_service_open_command *oc =
			container_of(p, struct fuse_service_open_command, p);
	uint32_t request_flags = ntohl(oc->request_flags);
	int ret;
	int fd;

	if (request_flags & ~FUSE_SERVICE_OPEN_FLAGS)
		return mount_service_send_file_error(mo, EINVAL, oc->path);

	fd = open(oc->path, ntohl(oc->open_flags), ntohl(oc->create_mode));
	if (fd < 0) {
		int error = errno;

		/*
		 * Don't print a busy device error report because the
		 * filesystem might decide to retry.
		 */
		if (errno != EBUSY)
			perror(oc->path);
		return mount_service_send_file_error(mo, error, oc->path);
	}

	if (S_ISBLK(mode)) {
		ret = prepare_bdev(oc, fd);
		if (ret) {
			close(fd);
			return mount_service_send_file_error(mo, ret,
							     oc->path);
		}
	}

	ret = mount_service_send_file(mo, oc->path, fd);
	close(fd);
	return ret;
}

static int mount_service_handle_open_cmd(struct mount_service *mo,
					 struct fuse_service_packet *p)
{
	return mount_service_handle_open_path(mo, 0, p);
}

static int mount_service_handle_open_bdev_cmd(struct mount_service *mo,
					      struct fuse_service_packet *p)
{
	return mount_service_handle_open_path(mo, S_IFBLK, p);
}

static int
mount_service_handle_fsopen_cmd(struct mount_service *mo,
				const struct fuse_service_packet *p)
{
	struct fuse_service_string_command *oc =
			container_of(p, struct fuse_service_string_command, p);

	mo->fsopenfd = -1;
#if 0
	mo->fsopenfd = fsopen(oc->value, FSOPEN_CLOEXEC);
#endif
	if (mo->fsopenfd >= 0)
		return mount_service_send_reply(mo, 0);

	if (mo->fstype) {
		fprintf(stderr, "mount.service: fstype respecified!\n");
		mount_service_send_reply(mo, EINVAL);
		return -1;
	}

	mo->fstype = strdup(oc->value);
	if (!mo->fstype) {
		perror("mount.service: alloc fstype string");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	return mount_service_send_reply(mo, 0);
}

static int
mount_service_handle_source_cmd(struct mount_service *mo,
				const struct fuse_service_packet *p)
{
	struct fuse_service_string_command *oc =
			container_of(p, struct fuse_service_string_command, p);
	int ret;

	if (mo->fsopenfd < 0) {
		if (mo->source) {
			fprintf(stderr, "mount.service: source respecified!\n");
			mount_service_send_reply(mo, EINVAL);
			return -1;
		}

		mo->source = strdup(oc->value);
		if (!mo->source) {
			perror("mount.service: alloc source string");
			mount_service_send_reply(mo, errno);
			return -1;
		}

		return mount_service_send_reply(mo, 0);
	}

	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "source", oc->value,
		       0);
	if (ret) {
		perror("mount.service: fsconfig source");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	return mount_service_send_reply(mo, 0);
}

static int
mount_service_handle_mntopts_cmd(struct mount_service *mo,
				 const struct fuse_service_packet *p)
{
	struct fuse_service_string_command *oc =
			container_of(p, struct fuse_service_string_command, p);
	char *tokstr = oc->value;
	char *tok, *savetok;
	int ret;

	if (mo->fsopenfd < 0) {
		if (mo->mntopts) {
			fprintf(stderr,
 "mount.service: mount options respecified!\n");
			mount_service_send_reply(mo, EINVAL);
			return -1;
		}

		mo->mntopts = strdup(oc->value);
		if (!mo->mntopts) {
			perror("mount.service: alloc mount options string");
			mount_service_send_reply(mo, errno);
			return -1;
		}

		return mount_service_send_reply(mo, 0);
	}

	while ((tok = strtok_r(tokstr, ",", &savetok)) != NULL) {
		char *equals = strchr(tok, '=');

		if (equals) {
			char oldchar = *equals;

			*equals = 0;
			ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, tok,
				       equals + 1, 0);
			*equals = oldchar;
		} else {
			ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_FLAG, tok,
				       NULL, 0);
		}
		if (ret) {
			perror("mount.service: set mount option");
			mount_service_send_reply(mo, errno);
			return -1;
		}

		tokstr = NULL;
	}

	return mount_service_send_reply(mo, 0);
}

static int
mount_service_handle_mountpoint_cmd(struct mount_service *mo,
				    const struct fuse_service_packet *p)
{
	struct fuse_service_string_command *oc =
			container_of(p, struct fuse_service_string_command, p);

	if (mo->mountpoint) {
		fprintf(stderr, "mount.service: mount point respecified!\n");
		mount_service_send_reply(mo, EINVAL);
		return -1;
	}

	mo->mountpoint = strdup(oc->value);
	if (!mo->mountpoint) {
		perror("mount.service: alloc mount point string");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	return mount_service_send_reply(mo, 0);
}

static inline int format_libfuse_mntopts(char *buf, size_t bufsz,
					 const struct mount_service *mo,
					 const struct stat *statbuf)
{
	if (mo->mntopts)
		return snprintf(buf, bufsz,
				"%s,fd=%i,rootmode=%o,user_id=%u,group_id=%u",
				mo->mntopts, mo->fusedevfd,
				statbuf->st_mode & S_IFMT,
				getuid(), getgid());

	return snprintf(buf, bufsz,
			"fd=%i,rootmode=%o,user_id=%u,group_id=%u",
			mo->fusedevfd, statbuf->st_mode & S_IFMT,
			getuid(), getgid());
}

static int mount_service_regular_mount(struct mount_service *mo,
				       struct fuse_service_mount_command *oc,
				       struct stat *stbuf)
{
	char *realmopts;
	int ret;

	if (!mo->fstype) {
		fprintf(stderr, "mount.service: missing mount type parameter\n");
		mount_service_send_reply(mo, EINVAL);
		return -1;
	}

	if (!mo->source) {
		fprintf(stderr, "mount.service: missing mount source parameter\n");
		mount_service_send_reply(mo, EINVAL);
		return -1;
	}

	ret = format_libfuse_mntopts(NULL, 0, mo, stbuf);
	if (ret < 0) {
		perror("mount.service: mount option preformatting");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	realmopts = malloc(ret + 1);
	if (!realmopts) {
		perror("mount.service: alloc real mount options string");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	ret = format_libfuse_mntopts(realmopts, ret + 1, mo, stbuf);
	if (ret < 0) {
		free(realmopts);
		perror("mount.service: mount options formatting");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	ret = mount(mo->source, mo->mountpoint, mo->fstype, ntohl(oc->flags),
		    realmopts);
	free(realmopts);
	if (ret) {
		perror("mount.service");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	return mount_service_send_reply(mo, 0);
}

static int mount_service_fsopen_mount(struct mount_service *mo,
				      struct fuse_service_mount_command *oc,
				      struct stat *stbuf)
{
	char tmp[64];
	int mfd;
	int ret;

	snprintf(tmp, sizeof(tmp), "%i", mo->fusedevfd);
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "fd", tmp, 0);
	if (ret) {
		perror("mount.service: set fd option");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	snprintf(tmp, sizeof(tmp), "%o", stbuf->st_mode & S_IFMT);
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "rootmode", tmp, 0);
	if (ret) {
		perror("mount.service: set rootmode option");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	snprintf(tmp, sizeof(tmp), "%u", getuid());
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "user_id", tmp, 0);
	if (ret) {
		perror("mount.service: set user_id option");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	snprintf(tmp, sizeof(tmp), "%u", getgid());
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "group_id", tmp, 0);
	if (ret) {
		perror("mount.service: set group_id option");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	mfd = fsmount(mo->fsopenfd, FSMOUNT_CLOEXEC, ntohl(oc->flags));
	if (mfd < 0) {
		perror("mount.service");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	ret = move_mount(mfd, "", AT_FDCWD, mo->mountpoint,
			 MOVE_MOUNT_F_EMPTY_PATH);
	close(mfd);
	if (ret) {
		perror("mount.service: move_mount");
		mount_service_send_reply(mo, errno);
		return -1;
	}

	return mount_service_send_reply(mo, 0);
}

static int mount_service_handle_mount_cmd(struct mount_service *mo,
					  struct fuse_service_packet *p)
{
	struct stat stbuf;
	char mountpoint[PATH_MAX] = "";
	struct fuse_service_mount_command *oc =
			container_of(p, struct fuse_service_mount_command, p);
	int ret;

	if (!mo->mountpoint) {
		fprintf(stderr, "mount.service: missing mount point parameter\n");
		mount_service_send_reply(mo, EINVAL);
		return -1;
	}

	if (realpath(mo->mountpoint, mountpoint) == NULL) {
		int error = errno;

		fprintf(stderr, "mount.service: bad mount point `%s': %s\n",
			mo->mountpoint, strerror(error));
		mount_service_send_reply(mo, error);
		return -1;
	}

	ret = stat(mo->mountpoint, &stbuf);
	if (ret == -1) {
		perror(mo->mountpoint);
		mount_service_send_reply(mo, errno);
		return -1;
	}

	if (mo->fsopenfd >= 0)
		return mount_service_fsopen_mount(mo, oc, &stbuf);
	return mount_service_regular_mount(mo, oc, &stbuf);
}

static int mount_service_handle_bye_cmd(struct fuse_service_packet *p)
{
	int error;

	struct fuse_service_bye_command *bc =
			container_of(p, struct fuse_service_bye_command, p);

	error = ntohl(bc->error);
	if (error) {
		fprintf(stderr, "mount.service: initialization failed: %s\n",
			strerror(error));
		return -1;
	}

	return 0;
}

static void mount_service_destroy(struct mount_service *mo)
{
	close(mo->fusedevfd);
	close(mo->argvfd);
	close(mo->fsopenfd);
	shutdown(mo->sockfd, SHUT_RDWR);
	close(mo->sockfd);

	free(mo->source);
	free(mo->mountpoint);
	free(mo->mntopts);
	free(mo->fstype);

	memset(mo, 0, sizeof(*mo));
	mo->fsopenfd = -1;
	mo->sockfd = -1;
	mo->argvfd = -1;
	mo->fusedevfd = -1;
}

int mount_service_main(int argc, char *argv[])
{
	const char *fusedev = getenv(FUSE_KERN_DEVICE_ENV) ?: FUSE_DEV;
	struct mount_service mo = { };
	bool running = true;
	int ret;

	if (argc < 3 || !strcmp(argv[1], "--help")) {
		printf("Usage: %s source mountpoint -t type [-o options]\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	ret = mount_service_init(&mo, argc, argv);
	if (ret) {
		fprintf(stderr, "%s: cannot determine filesystem type.\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	ret = mount_service_connect(&mo);
	if (ret) {
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = mount_service_send_hello(&mo);
	if (ret) {
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = mount_service_capture_args(&mo, argc, argv);
	if (ret) {
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = mount_service_send_required_files(&mo, fusedev);
	if (ret) {
		ret = EXIT_FAILURE;
		goto out;
	}

	while (running) {
		struct fuse_service_packet *p = NULL;

		ret = mount_service_receive_command(&mo, &p);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}

		switch (ntohl(p->magic)) {
		case FUSE_SERVICE_OPEN_CMD:
			ret = mount_service_handle_open_cmd(&mo, p);
			break;
		case FUSE_SERVICE_OPEN_BDEV_CMD:
			ret = mount_service_handle_open_bdev_cmd(&mo, p);
			break;
		case FUSE_SERVICE_FSOPEN_CMD:
			ret = mount_service_handle_fsopen_cmd(&mo, p);
			break;
		case FUSE_SERVICE_SOURCE_CMD:
			ret = mount_service_handle_source_cmd(&mo, p);
			break;
		case FUSE_SERVICE_MNTOPTS_CMD:
			ret = mount_service_handle_mntopts_cmd(&mo, p);
			break;
		case FUSE_SERVICE_MNTPT_CMD:
			ret = mount_service_handle_mountpoint_cmd(&mo, p);
			break;
		case FUSE_SERVICE_MOUNT_CMD:
			ret = mount_service_handle_mount_cmd(&mo, p);
			break;
		case FUSE_SERVICE_BYE_CMD:
			ret = mount_service_handle_bye_cmd(p);
			running = false;
			break;
		default:
			fprintf(stderr, "unrecognized packet 0x%x\n",
				ntohl(p->magic));
			ret = EXIT_FAILURE;
			break;
		}
		free(p);

		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	ret = EXIT_SUCCESS;
out:
	mount_service_destroy(&mo);
	return ret;
}
