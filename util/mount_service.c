/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025-2026 Oracle.
 * Author: Darrick J. Wong <djwong@kernel.org>
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 *
 * This program does the mounting of FUSE filesystems that run in systemd
 */
#define _GNU_SOURCE
#include "fuse_config.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#ifdef HAVE_NEW_MOUNT_API
#include <sys/mount.h>
#include <linux/mount.h>
#endif

#include "mount_util.h"
#include "util.h"
#include "fuse_i.h"
#include "fuse_service_priv.h"
#include "mount_service.h"

struct mount_service {
	/* prefix for printing error messages */
	const char *msgtag;

	/* fuse subtype based on -t cli argument */
	char *subtype;

	/* source argument to mount() */
	char *source;

	/* target argument (aka mountpoint) to mount() */
	char *mountpoint;

	/* mountpoint that we pass to mount() */
	char *real_mountpoint;

	/* resolved path to mountpoint that we use for mtab updates */
	char *resv_mountpoint;

	/* mount options */
	char *mntopts;

	/* mtab options */
	char *mtabopts;

	/* socket fd */
	int sockfd;

	/* /dev/fuse device */
	int fusedevfd;

	/* memfd for cli arguments */
	int argvfd;

	/* fd for mount point */
	int mountfd;

	/* fd for fsopen */
	int fsopenfd;

	/* did we actually mount successfully? */
	bool mounted;

	/* has the fsopen command already been submitted? */
	bool fsopened;

	/* is this a fuseblk mount? */
	bool fuseblk;
};

static char IGNORE_MTAB;

static inline bool have_real_mtabopts(const struct mount_service *mo)
{
	return mo->mtabopts && mo->mtabopts != &IGNORE_MTAB;
}

static ssize_t __send_fd(struct mount_service *mo,
			 struct fuse_service_requested_file *req,
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

	if (!cmsg) {
		errno = EINVAL;
		return -1;
	}

	memset(&cmsgu, 0, sizeof(cmsgu));
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	*((int *)CMSG_DATA(cmsg)) = fd;

	return sendmsg(mo->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
}

static ssize_t __send_packet(struct mount_service *mo, void *ptr, size_t len)
{
	struct iovec iov = {
		.iov_base = ptr,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	return sendmsg(mo->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
}

static ssize_t __recv_packet_size(struct mount_service *mo)
{
	struct iovec iov = { };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	return recvmsg(mo->sockfd, &msg, MSG_PEEK | MSG_TRUNC);
}

static ssize_t __recv_packet(struct mount_service *mo, void *ptr, size_t len)
{
	struct iovec iov = {
		.iov_base = ptr,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	return recvmsg(mo->sockfd, &msg, MSG_TRUNC);
}

/*
 * Filter out the subtype of the filesystem (e.g. fuse.Y[.Z] -> Y[.Z]).  The
 * fuse server determines if it's appropriate to set the "blockdev" mount
 * option (aka fuseblk).
 */
const char *mount_service_subtype(const char *fstype)
{
	const char *subtype;

	if (!strncmp(fstype, "fuse.", 5))
		subtype = fstype + 5;
	else if (!strncmp(fstype, "fuseblk.", 8))
		subtype = fstype + 8;
	else
		subtype = fstype;

	if (strchr(subtype, '/') != NULL) {
		fprintf(stderr,
			"%s: fs subtype cannot contain path separators\n",
			fstype);
		return NULL;
	}

	return subtype;
}

static int mount_service_init(struct mount_service *mo, int argc, char *argv[])
{
	char *fstype = NULL;
	const char *subtype;
	int i;

	mo->sockfd = -1;
	mo->argvfd = -1;
	mo->fusedevfd = -1;
	mo->mountfd = -1;
	mo->fsopenfd = -1;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-t") && i + 1 < argc) {
			fstype = argv[i + 1];
			break;
		}
	}
	if (!fstype) {
		fprintf(stderr, "%s: cannot determine filesystem type.\n",
			mo->msgtag);
		return -1;
	}

	subtype = mount_service_subtype(fstype);
	if (!subtype)
		return -1;

	mo->subtype = strdup(subtype);
	if (!mo->subtype) {
		int error = errno;

		fprintf(stderr, "%s: cannot alloc memory for fs subtype: %s\n",
			mo->msgtag, strerror(error));
		return -1;
	}

	return 0;
}

#ifdef SO_PASSRIGHTS
static int try_drop_passrights(struct mount_service *mo, int sockfd)
{
	int zero = 0;
	int ret;

	/*
	 * Don't let a malicious mount helper send us any fds.  We don't trust
	 * the fuse server not to pollute our fd namespace, so we'll end now.
	 */
	ret = setsockopt(sockfd, SOL_SOCKET, SO_PASSRIGHTS, &zero,
			 sizeof(zero));
	if (ret) {
		fprintf(stderr, "%s: disabling fd passing: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}

	return 0;
}
#else
# define try_drop_passrights(...)	(0)
#endif

static int check_sendbuf_size(struct mount_service *mo, int sockfd)
{
	const size_t min_size = sizeof_fuse_service_open_command(PATH_MAX);
	int sendbuf_size = -1;
	socklen_t optlen = sizeof(sendbuf_size);
	int ret;

	/*
	 * If we can't query the maximum send buffer length, just keep going.
	 * Most likely we won't be sending huge open commands, and if we do,
	 * the sendmsg will fail there too.
	 */
	ret = getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sendbuf_size, &optlen);
	if (ret || sendbuf_size < 0)
		return 0;

	if (sendbuf_size >= min_size)
		return 0;

	fprintf(stderr, "%s: max socket send buffer is %d, need at least %zu.\n",
		mo->msgtag, sendbuf_size, min_size);
	return MOUNT_SERVICE_FALLBACK_NEEDED;
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
	if (written >= sizeof(name.sun_path)) {
		fprintf(stderr, "%s: filesystem type name `%s' is too long.\n",
			mo->msgtag, mo->subtype);
		return -1;
	}

	sockfd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sockfd < 0) {
		int error = errno;

		fprintf(stderr, "%s: opening %s service socket: %s\n",
			mo->msgtag, mo->subtype, strerror(error));
		return -1;
	}

	ret = check_sendbuf_size(mo, sockfd);
	if (ret)
		return ret;

	ret = connect(sockfd, (const struct sockaddr *)&name, sizeof(name));
	if (ret && (errno == ENOENT || errno == ECONNREFUSED)) {
		fprintf(stderr, "%s: no safe filesystem driver for %s available.\n",
			mo->msgtag, mo->subtype);
		close(sockfd);
		return MOUNT_SERVICE_FALLBACK_NEEDED;
	}
	if (ret) {
		int error = errno;

		fprintf(stderr, "%s: %s: %s\n",
			mo->msgtag, name.sun_path, strerror(error));
		goto out;
	}

	ret = try_drop_passrights(mo, sockfd);
	if (ret)
		goto out;

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
	ssize_t size;

	if (getuid() == 0)
		hello.flags |= htonl(FUSE_SERVICE_FLAG_ALLOW_OTHER);

	size = __send_packet(mo, &hello, sizeof(hello));
	if (size < 0) {
		fprintf(stderr, "%s: send hello: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}

	size = __recv_packet(mo, &reply, sizeof(reply));
	if (size < 0) {
		fprintf(stderr, "%s: hello reply: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}
	if (size != sizeof(reply)) {
		fprintf(stderr, "%s: wrong hello reply size %zd, expected %zu\n",
			mo->msgtag, size, sizeof(reply));
		return -1;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_HELLO_REPLY) {
		fprintf(stderr, "%s: %s service server did not reply to hello\n",
			mo->msgtag, mo->subtype);
		return -1;
	}

	if (ntohs(reply.version) < FUSE_SERVICE_MIN_PROTO ||
	    ntohs(reply.version) > FUSE_SERVICE_MAX_PROTO) {
		fprintf(stderr, "%s: unsupported protocol version %u\n",
			mo->msgtag, ntohs(reply.version));
		return -1;
	}

	if (reply.padding) {
		fprintf(stderr, "%s: nonzero value in padding field\n",
			mo->msgtag);
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
		fprintf(stderr, "%s: memfd argv write: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}
	if (written < string_len) {
		fprintf(stderr, "%s: memfd argv[%u] wrote %zd, expected %zu\n",
			mo->msgtag, args->argc, written, string_len);
		return -1;
	}

	written = pwrite(mo->argvfd, &arg, sizeof(arg), *array_pos);
	if (written < 0) {
		fprintf(stderr, "%s: memfd arg write: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}
	if (written < sizeof(arg)) {
		fprintf(stderr, "%s: memfd arg[%u] wrote %zd, expected %zu\n",
			mo->msgtag, args->argc, written, sizeof(arg));
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
		fprintf(stderr, "%s: argc cannot be negative\n",
			mo->msgtag);
		return -1;
	}

	/*
	 * Create the memfd in which we'll stash arguments, and set the write
	 * pointer for the names.
	 */
	mo->argvfd = memfd_create("fuse service argv", MFD_CLOEXEC);
	if (mo->argvfd < 0) {
		fprintf(stderr, "%s: argvfd create: %s\n",
			mo->msgtag, strerror(errno));
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
		if (!strcmp(argv[i], "-t") && i + 1 < argc) {
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
		fprintf(stderr, "%s: memfd argv write: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}
	if (written < sizeof(args)) {
		fprintf(stderr, "%s: memfd argv wrote %zd, expected %zu\n",
			mo->msgtag, written, sizeof(args));
		return -1;
	}

	return 0;
}

static int mount_service_send_file(struct mount_service *mo,
				   const char *path, int fd)
{
	struct fuse_service_requested_file *req;
	const size_t req_sz =
			sizeof_fuse_service_requested_file(strlen(path));
	ssize_t written;
	int ret = 0;

	req = calloc(1, req_sz);
	if (!req) {
		fprintf(stderr, "%s: alloc send file reply: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}
	req->p.magic = htonl(FUSE_SERVICE_OPEN_REPLY);
	req->error = 0;
	strcpy(req->path, path);

	written = __send_fd(mo, req, req_sz, fd);
	if (written < 0) {
		fprintf(stderr, "%s: send file reply: %s\n",
			mo->msgtag, strerror(errno));
		ret = -1;
		goto out_req;
	}
	if (written < req_sz) {
		fprintf(stderr, "%s: send file reply wrote %zd, expected %zu\n",
			mo->msgtag, written, req_sz);
		ret = -1;
		goto out_req;
	}

out_req:
	free(req);
	return ret;
}

static int mount_service_send_file_error(struct mount_service *mo, int error,
					 const char *path)
{
	struct fuse_service_requested_file *req;
	const size_t req_sz =
			sizeof_fuse_service_requested_file(strlen(path));
	ssize_t written;
	int ret = 0;

	req = calloc(1, req_sz);
	if (!req) {
		fprintf(stderr, "%s: alloc send file error: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}
	req->p.magic = htonl(FUSE_SERVICE_OPEN_REPLY);
	req->error = htonl(error);
	strcpy(req->path, path);

	written = __send_packet(mo, req, req_sz);
	if (written < 0) {
		fprintf(stderr, "%s: send file error: %s\n",
			mo->msgtag, strerror(errno));
		ret = -1;
		goto out_req;
	}
	if (written < req_sz) {
		fprintf(stderr, "%s: send file error wrote %zd, expected %zu\n",
			mo->msgtag, written, req_sz);
		ret = -1;
		goto out_req;
	}

out_req:
	free(req);
	return ret;
}

static int mount_service_send_required_files(struct mount_service *mo,
					     const char *fusedev)
{
	int ret;

	mo->fusedevfd = open(fusedev, O_RDWR | O_CLOEXEC);
	if (mo->fusedevfd < 0) {
		int error = errno;

		fprintf(stderr, "%s: %s: %s\n",
			mo->msgtag, fusedev, strerror(error));
		return -1;
	}

	ret = mount_service_send_file(mo, FUSE_SERVICE_ARGV, mo->argvfd);
	if (ret)
		goto out_fusedevfd;

	close(mo->argvfd);
	mo->argvfd = -1;

	return mount_service_send_file(mo, FUSE_SERVICE_FUSEDEV,
				       mo->fusedevfd);

out_fusedevfd:
	close(mo->fusedevfd);
	mo->fusedevfd = -1;
	return ret;
}

static int mount_service_receive_command(struct mount_service *mo,
					 struct fuse_service_packet **commandp,
					 size_t *commandsz)
{
	struct fuse_service_packet *command;
	ssize_t alleged_size, size;

	alleged_size = __recv_packet_size(mo);
	if (alleged_size < 0) {
		fprintf(stderr, "%s: peek service command: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}
	if (alleged_size == 0) {
		/* fuse server probably exited early */
		fprintf(stderr, "%s: fuse server exited without saying goodbye!\n",
			mo->msgtag);
		return -1;
	}
	if (alleged_size < sizeof(struct fuse_service_packet)) {
		fprintf(stderr, "%s: wrong command packet size %zd, expected at least %zu\n",
			mo->msgtag, alleged_size,
			sizeof(struct fuse_service_packet));
		return -1;
	}
	if (alleged_size > FUSE_SERVICE_MAX_CMD_SIZE) {
		fprintf(stderr, "%s: wrong command packet size %zd, expected less than %d\n",
			mo->msgtag, alleged_size, FUSE_SERVICE_MAX_CMD_SIZE);
		return -1;
	}

	command = calloc(1, alleged_size + 1);
	if (!command) {
		fprintf(stderr, "%s: alloc service command: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}

	size = __recv_packet(mo, command, alleged_size);
	if (size < 0) {
		fprintf(stderr, "%s: receive service command: %s\n",
			mo->msgtag, strerror(errno));
		free(command);
		return -1;
	}
	if (size != alleged_size) {
		fprintf(stderr, "%s: wrong service command size %zd, expected %zd\n",
			mo->msgtag, size, alleged_size);
		free(command);
		return -1;
	}

	*commandp = command;
	*commandsz = size;
	return 0;
}

static int mount_service_send_reply(struct mount_service *mo, int error)
{
	struct fuse_service_simple_reply reply = {
		.p.magic = htonl(FUSE_SERVICE_SIMPLE_REPLY),
		.error = htonl(error),
	};
	ssize_t size;

	size = __send_packet(mo, &reply, sizeof(reply));
	if (size < 0) {
		fprintf(stderr, "%s: send service reply: %s\n",
			mo->msgtag, strerror(errno));
		return -1;
	}

	return 0;
}

static int prepare_bdev(struct mount_service *mo,
			struct fuse_service_open_command *oc, int fd)
{
	struct stat stbuf;
	int ret;

	ret = fstat(fd, &stbuf);
	if (ret) {
		int error = errno;

		fprintf(stderr, "%s: %s: %s\n",
			mo->msgtag, oc->path, strerror(error));
		return -error;
	}

	if (!S_ISBLK(stbuf.st_mode)) {
		fprintf(stderr, "%s: %s: %s\n",
			mo->msgtag, oc->path, strerror(ENOTBLK));
		return -ENOTBLK;
	}

	if (oc->block_size) {
		int block_size = ntohl(oc->block_size);

		ret = ioctl(fd, BLKBSZSET, &block_size);
		if (ret) {
			int error = errno;

			fprintf(stderr, "%s: %s: %s\n",
				mo->msgtag, oc->path, strerror(error));
			return -error;
		}
	}

	return 0;
}

static int mount_service_open_path(struct mount_service *mo,
				   mode_t expected_fmt,
				   struct fuse_service_packet *p, size_t psz)
{
	struct fuse_service_open_command *oc =
			container_of(p, struct fuse_service_open_command, p);
	uint32_t request_flags;
	int open_flags;
	int ret;
	int fd;

	if (psz < sizeof_fuse_service_open_command(1)) {
		fprintf(stderr, "%s: open command too small\n",
			mo->msgtag);
		return mount_service_send_file_error(mo, EINVAL, "?");
	}

	if (!check_null_endbyte(p, psz)) {
		fprintf(stderr, "%s: open command must be null terminated\n",
			mo->msgtag);
		return mount_service_send_file_error(mo, EINVAL, "?");
	}

	request_flags = ntohl(oc->request_flags);
	if (request_flags & ~FUSE_SERVICE_OPEN_FLAGS) {
		fprintf(stderr, "%s: open flags 0x%x not recognized\n",
			mo->msgtag, request_flags & ~FUSE_SERVICE_OPEN_FLAGS);
		return mount_service_send_file_error(mo, EINVAL, oc->path);
	}

	open_flags = ntohl(oc->open_flags) | O_CLOEXEC;
	fd = open(oc->path, open_flags, ntohl(oc->create_mode));
	if (fd < 0) {
		int error = errno;

		/*
		 * Don't print a busy device error report because the
		 * filesystem might decide to retry.
		 */
		if (error != EBUSY && !(request_flags & FUSE_SERVICE_OPEN_QUIET))
			fprintf(stderr, "%s: %s: %s\n",
				mo->msgtag, oc->path, strerror(error));
		return mount_service_send_file_error(mo, error, oc->path);
	}

	if (S_ISBLK(expected_fmt)) {
		ret = prepare_bdev(mo, oc, fd);
		if (ret < 0) {
			close(fd);
			return mount_service_send_file_error(mo, -ret,
							     oc->path);
		}
	}

	ret = mount_service_send_file(mo, oc->path, fd);
	close(fd);
	return ret;
}

static int mount_service_handle_open_cmd(struct mount_service *mo,
					 struct fuse_service_packet *p,
					 size_t psz)
{
	return mount_service_open_path(mo, 0, p, psz);
}

static int mount_service_handle_open_bdev_cmd(struct mount_service *mo,
					      struct fuse_service_packet *p,
					      size_t psz)
{
	return mount_service_open_path(mo, S_IFBLK, p, psz);
}

static inline const char *fsname(const struct mount_service *mo)
{
	return mo->fuseblk ? "fuseblk" : "fuse";
}

#ifdef HAVE_NEW_MOUNT_API
static void try_fsopen(struct mount_service *mo)
{
	/*
	 * As of Linux 7.0 you can pass subtypes to fsopen, but the manpage for
	 * fsopen only says that you can pass any value of the second column of
	 * /proc/filesystems into fsopen.
	 */
	mo->fsopenfd = fsopen(fsname(mo), FSOPEN_CLOEXEC);
}
#else
# define try_fsopen(...)	((void)0)
#endif

static int mount_service_handle_fsopen_cmd(struct mount_service *mo,
					   const struct fuse_service_packet *p,
					   size_t psz)
{
	struct fuse_service_fsopen_command *oc =
			container_of(p, struct fuse_service_fsopen_command, p);
	uint32_t fsopen_flags;

	if (psz != sizeof(struct fuse_service_fsopen_command)) {
		fprintf(stderr, "%s: fsopen command wrong size %zu, expected %zu\n",
			mo->msgtag, psz, sizeof(*oc));
		return mount_service_send_reply(mo, EINVAL);
	}

	if (mo->fsopened) {
		fprintf(stderr, "%s: fsopen command respecified\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	fsopen_flags = ntohl(oc->fsopen_flags);
	if (fsopen_flags & ~FUSE_SERVICE_FSOPEN_FLAGS) {
		fprintf(stderr, "%s: unknown fsopen flags, 0x%x\n",
			mo->msgtag, fsopen_flags & ~FUSE_SERVICE_FSOPEN_FLAGS);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (fsopen_flags & FUSE_SERVICE_FSOPEN_FUSEBLK) {
		if (getuid() != 0) {
			fprintf(stderr, "%s: fuseblk requires root privilege\n",
				mo->msgtag);
			return mount_service_send_reply(mo, EPERM);
		}

		mo->fuseblk = true;
	}
	mo->fsopened = true;

	/* If this fails we fall back on mount(); oc->value is mutated */
	try_fsopen(mo);
	return mount_service_send_reply(mo, 0);
}

#ifdef HAVE_NEW_MOUNT_API
/* callers must preserve errno */
static void emit_fsconfig_messages(const struct mount_service *mo)
{
	uint8_t buf[BUFSIZ];
	ssize_t sz;

	while ((sz = read(mo->fsopenfd, buf, sizeof(buf) - 1)) >= 1) {
		if (buf[sz - 1] == '\n')
			buf[--sz] = '\0';
		else
			buf[sz] = '\0';

		if (!*buf)
			continue;

		switch (buf[0]) {
		case 'e':
			fprintf(stderr, "Error: %s\n", buf + 2);
			break;
		case 'w':
			fprintf(stderr, "Warning: %s\n", buf + 2);
			break;
		case 'i':
			fprintf(stderr, "Info: %s\n", buf + 2);
			break;
		default:
			fprintf(stderr, " %s\n", buf);
			break;
		}
	}
}
#endif

static int mount_service_handle_source_cmd(struct mount_service *mo,
					   const struct fuse_service_packet *p,
					   size_t psz)
{
	struct fuse_service_string_command *oc =
			container_of(p, struct fuse_service_string_command, p);
	char *source;

	if (psz < sizeof_fuse_service_string_command(1)) {
		fprintf(stderr, "%s: source command too small\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (!check_null_endbyte(p, psz)) {
		fprintf(stderr, "%s: source command must be null terminated\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (mo->source) {
		fprintf(stderr, "%s: source respecified!\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	source = strdup(oc->value);
	if (!source) {
		int error = errno;

		fprintf(stderr, "%s: alloc source string: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

#ifdef HAVE_NEW_MOUNT_API
	if (mo->fsopenfd >= 0) {
		int ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "source",
			       oc->value, 0);
		if (ret) {
			int error = errno;

			fprintf(stderr, "%s: fsconfig source: %s\n",
				mo->msgtag, strerror(error));
			emit_fsconfig_messages(mo);
			free(source);
			return mount_service_send_reply(mo, error);
		}
	}
#endif

	mo->source = source;
	return mount_service_send_reply(mo, 0);
}

static int mount_service_handle_mntopts_cmd(struct mount_service *mo,
					    const struct fuse_service_packet *p,
					    size_t psz)
{
	struct fuse_service_string_command *oc =
			container_of(p, struct fuse_service_string_command, p);
	char *tokstr = oc->value;
	char *tok, *savetok;
	char *mntopts;

	if (psz < sizeof_fuse_service_string_command(1)) {
		fprintf(stderr, "%s: mount options command too small\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (!check_null_endbyte(p, psz)) {
		fprintf(stderr, "%s: mount options command must be null terminated\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (mo->mntopts) {
		fprintf(stderr, "%s: mount options respecified!\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	mntopts = strdup(oc->value);
	if (!mntopts) {
		int error = errno;

		fprintf(stderr, "%s: alloc mount options string: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	/* strtok_r mutates tokstr aka oc->value */
	while ((tok = strtok_r(tokstr, ",", &savetok)) != NULL) {
		char *equals = strchr(tok, '=');
		char oldchar = 0;

		if (equals) {
			oldchar = *equals;
			*equals = 0;
		}

#ifdef HAVE_NEW_MOUNT_API
		if (mo->fsopenfd >= 0) {
			int ret;

			if (equals)
				ret = fsconfig(mo->fsopenfd,
					       FSCONFIG_SET_STRING, tok,
					       equals + 1, 0);
			else
				ret = fsconfig(mo->fsopenfd,
					       FSCONFIG_SET_FLAG, tok,
					       NULL, 0);
			if (ret) {
				int error = errno;

				fprintf(stderr, "%s: set mount option: %s\n",
					mo->msgtag, strerror(error));
				emit_fsconfig_messages(mo);
				free(mntopts);
				return mount_service_send_reply(mo, error);
			}
		}
#endif

		if (equals)
			*equals = oldchar;

		tokstr = NULL;
	}

	mo->mntopts = mntopts;
	return mount_service_send_reply(mo, 0);
}

static int mount_service_handle_mtabopts_cmd(struct mount_service *mo,
					     const struct fuse_service_packet *p,
					     size_t psz)
{
	struct fuse_service_string_command *oc =
			container_of(p, struct fuse_service_string_command, p);
	char *tokstr = oc->value;
	char *tok, *savetok;

	if (psz < sizeof_fuse_service_string_command(1)) {
		fprintf(stderr, "%s: mtab options command too small\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (!check_null_endbyte(p, psz)) {
		fprintf(stderr, "%s: mtab options command must be null terminated\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (mo->mtabopts) {
		fprintf(stderr, "%s: mtab options respecified!\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	mo->mtabopts = strdup(oc->value);
	if (!mo->mtabopts) {
		int error = errno;

		fprintf(stderr, "%s: alloc mtab options string: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	/* strtok_r mutates tokstr aka oc->value */
	while ((tok = strtok_r(tokstr, ",", &savetok)) != NULL) {
		if (!strcmp(tok, "-n")) {
			free(mo->mtabopts);
			mo->mtabopts = &IGNORE_MTAB;
		}

		tokstr = NULL;
	}

	return mount_service_send_reply(mo, 0);
}

static int attach_to_mountpoint(struct mount_service *mo, mode_t expected_fmt,
				char *mntpt)
{
	struct stat stbuf;
	char *res_mntpt;
	int mountfd = -1;
	int error;
	int ret;

	/*
	 * Open the alleged mountpoint, make sure it's a dir or a file.
	 */
	mountfd = open(mntpt, O_RDONLY | O_CLOEXEC);
	if (mountfd < 0) {
		error = errno;
		fprintf(stderr, "%s: %s: %s\n", mo->msgtag, mntpt,
			strerror(error));
		goto out_error;
	}

	/*
	 * Make sure we can access the mountpoint and that it's either a
	 * directory or a regular file.  Linux can handle mounting atop special
	 * files, but we don't care to do such crazy things.
	 */
	ret = fstat(mountfd, &stbuf);
	if (ret) {
		error = errno;
		fprintf(stderr, "%s: %s: %s\n", mo->msgtag, mntpt,
			strerror(error));
		goto out_mountfd;
	}

	if (!S_ISDIR(stbuf.st_mode) && !S_ISREG(stbuf.st_mode)) {
		error = EACCES;
		fprintf(stderr, "%s: %s: Mount point must be directory or regular file.\n",
			mo->msgtag, mntpt);
		goto out_mountfd;
	}

	/*
	 * Resolve the (possibly relative) mountpoint path before chdir'ing
	 * onto it.
	 */
	res_mntpt = fuse_mnt_resolve_path(mo->msgtag, mntpt);
	if (!res_mntpt) {
		error = EACCES;
		fprintf(stderr, "%s: %s: Could not resolve path to mount point.\n",
			mo->msgtag, mntpt);
		goto out_mountfd;
	}

	/* Make sure the mountpoint type matches what the caller wanted */
	switch (expected_fmt) {
	case S_IFDIR:
		if (!S_ISDIR(stbuf.st_mode)) {
			error = ENOTDIR;
			fprintf(stderr, "%s: %s: %s\n",
				mo->msgtag, mntpt, strerror(error));
			goto out_res_mntpt;
		}
		break;
	case S_IFREG:
		if (!S_ISREG(stbuf.st_mode)) {
			error = EISDIR;
			fprintf(stderr, "%s: %s: %s\n",
				mo->msgtag, mntpt, strerror(error));
			goto out_res_mntpt;
		}
		break;
	}

	switch (stbuf.st_mode & S_IFMT) {
	case S_IFREG:
		/*
		 * This is a regular file, so we point mount() at the open file
		 * descriptor.
		 */
		asprintf(&mo->real_mountpoint, "/dev/fd/%d", mountfd);
		break;
	case S_IFDIR:
		/*
		 * Pin the mount so it can't go anywhere.  This only works for
		 * directories, which is fortunately the common case.
		 */
		ret = fchdir(mountfd);
		if (ret) {
			error = errno;
			fprintf(stderr, "%s: %s: %s\n", mo->msgtag, mntpt,
				strerror(error));
			goto out_res_mntpt;
		}

		/*
		 * Now that we're sitting on the mountpoint directory, we can
		 * pass "." to mount() and avoid races with directory tree
		 * mutations.
		 */
		mo->real_mountpoint = strdup(".");
		break;
	default:
		/* Should never get here */
		error = EINVAL;
		goto out_res_mntpt;
	}
	if (!mo->real_mountpoint) {
		error = ENOMEM;
		fprintf(stderr, "%s: %s: %s\n", mo->msgtag, mntpt,
			strerror(error));
		goto out_res_mntpt;
	}

	mo->mountpoint = mntpt;
	mo->mountfd = mountfd;
	mo->resv_mountpoint = res_mntpt;

	return mount_service_send_reply(mo, 0);

out_res_mntpt:
	free(res_mntpt);
out_mountfd:
	close(mountfd);
out_error:
	free(mntpt);
	return mount_service_send_reply(mo, error);
}

static int mount_service_handle_mountpoint_cmd(struct mount_service *mo,
					       const struct fuse_service_packet *p,
					       size_t psz, int argc, char *argv[])
{
	struct fuse_service_mountpoint_command *oc =
			container_of(p, struct fuse_service_mountpoint_command, p);
	char *mntpt;
	mode_t expected_fmt;
	bool foundit = false;
	int i;

	if (psz < sizeof_fuse_service_mountpoint_command(1)) {
		fprintf(stderr, "%s: mount point command too small\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (!check_null_endbyte(p, psz)) {
		fprintf(stderr, "%s: mount point command must be null terminated\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (oc->padding) {
		fprintf(stderr, "%s: nonzero value in padding field\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (mo->mountpoint) {
		fprintf(stderr, "%s: mount point respecified!\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	/* Make sure the mountpoint file format matches what the caller wanted */
	expected_fmt = ntohs(oc->expected_fmt);
	switch (expected_fmt) {
	case S_IFDIR:
	case S_IFREG:
	case 0:
		break;
	default:
		fprintf(stderr, "%s: %s: weird expected format 0%o\n",
			mo->msgtag, oc->value, expected_fmt);
		return mount_service_send_reply(mo, EINVAL);
	}

	/* Mountpoint must be mentioned in the caller's argument list */
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], oc->value)) {
			foundit = true;
			break;
		}
	}
	if (!foundit) {
		fprintf(stderr, "%s: mount point must be in command line arguments\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	mntpt = strdup(oc->value);
	if (!mntpt) {
		int error = errno;

		fprintf(stderr, "%s: alloc mount point string: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	return attach_to_mountpoint(mo, expected_fmt, mntpt);
}

static inline int format_libfuse_mntopts(char *buf, size_t bufsz,
					 const struct mount_service *mo,
					 const struct stat *stbuf)
{
	if (mo->mntopts)
		return snprintf(buf, bufsz,
				"%s,fd=%i,rootmode=%o,user_id=%u,group_id=%u",
				mo->mntopts, mo->fusedevfd,
				stbuf->st_mode & S_IFMT,
				getuid(), getgid());

	return snprintf(buf, bufsz,
			"fd=%i,rootmode=%o,user_id=%u,group_id=%u",
			mo->fusedevfd, stbuf->st_mode & S_IFMT,
			getuid(), getgid());
}

static int mount_service_regular_mount(struct mount_service *mo,
				       struct fuse_service_mount_command *oc,
				       struct stat *stbuf)
{
	char *fstype = NULL;
	char *realmopts;
	int ret;

	/* Compute the amount of buffer space needed for the mount options */
	ret = format_libfuse_mntopts(NULL, 0, mo, stbuf);
	if (ret < 0) {
		int error = errno;

		fprintf(stderr, "%s: mount option preformatting: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	realmopts = calloc(1, ret + 1);
	if (!realmopts) {
		int error = errno;

		fprintf(stderr, "%s: alloc real mount options string: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	ret = format_libfuse_mntopts(realmopts, ret + 1, mo, stbuf);
	if (ret < 0) {
		int error = errno;

		fprintf(stderr, "%s: mount options formatting: %s\n",
			mo->msgtag, strerror(error));
		ret = mount_service_send_reply(mo, error);
		goto out_realmopts;
	}

	asprintf(&fstype, "%s.%s", fsname(mo), mo->subtype);
	if (!fstype) {
		int error = errno;

		fprintf(stderr, "%s: mount fstype formatting: %s\n",
			mo->msgtag, strerror(error));
		ret = mount_service_send_reply(mo, error);
		goto out_realmopts;
	}

	ret = mount(mo->source, mo->real_mountpoint, fstype,
		    ntohl(oc->ms_flags), realmopts);
	if (ret) {
		int error = errno;

		fprintf(stderr, "%s: mount: %s\n",
			mo->msgtag, strerror(error));
		ret = mount_service_send_reply(mo, error);
		goto out_fstype;
	}

	/*
	 * The mount succeeded, so we send a positive reply even if the mtab
	 * update fails.
	 */
	if (have_real_mtabopts(mo))
		fuse_mnt_add_mount(mo->msgtag, mo->source, mo->resv_mountpoint,
				   fstype, mo->mtabopts);

	mo->mounted = true;
	ret = mount_service_send_reply(mo, 0);
out_fstype:
	free(fstype);
out_realmopts:
	free(realmopts);
	return ret;
}

#ifdef HAVE_NEW_MOUNT_API
struct ms_to_mount_map {
	unsigned long ms_flag;
	unsigned int mount_attr_flag;
};

static const struct ms_to_mount_map attrs[] = {
	{ MS_RDONLY,		MOUNT_ATTR_RDONLY },
	{ MS_NOSUID,		MOUNT_ATTR_NOSUID },
	{ MS_NODEV,		MOUNT_ATTR_NODEV },
	{ MS_NOEXEC,		MOUNT_ATTR_NOEXEC },
	{ MS_RELATIME,		MOUNT_ATTR_RELATIME },
	{ MS_NOATIME,		MOUNT_ATTR_NOATIME },
	{ MS_STRICTATIME,	MOUNT_ATTR_STRICTATIME },
	{ MS_NODIRATIME,	MOUNT_ATTR_NODIRATIME },
#ifdef MOUNT_ATTR_NOSYMFOLLOW
	{ MS_NOSYMFOLLOW,	MOUNT_ATTR_NOSYMFOLLOW },
#endif
	{ 0, 0 },
};

static void get_mount_attr_flags(const struct fuse_service_mount_command *oc,
				 unsigned int *attr_flags,
				 unsigned long *leftover_ms_flags)
{
	const struct ms_to_mount_map *i;
	unsigned int ms_flags = ntohl(oc->ms_flags);
	unsigned int mount_attr_flags = 0;

	for (i = attrs; i->ms_flag != 0; i++) {
		if (ms_flags & i->ms_flag)
			mount_attr_flags |= i->mount_attr_flag;
		ms_flags &= ~i->ms_flag;
	}

	*leftover_ms_flags = ms_flags;
	*attr_flags = mount_attr_flags;
}

struct ms_to_str_map {
	unsigned long ms_flag;
	const char *string;
};

static const struct ms_to_str_map strflags[] = {
	{ MS_SYNCHRONOUS,	"sync" },
	{ MS_DIRSYNC,		"dirsync" },
	{ MS_LAZYTIME,		"lazytime" },
	{ 0, 0 },
};

static int set_ms_flags(struct mount_service *mo, unsigned long ms_flags)
{
	const struct ms_to_str_map *i;
	int ret;

	for (i = strflags; i->ms_flag != 0; i++) {
		if (!(ms_flags & i->ms_flag))
			continue;

		ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_FLAG, i->string,
			       NULL, 0);
		if (ret) {
			int error = errno;

			fprintf(stderr, "%s: set %s option: %s\n",
				mo->msgtag, i->string, strerror(error));
			emit_fsconfig_messages(mo);

			errno = error;
			return -1;
		}
		ms_flags &= ~i->ms_flag;
	}

	/*
	 * We can't translate all the supplied MS_ flags into MOUNT_ATTR_ flags
	 * or string flags!  Return a magic code so the caller will fall back
	 * to regular mount(2).
	 */
	if (ms_flags)
		return FUSE_MOUNT_FALLBACK_NEEDED;

	return 0;
}

static int mount_service_fsopen_mount(struct mount_service *mo,
				      struct fuse_service_mount_command *oc,
				      struct stat *stbuf)
{
	char tmp[64];
	unsigned long ms_flags;
	unsigned int attr_flags;
	int mfd;
	int error;
	int ret;

	get_mount_attr_flags(oc, &attr_flags, &ms_flags);

	ret = set_ms_flags(mo, ms_flags);
	if (ret == FUSE_MOUNT_FALLBACK_NEEDED)
		return ret;
	if (ret) {
		error = errno;
		goto fail_mount;
	}

	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "subtype",
		       mo->subtype, 0);
	if (ret) {
		error = errno;

		/* The subtype option was merged after fsopen */
		if (error == EINVAL)
			return FUSE_MOUNT_FALLBACK_NEEDED;

		fprintf(stderr, "%s: set subtype option: %s\n",
			mo->msgtag, strerror(error));
		goto fail_fsconfig;
	}

	snprintf(tmp, sizeof(tmp), "%i", mo->fusedevfd);
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "fd", tmp, 0);
	if (ret) {
		error = errno;
		fprintf(stderr, "%s: set fd option: %s\n",
			mo->msgtag, strerror(error));
		goto fail_fsconfig;
	}

	snprintf(tmp, sizeof(tmp), "%o", stbuf->st_mode & S_IFMT);
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "rootmode", tmp, 0);
	if (ret) {
		error = errno;
		fprintf(stderr, "%s: set rootmode option: %s\n",
			mo->msgtag, strerror(error));
		goto fail_fsconfig;
	}

	snprintf(tmp, sizeof(tmp), "%u", getuid());
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "user_id", tmp, 0);
	if (ret) {
		error = errno;
		fprintf(stderr, "%s: set user_id option: %s\n",
			mo->msgtag, strerror(error));
		goto fail_fsconfig;
	}

	snprintf(tmp, sizeof(tmp), "%u", getgid());
	ret = fsconfig(mo->fsopenfd, FSCONFIG_SET_STRING, "group_id", tmp, 0);
	if (ret) {
		error = errno;
		fprintf(stderr, "%s: set group_id option: %s\n",
			mo->msgtag, strerror(error));
		goto fail_fsconfig;
	}

	ret = fsconfig(mo->fsopenfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (ret) {
		error = errno;
		fprintf(stderr, "%s: creating filesystem: %s\n",
			mo->msgtag, strerror(error));
		goto fail_fsconfig;
	}

	mfd = fsmount(mo->fsopenfd, FSMOUNT_CLOEXEC, attr_flags);
	if (mfd < 0) {
		error = errno;
		fprintf(stderr, "%s: fsmount: %s\n",
			mo->msgtag, strerror(error));
		goto fail_fsconfig;
	}

	ret = move_mount(mfd, "", mo->mountfd, "",
			 MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH);
	close(mfd);
	if (ret) {
		error = errno;
		fprintf(stderr, "%s: move_mount: %s\n",
			mo->msgtag, strerror(error));
		goto fail_mount;
	}

	/*
	 * The mount succeeded, so we send a positive reply even if the mtab
	 * update fails.
	 */
	if (have_real_mtabopts(mo)) {
		char *fstype = NULL;

		asprintf(&fstype, "%s.%s", fsname(mo), mo->subtype);
		if (fstype) {
			fuse_mnt_add_mount(mo->msgtag, mo->source,
					   mo->resv_mountpoint, fstype,
					   mo->mtabopts);
			free(fstype);
		}
	}

	mo->mounted = true;
	return mount_service_send_reply(mo, 0);

fail_fsconfig:
	emit_fsconfig_messages(mo);
fail_mount:
	return mount_service_send_reply(mo, error);
}
#else
# define mount_service_fsopen_mount(...)	(FUSE_MOUNT_FALLBACK_NEEDED)
#endif

static int mount_service_handle_mount_cmd(struct mount_service *mo,
					  struct fuse_service_packet *p,
					  size_t psz)
{
	struct stat stbuf;
	struct fuse_service_mount_command *oc =
			container_of(p, struct fuse_service_mount_command, p);
	int ret;

	if (psz != sizeof(struct fuse_service_mount_command)) {
		fprintf(stderr, "%s: mount command wrong size %zu, expected %zu\n",
			mo->msgtag, psz, sizeof(*oc));
		return mount_service_send_reply(mo, EINVAL);
	}

	if (!mo->source) {
		fprintf(stderr, "%s: missing mount source parameter\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	if (!mo->mountpoint) {
		fprintf(stderr, "%s: missing mount point parameter\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	/*
	 * Call fstat again because access modes might have changed since we
	 * validated the file type.  This is still racy with mount since we
	 * don't lock the path target.
	 */
	ret = fstat(mo->mountfd, &stbuf);
	if (ret < 0) {
		int error = errno;

		fprintf(stderr, "%s: %s: %s\n",
			mo->msgtag, mo->mountpoint, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	if (mo->fsopenfd >= 0) {
		ret = mount_service_fsopen_mount(mo, oc, &stbuf);
		if (ret != FUSE_MOUNT_FALLBACK_NEEDED)
			return ret;
	}

	return mount_service_regular_mount(mo, oc, &stbuf);
}

static int mount_service_handle_unmount_cmd(struct mount_service *mo,
					    struct fuse_service_packet *p,
					    size_t psz)
{
	int ret;

	(void)p;

	if (psz != sizeof(struct fuse_service_unmount_command)) {
		fprintf(stderr, "%s: unmount command wrong size %zu, expected %zu\n",
			mo->msgtag, psz, sizeof(struct fuse_service_unmount_command));
		return mount_service_send_reply(mo, EINVAL);
	}

	if (!mo->mounted) {
		fprintf(stderr, "%s: will not umount before successful mount!\n",
			mo->msgtag);
		return mount_service_send_reply(mo, EINVAL);
	}

	ret = chdir("/");
	if (ret) {
		int error = errno;

		fprintf(stderr, "%s: fuse server failed chdir: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	close(mo->mountfd);
	mo->mountfd = -1;

	/*
	 * Try to unmount the resolved mountpoint, and hope that we're not the
	 * victim of a race.
	 */
	ret = umount2(mo->resv_mountpoint, MNT_DETACH);
	if (ret) {
		int error = errno;

		fprintf(stderr, "%s: fuse server failed unmount: %s\n",
			mo->msgtag, strerror(error));
		return mount_service_send_reply(mo, error);
	}

	/*
	 * The unmount succeeded, so we send a positive reply even if the mtab
	 * update fails.
	 */
	if (have_real_mtabopts(mo))
		fuse_mnt_remove_mount(mo->msgtag, mo->resv_mountpoint);

	mo->mounted = false;
	return mount_service_send_reply(mo, 0);
}

static int mount_service_handle_bye_cmd(struct mount_service *mo,
					struct fuse_service_packet *p,
					size_t psz)
{
	struct fuse_service_bye_command *bc =
			container_of(p, struct fuse_service_bye_command, p);
	int ret;

	if (psz != sizeof(struct fuse_service_bye_command)) {
		fprintf(stderr, "%s: bye command wrong size %zu, expected %zu\n",
			mo->msgtag, psz, sizeof(*bc));
		return mount_service_send_reply(mo, EINVAL);
	}

	ret = ntohl(bc->exitcode);
	if (ret)
		fprintf(stderr, "%s: fuse server failed mount, check dmesg/logs for details.\n",
			mo->msgtag);

	return ret;
}

static void mount_service_destroy(struct mount_service *mo)
{
	close(mo->mountfd);
	close(mo->fusedevfd);
	close(mo->argvfd);
	close(mo->fsopenfd);
	shutdown(mo->sockfd, SHUT_RDWR);
	close(mo->sockfd);

	free(mo->source);
	free(mo->mountpoint);
	free(mo->real_mountpoint);
	free(mo->resv_mountpoint);
	if (have_real_mtabopts(mo))
		free(mo->mtabopts);
	free(mo->mntopts);
	free(mo->subtype);

	memset(mo, 0, sizeof(*mo));
	mo->sockfd = -1;
	mo->argvfd = -1;
	mo->fusedevfd = -1;
	mo->mountfd = -1;
	mo->fsopenfd = -1;
}

int mount_service_main(int argc, char *argv[])
{
	const char *fusedev = fuse_mnt_get_devname();
	struct mount_service mo = { };
	bool running = true;
	int ret;

	if (argc < 3 || !strcmp(argv[1], "--help")) {
		printf("Usage: %s source mountpoint -t type [-o options]\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	if (argc > 0 && argv[0])
		mo.msgtag = argv[0];
	else
		mo.msgtag = "mount.service";

	ret = mount_service_init(&mo, argc, argv);
	if (ret)
		return EXIT_FAILURE;

	ret = mount_service_connect(&mo);
	if (ret == MOUNT_SERVICE_FALLBACK_NEEDED)
		goto out;
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
		size_t sz;

		ret = mount_service_receive_command(&mo, &p, &sz);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}

		switch (ntohl(p->magic)) {
		case FUSE_SERVICE_OPEN_CMD:
			ret = mount_service_handle_open_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_OPEN_BDEV_CMD:
			ret = mount_service_handle_open_bdev_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_FSOPEN_CMD:
			ret = mount_service_handle_fsopen_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_SOURCE_CMD:
			ret = mount_service_handle_source_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_MNTOPTS_CMD:
			ret = mount_service_handle_mntopts_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_MNTPT_CMD:
			ret = mount_service_handle_mountpoint_cmd(&mo, p, sz,
								  argc, argv);
			break;
		case FUSE_SERVICE_MTABOPTS_CMD:
			ret = mount_service_handle_mtabopts_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_MOUNT_CMD:
			ret = mount_service_handle_mount_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_UNMOUNT_CMD:
			ret = mount_service_handle_unmount_cmd(&mo, p, sz);
			break;
		case FUSE_SERVICE_BYE_CMD:
			ret = mount_service_handle_bye_cmd(&mo, p, sz);
			free(p);
			goto out;
		default:
			fprintf(stderr, "%s: unrecognized packet 0x%x\n",
				mo.msgtag, ntohl(p->magic));
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
