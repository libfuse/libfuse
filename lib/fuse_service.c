/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025-2026 Oracle.
 * Author: Darrick J. Wong <djwong@kernel.org>
 *
 * Library functions to support fuse servers that can be run as "safe" systemd
 * containers.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <systemd/sd-daemon.h>
#include <arpa/inet.h>
#include <limits.h>

#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_service_priv.h"
#include "fuse_service.h"
#include "mount_common_i.h"

struct fuse_service {
	/* expected file format of the mount point */
	mode_t expected_fmt;

	/* socket fd */
	int sockfd;

	/* /dev/fuse device */
	int fusedevfd;

	/* memfd for cli arguments */
	int argvfd;

	/* do we own fusedevfd? */
	bool owns_fusedevfd;

	/* can we use allow_other? */
	bool allow_other;
};

static int __recv_fd(struct fuse_service *sf,
		     struct fuse_service_requested_file *buf,
		     ssize_t bufsize, int *fdp)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = bufsize,
	};
	union {
		struct cmsghdr cmsghdr;
		char control[CMSG_SPACE(sizeof(int))];
	} cmsgu;
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgu.control,
		.msg_controllen = sizeof(cmsgu.control),
	};
	struct cmsghdr *cmsg;
	ssize_t size;

	memset(&cmsgu, 0, sizeof(cmsgu));

	size = recvmsg(sf->sockfd, &msg, MSG_TRUNC | MSG_CMSG_CLOEXEC);
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service file reply: %s\n",
			 strerror(error));
		return -error;
	}
	if (size > bufsize ||
	    size < offsetof(struct fuse_service_requested_file, path)) {
		fuse_log(FUSE_LOG_ERR, "fuse: wrong service file reply size %zd, expected %zd\n",
			 size, bufsize);
		return -EBADMSG;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		/* no control message means mount.service sent us an error */
		return 0;
	}
	if (cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: wrong service file reply control data size %zd, expected %zd\n",
			 cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
		return -EBADMSG;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fuse_log(FUSE_LOG_ERR,
"fuse: wrong service file reply control data level %d type %d, expected %d and %d\n",
			 cmsg->cmsg_level, cmsg->cmsg_type, SOL_SOCKET,
			 SCM_RIGHTS);
		return -EBADMSG;
	}

	memcpy(fdp, (int *)CMSG_DATA(cmsg), sizeof(int));
	return 0;
}

static ssize_t __send_packet(struct fuse_service *sf, void *ptr, size_t len)
{
	struct iovec iov = {
		.iov_base = ptr,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	return sendmsg(sf->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
}

static ssize_t __recv_packet(struct fuse_service *sf, void *ptr, size_t len)
{
	struct iovec iov = {
		.iov_base = ptr,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	return recvmsg(sf->sockfd, &msg, MSG_TRUNC);
}

int fuse_service_receive_file(struct fuse_service *sf, const char *path,
			      int *fdp)
{
	struct fuse_service_requested_file *req;
	const size_t req_sz = sizeof_fuse_service_requested_file(strlen(path));
	int fd = -ENOENT;
	int ret;

	*fdp = -ENOENT;

	req = calloc(1, req_sz + 1);
	if (!req) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: alloc service file reply: %s\n",
			 strerror(error));
		return -error;
	}

	ret = __recv_fd(sf, req, req_sz, &fd);
	if (ret)
		goto out_req;

	if (ntohl(req->p.magic) != FUSE_SERVICE_OPEN_REPLY) {
		fuse_log(FUSE_LOG_ERR, "fuse: service file reply contains wrong magic!\n");
		ret = -EBADMSG;
		goto out_close;
	}
	if (strcmp(req->path, path)) {
		fuse_log(FUSE_LOG_ERR, "fuse: `%s': not the requested service file, got `%s'\n",
			 path, req->path);
		ret = -EBADMSG;
		goto out_close;
	}

	if (req->error) {
		*fdp = -ntohl(req->error);
		goto out_close;
	}

	if (fd == -ENOENT)
		fuse_log(FUSE_LOG_ERR, "fuse: did not receive `%s' but no error?\n",
			 path);

	*fdp = fd;
	goto out_req;

out_close:
	close(fd);
out_req:
	free(req);
	return ret;
}

#define FUSE_SERVICE_REQUEST_FILE_FLAGS	(FUSE_SERVICE_REQUEST_FILE_QUIET)

static int fuse_service_request_path(struct fuse_service *sf, const char *path,
				     mode_t expected_fmt, int open_flags,
				     mode_t create_mode,
				     unsigned int request_flags,
				     unsigned int block_size)
{
	struct fuse_service_open_command *cmd;
	const size_t cmdsz = sizeof_fuse_service_open_command(strlen(path));
	ssize_t size;
	unsigned int rqflags = 0;
	int ret;

	if (request_flags & ~FUSE_SERVICE_REQUEST_FILE_FLAGS) {
		fuse_log(FUSE_LOG_ERR, "fuse: invalid fuse service file request flags 0x%x\n",
			 request_flags);
		return -EINVAL;
	}

	if (request_flags & FUSE_SERVICE_REQUEST_FILE_QUIET)
		rqflags |= FUSE_SERVICE_OPEN_QUIET;

	cmd = calloc(1, cmdsz);
	if (!cmd) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: alloc service file request: %s\n",
			 strerror(error));
		return -error;
	}
	if (S_ISBLK(expected_fmt)) {
		cmd->p.magic = htonl(FUSE_SERVICE_OPEN_BDEV_CMD);
		cmd->block_size = htonl(block_size);
	} else {
		cmd->p.magic = htonl(FUSE_SERVICE_OPEN_CMD);
	}
	cmd->open_flags = htonl(open_flags);
	cmd->create_mode = htonl(create_mode);
	cmd->request_flags = htonl(rqflags);
	strcpy(cmd->path, path);

	size = __send_packet(sf, cmd, cmdsz);
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: request service file: %s\n",
			 strerror(error));
		ret = -error;
		goto out_free;
	}

	ret = 0;
out_free:
	free(cmd);
	return ret;
}

int fuse_service_request_file(struct fuse_service *sf, const char *path,
			      int open_flags, mode_t create_mode,
			      unsigned int request_flags)
{
	return fuse_service_request_path(sf, path, S_IFREG, open_flags,
					 create_mode, request_flags, 0);
}

int fuse_service_request_blockdev(struct fuse_service *sf, const char *path,
				  int open_flags, mode_t create_mode,
				  unsigned int request_flags,
				  unsigned int block_size)
{
	return fuse_service_request_path(sf, path, S_IFBLK, open_flags,
					 create_mode, request_flags,
					 block_size);
}

int fuse_service_send_goodbye(struct fuse_service *sf, int exitcode)
{
	struct fuse_service_bye_command c = {
		.p.magic = htonl(FUSE_SERVICE_BYE_CMD),
		.exitcode = htonl(exitcode),
	};
	ssize_t size;

	/* already gone? */
	if (sf->sockfd < 0)
		return 0;

	size = __send_packet(sf, &c, sizeof(c));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: send service goodbye: %s\n",
			 strerror(error));
		return -error;
	}

	shutdown(sf->sockfd, SHUT_RDWR);
	close(sf->sockfd);
	sf->sockfd = -1;
	return 0;
}

static int count_listen_fds(void)
{
	char *listen_fds;
	char *listen_pid;
	char *p;
	long l;

	/*
	 * No environment variables means we're not running as a system socket
	 * service, so we'll back out without logging anything.
	 */
	listen_fds = getenv("LISTEN_FDS");
	listen_pid = getenv("LISTEN_PID");
	if (!listen_fds || !listen_pid)
		return 0;

	/*
	 * LISTEN_PID is the pid of the process to which systemd thinks it gave
	 * the socket fd.  Hopefully that's us.
	 */
	errno = 0;
	l = strtol(listen_pid, &p, 10);
	if (errno || *p != 0 || l != getpid())
		return 0;

	/*
	 * LISTEN_FDS is the number of sockets that were opened in this
	 * process.
	 */
	errno = 0;
	l = strtol(listen_fds, &p, 10);
	if (errno || *p != 0 || l > INT_MAX || l < 0)
		return 0;

	return l;
}

static int check_sendbuf_size(int sockfd)
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

	fuse_log(FUSE_LOG_ERR, "max socket send buffer is %d, need at least %zu.\n",
		 sendbuf_size, min_size);
	return -ENOBUFS;
}

static int find_socket_fd(int nr_fds)
{
	struct stat stbuf;
	struct sockaddr_un urk;
	socklen_t urklen = sizeof(urk);
	int ret;

	if (nr_fds != 1) {
		fuse_log(FUSE_LOG_ERR, "fuse: can only handle 1 service socket, got %d.\n",
			 nr_fds);
		return -E2BIG;
	}

	ret = fstat(SD_LISTEN_FDS_START, &stbuf);
	if (ret) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service socket: %s\n",
			 strerror(error));
		return -error;
	}

	if (!S_ISSOCK(stbuf.st_mode)) {
		fuse_log(FUSE_LOG_ERR, "fuse: expected service fd %d to be a socket\n",
				SD_LISTEN_FDS_START);
		return -ENOTSOCK;
	}

	ret = getsockname(SD_LISTEN_FDS_START, &urk, &urklen);
	if (ret < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service socket family: %s\n",
			 strerror(error));
		return -error;
	}

	if (ret > 0 || urk.sun_family != AF_UNIX) {
		/*
		 * If getsockname wanted to return more data than fits in a
		 * sockaddr_un, then it's obviously not an AF_UNIX socket.
		 *
		 * If it filled the buffer exactly but the family isn't AF_UNIX
		 * then we also return false.
		 */
		fuse_log(FUSE_LOG_ERR, "fuse: service socket is not AF_UNIX\n");
		return -EAFNOSUPPORT;
	}

	ret = check_sendbuf_size(SD_LISTEN_FDS_START);
	if (ret)
		return ret;

	return SD_LISTEN_FDS_START;
}

static int negotiate_hello(struct fuse_service *sf)
{
	struct fuse_service_hello hello = { };
	struct fuse_service_hello_reply reply = {
		.p.magic = htonl(FUSE_SERVICE_HELLO_REPLY),
		.version = htons(FUSE_SERVICE_PROTO),
	};
	uint32_t flags;
	ssize_t size;

	size = __recv_packet(sf, &hello, sizeof(hello));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: receive service hello: %s\n",
			 strerror(error));
		return -error;
	}
	if (size != sizeof(hello)) {
		fuse_log(FUSE_LOG_ERR, "fuse: wrong service hello size %zd, expected %zd\n",
			 size, sizeof(hello));
		return -EBADMSG;
	}

	if (ntohl(hello.p.magic) != FUSE_SERVICE_HELLO_CMD) {
		fuse_log(FUSE_LOG_ERR, "fuse: service server did not send hello command\n");
		return -EBADMSG;
	}

	if (ntohs(hello.min_version) < FUSE_SERVICE_MIN_PROTO) {
		fuse_log(FUSE_LOG_ERR, "fuse: unsupported min service protocol version %u\n",
			ntohs(hello.min_version));
		return -EOPNOTSUPP;
	}

	if (ntohs(hello.max_version) > FUSE_SERVICE_MAX_PROTO) {
		fuse_log(FUSE_LOG_ERR, "fuse: unsupported max service protocol version %u\n",
			ntohs(hello.min_version));
		return -EOPNOTSUPP;
	}

	flags = ntohl(hello.flags);
	if (flags & ~FUSE_SERVICE_FLAGS) {
		fprintf(stderr, "fuse: invalid hello flags: 0x%x\n",
			flags & ~FUSE_SERVICE_FLAGS);
		return -EINVAL;
	}

	if (flags & FUSE_SERVICE_FLAG_ALLOW_OTHER)
		sf->allow_other = true;

	size = __send_packet(sf, &reply, sizeof(reply));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service hello reply: %s\n",
			 strerror(error));
		return -error;
	}

	return 0;
}

int fuse_service_accept(struct fuse_service **sfp)
{
	struct fuse_service *sf;
	int nr_fds;
	int sockfd;
	int flags;
	int ret = 0;

	*sfp = NULL;

	nr_fds = count_listen_fds();
	if (nr_fds == 0)
		return 0;

	/* Find the socket that connects us to mount.service */
	sockfd = find_socket_fd(nr_fds);
	if (sockfd < 0)
		return sockfd;

	flags = fcntl(sockfd, F_GETFD);
	if (flags < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service socket getfd: %s\n",
			 strerror(error));
		return -error;
	}

	if (!(flags & FD_CLOEXEC)) {
		ret = fcntl(sockfd, F_SETFD, flags | FD_CLOEXEC);
		if (ret) {
			int error = errno;

			fuse_log(FUSE_LOG_ERR, "fuse: service socket set cloexec: %s\n",
				 strerror(error));
			return -error;
		}
	}

	sf = calloc(1, sizeof(struct fuse_service));
	if (!sf) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service alloc: %s\n",
			 strerror(error));
		return -error;
	}
	sf->sockfd = sockfd;

	ret = negotiate_hello(sf);
	if (ret)
		goto out_sf;

	/* Receive the two critical sockets */
	ret = fuse_service_receive_file(sf, FUSE_SERVICE_ARGV, &sf->argvfd);
	if (ret < 0)
		goto out_sockfd;
	if (sf->argvfd < 0) {
		fuse_log(FUSE_LOG_ERR, "fuse: service mount options file: %s\n",
			 strerror(-sf->argvfd));
		ret = sf->argvfd;
		goto out_sockfd;
	}

	ret = fuse_service_receive_file(sf, FUSE_SERVICE_FUSEDEV,
					&sf->fusedevfd);
	if (ret < 0)
		goto out_argvfd;
	if (sf->fusedevfd < 0) {
		fuse_log(FUSE_LOG_ERR, "fuse: service fuse device: %s\n",
			 strerror(-sf->fusedevfd));
		ret = sf->fusedevfd;
		goto out_argvfd;
	}

	sf->owns_fusedevfd = true;
	*sfp = sf;
	return 0;

out_argvfd:
	close(sf->argvfd);
out_sockfd:
	shutdown(sf->sockfd, SHUT_RDWR);
	close(sf->sockfd);
out_sf:
	free(sf);
	return ret;
}

bool fuse_service_can_allow_other(struct fuse_service *sf)
{
	return sf->allow_other;
}

int fuse_service_append_args(struct fuse_service *sf,
			     struct fuse_args *existing_args)
{
	struct fuse_service_memfd_argv memfd_args = { };
	struct fuse_args new_args = {
		.allocated = 1,
	};
	char *str = NULL;
	off_t memfd_pos = 0;
	ssize_t received;
	unsigned int i;
	int ret;

	/* Figure out how many arguments we're getting from the mount helper. */
	received = pread(sf->argvfd, &memfd_args, sizeof(memfd_args), 0);
	if (received < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service args file: %s\n",
			 strerror(error));
		return -error;
	}
	if (received < sizeof(memfd_args)) {
		fuse_log(FUSE_LOG_ERR, "fuse: service args file length unreadable\n");
		return -EBADMSG;
	}
	if (ntohl(memfd_args.magic) != FUSE_SERVICE_ARGS_MAGIC) {
		fuse_log(FUSE_LOG_ERR, "fuse: service args file corrupt\n");
		return -EBADMSG;
	}
	memfd_args.magic = htonl(memfd_args.magic);
	memfd_args.argc = htonl(memfd_args.argc);
	memfd_pos += sizeof(memfd_args);

	/* Allocate a new array of argv string pointers */
	new_args.argv = calloc(memfd_args.argc + existing_args->argc,
			       sizeof(char *));
	if (!new_args.argv) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service new args: %s\n",
			 strerror(error));
		return -error;
	}

	/*
	 * Copy the fuse server's CLI arguments.  We'll leave new_args.argv[0]
	 * unset for now, because we'll set it in the next step with the fstype
	 * that the mount helper sent us.
	 */
	new_args.argc++;
	for (i = 1; i < existing_args->argc; i++) {
		if (existing_args->allocated) {
			new_args.argv[new_args.argc] = existing_args->argv[i];
			existing_args->argv[i] = NULL;
		} else {
			char *dup = strdup(existing_args->argv[i]);

			if (!dup) {
				int error = errno;

				fuse_log(FUSE_LOG_ERR,
					 "fuse: service duplicate existing args: %s\n",
					 strerror(error));
				ret = -error;
				goto out_new_args;
			}

			new_args.argv[new_args.argc] = dup;
		}

		new_args.argc++;
	}

	/* Copy the rest of the arguments from the helper */
	for (i = 0; i < memfd_args.argc; i++) {
		struct fuse_service_memfd_arg memfd_arg = { };

		/* Read argv iovec */
		received = pread(sf->argvfd, &memfd_arg, sizeof(memfd_arg),
				 memfd_pos);
		if (received < 0) {
			int error = errno;

			fuse_log(FUSE_LOG_ERR, "fuse: service args file iovec read: %s\n",
				 strerror(error));
			ret = -error;
			goto out_new_args;
		}
		if (received < sizeof(struct fuse_service_memfd_arg)) {
			fuse_log(FUSE_LOG_ERR,
				 "fuse: service args file argv[%u] iovec short read %zd",
				 i, received);
			ret = -EBADMSG;
			goto out_new_args;
		}
		memfd_arg.pos = htonl(memfd_arg.pos);
		memfd_arg.len = htonl(memfd_arg.len);
		memfd_pos += sizeof(memfd_arg);

		/* read arg string from file */
		str = calloc(1, memfd_arg.len + 1);
		if (!str) {
			int error = errno;

			fuse_log(FUSE_LOG_ERR, "fuse: service arg alloc: %s\n",
				 strerror(error));
			ret = -error;
			goto out_new_args;
		}

		received = pread(sf->argvfd, str, memfd_arg.len, memfd_arg.pos);
		if (received < 0) {
			int error = errno;

			fuse_log(FUSE_LOG_ERR, "fuse: service args file read: %s\n",
				 strerror(error));
			ret = -error;
			goto out_str;
		}
		if (received < memfd_arg.len) {
			fuse_log(FUSE_LOG_ERR, "fuse: service args file argv[%u] short read %zd",
				 i, received);
			ret = -EBADMSG;
			goto out_str;
		}

		/* move string into the args structure */
		if (i == 0) {
			/* the first argument is the fs type */
			new_args.argv[0] = str;
		} else {
			new_args.argv[new_args.argc] = str;
			new_args.argc++;
		}
		str = NULL;
	}

	/* drop existing args, move new args to existing args */
	fuse_opt_free_args(existing_args);
	memcpy(existing_args, &new_args, sizeof(*existing_args));

	close(sf->argvfd);
	sf->argvfd = -1;

	return 0;

out_str:
	free(str);
out_new_args:
	fuse_opt_free_args(&new_args);
	return ret;
}

#ifdef SO_PASSRIGHTS
int fuse_service_finish_file_requests(struct fuse_service *sf)
{
	int zero = 0;
	int ret;

	/*
	 * Don't let a malicious mount helper send us more fds.  If the kernel
	 * doesn't know about this new(ish) option that's ok, we'll trust the
	 * servicemount helper.
	 */
	ret = setsockopt(sf->sockfd, SOL_SOCKET, SO_PASSRIGHTS, &zero,
			 sizeof(zero));
	if (ret && errno == ENOPROTOOPT)
		ret = 0;
	if (ret) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: disabling fd passing: %s\n",
			 strerror(error));
		return -error;
	}

	return 0;
}
#else
int fuse_service_finish_file_requests(struct fuse_service *sf)
{
	(void)sf;
	return 0;
}
#endif

static int send_fsopen(struct fuse_service *sf, const char *fstype,
		       int *errorp)
{
	struct fuse_service_simple_reply reply = { };
	struct fuse_service_fsopen_command c = {
		.p.magic = htonl(FUSE_SERVICE_FSOPEN_CMD),
	};
	ssize_t size;

	if (!strncmp(fstype, "fuseblk", 7))
		c.fsopen_flags |= htonl(FUSE_SERVICE_FSOPEN_FUSEBLK);

	size = __send_packet(sf, &c, sizeof(c));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: send service fsopen command: %s\n",
			 strerror(error));
		return -error;
	}

	size = __recv_packet(sf, &reply, sizeof(reply));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service fsopen reply: %s\n",
			 strerror(error));
		return -error;
	}
	if (size != sizeof(reply)) {
		fuse_log(FUSE_LOG_ERR, "fuse: wrong service fsopen reply size %zd, expected %zd\n",
			size, sizeof(reply));
		return -EBADMSG;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_SIMPLE_REPLY) {
		fuse_log(FUSE_LOG_ERR, "fuse: service fsopen reply contains wrong magic!\n");
		return -EBADMSG;
	}

	*errorp = ntohl(reply.error);
	return 0;
}

static int send_string(struct fuse_service *sf, uint32_t command,
		       const char *value, int *errorp)
{
	struct fuse_service_simple_reply reply = { };
	struct fuse_service_string_command *cmd;
	const size_t cmdsz = sizeof_fuse_service_string_command(strlen(value));
	ssize_t size;

	cmd = calloc(1, cmdsz);
	if (!cmd) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: alloc service string send: %s\n",
			 strerror(error));
		return -error;
	}
	cmd->p.magic = htonl(command);
	strcpy(cmd->value, value);

	size = __send_packet(sf, cmd, cmdsz);
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: send service string: %s\n",
			 strerror(error));
		return -error;
	}
	free(cmd);

	size = __recv_packet(sf, &reply, sizeof(reply));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service string reply: %s\n",
			 strerror(error));
		return -error;
	}
	if (size != sizeof(reply)) {
		fuse_log(FUSE_LOG_ERR, "fuse: wrong service string reply size %zd, expected %zd\n",
			size, sizeof(reply));
		return -EBADMSG;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_SIMPLE_REPLY) {
		fuse_log(FUSE_LOG_ERR, "fuse: service string reply contains wrong magic!\n");
		return -EBADMSG;
	}

	*errorp = ntohl(reply.error);
	return 0;
}

static int send_mountpoint(struct fuse_service *sf, mode_t expected_fmt,
			   const char *value, int *errorp)
{
	struct fuse_service_simple_reply reply = { };
	struct fuse_service_mountpoint_command *cmd;
	const size_t cmdsz =
			sizeof_fuse_service_mountpoint_command(strlen(value));
	ssize_t size;

	cmd = calloc(1, cmdsz);
	if (!cmd) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: alloc service mountpoint send: %s\n",
			 strerror(error));
		return -error;
	}
	cmd->p.magic = htonl(FUSE_SERVICE_MNTPT_CMD);
	cmd->expected_fmt = htons(expected_fmt);
	strcpy(cmd->value, value);

	size = __send_packet(sf, cmd, cmdsz);
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: send service mountpoint: %s\n",
			 strerror(error));
		return -error;
	}
	free(cmd);

	size = __recv_packet(sf, &reply, sizeof(reply));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service mountpoint reply: %s\n",
			 strerror(error));
		return -error;
	}
	if (size != sizeof(reply)) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: wrong service mountpoint reply size %zd, expected %zd\n",
			 size, sizeof(reply));
		return -EBADMSG;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_SIMPLE_REPLY) {
		fuse_log(FUSE_LOG_ERR, "fuse: service mountpoint reply contains wrong magic!\n");
		return -EBADMSG;
	}

	*errorp = ntohl(reply.error);
	return 0;
}

static int send_mount(struct fuse_service *sf, unsigned int ms_flags,
		      int *errorp)
{
	struct fuse_service_simple_reply reply = { };
	struct fuse_service_mount_command c = {
		.p.magic = htonl(FUSE_SERVICE_MOUNT_CMD),
		.ms_flags = htonl(ms_flags),
	};
	ssize_t size;

	size = __send_packet(sf, &c, sizeof(c));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: send service mount command: %s\n",
			 strerror(error));
		return -error;
	}

	size = __recv_packet(sf, &reply, sizeof(reply));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service mount reply: %s\n",
			 strerror(error));
		return -error;
	}
	if (size != sizeof(reply)) {
		fuse_log(FUSE_LOG_ERR, "fuse: wrong service mount reply size %zd, expected %zd\n",
			size, sizeof(reply));
		return -EBADMSG;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_SIMPLE_REPLY) {
		fuse_log(FUSE_LOG_ERR, "fuse: service mount reply contains wrong magic!\n");
		return -EBADMSG;
	}

	*errorp = ntohl(reply.error);
	return 0;
}

void fuse_service_expect_mount_format(struct fuse_service *sf,
				      mode_t expected_fmt)
{
	sf->expected_fmt = expected_fmt;
}

int fuse_service_session_mount(struct fuse_service *sf, struct fuse_session *se,
			       mode_t expected_fmt,
			       struct fuse_cmdline_opts *opts)
{
	char *fstype = fuse_mnt_build_type(se->mo);
	char *source = fuse_mnt_build_source(se->mo);
	char *mntopts = fuse_mnt_kernel_opts(se->mo);
	char *mtabopts = fuse_mnt_mtab_opts(se->mo);
	char path[32];
	int ret;
	int error = 0;

	if (!fstype || !source) {
		fuse_log(FUSE_LOG_ERR, "fuse: cannot allocate service strings\n");
		ret = -ENOMEM;
		goto out_strings;
	}

	if (!expected_fmt)
		expected_fmt = sf->expected_fmt;

	/*
	 * The fuse session takes the fusedev fd if this succeeds.  It is
	 * required to use the "/dev/fd/XX" format.
	 */
	snprintf(path, sizeof(path), "/dev/fd/%d", sf->fusedevfd);
	errno = 0;
	ret = fuse_session_mount(se, path);
	if (ret) {
		/* Try to return richer errors than fuse_session_mount's -1 */
		ret = errno ? -errno : -EINVAL;
		goto out_strings;
	}
	sf->owns_fusedevfd = false;

	ret = send_fsopen(sf, fstype, &error);
	if (ret)
		goto out_strings;
	if (error) {
		fuse_log(FUSE_LOG_ERR, "fuse: service fsopen: %s\n",
			 strerror(error));
		ret = -error;
		goto out_strings;
	}

	ret = send_string(sf, FUSE_SERVICE_SOURCE_CMD, source, &error);
	if (ret)
		goto out_strings;
	if (error) {
		fuse_log(FUSE_LOG_ERR, "fuse: service fs source: %s\n",
			 strerror(error));
		ret = -error;
		goto out_strings;
	}

	ret = send_mountpoint(sf, expected_fmt, opts->mountpoint, &error);
	if (ret)
		goto out_strings;
	if (error) {
		fuse_log(FUSE_LOG_ERR, "fuse: service fs mountpoint: %s\n",
			 strerror(error));
		ret = -error;
		goto out_strings;
	}

	if (mntopts) {
		ret = send_string(sf, FUSE_SERVICE_MNTOPTS_CMD, mntopts,
				  &error);
		if (ret)
			goto out_strings;
		if (error) {
			fuse_log(FUSE_LOG_ERR, "fuse: service fs mount options: %s\n",
				 strerror(error));
			ret = -error;
			goto out_strings;
		}
	}

	if (mtabopts) {
		ret = send_string(sf, FUSE_SERVICE_MTABOPTS_CMD, mtabopts,
				  &error);
		if (ret)
			goto out_strings;
		if (error) {
			fuse_log(FUSE_LOG_ERR, "fuse: service fs mtab options: %s\n",
				 strerror(error));
			ret = -error;
			goto out_strings;
		}
	}

	ret = send_mount(sf, fuse_mnt_flags(se->mo), &error);
	if (ret)
		goto out_strings;
	if (error) {
		fuse_log(FUSE_LOG_ERR, "fuse: service mount: %s\n",
			 strerror(error));
		ret = -error;
		goto out_strings;
	}

	/*
	 * foreground mode is needed so that systemd actually tracks the
	 * service correctly and doesn't try to kill it; and so that
	 * stdout/stderr don't get zapped.  Change to the root directory so
	 * that the caller needn't call fuse_daemonize().
	 */
	opts->foreground = 1;
	(void)chdir("/");

out_strings:
	free(mtabopts);
	free(mntopts);
	free(source);
	free(fstype);
	return ret;
}

int fuse_service_session_unmount(struct fuse_service *sf)
{
	struct fuse_service_simple_reply reply = { };
	struct fuse_service_unmount_command c = {
		.p.magic = htonl(FUSE_SERVICE_UNMOUNT_CMD),
	};
	ssize_t size;

	/* already gone? */
	if (sf->sockfd < 0)
		return 0;

	size = __send_packet(sf, &c, sizeof(c));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: send service unmount: %s\n",
			 strerror(error));
		return -error;
	}

	size = __recv_packet(sf, &reply, sizeof(reply));
	if (size < 0) {
		int error = errno;

		fuse_log(FUSE_LOG_ERR, "fuse: service unmount reply: %s\n",
			 strerror(error));
		return -error;
	}
	if (size != sizeof(reply)) {
		fuse_log(FUSE_LOG_ERR, "fuse: wrong service unmount reply size %zd, expected %zd\n",
			size, sizeof(reply));
		return -EBADMSG;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_SIMPLE_REPLY) {
		fuse_log(FUSE_LOG_ERR, "fuse: service unmount reply contains wrong magic!\n");
		return -EBADMSG;
	}

	if (reply.error) {
		int error = ntohl(reply.error);

		fuse_log(FUSE_LOG_ERR, "fuse: service unmount: %s\n",
			 strerror(error));
		return -error;
	}

	return 0;
}

void fuse_service_release(struct fuse_service *sf)
{
	if (sf->owns_fusedevfd)
		close(sf->fusedevfd);
	sf->owns_fusedevfd = false;
	sf->fusedevfd = -1;
	close(sf->argvfd);
	sf->argvfd = -1;
	shutdown(sf->sockfd, SHUT_RDWR);
	close(sf->sockfd);
	sf->sockfd = -1;
}

void fuse_service_destroy(struct fuse_service **sfp)
{
	struct fuse_service *sf = *sfp;

	if (sf) {
		fuse_service_release(*sfp);
		free(sf);
	}

	*sfp = NULL;
}

char *fuse_service_cmdline(int argc, char *argv[], struct fuse_args *args)
{
	char *p, *dst;
	size_t len = 1;
	ssize_t ret;
	char *argv0;
	unsigned int i;

	/* Try to preserve argv[0] */
	if (argc > 0)
		argv0 = argv[0];
	else if (args->argc > 0)
		argv0 = args->argv[0];
	else
		return NULL;

	/* Pick up the alleged fstype from args->argv[0] */
	if (args->argc == 0)
		return NULL;

	len += strlen(argv0) + 1;
	len += 3; /* " -t" */
	for (i = 0; i < args->argc; i++)
		len += strlen(args->argv[i]) + 1;

	p = calloc(1, len);
	if (!p)
		return NULL;
	dst = p;

	/* Format: argv0 -t alleged_fstype [all other options...] */
	ret = sprintf(dst, "%s -t", argv0);
	dst += ret;
	for (i = 0; i < args->argc; i++) {
		ret = sprintf(dst, " %s", args->argv[i]);
		dst += ret;
	}

	return p;
}

int fuse_service_parse_cmdline_opts(struct fuse_args *args,
				    struct fuse_cmdline_opts *opts)
{
	return fuse_parse_cmdline_service(args, opts);
}

int fuse_service_exit(int ret)
{
	/*
	 * We have to sleep 2 seconds here because journald uses the pid to
	 * connect our log messages to the systemd service.  This is critical
	 * for capturing all the log messages if the service fails, because
	 * failure analysis tools use the service name to gather log messages
	 * for reporting.
	 */
	sleep(2);

	/*
	 * If we're being run as a service, the return code must fit the LSB
	 * init script action error guidelines, which is to say that we
	 * compress all errors to 1 ("generic or unspecified error", LSB 5.0
	 * section 22.2) and hope the admin will scan the log for what actually
	 * happened.
	 */
	return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
