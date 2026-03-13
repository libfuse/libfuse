/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  Library functions to support fuse servers that can be run as "safe" systemd
  containers.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt
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

#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_service_priv.h"
#include "fuse_service.h"

struct fuse_service {
	/* socket fd */
	int sockfd;

	/* /dev/fuse device */
	int fusedevfd;

	/* memfd for cli arguments */
	int argvfd;

	/* do we own fusedevfd? */
	int owns_fusedevfd:1;
};

static int __recv_fd(int sockfd, struct fuse_service_requested_file *buf,
		     ssize_t bufsize, int *fdp)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = bufsize,
	};
	union {
		struct cmsghdr cmsghdr;
		char control[CMSG_SPACE(sizeof (int))];
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

	size = recvmsg(sockfd, &msg, MSG_TRUNC);
	if (size < 0) {
		perror("fuse: service file reply");
		return -1;
	}
	if (size > bufsize ||
	    size < offsetof(struct fuse_service_requested_file, path)) {
		fprintf(stderr,
 "fuse: wrong service file reply size %zd, expected %zd\n",
			size, bufsize);
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		/* no control message means mount.service sent us an error */
		return 0;
	}
	if (cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
		fprintf(stderr,
 "fuse: wrong service file reply control data size %zd, expected %zd\n",
			cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
		return -1;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr,
 "fuse: wrong service file reply control data level %d type %d, expected %d and %d\n",
			cmsg->cmsg_level, cmsg->cmsg_type, SOL_SOCKET,
			SCM_RIGHTS);
		return -1;
	}

	memcpy(fdp, (int *)CMSG_DATA(cmsg), sizeof(int));
	return 0;
}

static int recv_requested_file(int sockfd, const char *path, int *fdp)
{
	struct fuse_service_requested_file *req;
	const size_t req_sz = sizeof_fuse_service_requested_file(strlen(path));
	int ret;

	*fdp = -1;
	req = calloc(1, req_sz + 1);
	if (!req) {
		perror("fuse: alloc service file reply");
		return -1;
	}

	ret = __recv_fd(sockfd, req, req_sz, fdp);
	if (ret)
		goto out_req;

	if (req->p.magic != ntohl(FUSE_SERVICE_OPEN_REPLY)) {
		fprintf(stderr,
 "fuse: service file reply contains wrong magic!\n");
		ret = -1;
		goto out_close;
	}
	if (strcmp(req->path, path)) {
		fprintf(stderr,
 "fuse: `%s': not the requested service file, got `%s'\n",
			path, req->path);
		ret = -1;
		goto out_close;
	}

	if (req->error) {
		errno = ntohl(req->error);
		ret = 0;
		goto out_req;
	}

	free(req);
	return 0;

out_close:
	close(*fdp);
	*fdp = -1;
out_req:
	free(req);
	return ret;
}

int fuse_service_receive_file(struct fuse_service *sf, const char *path,
			      int *fdp)
{
	return recv_requested_file(sf->sockfd, path, fdp);
}

#define FUSE_SERVICE_REQUEST_FILE_FLAGS	(0)

static int fuse_service_request_path(struct fuse_service *sf, const char *path,
				     mode_t mode, int open_flags,
				     mode_t create_mode,
				     unsigned int request_flags,
				     unsigned int block_size)
{
	struct iovec iov = {
		.iov_len = sizeof_fuse_service_open_command(strlen(path)),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct fuse_service_open_command *cmd;
	ssize_t size;
	unsigned int rqflags = 0;
	int ret;

	if (request_flags & ~FUSE_SERVICE_REQUEST_FILE_FLAGS) {
		fprintf(stderr,
 "fuse: invalid fuse service file request flags 0x%x\n", request_flags);
		errno = EINVAL;
		return -1;
	}

	cmd = calloc(1, iov.iov_len);
	if (!cmd) {
		perror("fuse: alloc service file request");
		return -1;
	}
	if (S_ISBLK(mode)) {
		cmd->p.magic = htonl(FUSE_SERVICE_OPEN_BDEV_CMD);
		cmd->block_size = htonl(block_size);
	} else {
		cmd->p.magic = htonl(FUSE_SERVICE_OPEN_CMD);
	}
	cmd->open_flags = htonl(open_flags);
	cmd->create_mode = htonl(create_mode);
	cmd->request_flags = htonl(rqflags);
	strcpy(cmd->path, path);
	iov.iov_base = cmd;

	size = sendmsg(sf->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
	if (size < 0) {
		perror("fuse: request service file");
		ret = -1;
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

int fuse_service_send_goodbye(struct fuse_service *sf, int error)
{
	struct fuse_service_bye_command c = {
		.p.magic = htonl(FUSE_SERVICE_BYE_CMD),
		.error = htonl(error),
	};
	struct iovec iov = {
		.iov_base = &c,
		.iov_len = sizeof(c),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t size;

	/* already gone? */
	if (sf->sockfd < 0)
		return 0;

	size = sendmsg(sf->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
	if (size < 0) {
		perror("fuse: send service goodbye");
		return -1;
	}

	shutdown(sf->sockfd, SHUT_RDWR);
	close(sf->sockfd);
	sf->sockfd = -1;
	return 0;
}

static int find_socket_fd(void)
{
	struct stat statbuf;
	char *listen_fds;
	int nr_fds;
	int ret;

	listen_fds = getenv("LISTEN_FDS");
	if (!listen_fds)
		return -2;

	nr_fds = atoi(listen_fds);
	if (nr_fds != 1) {
		fprintf(stderr,
 "fuse: can only handle 1 service socket, got %d.\n",
			nr_fds);
		return -1;
	}

	ret = fstat(SD_LISTEN_FDS_START, &statbuf);
	if (ret) {
		perror("fuse: service socket");
		return -1;
	}

	if (!S_ISSOCK(statbuf.st_mode)) {
		fprintf(stderr,
 "fuse: expected service fd %d to be a socket\n",
				SD_LISTEN_FDS_START);
		return -1;
	}

	return SD_LISTEN_FDS_START;
}

static int negotiate_hello(int sockfd)
{
	struct fuse_service_hello hello = { };
	struct fuse_service_hello_reply reply = {
		.p.magic = htonl(FUSE_SERVICE_HELLO_REPLY),
		.version = htons(FUSE_SERVICE_PROTO),
	};
	struct iovec iov = {
		.iov_base = &hello,
		.iov_len = sizeof(hello),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t size;

	size = recvmsg(sockfd, &msg, MSG_TRUNC);
	if (size < 0) {
		perror("fuse: receive service hello");
		return -1;
	}
	if (size != sizeof(hello)) {
		fprintf(stderr,
 "fuse: wrong service hello size %zd, expected %zd\n",
			size, sizeof(hello));
		return -1;
	}

	if (hello.p.magic != ntohl(FUSE_SERVICE_HELLO_CMD)) {
		fprintf(stderr,
 "fuse: service server did not send hello command\n");
		return -1;
	}

	if (ntohs(hello.min_version) < FUSE_SERVICE_MIN_PROTO) {
		fprintf(stderr,
 "fuse: unsupported min service protocol version %u\n",
			ntohs(hello.min_version));
		return -1;
	}

	if (ntohs(hello.max_version) > FUSE_SERVICE_MAX_PROTO) {
		fprintf(stderr,
 "fuse: unsupported max service protocol version %u\n",
			ntohs(hello.min_version));
		return -1;
	}

	iov.iov_base = &reply;
	iov.iov_len = sizeof(reply);

	size = sendmsg(sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
	if (size < 0) {
		perror("fuse: service hello reply");
		return -1;
	}

	return 0;
}

int fuse_service_accept(struct fuse_service **sfp)
{
	struct fuse_service *sf;
	int ret = 0;

	*sfp = NULL;

	sf = calloc(1, sizeof(struct fuse_service));
	if (!sf) {
		perror("fuse: service alloc");
		return -1;
	}

	/* Find the socket that connects us to mount.service */
	sf->sockfd = find_socket_fd();
	if (sf->sockfd == -2) {
		/* magic code that means no service configured */
		ret = 0;
		goto out_sf;
	}
	if (sf->sockfd < 0) {
		ret = -1;
		goto out_sf;
	}

	ret = negotiate_hello(sf->sockfd);
	if (ret)
		goto out_sf;

	/* Receive the two critical sockets */
	ret = recv_requested_file(sf->sockfd, FUSE_SERVICE_ARGV, &sf->argvfd);
	if (ret < 0)
		goto out_sockfd;
	if (sf->argvfd < 0) {
		perror("fuse: service mount options file");
		goto out_sockfd;
	}

	ret = recv_requested_file(sf->sockfd, FUSE_SERVICE_FUSEDEV,
				  &sf->fusedevfd);
	if (ret < 0)
		goto out_argvfd;
	if (sf->fusedevfd < 0) {
		perror("fuse: service fuse device");
		goto out_argvfd;
	}

	sf->owns_fusedevfd = 1;
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
		perror("fuse: service args file");
		return -1;
	}
	if (received < sizeof(memfd_args)) {
		fprintf(stderr,
 "fuse: service args file length unreadable\n");
		return -1;
	}
	if (ntohl(memfd_args.magic) != FUSE_SERVICE_ARGS_MAGIC) {
		fprintf(stderr, "fuse: service args file corrupt\n");
		return -1;
	}
	memfd_args.magic = ntohl(memfd_args.magic);
	memfd_args.argc = ntohl(memfd_args.argc);
	memfd_pos += sizeof(memfd_args);

	/* Allocate a new array of argv string pointers */
	new_args.argv = calloc(memfd_args.argc + existing_args->argc,
			       sizeof(char *));
	if (!new_args.argv) {
		perror("fuse: service new args");
		return -1;
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
			new_args.argv[new_args.argc] =
						strdup(existing_args->argv[i]);
			if (!new_args.argv[new_args.argc]) {
				perror("fuse: service duplicate existing args");
				ret = -1;
				goto out_new_args;
			}
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
			perror("fuse: service args file iovec read");
			ret = -1;
			goto out_new_args;
		}
		if (received < sizeof(struct fuse_service_memfd_arg)) {
			fprintf(stderr,
 "fuse: service args file argv[%u] iovec short read %zd",
				i, received);
			ret = -1;
			goto out_new_args;
		}
		memfd_arg.pos = ntohl(memfd_arg.pos);
		memfd_arg.len = ntohl(memfd_arg.len);
		memfd_pos += sizeof(memfd_arg);

		/* read arg string from file */
		str = calloc(1, memfd_arg.len + 1);
		if (!str) {
			perror("fuse: service arg alloc");
			ret = -1;
			goto out_new_args;
		}

		received = pread(sf->argvfd, str, memfd_arg.len, memfd_arg.pos);
		if (received < 0) {
			perror("fuse: service args file read");
			ret = -1;
			goto out_str;
		}
		if (received < memfd_arg.len) {
			fprintf(stderr,
 "fuse: service args file argv[%u] short read %zd",
				i, received);
			ret = -1;
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

int fuse_service_take_fusedev(struct fuse_service *sfp)
{
	sfp->owns_fusedevfd = 0;
	return sfp->fusedevfd;
}

int fuse_service_finish_file_requests(struct fuse_service *sf)
{
#ifdef SO_PASSRIGHTS
	int zero = 0;

	/* don't let a malicious mount helper send us more fds */
	return setsockopt(sf->sockfd, SOL_SOCKET, SO_PASSRIGHTS, &zero,
			  sizeof(zero));
#else
	/* shut up gcc */
	sf = sf;
	return 0;
#endif
}

static int send_string(struct fuse_service *sf, uint32_t command,
		       const char *value, int *error)
{
	struct fuse_service_simple_reply reply = { };
	struct iovec iov = {
		.iov_len = sizeof_fuse_service_string_command(strlen(value)),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct fuse_service_string_command *cmd;
	ssize_t size;

	cmd = malloc(iov.iov_len);
	if (!cmd) {
		perror("fuse: alloc service string send");
		return -1;
	}
	cmd->p.magic = ntohl(command);
	strcpy(cmd->value, value);
	iov.iov_base = cmd;

	size = sendmsg(sf->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
	if (size < 0) {
		perror("fuse: send service string");
		return -1;
	}
	free(cmd);

	iov.iov_base = &reply;
	iov.iov_len = sizeof(reply);
	size = recvmsg(sf->sockfd, &msg, MSG_TRUNC);
	if (size < 0) {
		perror("fuse: service string reply");
		return -1;
	}
	if (size != sizeof(reply)) {
		fprintf(stderr,
 "fuse: wrong service string reply size %zd, expected %zd\n",
			size, sizeof(reply));
		return -1;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_SIMPLE_REPLY) {
		fprintf(stderr,
 "fuse: service string reply contains wrong magic!\n");
		return -1;
	}

	*error = ntohl(reply.error);
	return 0;
}

static int send_mount(struct fuse_service *sf, unsigned int flags, int *error)
{
	struct fuse_service_simple_reply reply = { };
	struct fuse_service_mount_command c = {
		.p.magic = htonl(FUSE_SERVICE_MOUNT_CMD),
		.flags = htonl(flags),
	};
	struct iovec iov = {
		.iov_base = &c,
		.iov_len = sizeof(c),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t size;

	size = sendmsg(sf->sockfd, &msg, MSG_EOR | MSG_NOSIGNAL);
	if (size < 0) {
		perror("fuse: send service mount command");
		return -1;
	}

	iov.iov_base = &reply;
	iov.iov_len = sizeof(reply);
	size = recvmsg(sf->sockfd, &msg, MSG_TRUNC);
	if (size < 0) {
		perror("fuse: service mount reply");
		return -1;
	}
	if (size != sizeof(reply)) {
		fprintf(stderr,
 "fuse: wrong service mount reply size %zd, expected %zd\n",
			size, sizeof(reply));
		return -1;
	}

	if (ntohl(reply.p.magic) != FUSE_SERVICE_SIMPLE_REPLY) {
		fprintf(stderr,
 "fuse: service mount reply contains wrong magic!\n");
		return -1;
	}

	*error = ntohl(reply.error);
	return 0;
}

int fuse_service_session_mount(struct fuse_service *sf, struct fuse_session *se,
			       struct fuse_cmdline_opts *opts)
{
	char *fstype = fuse_mountopts_fstype(se->mo);
	char *source = fuse_mountopts_source(se->mo, "???");
	char *mntopts = fuse_mountopts_kernel_opts(se->mo);
	char path[32];
	int ret;
	int error;

	if (!fstype || !source) {
		fprintf(stderr, "fuse: cannot allocate service strings\n");
		ret = -1;
		goto out_strings;
	}

	snprintf(path, sizeof(path), "/dev/fd/%d", sf->fusedevfd);
	ret = fuse_session_mount(se, path);
	if (ret)
		goto out_strings;

	ret = send_string(sf, FUSE_SERVICE_FSOPEN_CMD, fstype, &error);
	if (ret)
		goto out_strings;
	if (error) {
		fprintf(stderr, "fuse: service fsopen: %s\n",
			strerror(error));
		ret = -1;
		goto out_strings;
	}

	ret = send_string(sf, FUSE_SERVICE_SOURCE_CMD, source, &error);
	if (ret)
		goto out_strings;
	if (error) {
		fprintf(stderr, "fuse: service fs source: %s\n",
			strerror(error));
		ret = -1;
		goto out_strings;
	}

	ret = send_string(sf, FUSE_SERVICE_MNTPT_CMD, opts->mountpoint, &error);
	if (ret)
		goto out_strings;
	if (error) {
		fprintf(stderr, "fuse: service fs mountpoint: %s\n",
			strerror(error));
		ret = -1;
		goto out_strings;
	}

	if (mntopts) {
		ret = send_string(sf, FUSE_SERVICE_MNTOPTS_CMD, mntopts,
				  &error);
		if (ret)
			goto out_strings;
		if (error) {
			fprintf(stderr,
 "fuse: service fs mount options: %s\n",
				strerror(error));
			ret = -1;
			goto out_strings;
		}
	}

	ret = send_mount(sf, fuse_mountopts_flags(se->mo), &error);
	if (ret)
		goto out_strings;
	if (error) {
		fprintf(stderr, "fuse: service mount: %s\n", strerror(error));
		ret = -1;
		goto out_strings;
	}

	/*
	 * foreground mode is needed so that systemd actually tracks the
	 * service correctly and doesnt try to kill it; and so that
	 * stdout/stderr don't get zapped
	 */
	opts->foreground = 1;

out_strings:
	free(mntopts);
	free(source);
	free(fstype);
	return ret;
}

void fuse_service_release(struct fuse_service *sf)
{
	if (sf->owns_fusedevfd)
		close(sf->fusedevfd);
	sf->owns_fusedevfd = 0;
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
	for (i = 0; i < args->argc; i++) {
		len += strlen(args->argv[i]) + 1;
	}

	p = malloc(len);
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
