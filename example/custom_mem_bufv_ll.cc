/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2023-2025  Xiaoguang Wang <lege.wang@jaguarmicro.com>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/**
 * minimal example filesystem using low-level API and a custom io. This custom
 * io is implemented using memory-mapped buffer. Currently for simplicity, this
 * test uses global variable's address as memory-mapped buffer address. In
 * practical scenarios, memory-mapped buffer may come from guest vm by
 * vhost-user protocol.
 */

#define FUSE_USE_VERSION 34


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fuse_lowlevel.h>
#include <fuse_kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <iostream>
#include <unordered_map>

using namespace std;

struct request {
	struct fuse_bufvec *in_bufv;
	struct fuse_bufvec *out_bufv;

	request(struct fuse_bufvec *in, struct fuse_bufvec *out) : in_bufv(in), out_bufv(out) {}
};

unordered_map<int, struct request> req_map;

static struct fuse_in_header in_header;
static struct fuse_init_in  init_in;
static struct fuse_out_header out_header;
static struct fuse_init_out init_out;

static const struct fuse_lowlevel_ops fuse_ll_oper = {};

static int create_socket(const char *socket_path) {
	struct sockaddr_un addr;

	if (strnlen(socket_path, sizeof(addr.sun_path)) >=
		sizeof(addr.sun_path)) {
		printf("Socket path may not be longer than %lu characters\n",
			 sizeof(addr.sun_path) - 1);
		return -1;
	}

	if (remove(socket_path) == -1 && errno != ENOENT) {
		printf("Could not delete previous socket file entry at %s. Error: "
			 "%s\n", socket_path, strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	strcpy(addr.sun_path, socket_path);

	int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1) {
		printf("Could not create socket. Error: %s\n", strerror(errno));
		return -1;
	}

	addr.sun_family = AF_UNIX;
	if (bind(sfd, (struct sockaddr *) &addr,
		   sizeof(struct sockaddr_un)) == -1) {
		printf("Could not bind socket. Error: %s\n", strerror(errno));
		return -1;
	}

	if (listen(sfd, 1) == -1)
		return -1;

	printf("Awaiting connection on socket at %s...\n", socket_path);
	int cfd = accept(sfd, NULL, NULL);
	if (cfd == -1) {
		printf("Could not accept connection. Error: %s\n",
			 strerror(errno));
		return -1;
	} else {
		printf("Accepted connection!\n");
	}
	return cfd;
}

static ssize_t readall(int fd, void *buf, size_t len)
{
	int i;
	size_t count = 0;

	(void)buf;
	while (count < len) {
		i = read(fd, (char *)buf + count, len - count);
		if (!i)
			break;
		if (i < 0)
			return i;
		count += i;
	}
	return count;
}

static ssize_t get_mem_buf(int fd, struct fuse_bufvec **bufv, void *userdata)
{
	struct fuse_bufvec *in = *bufv, *out = NULL;
	ssize_t res;

	(void)userdata;

	if (!in || in->count < 2) {
		free(in);
		*bufv = NULL;
		in = (struct fuse_bufvec *)malloc(sizeof(struct fuse_bufvec) +
						  sizeof(struct fuse_buf));
	} else {
		in = *bufv;
	}

	out = (struct fuse_bufvec *)malloc(sizeof(struct fuse_bufvec) +
					   sizeof(struct fuse_buf));

	res = readall(fd, &in_header, sizeof(in_header));
	if (res != sizeof(in_header))
		exit(-1);
	res = readall(fd, &init_in, sizeof(init_in));
	if (res != sizeof(init_in))
		exit(-1);

	in->buf[0].size = sizeof(in_header);
	in->buf[0].mem = &in_header;
	in->buf[0].flags = FUSE_BUF_IS_CUSTOM_BUF;
	in->buf[1].size = sizeof(init_in);
	in->buf[1].mem = &init_in;
	in->buf[1].flags = FUSE_BUF_IS_CUSTOM_BUF;
	in->count = 2;
	in->idx = 0;
	in->off = 0;

	out->buf[0].size = sizeof(out_header);
	out->buf[0].mem = &out_header;
	out->buf[1].size = sizeof(init_out);
	out->buf[1].mem = &init_out;
	out->count = 2;
	out->idx = 0;
	out->off = 0;

	*bufv = in;
	req_map.insert(make_pair(in_header.unique, request(in, out)));
	return sizeof(in_header) + sizeof(init_in);
}

static ssize_t get_reply_mem_bufv(int fd, uint64_t unique,
			   struct fuse_bufvec **bufv, void *userdata)
{
	(void)fd;
	(void)unique;
	(void)bufv;
	(void)userdata;

	auto it = req_map.find(unique);
	if (it == req_map.end())
		return -1;

	*bufv = it->second.out_bufv;
	return 1;
}

static ssize_t commit_req(int fd, uint64_t unique, void *userdata)
{
	ssize_t ret;

	(void)fd;
	(void)unique;
	(void)userdata;

	auto it = req_map.find(unique);
	if (it != req_map.end()) {
		ret = write(fd, &out_header, sizeof(out_header));
		if (ret != sizeof(out_header))
			exit(-1);
		ret = write(fd, &init_out, sizeof(init_out));
		if (ret != sizeof(init_out))
			exit(-1);
		return 1;
	}
	return 0;
}

static void fuse_cmdline_help_uds(void)
{
	printf("    -h   --help            print help\n"
	       "    -V   --version         print version\n"
	       "    -d   -o debug          enable debug output (implies -f)\n");
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	const struct fuse_custom_io io = {
		.writev = NULL,
		.read = NULL,
		.splice_receive = NULL,
		.splice_send = NULL,
		.get_mem_bufv = get_mem_buf,
		.get_reply_mem_bufv = get_reply_mem_bufv,
		.commit_req = commit_req,
	};
	int cfd = -1;
	int ret = -1;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;
	if (opts.show_help) {
		printf("usage: %s [options]\n\n", argv[0]);
		fuse_cmdline_help_uds();
		fuse_lowlevel_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

	se = fuse_session_new(&args, &fuse_ll_oper,
			      sizeof(fuse_ll_oper), NULL);
	if (se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
	    goto err_out2;

	cfd = create_socket("/tmp/libfuse-custom-mem-ll.sock");
	if (cfd == -1)
		goto err_out3;

	if (fuse_session_custom_io(se, &io, cfd) != 0)
		goto err_out3;

	/* Block until ctrl+c */
	ret = fuse_session_loop(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}
