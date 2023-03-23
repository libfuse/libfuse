/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2022  Tofik Sonono <tofik.sonono@intel.com>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * minimal example filesystem using low-level API and a custom io. This custom
 * io is implemented using UNIX domain sockets (of type SOCK_STREAM)
 *
 * Compile with:
 *
 *     gcc -Wall hello_ll_uds.c `pkg-config fuse3 --cflags --libs` -o hello_ll_uds
 *
 * ## Source code ##
 * \include hello_ll.c
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

static const char *hello_str = "Hello World!\n";
static const char *hello_name = "hello";

static int hello_stat(fuse_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ino = ino;
	switch (ino) {
	case 1:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		break;

	case 2:
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(hello_str);
		break;

	default:
		return -1;
	}
	return 0;
}

static void hello_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (hello_stat(ino, &stbuf) == -1)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

static void hello_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;

	if (parent != 1 || strcmp(name, hello_name) != 0)
		fuse_reply_err(req, ENOENT);
	else {
		memset(&e, 0, sizeof(e));
		e.ino = 2;
		e.attr_timeout = 1.0;
		e.entry_timeout = 1.0;
		hello_stat(e.ino, &e.attr);

		fuse_reply_entry(req, &e);
	}
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
		       fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;
	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
			  b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
			     off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off,
				      min(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

static void hello_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *fi)
{
	(void) fi;

	if (ino != 1)
		fuse_reply_err(req, ENOTDIR);
	else {
		struct dirbuf b;

		memset(&b, 0, sizeof(b));
		dirbuf_add(req, &b, ".", 1);
		dirbuf_add(req, &b, "..", 1);
		dirbuf_add(req, &b, hello_name, 2);
		reply_buf_limited(req, b.p, b.size, off, size);
		free(b.p);
	}
}

static void hello_ll_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	if (ino != 2)
		fuse_reply_err(req, EISDIR);
	else if ((fi->flags & O_ACCMODE) != O_RDONLY)
		fuse_reply_err(req, EACCES);
	else
		fuse_reply_open(req, fi);
}

static void hello_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	(void) fi;

	assert(ino == 2);
	reply_buf_limited(req, hello_str, strlen(hello_str), off, size);
}

static const struct fuse_lowlevel_ops hello_ll_oper = {
	.lookup		= hello_ll_lookup,
	.getattr	= hello_ll_getattr,
	.readdir	= hello_ll_readdir,
	.open		= hello_ll_open,
	.read		= hello_ll_read,
};

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

static ssize_t stream_writev(int fd, struct iovec *iov, int count,
                             void *userdata) {
	(void)userdata;

	ssize_t written = 0;
	int cur = 0;
	for (;;) {
		written = writev(fd, iov+cur, count-cur);
		if (written < 0)
			return written;

		while (cur < count && written >= iov[cur].iov_len)
			written -= iov[cur++].iov_len;
		if (cur == count)
			break;

		iov[cur].iov_base = (char *)iov[cur].iov_base + written;
		iov[cur].iov_len -= written;
	}
	return written;
}


static ssize_t readall(int fd, void *buf, size_t len) {
	size_t count = 0;

	while (count < len) {
		int i = read(fd, (char *)buf + count, len - count);
		if (!i)
			break;

		if (i < 0)
			return i;

		count += i;
	}
	return count;
}

static ssize_t stream_read(int fd, void *buf, size_t buf_len, void *userdata) {
    (void)userdata;

	int res = readall(fd, buf, sizeof(struct fuse_in_header));
	if (res == -1)
    	return res;


    uint32_t packet_len = ((struct fuse_in_header *)buf)->len;
    if (packet_len > buf_len)
    	return -1;

    int prev_res = res;

    res = readall(fd, (char *)buf + sizeof(struct fuse_in_header),
                  packet_len - sizeof(struct fuse_in_header));

    return  (res == -1) ? res : (res + prev_res);
}

static ssize_t stream_splice_send(int fdin, off_t *offin, int fdout,
					    off_t *offout, size_t len,
                                  unsigned int flags, void *userdata) {
	(void)userdata;

	size_t count = 0;
	while (count < len) {
		int i = splice(fdin, offin, fdout, offout, len - count, flags);
		if (i < 1)
			return i;

		count += i;
	}
	return count;
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
		.writev = stream_writev,
		.read = stream_read,
		.splice_receive = NULL,
		.splice_send = stream_splice_send,
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

	se = fuse_session_new(&args, &hello_ll_oper,
			      sizeof(hello_ll_oper), NULL);
	if (se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
	    goto err_out2;

	cfd = create_socket("/tmp/libfuse-hello-ll.sock");
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
