/*
 * FUSE fioc_ll: FUSE ioctl example (low-level API)
 * Copyright (C) 2008       SUSE Linux Products GmbH
 * Copyright (C) 2008       Tejun Heo <teheo@suse.de>
 * Copyright (C) 2026       libfuse maintainers
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

/** @file
 * @tableofcontents
 *
 * This example illustrates how to write a FUSE low-level file system
 * that can process ioctls. It demonstrates both:
 *
 * 1. Restricted ioctls (FIOC_GET_SIZE, FIOC_SET_SIZE) - use _IOR/_IOW
 *    encoding, kernel handles data transfer automatically
 *
 * 2. Unrestricted ioctls (FIOC_READ, FIOC_WRITE) - use _IO encoding,
 *    require fuse_reply_ioctl_retry() to request data from kernel
 *
 * Note: Unrestricted ioctls only work with CUSE (character devices).
 * The kernel blocks fuse_reply_ioctl_retry() for regular FUSE mounts,
 * returning -EIO regardless of privileges. This is by design - FUSE is
 * for filesystems, CUSE is for character devices with arbitrary ioctls.
 *
 * Compile with:
 *
 *     gcc -Wall ioctl_ll.c `pkg-config fuse3 --cflags --libs` -o ioctl_ll
 *
 * ## Source code ##
 * \include ioctl_ll.c
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "ioctl.h"

#define FIOC_NAME "fioc"

enum {
	FIOC_NONE,
	FIOC_ROOT,
	FIOC_FILE,
};

static void *fioc_buf;
static size_t fioc_size;

static int fioc_resize(size_t new_size)
{
	void *new_buf;

	if (new_size == fioc_size)
		return 0;

	new_buf = realloc(fioc_buf, new_size);
	if (!new_buf && new_size)
		return -ENOMEM;

	if (new_size > fioc_size)
		memset((char *)new_buf + fioc_size, 0, new_size - fioc_size);

	fioc_buf = new_buf;
	fioc_size = new_size;

	return 0;
}

static int fioc_expand(size_t new_size)
{
	if (new_size > fioc_size)
		return fioc_resize(new_size);
	return 0;
}

static int fioc_stat(fuse_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ino = ino;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();

	switch (ino) {
	case 1:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		break;
	case 2:
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = fioc_size;
		break;
	default:
		return -1;
	}
	return 0;
}

static void fioc_ll_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;
	(void)conn;
}

static void fioc_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void)fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (fioc_stat(ino, &stbuf) == -1)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

static void fioc_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param ep;

	if (parent != 1 || strcmp(name, FIOC_NAME) != 0) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	memset(&ep, 0, sizeof(ep));
	ep.ino = 2;
	ep.attr_timeout = 1.0;
	ep.entry_timeout = 1.0;
	fioc_stat(ep.ino, &ep.attr);

	fuse_reply_entry(req, &ep);
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
	b->p = (char *)realloc(b->p, b->size);
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

static void fioc_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			    off_t off, struct fuse_file_info *fi)
{
	(void)fi;

	if (ino != 1) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	struct dirbuf b;

	memset(&b, 0, sizeof(b));
	dirbuf_add(req, &b, ".", 1);
	dirbuf_add(req, &b, "..", 1);
	dirbuf_add(req, &b, FIOC_NAME, 2);
	reply_buf_limited(req, b.p, b.size, off, size);
	free(b.p);
}

static void fioc_ll_open(fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi)
{
	if (ino != 2) {
		fuse_reply_err(req, EISDIR);
		return;
	}
	fuse_reply_open(req, fi);
}

static void fioc_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			 off_t off, struct fuse_file_info *fi)
{
	(void)fi;
	assert(ino == 2);

	if ((size_t)off >= fioc_size) {
		fuse_reply_buf(req, NULL, 0);
		return;
	}

	size_t len = min(fioc_size - off, size);

	fuse_reply_buf(req, (char *)fioc_buf + off, len);
}

static void fioc_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			  size_t size, off_t off, struct fuse_file_info *fi)
{
	(void)fi;
	assert(ino == 2);

	if (fioc_expand(off + size)) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	memcpy((char *)fioc_buf + off, buf, size);
	fuse_reply_write(req, size);
}

/*
 * Unrestricted ioctl handler for FIOC_READ and FIOC_WRITE.
 * These ioctls use _IO() encoding without size info, so the kernel
 * cannot automatically transfer data. We must use fuse_reply_ioctl_retry()
 * to tell the kernel what data to fetch/prepare.
 */
static void fioc_do_rw(fuse_req_t req, void *addr, const void *in_buf,
		       size_t in_bufsz, size_t out_bufsz, int is_read)
{
	const struct fioc_rw_arg *arg;
	struct iovec in_iov[2], out_iov[3], iov[3];
	size_t cur_size;

	/* First call: request the fioc_rw_arg structure */
	in_iov[0].iov_base = addr;
	in_iov[0].iov_len = sizeof(*arg);
	if (!in_bufsz) {
		fuse_reply_ioctl_retry(req, in_iov, 1, NULL, 0);
		return;
	}

	arg = in_buf;
	in_buf = (const char *)in_buf + sizeof(*arg);
	in_bufsz -= sizeof(*arg);

	/* Prepare output iovecs for prev_size and new_size */
	out_iov[0].iov_base = (char *)addr + offsetof(struct fioc_rw_arg, prev_size);
	out_iov[0].iov_len = sizeof(arg->prev_size);

	out_iov[1].iov_base = (char *)addr + offsetof(struct fioc_rw_arg, new_size);
	out_iov[1].iov_len = sizeof(arg->new_size);

	/* Prepare client buffer iovec */
	if (is_read) {
		out_iov[2].iov_base = arg->buf;
		out_iov[2].iov_len = arg->size;
		if (!out_bufsz) {
			fuse_reply_ioctl_retry(req, in_iov, 1, out_iov, 3);
			return;
		}
	} else {
		in_iov[1].iov_base = arg->buf;
		in_iov[1].iov_len = arg->size;
		if (arg->size && !in_bufsz) {
			fuse_reply_ioctl_retry(req, in_iov, 2, out_iov, 2);
			return;
		}
	}

	/* All data available, perform the operation */
	cur_size = fioc_size;
	iov[0].iov_base = &cur_size;
	iov[0].iov_len = sizeof(cur_size);

	iov[1].iov_base = &fioc_size;
	iov[1].iov_len = sizeof(fioc_size);

	if (is_read) {
		size_t off = arg->offset;
		size_t sz = arg->size;

		if (off >= fioc_size)
			off = fioc_size;
		if (sz > fioc_size - off)
			sz = fioc_size - off;

		iov[2].iov_base = (char *)fioc_buf + off;
		iov[2].iov_len = sz;
		fuse_reply_ioctl_iov(req, sz, iov, 3);
	} else {
		if (fioc_expand(arg->offset + in_bufsz)) {
			fuse_reply_err(req, ENOMEM);
			return;
		}

		memcpy((char *)fioc_buf + arg->offset, in_buf, in_bufsz);
		fuse_reply_ioctl_iov(req, in_bufsz, iov, 2);
	}
}

/*
 * Ioctl handler for low-level API.
 *
 * Restricted ioctls (FIOC_GET_SIZE, FIOC_SET_SIZE):
 *   - Use _IOR/_IOW encoding with size information
 *   - Kernel automatically handles data transfer
 *   - in_buf contains input data, out_bufsz indicates expected output size
 *
 * Unrestricted ioctls (FIOC_READ, FIOC_WRITE):
 *   - Use _IO encoding without size information
 *   - Require fuse_reply_ioctl_retry() to request data
 *   - Only work with CUSE or privileged mounts
 */
static void fioc_ll_ioctl(fuse_req_t req, fuse_ino_t ino, unsigned int cmd,
			  void *arg, struct fuse_file_info *fi,
			  unsigned int flags, const void *in_buf,
			  size_t in_bufsz, size_t out_bufsz)
{
	(void)fi;

	if (ino != 2) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	if (flags & FUSE_IOCTL_COMPAT) {
		fuse_reply_err(req, ENOSYS);
		return;
	}

	switch (cmd) {
	case FIOC_GET_SIZE:
		/*
		 * Restricted ioctl: kernel decoded _IOR and knows we want
		 * to return sizeof(size_t) bytes. Just reply with the data.
		 */
		if (!out_bufsz) {
			/* Unrestricted path: request output buffer */
			struct iovec iov = { arg, sizeof(size_t) };

			fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
		} else {
			fuse_reply_ioctl(req, 0, &fioc_size, sizeof(fioc_size));
		}
		break;

	case FIOC_SET_SIZE:
		/*
		 * Restricted ioctl: kernel decoded _IOW and provides
		 * the input data in in_buf.
		 */
		if (!in_bufsz) {
			/* Unrestricted path: request input data */
			struct iovec iov = { arg, sizeof(size_t) };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else {
			fioc_resize(*(const size_t *)in_buf);
			fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;

	case FIOC_READ:
		/* Unrestricted ioctl: requires retry mechanism */
		fioc_do_rw(req, arg, in_buf, in_bufsz, out_bufsz, 1);
		break;

	case FIOC_WRITE:
		/* Unrestricted ioctl: requires retry mechanism */
		fioc_do_rw(req, arg, in_buf, in_bufsz, out_bufsz, 0);
		break;

	default:
		fuse_reply_err(req, EINVAL);
	}
}

static const struct fuse_lowlevel_ops fioc_ll_oper = {
	.init		= fioc_ll_init,
	.lookup		= fioc_ll_lookup,
	.getattr	= fioc_ll_getattr,
	.readdir	= fioc_ll_readdir,
	.open		= fioc_ll_open,
	.read		= fioc_ll_read,
	.write		= fioc_ll_write,
	.ioctl		= fioc_ll_ioctl,
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct fuse_loop_config *config;
	int ret = -1;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;
	if (opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

	if (opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}

	se = fuse_session_new(&args, &fioc_ll_oper,
			      sizeof(fioc_ll_oper), NULL);
	if (se == NULL)
		goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;

	if (fuse_session_mount(se, opts.mountpoint) != 0)
		goto err_out3;

	fuse_daemonize(opts.foreground);

	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else {
		config = fuse_loop_cfg_create();
		fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
		fuse_loop_cfg_set_max_threads(config, opts.max_threads);
		ret = fuse_session_loop_mt(se, config);
		fuse_loop_cfg_destroy(config);
		config = NULL;
	}

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}

