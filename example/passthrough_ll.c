/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This file system mirrors the existing file system hierarchy of the
 * system, starting at the root file system. This is implemented by
 * just "passing through" all requests to the corresponding user-space
 * libc functions. In contrast to passthrough.c and passthrough_fh.c,
 * this implementation ises the low-level API. Its performance should
 * be the least bad among the three.
 *
 * Compile with:
 *
 *     gcc -Wall passthrough_ll.c `pkg-config fuse3 --cflags --libs` -o passthrough_ll
 *
 * ## Source code ##
 * \include passthrough_ll.c
 */

#define _GNU_SOURCE
#define FUSE_USE_VERSION 30

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fuse_lowlevel.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

/* Compat stuff.  Doesn't make it work, just makes it compile. */
#ifndef HAVE_FSTATAT
#warning fstatat(2) needed by this program
int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
	errno = ENOSYS;
	return -1;
}
#endif
#ifndef HAVE_OPENAT
#warning openat(2) needed by this program
int openat(int dirfd, const char *pathname, int flags, ...)
{
	errno = ENOSYS;
	return -1;
}
#endif
#ifndef HAVE_READLINKAT
#warning readlinkat(2) needed by this program
ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
	errno = ENOSYS;
	return -1;
}
#endif
#ifndef AT_EMPTY_PATH
#warning AT_EMPTY_PATH needed by this program
#define AT_EMPTY_PATH 0
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#warning AT_SYMLINK_NOFOLLOW needed by this program
#define AT_SYMLINK_NOFOLLOW 0
#endif
#ifndef O_PATH
#warning O_PATH needed by this program
#define O_PATH 0
#endif
#ifndef O_NOFOLLOW
#warning O_NOFOLLOW needed by this program
#define O_NOFOLLOW 0
#endif

struct lo_inode {
	struct lo_inode *next;
	struct lo_inode *prev;
	int fd;
	ino_t ino;
	dev_t dev;
	uint64_t nlookup;
};

struct lo_data {
	int debug;
	struct lo_inode root;
};

static struct lo_data *lo_data(fuse_req_t req)
{
	return (struct lo_data *) fuse_req_userdata(req);
}

static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return &lo_data(req)->root;
	else
		return (struct lo_inode *) (uintptr_t) ino;
}

static int lo_fd(fuse_req_t req, fuse_ino_t ino)
{
	return lo_inode(req, ino)->fd;
}

static bool lo_debug(fuse_req_t req)
{
	return lo_data(req)->debug != 0;
}

static void lo_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	int res;
	struct stat buf;
	(void) fi;

	res = fstatat(lo_fd(req, ino), "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return (void) fuse_reply_err(req, errno);

	fuse_reply_attr(req, &buf, 1.0);
}

static struct lo_inode *lo_find(struct lo_data *lo, struct stat *st)
{
	struct lo_inode *p;

	for (p = lo->root.next; p != &lo->root; p = p->next) {
		if (p->ino == st->st_ino && p->dev == st->st_dev)
			return p;
	}
	return NULL;
}

static int lo_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name,
			 struct fuse_entry_param *e)
{
	int newfd;
	int res;
	int saverr;
	struct lo_inode *inode;

	memset(e, 0, sizeof(*e));
	e->attr_timeout = 1.0;
	e->entry_timeout = 1.0;

	newfd = openat(lo_fd(req, parent), name, O_PATH | O_NOFOLLOW);
	if (newfd == -1)
		goto out_err;

	res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		goto out_err;

	inode = lo_find(lo_data(req), &e->attr);
	if (inode) {
		close(newfd);
		newfd = -1;
	} else {
		struct lo_inode *prev = &lo_data(req)->root;
		struct lo_inode *next = prev->next;
		saverr = ENOMEM;
		inode = calloc(1, sizeof(struct lo_inode));
		if (!inode)
			goto out_err;

		inode->fd = newfd;
		inode->ino = e->attr.st_ino;
		inode->dev = e->attr.st_dev;

		next->prev = inode;
		inode->next = next;
		inode->prev = prev;
		prev->next = inode;
	}
	inode->nlookup++;
	e->ino = (uintptr_t) inode;

	if (lo_debug(req))
		fprintf(stderr, "  %lli/%s -> %lli\n",
			(unsigned long long) parent, name, (unsigned long long) e->ino);

	return 0;

out_err:
	saverr = errno;
	if (newfd != -1)
		close(newfd);
	return saverr;
}

static void lo_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	int err;

	err = lo_do_lookup(req, parent, name, &e);
	if (err)
		fuse_reply_err(req, err);
	else
		fuse_reply_entry(req, &e);
}

static void lo_free(struct lo_inode *inode)
{
	struct lo_inode *prev = inode->prev;
	struct lo_inode *next = inode->next;

	next->prev = prev;
	prev->next = next;
	close(inode->fd);
	free(inode);
}

static void lo_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct lo_inode *inode = lo_inode(req, ino);

	if (lo_debug(req)) {
		fprintf(stderr, "  forget %lli %lli -%lli\n",
			(unsigned long long) ino, (unsigned long long) inode->nlookup,
			(unsigned long long) nlookup);
	}

	assert(inode->nlookup >= nlookup);
	inode->nlookup -= nlookup;

	if (!inode->nlookup)
		lo_free(inode);

	fuse_reply_none(req);
}

static void lo_readlink(fuse_req_t req, fuse_ino_t ino)
{
	char buf[PATH_MAX + 1];
	int res;

	res = readlinkat(lo_fd(req, ino), "", buf, sizeof(buf));
	if (res == -1)
		return (void) fuse_reply_err(req, errno);

	if (res == sizeof(buf))
		return (void) fuse_reply_err(req, ENAMETOOLONG);

	buf[res] = '\0';

	fuse_reply_readlink(req, buf);
}

struct lo_dirp {
	int fd;
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static struct lo_dirp *lo_dirp(struct fuse_file_info *fi)
{
	return (struct lo_dirp *) (uintptr_t) fi->fh;
}

static void lo_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int error = ENOMEM;
	struct lo_dirp *d = calloc(1, sizeof(struct lo_dirp));
	if (d == NULL)
		goto out_err;

	d->fd = openat(lo_fd(req, ino), ".", O_RDONLY);
	if (d->fd == -1)
		goto out_errno;

	d->dp = fdopendir(d->fd);
	if (d->dp == NULL)
		goto out_errno;

	d->offset = 0;
	d->entry = NULL;

	fi->fh = (uintptr_t) d;
	fuse_reply_open(req, fi);
	return;

out_errno:
	error = errno;
out_err:
	if (d) {
		if (d->fd != -1)
			close(d->fd);
		free(d);
	}
	fuse_reply_err(req, error);
}

static void lo_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t offset, struct fuse_file_info *fi, int plus)
{
	struct lo_dirp *d = lo_dirp(fi);
	char *buf;
	char *p;
	size_t rem;
	int err;

	(void) ino;

	buf = calloc(size, 1);
	if (!buf)
		return (void) fuse_reply_err(req, ENOMEM);

	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}
	p = buf;
	rem = size;
	while (1) {
		size_t entsize;
		off_t nextoff;

		if (!d->entry) {
			errno = 0;
			d->entry = readdir(d->dp);
			if (!d->entry) {
				if (errno && rem == size) {
					err = errno;
					goto error;
				}
				break;
			}
		}
		nextoff = telldir(d->dp);
		if (plus) {
			struct fuse_entry_param e;

			err = lo_do_lookup(req, ino, d->entry->d_name, &e);
			if (err)
				goto error;

			entsize = fuse_add_direntry_plus(req, p, rem,
							 d->entry->d_name,
							 &e, nextoff);
		} else {
			struct stat st = {
				.st_ino = d->entry->d_ino,
				.st_mode = d->entry->d_type << 12,
			};
			entsize = fuse_add_direntry(req, p, rem,
						    d->entry->d_name,
						    &st, nextoff);
		}
		if (entsize > rem)
			break;

		p += entsize;
		rem -= entsize;

		d->entry = NULL;
		d->offset = nextoff;
	}

	fuse_reply_buf(req, buf, size - rem);
	free(buf);
	return;

error:
	free(buf);
	fuse_reply_err(req, err);
}

static void lo_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	lo_do_readdir(req, ino, size, offset, fi, 0);
}

static void lo_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			   off_t offset, struct fuse_file_info *fi)
{
	lo_do_readdir(req, ino, size, offset, fi, 1);
}

static void lo_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct lo_dirp *d = lo_dirp(fi);
	(void) ino;
	closedir(d->dp);
	free(d);
	fuse_reply_err(req, 0);
}

static void lo_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	int fd;
	char buf[64];

	sprintf(buf, "/proc/self/fd/%i", lo_fd(req, ino));
	fd = open(buf, fi->flags & ~O_NOFOLLOW);
	if (fd == -1)
		return (void) fuse_reply_err(req, errno);

	fi->fh = fd;
	fuse_reply_open(req, fi);
}

static void lo_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	(void) ino;

	close(fi->fh);
	fuse_reply_err(req, 0);
}

static void lo_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t offset, struct fuse_file_info *fi)
{
	struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);

	(void) ino;

	buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	buf.buf[0].fd = fi->fh;
	buf.buf[0].pos = offset;

	fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
}

static struct fuse_lowlevel_ops lo_oper = {
	.lookup		= lo_lookup,
	.forget		= lo_forget,
	.getattr	= lo_getattr,
	.readlink	= lo_readlink,
	.opendir	= lo_opendir,
	.readdir	= lo_readdir,
	.readdirplus	= lo_readdirplus,
	.releasedir	= lo_releasedir,
	.open		= lo_open,
	.release	= lo_release,
	.read		= lo_read,
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct lo_data lo = { .debug = 0 };
	int ret = -1;

	lo.root.next = lo.root.prev = &lo.root;
	lo.root.fd = -1;

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

	lo.debug = opts.debug;
	lo.root.fd = open("/", O_PATH);
	lo.root.nlookup = 2;
	if (lo.root.fd == -1)
		err(1, "open(\"/\", O_PATH)");

	se = fuse_session_new(&args, &lo_oper, sizeof(lo_oper), &lo);
	if (se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
	    goto err_out2;

	if (fuse_session_mount(se, opts.mountpoint) != 0)
	    goto err_out3;

	fuse_daemonize(opts.foreground);

	/* Block until ctrl+c or fusermount -u */
	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else
		ret = fuse_session_loop_mt(se, opts.clone_fd);

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	while (lo.root.next != &lo.root)
		lo_free(lo.root.next);
	if (lo.root.fd >= 0)
		close(lo.root.fd);

	return ret ? 1 : 0;
}
