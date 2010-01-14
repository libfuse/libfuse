/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_opt.h"
#include "fuse_misc.h"
#include "fuse_common_compat.h"
#include "fuse_lowlevel_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#define PARAM(inarg) (((char *)(inarg)) + sizeof(*(inarg)))
#define OFFSET_MAX 0x7fffffffffffffffLL

struct fuse_pollhandle {
	uint64_t kh;
	struct fuse_chan *ch;
	struct fuse_ll *f;
};

static void convert_stat(const struct stat *stbuf, struct fuse_attr *attr)
{
	attr->ino	= stbuf->st_ino;
	attr->mode	= stbuf->st_mode;
	attr->nlink	= stbuf->st_nlink;
	attr->uid	= stbuf->st_uid;
	attr->gid	= stbuf->st_gid;
	attr->rdev	= stbuf->st_rdev;
	attr->size	= stbuf->st_size;
	attr->blksize	= stbuf->st_blksize;
	attr->blocks	= stbuf->st_blocks;
	attr->atime	= stbuf->st_atime;
	attr->mtime	= stbuf->st_mtime;
	attr->ctime	= stbuf->st_ctime;
	attr->atimensec = ST_ATIM_NSEC(stbuf);
	attr->mtimensec = ST_MTIM_NSEC(stbuf);
	attr->ctimensec = ST_CTIM_NSEC(stbuf);
}

static void convert_attr(const struct fuse_setattr_in *attr, struct stat *stbuf)
{
	stbuf->st_mode	       = attr->mode;
	stbuf->st_uid	       = attr->uid;
	stbuf->st_gid	       = attr->gid;
	stbuf->st_size	       = attr->size;
	stbuf->st_atime	       = attr->atime;
	stbuf->st_mtime	       = attr->mtime;
	ST_ATIM_NSEC_SET(stbuf, attr->atimensec);
	ST_MTIM_NSEC_SET(stbuf, attr->mtimensec);
}

static	size_t iov_length(const struct iovec *iov, size_t count)
{
	size_t seg;
	size_t ret = 0;

	for (seg = 0; seg < count; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

static void list_init_req(struct fuse_req *req)
{
	req->next = req;
	req->prev = req;
}

static void list_del_req(struct fuse_req *req)
{
	struct fuse_req *prev = req->prev;
	struct fuse_req *next = req->next;
	prev->next = next;
	next->prev = prev;
}

static void list_add_req(struct fuse_req *req, struct fuse_req *next)
{
	struct fuse_req *prev = next->prev;
	req->next = next;
	req->prev = prev;
	prev->next = req;
	next->prev = req;
}

static void destroy_req(fuse_req_t req)
{
	pthread_mutex_destroy(&req->lock);
	free(req);
}

void fuse_free_req(fuse_req_t req)
{
	int ctr;
	struct fuse_ll *f = req->f;

	pthread_mutex_lock(&f->lock);
	req->u.ni.func = NULL;
	req->u.ni.data = NULL;
	list_del_req(req);
	ctr = --req->ctr;
	pthread_mutex_unlock(&f->lock);
	if (!ctr)
		destroy_req(req);
}

int fuse_send_reply_iov_nofree(fuse_req_t req, int error, struct iovec *iov,
			       int count)
{
	struct fuse_out_header out;

	if (error <= -1000 || error > 0) {
		fprintf(stderr, "fuse: bad error value: %i\n",	error);
		error = -ERANGE;
	}

	out.unique = req->unique;
	out.error = error;
	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct fuse_out_header);
	out.len = iov_length(iov, count);

	if (req->f->debug) {
		if (out.error) {
			fprintf(stderr,
				"   unique: %llu, error: %i (%s), outsize: %i\n",
				(unsigned long long) out.unique, out.error,
				strerror(-out.error), out.len);
		} else {
			fprintf(stderr,
				"   unique: %llu, success, outsize: %i\n",
				(unsigned long long) out.unique, out.len);
		}
	}

	return fuse_chan_send(req->ch, iov, count);
}

static int send_reply_iov(fuse_req_t req, int error, struct iovec *iov,
			  int count)
{
	int res;

	res = fuse_send_reply_iov_nofree(req, error, iov, count);
	fuse_free_req(req);
	return res;
}

static int send_reply(fuse_req_t req, int error, const void *arg,
		      size_t argsize)
{
	struct iovec iov[2];
	int count = 1;
	if (argsize) {
		iov[1].iov_base = (void *) arg;
		iov[1].iov_len = argsize;
		count++;
	}
	return send_reply_iov(req, error, iov, count);
}

int fuse_reply_iov(fuse_req_t req, const struct iovec *iov, int count)
{
	int res;
	struct iovec *padded_iov;

	padded_iov = malloc((count + 1) * sizeof(struct iovec));
	if (padded_iov == NULL)
		return fuse_reply_err(req, -ENOMEM);

	memcpy(padded_iov + 1, iov, count * sizeof(struct iovec));
	count++;

	res = send_reply_iov(req, 0, padded_iov, count);
	free(padded_iov);

	return res;
}

size_t fuse_dirent_size(size_t namelen)
{
	return FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
}

char *fuse_add_dirent(char *buf, const char *name, const struct stat *stbuf,
		      off_t off)
{
	unsigned namelen = strlen(name);
	unsigned entlen = FUSE_NAME_OFFSET + namelen;
	unsigned entsize = fuse_dirent_size(namelen);
	unsigned padlen = entsize - entlen;
	struct fuse_dirent *dirent = (struct fuse_dirent *) buf;

	dirent->ino = stbuf->st_ino;
	dirent->off = off;
	dirent->namelen = namelen;
	dirent->type = (stbuf->st_mode & 0170000) >> 12;
	strncpy(dirent->name, name, namelen);
	if (padlen)
		memset(buf + entlen, 0, padlen);

	return buf + entsize;
}

size_t fuse_add_direntry(fuse_req_t req, char *buf, size_t bufsize,
			 const char *name, const struct stat *stbuf, off_t off)
{
	size_t entsize;

	(void) req;
	entsize = fuse_dirent_size(strlen(name));
	if (entsize <= bufsize && buf)
		fuse_add_dirent(buf, name, stbuf, off);
	return entsize;
}

static void convert_statfs(const struct statvfs *stbuf,
			   struct fuse_kstatfs *kstatfs)
{
	kstatfs->bsize	 = stbuf->f_bsize;
	kstatfs->frsize	 = stbuf->f_frsize;
	kstatfs->blocks	 = stbuf->f_blocks;
	kstatfs->bfree	 = stbuf->f_bfree;
	kstatfs->bavail	 = stbuf->f_bavail;
	kstatfs->files	 = stbuf->f_files;
	kstatfs->ffree	 = stbuf->f_ffree;
	kstatfs->namelen = stbuf->f_namemax;
}

static int send_reply_ok(fuse_req_t req, const void *arg, size_t argsize)
{
	return send_reply(req, 0, arg, argsize);
}

int fuse_reply_err(fuse_req_t req, int err)
{
	return send_reply(req, -err, NULL, 0);
}

void fuse_reply_none(fuse_req_t req)
{
	fuse_chan_send(req->ch, NULL, 0);
	fuse_free_req(req);
}

static unsigned long calc_timeout_sec(double t)
{
	if (t > (double) ULONG_MAX)
		return ULONG_MAX;
	else if (t < 0.0)
		return 0;
	else
		return (unsigned long) t;
}

static unsigned int calc_timeout_nsec(double t)
{
	double f = t - (double) calc_timeout_sec(t);
	if (f < 0.0)
		return 0;
	else if (f >= 0.999999999)
		return 999999999;
	else
		return (unsigned int) (f * 1.0e9);
}

static void fill_entry(struct fuse_entry_out *arg,
		       const struct fuse_entry_param *e)
{
	arg->nodeid = e->ino;
	arg->generation = e->generation;
	arg->entry_valid = calc_timeout_sec(e->entry_timeout);
	arg->entry_valid_nsec = calc_timeout_nsec(e->entry_timeout);
	arg->attr_valid = calc_timeout_sec(e->attr_timeout);
	arg->attr_valid_nsec = calc_timeout_nsec(e->attr_timeout);
	convert_stat(&e->attr, &arg->attr);
}

static void fill_open(struct fuse_open_out *arg,
		      const struct fuse_file_info *f)
{
	arg->fh = f->fh;
	if (f->direct_io)
		arg->open_flags |= FOPEN_DIRECT_IO;
	if (f->keep_cache)
		arg->open_flags |= FOPEN_KEEP_CACHE;
	if (f->nonseekable)
		arg->open_flags |= FOPEN_NONSEEKABLE;
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e)
{
	struct fuse_entry_out arg;
	size_t size = req->f->conn.proto_minor < 9 ?
		FUSE_COMPAT_ENTRY_OUT_SIZE : sizeof(arg);

	/* before ABI 7.4 e->ino == 0 was invalid, only ENOENT meant
	   negative entry */
	if (!e->ino && req->f->conn.proto_minor < 4)
		return fuse_reply_err(req, ENOENT);

	memset(&arg, 0, sizeof(arg));
	fill_entry(&arg, e);
	return send_reply_ok(req, &arg, size);
}

int fuse_reply_create(fuse_req_t req, const struct fuse_entry_param *e,
		      const struct fuse_file_info *f)
{
	char buf[sizeof(struct fuse_entry_out) + sizeof(struct fuse_open_out)];
	size_t entrysize = req->f->conn.proto_minor < 9 ?
		FUSE_COMPAT_ENTRY_OUT_SIZE : sizeof(struct fuse_entry_out);
	struct fuse_entry_out *earg = (struct fuse_entry_out *) buf;
	struct fuse_open_out *oarg = (struct fuse_open_out *) (buf + entrysize);

	memset(buf, 0, sizeof(buf));
	fill_entry(earg, e);
	fill_open(oarg, f);
	return send_reply_ok(req, buf,
			     entrysize + sizeof(struct fuse_open_out));
}

int fuse_reply_attr(fuse_req_t req, const struct stat *attr,
		    double attr_timeout)
{
	struct fuse_attr_out arg;
	size_t size = req->f->conn.proto_minor < 9 ?
		FUSE_COMPAT_ATTR_OUT_SIZE : sizeof(arg);

	memset(&arg, 0, sizeof(arg));
	arg.attr_valid = calc_timeout_sec(attr_timeout);
	arg.attr_valid_nsec = calc_timeout_nsec(attr_timeout);
	convert_stat(attr, &arg.attr);

	return send_reply_ok(req, &arg, size);
}

int fuse_reply_readlink(fuse_req_t req, const char *linkname)
{
	return send_reply_ok(req, linkname, strlen(linkname));
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *f)
{
	struct fuse_open_out arg;

	memset(&arg, 0, sizeof(arg));
	fill_open(&arg, f);
	return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
	struct fuse_write_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.size = count;

	return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
	return send_reply_ok(req, buf, size);
}

int fuse_reply_statfs(fuse_req_t req, const struct statvfs *stbuf)
{
	struct fuse_statfs_out arg;
	size_t size = req->f->conn.proto_minor < 4 ?
		FUSE_COMPAT_STATFS_SIZE : sizeof(arg);

	memset(&arg, 0, sizeof(arg));
	convert_statfs(stbuf, &arg.st);

	return send_reply_ok(req, &arg, size);
}

int fuse_reply_xattr(fuse_req_t req, size_t count)
{
	struct fuse_getxattr_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.size = count;

	return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_lock(fuse_req_t req, struct flock *lock)
{
	struct fuse_lk_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.lk.type = lock->l_type;
	if (lock->l_type != F_UNLCK) {
		arg.lk.start = lock->l_start;
		if (lock->l_len == 0)
			arg.lk.end = OFFSET_MAX;
		else
			arg.lk.end = lock->l_start + lock->l_len - 1;
	}
	arg.lk.pid = lock->l_pid;
	return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_bmap(fuse_req_t req, uint64_t idx)
{
	struct fuse_bmap_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.block = idx;

	return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_ioctl_retry(fuse_req_t req,
			   const struct iovec *in_iov, size_t in_count,
			   const struct iovec *out_iov, size_t out_count)
{
	struct fuse_ioctl_out arg;
	struct iovec iov[4];
	size_t count = 1;

	memset(&arg, 0, sizeof(arg));
	arg.flags |= FUSE_IOCTL_RETRY;
	arg.in_iovs = in_count;
	arg.out_iovs = out_count;
	iov[count].iov_base = &arg;
	iov[count].iov_len = sizeof(arg);
	count++;

	if (in_count) {
		iov[count].iov_base = (void *)in_iov;
		iov[count].iov_len = sizeof(in_iov[0]) * in_count;
		count++;
	}

	if (out_count) {
		iov[count].iov_base = (void *)out_iov;
		iov[count].iov_len = sizeof(out_iov[0]) * out_count;
		count++;
	}

	return send_reply_iov(req, 0, iov, count);
}

int fuse_reply_ioctl(fuse_req_t req, int result, const void *buf, size_t size)
{
	struct fuse_ioctl_out arg;
	struct iovec iov[3];
	size_t count = 1;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;
	iov[count].iov_base = &arg;
	iov[count].iov_len = sizeof(arg);
	count++;

	if (size) {
		iov[count].iov_base = (char *) buf;
		iov[count].iov_len = size;
		count++;
	}

	return send_reply_iov(req, 0, iov, count);
}

int fuse_reply_ioctl_iov(fuse_req_t req, int result, const struct iovec *iov,
			 int count)
{
	struct iovec *padded_iov;
	struct fuse_ioctl_out arg;
	int res;

	padded_iov = malloc((count + 2) * sizeof(struct iovec));
	if (padded_iov == NULL)
		return fuse_reply_err(req, -ENOMEM);

	memset(&arg, 0, sizeof(arg));
	arg.result = result;
	padded_iov[1].iov_base = &arg;
	padded_iov[1].iov_len = sizeof(arg);

	memcpy(&padded_iov[2], iov, count * sizeof(struct iovec));

	res = send_reply_iov(req, 0, padded_iov, count + 2);
	free(padded_iov);

	return res;
}

int fuse_reply_poll(fuse_req_t req, unsigned revents)
{
	struct fuse_poll_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.revents = revents;

	return send_reply_ok(req, &arg, sizeof(arg));
}

static void do_lookup(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.lookup)
		req->f->op.lookup(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_forget(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_forget_in *arg = (struct fuse_forget_in *) inarg;

	if (req->f->op.forget)
		req->f->op.forget(req, nodeid, arg->nlookup);
	else
		fuse_reply_none(req);
}

static void do_getattr(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_file_info *fip = NULL;
	struct fuse_file_info fi;

	if (req->f->conn.proto_minor >= 9) {
		struct fuse_getattr_in *arg = (struct fuse_getattr_in *) inarg;

		if (arg->getattr_flags & FUSE_GETATTR_FH) {
			memset(&fi, 0, sizeof(fi));
			fi.fh = arg->fh;
			fi.fh_old = fi.fh;
			fip = &fi;
		}
	}

	if (req->f->op.getattr)
		req->f->op.getattr(req, nodeid, fip);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_setattr(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_setattr_in *arg = (struct fuse_setattr_in *) inarg;

	if (req->f->op.setattr) {
		struct fuse_file_info *fi = NULL;
		struct fuse_file_info fi_store;
		struct stat stbuf;
		memset(&stbuf, 0, sizeof(stbuf));
		convert_attr(arg, &stbuf);
		if (arg->valid & FATTR_FH) {
			arg->valid &= ~FATTR_FH;
			memset(&fi_store, 0, sizeof(fi_store));
			fi = &fi_store;
			fi->fh = arg->fh;
			fi->fh_old = fi->fh;
		}
		arg->valid &=
			FUSE_SET_ATTR_MODE	|
			FUSE_SET_ATTR_UID	|
			FUSE_SET_ATTR_GID	|
			FUSE_SET_ATTR_SIZE	|
			FUSE_SET_ATTR_ATIME	|
			FUSE_SET_ATTR_MTIME	|
			FUSE_SET_ATTR_ATIME_NOW	|
			FUSE_SET_ATTR_MTIME_NOW;

		req->f->op.setattr(req, nodeid, &stbuf, arg->valid, fi);
	} else
		fuse_reply_err(req, ENOSYS);
}

static void do_access(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_access_in *arg = (struct fuse_access_in *) inarg;

	if (req->f->op.access)
		req->f->op.access(req, nodeid, arg->mask);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_readlink(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	(void) inarg;

	if (req->f->op.readlink)
		req->f->op.readlink(req, nodeid);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_mknod(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_mknod_in *arg = (struct fuse_mknod_in *) inarg;
	char *name = PARAM(arg);

	if (req->f->conn.proto_minor >= 12)
		req->ctx.umask = arg->umask;
	else
		name = (char *) inarg + FUSE_COMPAT_MKNOD_IN_SIZE;

	if (req->f->op.mknod)
		req->f->op.mknod(req, nodeid, name, arg->mode, arg->rdev);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_mkdir(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_mkdir_in *arg = (struct fuse_mkdir_in *) inarg;

	if (req->f->conn.proto_minor >= 12)
		req->ctx.umask = arg->umask;

	if (req->f->op.mkdir)
		req->f->op.mkdir(req, nodeid, PARAM(arg), arg->mode);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_unlink(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.unlink)
		req->f->op.unlink(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_rmdir(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.rmdir)
		req->f->op.rmdir(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_symlink(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;
	char *linkname = ((char *) inarg) + strlen((char *) inarg) + 1;

	if (req->f->op.symlink)
		req->f->op.symlink(req, linkname, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_rename(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_rename_in *arg = (struct fuse_rename_in *) inarg;
	char *oldname = PARAM(arg);
	char *newname = oldname + strlen(oldname) + 1;

	if (req->f->op.rename)
		req->f->op.rename(req, nodeid, oldname, arg->newdir, newname);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_link(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_link_in *arg = (struct fuse_link_in *) inarg;

	if (req->f->op.link)
		req->f->op.link(req, arg->oldnodeid, nodeid, PARAM(arg));
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_create(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_create_in *arg = (struct fuse_create_in *) inarg;

	if (req->f->op.create) {
		struct fuse_file_info fi;
		char *name = PARAM(arg);

		memset(&fi, 0, sizeof(fi));
		fi.flags = arg->flags;

		if (req->f->conn.proto_minor >= 12)
			req->ctx.umask = arg->umask;
		else
			name = (char *) inarg + sizeof(struct fuse_open_in);

		req->f->op.create(req, nodeid, name, arg->mode, &fi);
	} else
		fuse_reply_err(req, ENOSYS);
}

static void do_open(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_open_in *arg = (struct fuse_open_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;

	if (req->f->op.open)
		req->f->op.open(req, nodeid, &fi);
	else
		fuse_reply_open(req, &fi);
}

static void do_read(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_read_in *arg = (struct fuse_read_in *) inarg;

	if (req->f->op.read) {
		struct fuse_file_info fi;

		memset(&fi, 0, sizeof(fi));
		fi.fh = arg->fh;
		fi.fh_old = fi.fh;
		if (req->f->conn.proto_minor >= 9) {
			fi.lock_owner = arg->lock_owner;
			fi.flags = arg->flags;
		}
		req->f->op.read(req, nodeid, arg->size, arg->offset, &fi);
	} else
		fuse_reply_err(req, ENOSYS);
}

static void do_write(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_write_in *arg = (struct fuse_write_in *) inarg;
	struct fuse_file_info fi;
	char *param;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;
	fi.writepage = arg->write_flags & 1;

	if (req->f->conn.proto_minor < 9) {
		param = ((char *) arg) + FUSE_COMPAT_WRITE_IN_SIZE;
	} else {
		fi.lock_owner = arg->lock_owner;
		fi.flags = arg->flags;
		param = PARAM(arg);
	}

	if (req->f->op.write)
		req->f->op.write(req, nodeid, param, arg->size,
				 arg->offset, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_flush(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_flush_in *arg = (struct fuse_flush_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;
	fi.flush = 1;
	if (req->f->conn.proto_minor >= 7)
		fi.lock_owner = arg->lock_owner;

	if (req->f->op.flush)
		req->f->op.flush(req, nodeid, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_release(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_release_in *arg = (struct fuse_release_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;
	if (req->f->conn.proto_minor >= 8) {
		fi.flush = (arg->release_flags & FUSE_RELEASE_FLUSH) ? 1 : 0;
		fi.lock_owner = arg->lock_owner;
	}

	if (req->f->op.release)
		req->f->op.release(req, nodeid, &fi);
	else
		fuse_reply_err(req, 0);
}

static void do_fsync(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_fsync_in *arg = (struct fuse_fsync_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.fsync)
		req->f->op.fsync(req, nodeid, arg->fsync_flags & 1, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_opendir(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_open_in *arg = (struct fuse_open_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;

	if (req->f->op.opendir)
		req->f->op.opendir(req, nodeid, &fi);
	else
		fuse_reply_open(req, &fi);
}

static void do_readdir(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_read_in *arg = (struct fuse_read_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.readdir)
		req->f->op.readdir(req, nodeid, arg->size, arg->offset, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_releasedir(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_release_in *arg = (struct fuse_release_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.releasedir)
		req->f->op.releasedir(req, nodeid, &fi);
	else
		fuse_reply_err(req, 0);
}

static void do_fsyncdir(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_fsync_in *arg = (struct fuse_fsync_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.fsyncdir)
		req->f->op.fsyncdir(req, nodeid, arg->fsync_flags & 1, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_statfs(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	(void) nodeid;
	(void) inarg;

	if (req->f->op.statfs)
		req->f->op.statfs(req, nodeid);
	else {
		struct statvfs buf = {
			.f_namemax = 255,
			.f_bsize = 512,
		};
		fuse_reply_statfs(req, &buf);
	}
}

static void do_setxattr(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_setxattr_in *arg = (struct fuse_setxattr_in *) inarg;
	char *name = PARAM(arg);
	char *value = name + strlen(name) + 1;

	if (req->f->op.setxattr)
		req->f->op.setxattr(req, nodeid, name, value, arg->size,
				    arg->flags);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_getxattr(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_getxattr_in *arg = (struct fuse_getxattr_in *) inarg;

	if (req->f->op.getxattr)
		req->f->op.getxattr(req, nodeid, PARAM(arg), arg->size);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_listxattr(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_getxattr_in *arg = (struct fuse_getxattr_in *) inarg;

	if (req->f->op.listxattr)
		req->f->op.listxattr(req, nodeid, arg->size);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_removexattr(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.removexattr)
		req->f->op.removexattr(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void convert_fuse_file_lock(struct fuse_file_lock *fl,
				   struct flock *flock)
{
	memset(flock, 0, sizeof(struct flock));
	flock->l_type = fl->type;
	flock->l_whence = SEEK_SET;
	flock->l_start = fl->start;
	if (fl->end == OFFSET_MAX)
		flock->l_len = 0;
	else
		flock->l_len = fl->end - fl->start + 1;
	flock->l_pid = fl->pid;
}

static void do_getlk(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_lk_in *arg = (struct fuse_lk_in *) inarg;
	struct fuse_file_info fi;
	struct flock flock;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.lock_owner = arg->owner;

	convert_fuse_file_lock(&arg->lk, &flock);
	if (req->f->op.getlk)
		req->f->op.getlk(req, nodeid, &fi, &flock);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_setlk_common(fuse_req_t req, fuse_ino_t nodeid,
			    const void *inarg, int sleep)
{
	struct fuse_lk_in *arg = (struct fuse_lk_in *) inarg;
	struct fuse_file_info fi;
	struct flock flock;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.lock_owner = arg->owner;

	convert_fuse_file_lock(&arg->lk, &flock);
	if (req->f->op.setlk)
		req->f->op.setlk(req, nodeid, &fi, &flock, sleep);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_setlk(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	do_setlk_common(req, nodeid, inarg, 0);
}

static void do_setlkw(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	do_setlk_common(req, nodeid, inarg, 1);
}

static int find_interrupted(struct fuse_ll *f, struct fuse_req *req)
{
	struct fuse_req *curr;

	for (curr = f->list.next; curr != &f->list; curr = curr->next) {
		if (curr->unique == req->u.i.unique) {
			fuse_interrupt_func_t func;
			void *data;

			curr->ctr++;
			pthread_mutex_unlock(&f->lock);

			/* Ugh, ugly locking */
			pthread_mutex_lock(&curr->lock);
			pthread_mutex_lock(&f->lock);
			curr->interrupted = 1;
			func = curr->u.ni.func;
			data = curr->u.ni.data;
			pthread_mutex_unlock(&f->lock);
			if (func)
				func(curr, data);
			pthread_mutex_unlock(&curr->lock);

			pthread_mutex_lock(&f->lock);
			curr->ctr--;
			if (!curr->ctr)
				destroy_req(curr);

			return 1;
		}
	}
	for (curr = f->interrupts.next; curr != &f->interrupts;
	     curr = curr->next) {
		if (curr->u.i.unique == req->u.i.unique)
			return 1;
	}
	return 0;
}

static void do_interrupt(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_interrupt_in *arg = (struct fuse_interrupt_in *) inarg;
	struct fuse_ll *f = req->f;

	(void) nodeid;
	if (f->debug)
		fprintf(stderr, "INTERRUPT: %llu\n",
			(unsigned long long) arg->unique);

	req->u.i.unique = arg->unique;

	pthread_mutex_lock(&f->lock);
	if (find_interrupted(f, req))
		destroy_req(req);
	else
		list_add_req(req, &f->interrupts);
	pthread_mutex_unlock(&f->lock);
}

static struct fuse_req *check_interrupt(struct fuse_ll *f, struct fuse_req *req)
{
	struct fuse_req *curr;

	for (curr = f->interrupts.next; curr != &f->interrupts;
	     curr = curr->next) {
		if (curr->u.i.unique == req->unique) {
			req->interrupted = 1;
			list_del_req(curr);
			free(curr);
			return NULL;
		}
	}
	curr = f->interrupts.next;
	if (curr != &f->interrupts) {
		list_del_req(curr);
		list_init_req(curr);
		return curr;
	} else
		return NULL;
}

static void do_bmap(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_bmap_in *arg = (struct fuse_bmap_in *) inarg;

	if (req->f->op.bmap)
		req->f->op.bmap(req, nodeid, arg->blocksize, arg->block);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_ioctl(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_ioctl_in *arg = (struct fuse_ioctl_in *) inarg;
	unsigned int flags = arg->flags;
	void *in_buf = arg->in_size ? PARAM(arg) : NULL;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.ioctl)
		req->f->op.ioctl(req, nodeid, arg->cmd,
				 (void *)(uintptr_t)arg->arg, &fi, flags,
				 in_buf, arg->in_size, arg->out_size);
	else
		fuse_reply_err(req, ENOSYS);
}

void fuse_pollhandle_destroy(struct fuse_pollhandle *ph)
{
	free(ph);
}

static void do_poll(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_poll_in *arg = (struct fuse_poll_in *) inarg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.poll) {
		struct fuse_pollhandle *ph = NULL;

		if (arg->flags & FUSE_POLL_SCHEDULE_NOTIFY) {
			ph = malloc(sizeof(struct fuse_pollhandle));
			if (ph == NULL) {
				fuse_reply_err(req, ENOMEM);
				return;
			}
			ph->kh = arg->kh;
			ph->ch = req->ch;
			ph->f = req->f;
		}

		req->f->op.poll(req, nodeid, &fi, ph);
	} else {
		fuse_reply_err(req, ENOSYS);
	}
}

static void do_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_init_in *arg = (struct fuse_init_in *) inarg;
	struct fuse_init_out outarg;
	struct fuse_ll *f = req->f;
	size_t bufsize = fuse_chan_bufsize(req->ch);

	(void) nodeid;
	if (f->debug) {
		fprintf(stderr, "INIT: %u.%u\n", arg->major, arg->minor);
		if (arg->major == 7 && arg->minor >= 6) {
			fprintf(stderr, "flags=0x%08x\n", arg->flags);
			fprintf(stderr, "max_readahead=0x%08x\n",
				arg->max_readahead);
		}
	}
	f->conn.proto_major = arg->major;
	f->conn.proto_minor = arg->minor;
	f->conn.capable = 0;
	f->conn.want = 0;

	memset(&outarg, 0, sizeof(outarg));
	outarg.major = FUSE_KERNEL_VERSION;
	outarg.minor = FUSE_KERNEL_MINOR_VERSION;

	if (arg->major < 7) {
		fprintf(stderr, "fuse: unsupported protocol version: %u.%u\n",
			arg->major, arg->minor);
		fuse_reply_err(req, EPROTO);
		return;
	}

	if (arg->major > 7) {
		/* Wait for a second INIT request with a 7.X version */
		send_reply_ok(req, &outarg, sizeof(outarg));
		return;
	}

	if (arg->minor >= 6) {
		if (f->conn.async_read)
			f->conn.async_read = arg->flags & FUSE_ASYNC_READ;
		if (arg->max_readahead < f->conn.max_readahead)
			f->conn.max_readahead = arg->max_readahead;
		if (arg->flags & FUSE_ASYNC_READ)
			f->conn.capable |= FUSE_CAP_ASYNC_READ;
		if (arg->flags & FUSE_POSIX_LOCKS)
			f->conn.capable |= FUSE_CAP_POSIX_LOCKS;
		if (arg->flags & FUSE_ATOMIC_O_TRUNC)
			f->conn.capable |= FUSE_CAP_ATOMIC_O_TRUNC;
		if (arg->flags & FUSE_EXPORT_SUPPORT)
			f->conn.capable |= FUSE_CAP_EXPORT_SUPPORT;
		if (arg->flags & FUSE_BIG_WRITES)
			f->conn.capable |= FUSE_CAP_BIG_WRITES;
		if (arg->flags & FUSE_DONT_MASK)
			f->conn.capable |= FUSE_CAP_DONT_MASK;
	} else {
		f->conn.async_read = 0;
		f->conn.max_readahead = 0;
	}

	if (f->atomic_o_trunc)
		f->conn.want |= FUSE_CAP_ATOMIC_O_TRUNC;
	if (f->op.getlk && f->op.setlk && !f->no_remote_lock)
		f->conn.want |= FUSE_CAP_POSIX_LOCKS;
	if (f->big_writes)
		f->conn.want |= FUSE_CAP_BIG_WRITES;

	if (bufsize < FUSE_MIN_READ_BUFFER) {
		fprintf(stderr, "fuse: warning: buffer size too small: %zu\n",
			bufsize);
		bufsize = FUSE_MIN_READ_BUFFER;
	}

	bufsize -= 4096;
	if (bufsize < f->conn.max_write)
		f->conn.max_write = bufsize;

	f->got_init = 1;
	if (f->op.init)
		f->op.init(f->userdata, &f->conn);

	if (f->conn.async_read || (f->conn.want & FUSE_CAP_ASYNC_READ))
		outarg.flags |= FUSE_ASYNC_READ;
	if (f->conn.want & FUSE_CAP_POSIX_LOCKS)
		outarg.flags |= FUSE_POSIX_LOCKS;
	if (f->conn.want & FUSE_CAP_ATOMIC_O_TRUNC)
		outarg.flags |= FUSE_ATOMIC_O_TRUNC;
	if (f->conn.want & FUSE_CAP_EXPORT_SUPPORT)
		outarg.flags |= FUSE_EXPORT_SUPPORT;
	if (f->conn.want & FUSE_CAP_BIG_WRITES)
		outarg.flags |= FUSE_BIG_WRITES;
	if (f->conn.want & FUSE_CAP_DONT_MASK)
		outarg.flags |= FUSE_DONT_MASK;
	outarg.max_readahead = f->conn.max_readahead;
	outarg.max_write = f->conn.max_write;

	if (f->debug) {
		fprintf(stderr, "   INIT: %u.%u\n", outarg.major, outarg.minor);
		fprintf(stderr, "   flags=0x%08x\n", outarg.flags);
		fprintf(stderr, "   max_readahead=0x%08x\n",
			outarg.max_readahead);
		fprintf(stderr, "   max_write=0x%08x\n", outarg.max_write);
	}

	send_reply_ok(req, &outarg, arg->minor < 5 ? 8 : sizeof(outarg));
}

static void do_destroy(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_ll *f = req->f;

	(void) nodeid;
	(void) inarg;

	f->got_destroy = 1;
	if (f->op.destroy)
		f->op.destroy(f->userdata);

	send_reply_ok(req, NULL, 0);
}

static int send_notify_iov(struct fuse_ll *f, struct fuse_chan *ch,
			   int notify_code, struct iovec *iov, int count)
{
	struct fuse_out_header out;

	out.unique = 0;
	out.error = notify_code;
	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct fuse_out_header);
	out.len = iov_length(iov, count);

	if (f->debug)
		fprintf(stderr, "NOTIFY: code=%d count=%d length=%u\n",
			notify_code, count, out.len);

	return fuse_chan_send(ch, iov, count);
}

int fuse_lowlevel_notify_poll(struct fuse_pollhandle *ph)
{
	if (ph != NULL) {
		struct fuse_notify_poll_wakeup_out outarg;
		struct iovec iov[2];

		outarg.kh = ph->kh;

		iov[1].iov_base = &outarg;
		iov[1].iov_len = sizeof(outarg);

		return send_notify_iov(ph->f, ph->ch, FUSE_NOTIFY_POLL, iov, 2);
	} else {
		return 0;
	}
}

int fuse_lowlevel_notify_inval_inode(struct fuse_chan *ch, fuse_ino_t ino,
                                     off_t off, off_t len)
{
	struct fuse_notify_inval_inode_out outarg;
	struct fuse_ll *f;
	struct iovec iov[2];

	if (!ch)
		return -EINVAL;

	f = (struct fuse_ll *)fuse_session_data(fuse_chan_session(ch));
	if (!f)
		return -ENODEV;

	outarg.ino = ino;
	outarg.off = off;
	outarg.len = len;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);

	return send_notify_iov(f, ch, FUSE_NOTIFY_INVAL_INODE, iov, 2);
}

int fuse_lowlevel_notify_inval_entry(struct fuse_chan *ch, fuse_ino_t parent,
                                     const char *name, size_t namelen)
{
	struct fuse_notify_inval_entry_out outarg;
	struct fuse_ll *f;
	struct iovec iov[3];

	if (!ch)
		return -EINVAL;

	f = (struct fuse_ll *)fuse_session_data(fuse_chan_session(ch));
	if (!f)
		return -ENODEV;

	outarg.parent = parent;
	outarg.namelen = namelen;
	outarg.padding = 0;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);
	iov[2].iov_base = (void *)name;
	iov[2].iov_len = namelen + 1;

	return send_notify_iov(f, ch, FUSE_NOTIFY_INVAL_ENTRY, iov, 3);
}

void *fuse_req_userdata(fuse_req_t req)
{
	return req->f->userdata;
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
	return &req->ctx;
}

/*
 * The size of fuse_ctx got extended, so need to be careful about
 * incompatibility (i.e. a new binary cannot work with an old
 * library).
 */
const struct fuse_ctx *fuse_req_ctx_compat24(fuse_req_t req);
const struct fuse_ctx *fuse_req_ctx_compat24(fuse_req_t req)
{
	return fuse_req_ctx(req);
}
FUSE_SYMVER(".symver fuse_req_ctx_compat24,fuse_req_ctx@FUSE_2.4");


void fuse_req_interrupt_func(fuse_req_t req, fuse_interrupt_func_t func,
			     void *data)
{
	pthread_mutex_lock(&req->lock);
	pthread_mutex_lock(&req->f->lock);
	req->u.ni.func = func;
	req->u.ni.data = data;
	pthread_mutex_unlock(&req->f->lock);
	if (req->interrupted && func)
		func(req, data);
	pthread_mutex_unlock(&req->lock);
}

int fuse_req_interrupted(fuse_req_t req)
{
	int interrupted;

	pthread_mutex_lock(&req->f->lock);
	interrupted = req->interrupted;
	pthread_mutex_unlock(&req->f->lock);

	return interrupted;
}

static struct {
	void (*func)(fuse_req_t, fuse_ino_t, const void *);
	const char *name;
} fuse_ll_ops[] = {
	[FUSE_LOOKUP]	   = { do_lookup,      "LOOKUP"	     },
	[FUSE_FORGET]	   = { do_forget,      "FORGET"	     },
	[FUSE_GETATTR]	   = { do_getattr,     "GETATTR"     },
	[FUSE_SETATTR]	   = { do_setattr,     "SETATTR"     },
	[FUSE_READLINK]	   = { do_readlink,    "READLINK"    },
	[FUSE_SYMLINK]	   = { do_symlink,     "SYMLINK"     },
	[FUSE_MKNOD]	   = { do_mknod,       "MKNOD"	     },
	[FUSE_MKDIR]	   = { do_mkdir,       "MKDIR"	     },
	[FUSE_UNLINK]	   = { do_unlink,      "UNLINK"	     },
	[FUSE_RMDIR]	   = { do_rmdir,       "RMDIR"	     },
	[FUSE_RENAME]	   = { do_rename,      "RENAME"	     },
	[FUSE_LINK]	   = { do_link,	       "LINK"	     },
	[FUSE_OPEN]	   = { do_open,	       "OPEN"	     },
	[FUSE_READ]	   = { do_read,	       "READ"	     },
	[FUSE_WRITE]	   = { do_write,       "WRITE"	     },
	[FUSE_STATFS]	   = { do_statfs,      "STATFS"	     },
	[FUSE_RELEASE]	   = { do_release,     "RELEASE"     },
	[FUSE_FSYNC]	   = { do_fsync,       "FSYNC"	     },
	[FUSE_SETXATTR]	   = { do_setxattr,    "SETXATTR"    },
	[FUSE_GETXATTR]	   = { do_getxattr,    "GETXATTR"    },
	[FUSE_LISTXATTR]   = { do_listxattr,   "LISTXATTR"   },
	[FUSE_REMOVEXATTR] = { do_removexattr, "REMOVEXATTR" },
	[FUSE_FLUSH]	   = { do_flush,       "FLUSH"	     },
	[FUSE_INIT]	   = { do_init,	       "INIT"	     },
	[FUSE_OPENDIR]	   = { do_opendir,     "OPENDIR"     },
	[FUSE_READDIR]	   = { do_readdir,     "READDIR"     },
	[FUSE_RELEASEDIR]  = { do_releasedir,  "RELEASEDIR"  },
	[FUSE_FSYNCDIR]	   = { do_fsyncdir,    "FSYNCDIR"    },
	[FUSE_GETLK]	   = { do_getlk,       "GETLK"	     },
	[FUSE_SETLK]	   = { do_setlk,       "SETLK"	     },
	[FUSE_SETLKW]	   = { do_setlkw,      "SETLKW"	     },
	[FUSE_ACCESS]	   = { do_access,      "ACCESS"	     },
	[FUSE_CREATE]	   = { do_create,      "CREATE"	     },
	[FUSE_INTERRUPT]   = { do_interrupt,   "INTERRUPT"   },
	[FUSE_BMAP]	   = { do_bmap,	       "BMAP"	     },
	[FUSE_IOCTL]	   = { do_ioctl,       "IOCTL"	     },
	[FUSE_POLL]	   = { do_poll,        "POLL"	     },
	[FUSE_DESTROY]	   = { do_destroy,     "DESTROY"     },
	[CUSE_INIT]	   = { cuse_lowlevel_init, "CUSE_INIT"   },
};

#define FUSE_MAXOP (sizeof(fuse_ll_ops) / sizeof(fuse_ll_ops[0]))

static const char *opname(enum fuse_opcode opcode)
{
	if (opcode >= FUSE_MAXOP || !fuse_ll_ops[opcode].name)
		return "???";
	else
		return fuse_ll_ops[opcode].name;
}

static void fuse_ll_process(void *data, const char *buf, size_t len,
			    struct fuse_chan *ch)
{
	struct fuse_ll *f = (struct fuse_ll *) data;
	struct fuse_in_header *in = (struct fuse_in_header *) buf;
	const void *inarg = buf + sizeof(struct fuse_in_header);
	struct fuse_req *req;
	int err;

	if (f->debug)
		fprintf(stderr,
			"unique: %llu, opcode: %s (%i), nodeid: %lu, insize: %zu\n",
			(unsigned long long) in->unique,
			opname((enum fuse_opcode) in->opcode), in->opcode,
			(unsigned long) in->nodeid, len);

	req = (struct fuse_req *) calloc(1, sizeof(struct fuse_req));
	if (req == NULL) {
		fprintf(stderr, "fuse: failed to allocate request\n");
		return;
	}

	req->f = f;
	req->unique = in->unique;
	req->ctx.uid = in->uid;
	req->ctx.gid = in->gid;
	req->ctx.pid = in->pid;
	req->ch = ch;
	req->ctr = 1;
	list_init_req(req);
	fuse_mutex_init(&req->lock);

	err = EIO;
	if (!f->got_init) {
		enum fuse_opcode expected;

		expected = f->cuse_data ? CUSE_INIT : FUSE_INIT;
		if (in->opcode != expected)
			goto reply_err;
	} else if (in->opcode == FUSE_INIT || in->opcode == CUSE_INIT)
		goto reply_err;

	err = EACCES;
	if (f->allow_root && in->uid != f->owner && in->uid != 0 &&
		 in->opcode != FUSE_INIT && in->opcode != FUSE_READ &&
		 in->opcode != FUSE_WRITE && in->opcode != FUSE_FSYNC &&
		 in->opcode != FUSE_RELEASE && in->opcode != FUSE_READDIR &&
		 in->opcode != FUSE_FSYNCDIR && in->opcode != FUSE_RELEASEDIR)
		goto reply_err;

	err = ENOSYS;
	if (in->opcode >= FUSE_MAXOP || !fuse_ll_ops[in->opcode].func)
		goto reply_err;
	if (in->opcode != FUSE_INTERRUPT) {
		struct fuse_req *intr;
		pthread_mutex_lock(&f->lock);
		intr = check_interrupt(f, req);
		list_add_req(req, &f->list);
		pthread_mutex_unlock(&f->lock);
		if (intr)
			fuse_reply_err(intr, EAGAIN);
	}
	fuse_ll_ops[in->opcode].func(req, in->nodeid, inarg);
	return;

 reply_err:
	fuse_reply_err(req, err);
}

enum {
	KEY_HELP,
	KEY_VERSION,
};

static struct fuse_opt fuse_ll_opts[] = {
	{ "debug", offsetof(struct fuse_ll, debug), 1 },
	{ "-d", offsetof(struct fuse_ll, debug), 1 },
	{ "allow_root", offsetof(struct fuse_ll, allow_root), 1 },
	{ "max_write=%u", offsetof(struct fuse_ll, conn.max_write), 0 },
	{ "max_readahead=%u", offsetof(struct fuse_ll, conn.max_readahead), 0 },
	{ "async_read", offsetof(struct fuse_ll, conn.async_read), 1 },
	{ "sync_read", offsetof(struct fuse_ll, conn.async_read), 0 },
	{ "atomic_o_trunc", offsetof(struct fuse_ll, atomic_o_trunc), 1},
	{ "no_remote_lock", offsetof(struct fuse_ll, no_remote_lock), 1},
	{ "big_writes", offsetof(struct fuse_ll, big_writes), 1},
	FUSE_OPT_KEY("max_read=", FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("-h", KEY_HELP),
	FUSE_OPT_KEY("--help", KEY_HELP),
	FUSE_OPT_KEY("-V", KEY_VERSION),
	FUSE_OPT_KEY("--version", KEY_VERSION),
	FUSE_OPT_END
};

static void fuse_ll_version(void)
{
	fprintf(stderr, "using FUSE kernel interface version %i.%i\n",
		FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);
}

static void fuse_ll_help(void)
{
	fprintf(stderr,
"    -o max_write=N         set maximum size of write requests\n"
"    -o max_readahead=N     set maximum readahead\n"
"    -o async_read          perform reads asynchronously (default)\n"
"    -o sync_read           perform reads synchronously\n"
"    -o atomic_o_trunc      enable atomic open+truncate support\n"
"    -o big_writes          enable larger than 4kB writes\n"
"    -o no_remote_lock      disable remote file locking\n");
}

static int fuse_ll_opt_proc(void *data, const char *arg, int key,
			    struct fuse_args *outargs)
{
	(void) data; (void) outargs;

	switch (key) {
	case KEY_HELP:
		fuse_ll_help();
		break;

	case KEY_VERSION:
		fuse_ll_version();
		break;

	default:
		fprintf(stderr, "fuse: unknown option `%s'\n", arg);
	}

	return -1;
}

int fuse_lowlevel_is_lib_option(const char *opt)
{
	return fuse_opt_match(fuse_ll_opts, opt);
}

static void fuse_ll_destroy(void *data)
{
	struct fuse_ll *f = (struct fuse_ll *) data;

	if (f->got_init && !f->got_destroy) {
		if (f->op.destroy)
			f->op.destroy(f->userdata);
	}

	pthread_mutex_destroy(&f->lock);
	free(f->cuse_data);
	free(f);
}

/*
 * always call fuse_lowlevel_new_common() internally, to work around a
 * misfeature in the FreeBSD runtime linker, which links the old
 * version of a symbol to internal references.
 */
struct fuse_session *fuse_lowlevel_new_common(struct fuse_args *args,
					      const struct fuse_lowlevel_ops *op,
					      size_t op_size, void *userdata)
{
	struct fuse_ll *f;
	struct fuse_session *se;
	struct fuse_session_ops sop = {
		.process = fuse_ll_process,
		.destroy = fuse_ll_destroy,
	};

	if (sizeof(struct fuse_lowlevel_ops) < op_size) {
		fprintf(stderr, "fuse: warning: library too old, some operations may not work\n");
		op_size = sizeof(struct fuse_lowlevel_ops);
	}

	f = (struct fuse_ll *) calloc(1, sizeof(struct fuse_ll));
	if (f == NULL) {
		fprintf(stderr, "fuse: failed to allocate fuse object\n");
		goto out;
	}

	f->conn.async_read = 1;
	f->conn.max_write = UINT_MAX;
	f->conn.max_readahead = UINT_MAX;
	f->atomic_o_trunc = 0;
	list_init_req(&f->list);
	list_init_req(&f->interrupts);
	fuse_mutex_init(&f->lock);

	if (fuse_opt_parse(args, f, fuse_ll_opts, fuse_ll_opt_proc) == -1)
		goto out_free;

	if (f->debug)
		fprintf(stderr, "FUSE library version: %s\n", PACKAGE_VERSION);

	memcpy(&f->op, op, op_size);
	f->owner = getuid();
	f->userdata = userdata;

	se = fuse_session_new(&sop, f);
	if (!se)
		goto out_free;

	return se;

out_free:
	free(f);
out:
	return NULL;
}


struct fuse_session *fuse_lowlevel_new(struct fuse_args *args,
				       const struct fuse_lowlevel_ops *op,
				       size_t op_size, void *userdata)
{
	return fuse_lowlevel_new_common(args, op, op_size, userdata);
}

#ifdef linux
int fuse_req_getgroups(fuse_req_t req, int size, gid_t list[])
{
	char *buf;
	size_t bufsize = 1024;
	char path[128];
	int ret;
	int fd;
	unsigned long pid = req->ctx.pid;
	char *s;

	sprintf(path, "/proc/%lu/task/%lu/status", pid, pid);

retry:
	buf = malloc(bufsize);
	if (buf == NULL)
		return -ENOMEM;

	ret = -EIO;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		goto out_free;

	ret = read(fd, buf, bufsize);
	close(fd);
	if (ret == -1) {
		ret = -EIO;
		goto out_free;
	}

	if (ret == bufsize) {
		free(buf);
		bufsize *= 4;
		goto retry;
	}

	ret = -EIO;
	s = strstr(buf, "\nGroups:");
	if (s == NULL)
		goto out_free;

	s += 8;
	ret = 0;
	while (1) {
		char *end;
		unsigned long val = strtoul(s, &end, 0);
		if (end == s)
			break;

		s = end;
		if (ret < size)
			list[ret] = val;
		ret++;
	}

out_free:
	free(buf);
	return ret;
}
#else /* linux */
/*
 * This is currently not implemented on other than Linux...
 */
int fuse_req_getgroups(fuse_req_t req, int size, gid_t list[])
{
	return -ENOSYS;
}
#endif

#ifndef __FreeBSD__

static void fill_open_compat(struct fuse_open_out *arg,
			     const struct fuse_file_info_compat *f)
{
	arg->fh = f->fh;
	if (f->direct_io)
		arg->open_flags |= FOPEN_DIRECT_IO;
	if (f->keep_cache)
		arg->open_flags |= FOPEN_KEEP_CACHE;
}

static void convert_statfs_compat(const struct statfs *compatbuf,
				  struct statvfs *buf)
{
	buf->f_bsize	= compatbuf->f_bsize;
	buf->f_blocks	= compatbuf->f_blocks;
	buf->f_bfree	= compatbuf->f_bfree;
	buf->f_bavail	= compatbuf->f_bavail;
	buf->f_files	= compatbuf->f_files;
	buf->f_ffree	= compatbuf->f_ffree;
	buf->f_namemax	= compatbuf->f_namelen;
}

int fuse_reply_open_compat(fuse_req_t req,
			   const struct fuse_file_info_compat *f)
{
	struct fuse_open_out arg;

	memset(&arg, 0, sizeof(arg));
	fill_open_compat(&arg, f);
	return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_statfs_compat(fuse_req_t req, const struct statfs *stbuf)
{
	struct statvfs newbuf;

	memset(&newbuf, 0, sizeof(newbuf));
	convert_statfs_compat(stbuf, &newbuf);

	return fuse_reply_statfs(req, &newbuf);
}

struct fuse_session *fuse_lowlevel_new_compat(const char *opts,
				const struct fuse_lowlevel_ops_compat *op,
				size_t op_size, void *userdata)
{
	struct fuse_session *se;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

	if (opts &&
	    (fuse_opt_add_arg(&args, "") == -1 ||
	     fuse_opt_add_arg(&args, "-o") == -1 ||
	     fuse_opt_add_arg(&args, opts) == -1)) {
		fuse_opt_free_args(&args);
		return NULL;
	}
	se = fuse_lowlevel_new(&args, (const struct fuse_lowlevel_ops *) op,
			       op_size, userdata);
	fuse_opt_free_args(&args);

	return se;
}

struct fuse_ll_compat_conf {
	unsigned max_read;
	int set_max_read;
};

static const struct fuse_opt fuse_ll_opts_compat[] = {
	{ "max_read=", offsetof(struct fuse_ll_compat_conf, set_max_read), 1 },
	{ "max_read=%u", offsetof(struct fuse_ll_compat_conf, max_read), 0 },
	FUSE_OPT_KEY("max_read=", FUSE_OPT_KEY_KEEP),
	FUSE_OPT_END
};

int fuse_sync_compat_args(struct fuse_args *args)
{
	struct fuse_ll_compat_conf conf;

	memset(&conf, 0, sizeof(conf));
	if (fuse_opt_parse(args, &conf, fuse_ll_opts_compat, NULL) == -1)
		return -1;

	if (fuse_opt_insert_arg(args, 1, "-osync_read"))
		return -1;

	if (conf.set_max_read) {
		char tmpbuf[64];

		sprintf(tmpbuf, "-omax_readahead=%u", conf.max_read);
		if (fuse_opt_insert_arg(args, 1, tmpbuf) == -1)
			return -1;
	}
	return 0;
}

FUSE_SYMVER(".symver fuse_reply_statfs_compat,fuse_reply_statfs@FUSE_2.4");
FUSE_SYMVER(".symver fuse_reply_open_compat,fuse_reply_open@FUSE_2.4");
FUSE_SYMVER(".symver fuse_lowlevel_new_compat,fuse_lowlevel_new@FUSE_2.4");

#else /* __FreeBSD__ */

int fuse_sync_compat_args(struct fuse_args *args)
{
	(void) args;
	return 0;
}

#endif /* __FreeBSD__ */

struct fuse_session *fuse_lowlevel_new_compat25(struct fuse_args *args,
				const struct fuse_lowlevel_ops_compat25 *op,
				size_t op_size, void *userdata)
{
	if (fuse_sync_compat_args(args) == -1)
		return NULL;

	return fuse_lowlevel_new_common(args,
					(const struct fuse_lowlevel_ops *) op,
					op_size, userdata);
}

FUSE_SYMVER(".symver fuse_lowlevel_new_compat25,fuse_lowlevel_new@FUSE_2.5");
