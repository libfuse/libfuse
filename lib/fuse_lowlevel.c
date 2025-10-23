/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Implementation of (most of) the low-level FUSE API. The session loop
  functions are implemented in separate files.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt
*/

#define _GNU_SOURCE

#include "fuse_config.h"
#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_opt.h"
#include "fuse_misc.h"
#include "mount_util.h"
#include "util.h"
#include "fuse_uring_i.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdalign.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <stdalign.h>

#ifdef USDT_ENABLED
#include "usdt.h"
#endif

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE       1024
#endif
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#endif

#define PARAM(inarg) (((char *)(inarg)) + sizeof(*(inarg)))
#define OFFSET_MAX 0x7fffffffffffffffLL

struct fuse_pollhandle {
	uint64_t kh;
	struct fuse_session *se;
};

static size_t pagesize;

static __attribute__((constructor)) void fuse_ll_init_pagesize(void)
{
	pagesize = getpagesize();
}

#ifdef USDT_ENABLED
/* tracepoints */
static void trace_request_receive(int err)
{
	USDT(libfuse, request_receive, err);
}

static void trace_request_process(unsigned int opcode, unsigned int unique)
{
	USDT(libfuse, request_process, opcode, unique);
}

static void trace_request_reply(uint64_t unique, unsigned int len,
				int error, int reply_err)
{
	USDT(libfuse, request_reply, unique, len, error, reply_err);
}
#else
static void trace_request_receive(int err)
{
	(void)err;
}

static void trace_request_process(unsigned int opcode, unsigned int unique)
{
	(void)opcode;
	(void)unique;
}

static void trace_request_reply(uint64_t unique, unsigned int len,
				int error, int reply_err)
{
	(void)unique;
	(void)len;
	(void)error;
	(void)reply_err;
}
#endif

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
	stbuf->st_ctime        = attr->ctime;
	ST_ATIM_NSEC_SET(stbuf, attr->atimensec);
	ST_MTIM_NSEC_SET(stbuf, attr->mtimensec);
	ST_CTIM_NSEC_SET(stbuf, attr->ctimensec);
}

static	size_t iov_length(const struct iovec *iov, size_t count)
{
	size_t seg;
	size_t ret = 0;

	for (seg = 0; seg < count; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

void list_init_req(struct fuse_req *req)
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
	if (req->flags.is_uring) {
		fuse_log(FUSE_LOG_ERR, "Refusing to destruct uring req\n");
		return;
	}
	assert(req->ch == NULL);
	pthread_mutex_destroy(&req->lock);
	free(req);
}

void fuse_free_req(fuse_req_t req)
{
	int ctr;
	struct fuse_session *se = req->se;

	/* XXX: for now no support for interrupts with io-uring
	 *      It actually might work already, though. But then would add
	 *      a lock across ring queues.
	 */
	if (se->conn.no_interrupt || req->flags.is_uring) {
		ctr = --req->ref_cnt;
		fuse_chan_put(req->ch);
		req->ch = NULL;
	} else {
		pthread_mutex_lock(&se->lock);
		req->u.ni.func = NULL;
		req->u.ni.data = NULL;
		list_del_req(req);
		ctr = --req->ref_cnt;
		fuse_chan_put(req->ch);
		req->ch = NULL;
		pthread_mutex_unlock(&se->lock);
	}
	if (!ctr)
		destroy_req(req);
}

static struct fuse_req *fuse_ll_alloc_req(struct fuse_session *se)
{
	struct fuse_req *req;

	req = (struct fuse_req *) calloc(1, sizeof(struct fuse_req));
	if (req == NULL) {
		fuse_log(FUSE_LOG_ERR, "fuse: failed to allocate request\n");
	} else {
		req->se = se;
		req->ref_cnt = 1;
		list_init_req(req);
		pthread_mutex_init(&req->lock, NULL);
	}

	return req;
}

/*
 * Send data to fuse-kernel using an fd of the fuse device.
 */
static int fuse_write_msg_dev(struct fuse_session *se, struct fuse_chan *ch,
			     struct iovec *iov, int count)
{
	ssize_t res;
	int err;

	if (se->io != NULL)

		/* se->io->writev is never NULL if se->io is not NULL as
		 * specified by fuse_session_custom_io()
		 */
		res = se->io->writev(ch ? ch->fd : se->fd, iov, count,
				     se->userdata);
	else
		res = writev(ch ? ch->fd : se->fd, iov, count);

	if (res == -1) {
		/* ENOENT means the operation was interrupted */
		err = errno;
		if (!fuse_session_exited(se) && err != ENOENT)
			perror("fuse: writing device");
		return -err;
	}

	return 0;
}

static int fuse_send_msg(struct fuse_session *se, struct fuse_chan *ch,
			 struct iovec *iov, int count, fuse_req_t req)
{
	struct fuse_out_header *out = iov[0].iov_base;
	int err;
	bool is_uring = req && req->flags.is_uring ? true : false;

	if (!is_uring)
		assert(se != NULL);
	out->len = iov_length(iov, count);

	if (se->debug) {
		if (out->unique == 0) {
			fuse_log(FUSE_LOG_DEBUG, "NOTIFY: code=%d length=%u\n",
				out->error, out->len);
		} else if (out->error) {
			fuse_log(FUSE_LOG_DEBUG,
				"   unique: %llu, error: %i (%s), outsize: %i\n",
				(unsigned long long) out->unique, out->error,
				strerror(-out->error), out->len);
		} else {
			fuse_log(FUSE_LOG_DEBUG,
				"   unique: %llu, success, outsize: %i\n",
				(unsigned long long) out->unique, out->len);
		}
	}

	if (is_uring)
		err = fuse_send_msg_uring(req, iov, count);
	else
		err = fuse_write_msg_dev(se, ch, iov, count);

	trace_request_reply(out->unique, out->len, out->error, err);
	return err;
}

int fuse_send_reply_iov_nofree(fuse_req_t req, int error, struct iovec *iov,
			       int count)
{
	struct fuse_out_header out;

#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 32
	const char *str = strerrordesc_np(error * -1);
	if ((str == NULL && error != 0) || error > 0) {
#else
	if (error <= -1000 || error > 0) {
#endif
		fuse_log(FUSE_LOG_ERR, "fuse: bad error value: %i\n",	error);
		error = -ERANGE;
	}

	out.unique = req->unique;
	out.error = error;

	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct fuse_out_header);

	return fuse_send_msg(req->se, req->ch, iov, count, req);
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
	if (req->flags.is_uring)
		return send_reply_uring(req, error, arg, argsize);

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
		return fuse_reply_err(req, ENOMEM);

	memcpy(padded_iov + 1, iov, count * sizeof(struct iovec));
	count++;

	res = send_reply_iov(req, 0, padded_iov, count);
	free(padded_iov);

	return res;
}


/* `buf` is allowed to be empty so that the proper size may be
   allocated by the caller */
size_t fuse_add_direntry(fuse_req_t req, char *buf, size_t bufsize,
			 const char *name, const struct stat *stbuf, off_t off)
{
	(void)req;
	size_t namelen;
	size_t entlen;
	size_t entlen_padded;
	struct fuse_dirent *dirent;

	namelen = strlen(name);
	entlen = FUSE_NAME_OFFSET + namelen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);

	if ((buf == NULL) || (entlen_padded > bufsize))
	  return entlen_padded;

	dirent = (struct fuse_dirent*) buf;
	dirent->ino = stbuf->st_ino;
	dirent->off = off;
	dirent->namelen = namelen;
	dirent->type = (stbuf->st_mode & S_IFMT) >> 12;
	memcpy(dirent->name, name, namelen);
	memset(dirent->name + namelen, 0, entlen_padded - entlen);

	return entlen_padded;
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

/* `buf` is allowed to be empty so that the proper size may be
   allocated by the caller */
size_t fuse_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize,
			      const char *name,
			      const struct fuse_entry_param *e, off_t off)
{
	(void)req;
	size_t namelen;
	size_t entlen;
	size_t entlen_padded;

	namelen = strlen(name);
	entlen = FUSE_NAME_OFFSET_DIRENTPLUS + namelen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if ((buf == NULL) || (entlen_padded > bufsize))
	  return entlen_padded;

	struct fuse_direntplus *dp = (struct fuse_direntplus *) buf;
	memset(&dp->entry_out, 0, sizeof(dp->entry_out));
	fill_entry(&dp->entry_out, e);

	struct fuse_dirent *dirent = &dp->dirent;
	dirent->ino = e->attr.st_ino;
	dirent->off = off;
	dirent->namelen = namelen;
	dirent->type = (e->attr.st_mode & S_IFMT) >> 12;
	memcpy(dirent->name, name, namelen);
	memset(dirent->name + namelen, 0, entlen_padded - entlen);

	return entlen_padded;
}

static void fill_open(struct fuse_open_out *arg,
		      const struct fuse_file_info *f)
{
	arg->fh = f->fh;
	if (f->backing_id > 0) {
		arg->backing_id = f->backing_id;
		arg->open_flags |= FOPEN_PASSTHROUGH;
	}
	if (f->direct_io)
		arg->open_flags |= FOPEN_DIRECT_IO;
	if (f->keep_cache)
		arg->open_flags |= FOPEN_KEEP_CACHE;
	if (f->cache_readdir)
		arg->open_flags |= FOPEN_CACHE_DIR;
	if (f->nonseekable)
		arg->open_flags |= FOPEN_NONSEEKABLE;
	if (f->noflush)
		arg->open_flags |= FOPEN_NOFLUSH;
	if (f->parallel_direct_writes)
		arg->open_flags |= FOPEN_PARALLEL_DIRECT_WRITES;
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e)
{
	struct fuse_entry_out arg;
	size_t size = req->se->conn.proto_minor < 9 ?
		FUSE_COMPAT_ENTRY_OUT_SIZE : sizeof(arg);

	/* before ABI 7.4 e->ino == 0 was invalid, only ENOENT meant
	   negative entry */
	if (!e->ino && req->se->conn.proto_minor < 4)
		return fuse_reply_err(req, ENOENT);

	memset(&arg, 0, sizeof(arg));
	fill_entry(&arg, e);
	return send_reply_ok(req, &arg, size);
}

int fuse_reply_create(fuse_req_t req, const struct fuse_entry_param *e,
		      const struct fuse_file_info *f)
{
	alignas(uint64_t) char buf[sizeof(struct fuse_entry_out) + sizeof(struct fuse_open_out)];
	size_t entrysize = req->se->conn.proto_minor < 9 ?
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
	size_t size = req->se->conn.proto_minor < 9 ?
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

int fuse_passthrough_open(fuse_req_t req, int fd)
{
	struct fuse_backing_map map = { .fd = fd };
	int ret;

	ret = ioctl(req->se->fd, FUSE_DEV_IOC_BACKING_OPEN, &map);
	if (ret <= 0) {
		fuse_log(FUSE_LOG_ERR, "fuse: passthrough_open: %s\n", strerror(errno));
		return 0;
	}

	return ret;
}

int fuse_passthrough_close(fuse_req_t req, int backing_id)
{
	int ret;

	ret = ioctl(req->se->fd, FUSE_DEV_IOC_BACKING_CLOSE, &backing_id);
	if (ret < 0)
		fuse_log(FUSE_LOG_ERR, "fuse: passthrough_close: %s\n", strerror(errno));

	return ret;
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *f)
{
	struct fuse_open_out arg;

	memset(&arg, 0, sizeof(arg));
	fill_open(&arg, f);
	return send_reply_ok(req, &arg, sizeof(arg));
}

static int do_fuse_reply_write(fuse_req_t req, size_t count)
{
	struct fuse_write_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.size = count;

	return send_reply_ok(req, &arg, sizeof(arg));
}

static int do_fuse_reply_copy(fuse_req_t req, size_t count)
{
	struct fuse_copy_file_range_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.bytes_copied = count;

	return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
	/*
	 * This function is also used by FUSE_COPY_FILE_RANGE and its 64-bit
	 * variant.
	 */
	if (req->flags.is_copy_file_range_64)
		return do_fuse_reply_copy(req, count);
	else
		return do_fuse_reply_write(req, count);
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
	return send_reply_ok(req, buf, size);
}

static int fuse_send_data_iov_fallback(struct fuse_session *se,
				       struct fuse_chan *ch,
				       struct iovec *iov, int iov_count,
				       struct fuse_bufvec *buf,
				       size_t len, fuse_req_t req)
{
	struct fuse_bufvec mem_buf = FUSE_BUFVEC_INIT(len);
	void *mbuf;
	int res;

	/* Optimize common case */
	if (buf->count == 1 && buf->idx == 0 && buf->off == 0 &&
	    !(buf->buf[0].flags & FUSE_BUF_IS_FD)) {
		/* FIXME: also avoid memory copy if there are multiple buffers
		   but none of them contain an fd */

		iov[iov_count].iov_base = buf->buf[0].mem;
		iov[iov_count].iov_len = len;
		iov_count++;
		return fuse_send_msg(se, ch, iov, iov_count, req);
	}

	res = posix_memalign(&mbuf, pagesize, len);
	if (res != 0)
		return res;

	mem_buf.buf[0].mem = mbuf;
	res = fuse_buf_copy(&mem_buf, buf, 0);
	if (res < 0) {
		free(mbuf);
		return -res;
	}
	len = res;

	iov[iov_count].iov_base = mbuf;
	iov[iov_count].iov_len = len;
	iov_count++;
	res = fuse_send_msg(se, ch, iov, iov_count, req);
	free(mbuf);

	return res;
}

struct fuse_ll_pipe {
	size_t size;
	int can_grow;
	int pipe[2];
};

static void fuse_ll_pipe_free(struct fuse_ll_pipe *llp)
{
	close(llp->pipe[0]);
	close(llp->pipe[1]);
	free(llp);
}

#ifdef HAVE_SPLICE
#if !defined(HAVE_PIPE2) || !defined(O_CLOEXEC)
static int fuse_pipe(int fds[2])
{
	int rv = pipe(fds);

	if (rv == -1)
		return rv;

	if (fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1 ||
	    fcntl(fds[1], F_SETFL, O_NONBLOCK) == -1 ||
	    fcntl(fds[0], F_SETFD, FD_CLOEXEC) == -1 ||
	    fcntl(fds[1], F_SETFD, FD_CLOEXEC) == -1) {
		close(fds[0]);
		close(fds[1]);
		rv = -1;
	}
	return rv;
}
#else
static int fuse_pipe(int fds[2])
{
	return pipe2(fds, O_CLOEXEC | O_NONBLOCK);
}
#endif

static struct fuse_ll_pipe *fuse_ll_get_pipe(struct fuse_session *se)
{
	struct fuse_ll_pipe *llp = pthread_getspecific(se->pipe_key);
	if (llp == NULL) {
		int res;

		llp = malloc(sizeof(struct fuse_ll_pipe));
		if (llp == NULL)
			return NULL;

		res = fuse_pipe(llp->pipe);
		if (res == -1) {
			free(llp);
			return NULL;
		}

		/*
		 *the default size is 16 pages on linux
		 */
		llp->size = pagesize * 16;
		llp->can_grow = 1;

		pthread_setspecific(se->pipe_key, llp);
	}

	return llp;
}
#endif

static void fuse_ll_clear_pipe(struct fuse_session *se)
{
	struct fuse_ll_pipe *llp = pthread_getspecific(se->pipe_key);
	if (llp) {
		pthread_setspecific(se->pipe_key, NULL);
		fuse_ll_pipe_free(llp);
	}
}

#if defined(HAVE_SPLICE) && defined(HAVE_VMSPLICE)
static int read_back(int fd, char *buf, size_t len)
{
	int res;

	res = read(fd, buf, len);
	if (res == -1) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: internal error: failed to read back from pipe: %s\n",
			 strerror(errno));
		return -EIO;
	}
	if (res != len) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: internal error: short read back from pipe: %i from %zd\n",
			 res, len);
		return -EIO;
	}
	return 0;
}

static int grow_pipe_to_max(int pipefd)
{
	int res;
	long max;
	long maxfd;
	char buf[32];

	maxfd = open("/proc/sys/fs/pipe-max-size", O_RDONLY);
	if (maxfd < 0)
		return -errno;

	res = read(maxfd, buf, sizeof(buf) - 1);
	if (res < 0) {
		int saved_errno;

		saved_errno = errno;
		close(maxfd);
		return -saved_errno;
	}
	close(maxfd);
	buf[res] = '\0';

	res = libfuse_strtol(buf, &max);
	if (res)
		return res;
	res = fcntl(pipefd, F_SETPIPE_SZ, max);
	if (res < 0)
		return -errno;
	return max;
}

static int fuse_send_data_iov(struct fuse_session *se, struct fuse_chan *ch,
			      struct iovec *iov, int iov_count,
			      struct fuse_bufvec *buf, unsigned int flags,
			      fuse_req_t req)
{
	int res;
	size_t len = fuse_buf_size(buf);
	struct fuse_out_header *out = iov[0].iov_base;
	struct fuse_ll_pipe *llp;
	int splice_flags;
	size_t pipesize;
	size_t total_buf_size;
	size_t idx;
	size_t headerlen;
	struct fuse_bufvec pipe_buf = FUSE_BUFVEC_INIT(len);

	if (se->broken_splice_nonblock)
		goto fallback;

	if (flags & FUSE_BUF_NO_SPLICE)
		goto fallback;

	total_buf_size = 0;
	for (idx = buf->idx; idx < buf->count; idx++) {
		total_buf_size += buf->buf[idx].size;
		if (idx == buf->idx)
			total_buf_size -= buf->off;
	}
	if (total_buf_size < 2 * pagesize)
		goto fallback;

	if (se->conn.proto_minor < 14 ||
	    !(se->conn.want_ext & FUSE_CAP_SPLICE_WRITE))
		goto fallback;

	llp = fuse_ll_get_pipe(se);
	if (llp == NULL)
		goto fallback;


	headerlen = iov_length(iov, iov_count);

	out->len = headerlen + len;

	/*
	 * Heuristic for the required pipe size, does not work if the
	 * source contains less than page size fragments
	 */
	pipesize = pagesize * (iov_count + buf->count + 1) + out->len;

	if (llp->size < pipesize) {
		if (llp->can_grow) {
			res = fcntl(llp->pipe[0], F_SETPIPE_SZ, pipesize);
			if (res == -1) {
				res = grow_pipe_to_max(llp->pipe[0]);
				if (res > 0)
					llp->size = res;
				llp->can_grow = 0;
				goto fallback;
			}
			llp->size = res;
		}
		if (llp->size < pipesize)
			goto fallback;
	}


	res = vmsplice(llp->pipe[1], iov, iov_count, SPLICE_F_NONBLOCK);
	if (res == -1)
		goto fallback;

	if (res != headerlen) {
		res = -EIO;
		fuse_log(FUSE_LOG_ERR, "fuse: short vmsplice to pipe: %u/%zu\n", res,
			headerlen);
		goto clear_pipe;
	}

	pipe_buf.buf[0].flags = FUSE_BUF_IS_FD;
	pipe_buf.buf[0].fd = llp->pipe[1];

	res = fuse_buf_copy(&pipe_buf, buf,
			    FUSE_BUF_FORCE_SPLICE | FUSE_BUF_SPLICE_NONBLOCK);
	if (res < 0) {
		if (res == -EAGAIN || res == -EINVAL) {
			/*
			 * Should only get EAGAIN on kernels with
			 * broken SPLICE_F_NONBLOCK support (<=
			 * 2.6.35) where this error or a short read is
			 * returned even if the pipe itself is not
			 * full
			 *
			 * EINVAL might mean that splice can't handle
			 * this combination of input and output.
			 */
			if (res == -EAGAIN)
				se->broken_splice_nonblock = 1;

			pthread_setspecific(se->pipe_key, NULL);
			fuse_ll_pipe_free(llp);
			goto fallback;
		}
		res = -res;
		goto clear_pipe;
	}

	if (res != 0 && res < len) {
		struct fuse_bufvec mem_buf = FUSE_BUFVEC_INIT(len);
		void *mbuf;
		size_t now_len = res;
		/*
		 * For regular files a short count is either
		 *  1) due to EOF, or
		 *  2) because of broken SPLICE_F_NONBLOCK (see above)
		 *
		 * For other inputs it's possible that we overflowed
		 * the pipe because of small buffer fragments.
		 */

		res = posix_memalign(&mbuf, pagesize, len);
		if (res != 0)
			goto clear_pipe;

		mem_buf.buf[0].mem = mbuf;
		mem_buf.off = now_len;
		res = fuse_buf_copy(&mem_buf, buf, 0);
		if (res > 0) {
			char *tmpbuf;
			size_t extra_len = res;
			/*
			 * Trickiest case: got more data.  Need to get
			 * back the data from the pipe and then fall
			 * back to regular write.
			 */
			tmpbuf = malloc(headerlen);
			if (tmpbuf == NULL) {
				free(mbuf);
				res = ENOMEM;
				goto clear_pipe;
			}
			res = read_back(llp->pipe[0], tmpbuf, headerlen);
			free(tmpbuf);
			if (res != 0) {
				free(mbuf);
				goto clear_pipe;
			}
			res = read_back(llp->pipe[0], mbuf, now_len);
			if (res != 0) {
				free(mbuf);
				goto clear_pipe;
			}
			len = now_len + extra_len;
			iov[iov_count].iov_base = mbuf;
			iov[iov_count].iov_len = len;
			iov_count++;
			res = fuse_send_msg(se, ch, iov, iov_count, req);
			free(mbuf);
			return res;
		}
		free(mbuf);
		res = now_len;
	}
	len = res;
	out->len = headerlen + len;

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG,
			"   unique: %llu, success, outsize: %i (splice)\n",
			(unsigned long long) out->unique, out->len);
	}

	splice_flags = 0;
	if ((flags & FUSE_BUF_SPLICE_MOVE) &&
	    (se->conn.want_ext & FUSE_CAP_SPLICE_MOVE))
		splice_flags |= SPLICE_F_MOVE;

	if (se->io != NULL && se->io->splice_send != NULL) {
		res = se->io->splice_send(llp->pipe[0], NULL,
						  ch ? ch->fd : se->fd, NULL, out->len,
					  	  splice_flags, se->userdata);
	} else {
		res = splice(llp->pipe[0], NULL, ch ? ch->fd : se->fd, NULL,
			       out->len, splice_flags);
	}
	if (res == -1) {
		res = -errno;
		perror("fuse: splice from pipe");
		goto clear_pipe;
	}
	if (res != out->len) {
		res = -EIO;
		fuse_log(FUSE_LOG_ERR, "fuse: short splice from pipe: %u/%u\n",
			res, out->len);
		goto clear_pipe;
	}
	return 0;

clear_pipe:
	fuse_ll_clear_pipe(se);
	return res;

fallback:
	return fuse_send_data_iov_fallback(se, ch, iov, iov_count, buf, len, req);
}
#else
static int fuse_send_data_iov(struct fuse_session *se, struct fuse_chan *ch,
			       struct iovec *iov, int iov_count,
			       struct fuse_bufvec *req_data, unsigned int flags,
			       fuse_req_t req)
{
	size_t len = fuse_buf_size(req_data);
	(void) flags;

	return fuse_send_data_iov_fallback(se, ch, iov, iov_count, req_data, len, req);
}
#endif

int fuse_reply_data(fuse_req_t req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags)
{
	struct iovec iov[2];
	struct fuse_out_header out;
	int res;

	if (req->flags.is_uring)
		return fuse_reply_data_uring(req, bufv, flags);

	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct fuse_out_header);

	out.unique = req->unique;
	out.error = 0;

	res = fuse_send_data_iov(req->se, req->ch, iov, 1, bufv, flags, req);
	if (res <= 0) {
		fuse_free_req(req);
		return res;
	} else {
		return fuse_reply_err(req, res);
	}
}

int fuse_reply_statfs(fuse_req_t req, const struct statvfs *stbuf)
{
	struct fuse_statfs_out arg;
	size_t size = req->se->conn.proto_minor < 4 ?
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

int fuse_reply_lock(fuse_req_t req, const struct flock *lock)
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

static struct fuse_ioctl_iovec *fuse_ioctl_iovec_copy(const struct iovec *iov,
						      size_t count)
{
	struct fuse_ioctl_iovec *fiov;
	size_t i;

	fiov = malloc(sizeof(fiov[0]) * count);
	if (!fiov)
		return NULL;

	for (i = 0; i < count; i++) {
		fiov[i].base = (uintptr_t) iov[i].iov_base;
		fiov[i].len = iov[i].iov_len;
	}

	return fiov;
}

int fuse_reply_ioctl_retry(fuse_req_t req,
			   const struct iovec *in_iov, size_t in_count,
			   const struct iovec *out_iov, size_t out_count)
{
	struct fuse_ioctl_out arg;
	struct fuse_ioctl_iovec *in_fiov = NULL;
	struct fuse_ioctl_iovec *out_fiov = NULL;
	struct iovec iov[4];
	size_t count = 1;
	int res;

	memset(&arg, 0, sizeof(arg));
	arg.flags |= FUSE_IOCTL_RETRY;
	arg.in_iovs = in_count;
	arg.out_iovs = out_count;
	iov[count].iov_base = &arg;
	iov[count].iov_len = sizeof(arg);
	count++;

	if (req->se->conn.proto_minor < 16) {
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
	} else {
		/* Can't handle non-compat 64bit ioctls on 32bit */
		if (sizeof(void *) == 4 && req->flags.ioctl_64bit) {
			res = fuse_reply_err(req, EINVAL);
			goto out;
		}

		if (in_count) {
			in_fiov = fuse_ioctl_iovec_copy(in_iov, in_count);
			if (!in_fiov)
				goto enomem;

			iov[count].iov_base = (void *)in_fiov;
			iov[count].iov_len = sizeof(in_fiov[0]) * in_count;
			count++;
		}
		if (out_count) {
			out_fiov = fuse_ioctl_iovec_copy(out_iov, out_count);
			if (!out_fiov)
				goto enomem;

			iov[count].iov_base = (void *)out_fiov;
			iov[count].iov_len = sizeof(out_fiov[0]) * out_count;
			count++;
		}
	}

	res = send_reply_iov(req, 0, iov, count);
out:
	free(in_fiov);
	free(out_fiov);

	return res;

enomem:
	res = fuse_reply_err(req, ENOMEM);
	goto out;
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
		return fuse_reply_err(req, ENOMEM);

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

int fuse_reply_lseek(fuse_req_t req, off_t off)
{
	struct fuse_lseek_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.offset = off;

	return send_reply_ok(req, &arg, sizeof(arg));
}

#ifdef HAVE_STATX
int fuse_reply_statx(fuse_req_t req, int flags, struct statx *statx,
		     double attr_timeout)
{
	struct fuse_statx_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.flags = flags;
	arg.attr_valid = calc_timeout_sec(attr_timeout);
	arg.attr_valid_nsec = calc_timeout_nsec(attr_timeout);
	memcpy(&arg.stat, statx, sizeof(arg.stat));

	return send_reply_ok(req, &arg, sizeof(arg));
}
#else
int fuse_reply_statx(fuse_req_t req, int flags, struct statx *statx,
		     double attr_timeout)
{
	(void)req;
	(void)flags;
	(void)statx;
	(void)attr_timeout;

	return -ENOSYS;
}
#endif

static void _do_lookup(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	(void)op_in;

	char *name = (char *)in_payload;

	if (req->se->op.lookup)
		req->se->op.lookup(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_lookup(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *inarg)
{
	_do_lookup(req, nodeid, NULL, inarg);
}

static void _do_forget(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	(void)in_payload;

	struct fuse_forget_in *arg = (struct fuse_forget_in *)op_in;

	if (req->se->op.forget)
		req->se->op.forget(req, nodeid, arg->nlookup);
	else
		fuse_reply_none(req);
}

static void do_forget(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *inarg)
{
	_do_forget(req, nodeid, inarg, NULL);
}

static void _do_batch_forget(fuse_req_t req, const fuse_ino_t nodeid,
			     const void *op_in, const void *in_payload)
{
	(void)nodeid;
	unsigned int i;

	const struct fuse_batch_forget_in *arg = op_in;
	const struct fuse_forget_one *forgets = in_payload;

	if (req->se->op.forget_multi) {
		req->se->op.forget_multi(req, arg->count,
					 (struct fuse_forget_data *)in_payload);
	} else if (req->se->op.forget) {
		for (i = 0; i < arg->count; i++) {
			const struct fuse_forget_one *forget = &forgets[i];
			struct fuse_req *dummy_req;

			dummy_req = fuse_ll_alloc_req(req->se);
			if (dummy_req == NULL)
				break;

			dummy_req->unique = req->unique;
			dummy_req->ctx = req->ctx;
			dummy_req->ch = NULL;

			req->se->op.forget(dummy_req, forget->nodeid,
					  forget->nlookup);
		}
		fuse_reply_none(req);
	} else {
		fuse_reply_none(req);
	}
}

static void do_batch_forget(fuse_req_t req, const fuse_ino_t nodeid,
			    const void *inarg)
{
	struct fuse_batch_forget_in *arg = (void *)inarg;
	struct fuse_forget_one *param = (void *)PARAM(arg);

	_do_batch_forget(req, nodeid, inarg, param);
}

static void _do_getattr(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	struct fuse_getattr_in *arg = (struct fuse_getattr_in *)op_in;
	(void)in_payload;

	struct fuse_file_info *fip = NULL;
	struct fuse_file_info fi;

	if (req->se->conn.proto_minor >= 9) {
		if (arg->getattr_flags & FUSE_GETATTR_FH) {
			memset(&fi, 0, sizeof(fi));
			fi.fh = arg->fh;
			fip = &fi;
		}
	}

	if (req->se->op.getattr)
		req->se->op.getattr(req, nodeid, fip);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_getattr(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *inarg)
{
	_do_getattr(req, nodeid, inarg, NULL);
}

static void _do_setattr(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_setattr_in *arg = op_in;
	uint32_t valid = arg->valid;

	if (req->se->op.setattr) {
		struct fuse_file_info *fi = NULL;
		struct fuse_file_info fi_store;
		struct stat stbuf;
		memset(&stbuf, 0, sizeof(stbuf));
		convert_attr(arg, &stbuf);
		if (arg->valid & FATTR_FH) {
			valid &= ~FATTR_FH;
			memset(&fi_store, 0, sizeof(fi_store));
			fi = &fi_store;
			fi->fh = arg->fh;
		}
		valid &= FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID |
			 FUSE_SET_ATTR_GID | FUSE_SET_ATTR_SIZE |
			 FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME |
			 FUSE_SET_ATTR_KILL_SUID | FUSE_SET_ATTR_KILL_SGID |
			 FUSE_SET_ATTR_ATIME_NOW | FUSE_SET_ATTR_MTIME_NOW |
			 FUSE_SET_ATTR_CTIME;

		req->se->op.setattr(req, nodeid, &stbuf, valid, fi);
	} else
		fuse_reply_err(req, ENOSYS);
}

static void do_setattr(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *inarg)
{
	_do_setattr(req, nodeid, inarg, NULL);
}

static void _do_access(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_access_in *arg = op_in;

	if (req->se->op.access)
		req->se->op.access(req, nodeid, arg->mask);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_access(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *inarg)
{
	_do_access(req, nodeid, inarg, NULL);
}

static void _do_readlink(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *op_in, const void *in_payload)
{
	(void)op_in;
	(void)in_payload;

	if (req->se->op.readlink)
		req->se->op.readlink(req, nodeid);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_readlink(fuse_req_t req, const fuse_ino_t nodeid,
			const void *inarg)
{
	_do_readlink(req, nodeid, inarg, NULL);
}

static void _do_mknod(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	const struct fuse_mknod_in *arg = (struct fuse_mknod_in *)op_in;
	const char *name = in_payload;

	if (req->se->conn.proto_minor >= 12)
		req->ctx.umask = arg->umask;

	if (req->se->op.mknod)
		req->se->op.mknod(req, nodeid, name, arg->mode, arg->rdev);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_mknod(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_mknod_in *arg = (struct fuse_mknod_in *)inarg;
	char *name = PARAM(arg);

	if (req->se->conn.proto_minor < 12)
		name = (char *)inarg + FUSE_COMPAT_MKNOD_IN_SIZE;

	_do_mknod(req, nodeid, inarg, name);
}

static void _do_mkdir(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	const char *name = in_payload;
	const struct fuse_mkdir_in *arg = op_in;

	if (req->se->conn.proto_minor >= 12)
		req->ctx.umask = arg->umask;

	if (req->se->op.mkdir)
		req->se->op.mkdir(req, nodeid, name, arg->mode);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_mkdir(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	const struct fuse_mkdir_in *arg = inarg;
	const char *name = PARAM(arg);

	_do_mkdir(req, nodeid, inarg, name);
}

static void _do_unlink(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	(void)op_in;
	const char *name = in_payload;

	if (req->se->op.unlink)
		req->se->op.unlink(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_unlink(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *inarg)
{
	_do_unlink(req, nodeid, NULL, inarg);
}

static void _do_rmdir(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)op_in;
	const char *name = in_payload;

	if (req->se->op.rmdir)
		req->se->op.rmdir(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_rmdir(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_rmdir(req, nodeid, NULL, inarg);
}

static void _do_symlink(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	(void)op_in;
	const char *name = (char *)in_payload;
	const char *linkname = name + strlen(name) + 1;

	if (req->se->op.symlink)
		req->se->op.symlink(req, linkname, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_symlink(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *inarg)
{
	_do_symlink(req, nodeid, NULL, inarg);
}

static void _do_rename(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	const struct fuse_rename_in *arg = (struct fuse_rename_in *)op_in;
	const char *oldname = in_payload;
	const char *newname = oldname + strlen(oldname) + 1;

	if (req->se->op.rename)
		req->se->op.rename(req, nodeid, oldname, arg->newdir, newname,
				   0);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_rename(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *inarg)
{
	const struct fuse_rename_in *arg = inarg;
	const void *payload = PARAM(arg);

	_do_rename(req, nodeid, arg, payload);
}

static void _do_rename2(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	const struct fuse_rename2_in *arg = op_in;
	const char *oldname = in_payload;
	const char *newname = oldname + strlen(oldname) + 1;

	if (req->se->op.rename)
		req->se->op.rename(req, nodeid, oldname, arg->newdir, newname,
				   arg->flags);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_rename2(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *inarg)
{
	const struct fuse_rename2_in *arg = inarg;
	const void *payload = PARAM(arg);

	_do_rename2(req, nodeid, arg, payload);
}

static void _do_tmpfile(fuse_req_t req, fuse_ino_t nodeid, const void *op_in,
			const void *in_payload)
{
	(void)in_payload;
	const struct fuse_create_in *arg = op_in;

	if (req->se->op.tmpfile) {
		struct fuse_file_info fi;

		memset(&fi, 0, sizeof(fi));
		fi.flags = arg->flags;

		if (req->se->conn.proto_minor >= 12)
			req->ctx.umask = arg->umask;

		req->se->op.tmpfile(req, nodeid, arg->mode, &fi);
	} else
		fuse_reply_err(req, ENOSYS);
}

static void do_tmpfile(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_create_in *arg = (struct fuse_create_in *) inarg;

	_do_tmpfile(req, nodeid, arg, NULL);
}

static void _do_link(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
		     const void *in_payload)
{
	struct fuse_link_in *arg = (struct fuse_link_in *)op_in;

	if (req->se->op.link)
		req->se->op.link(req, arg->oldnodeid, nodeid, in_payload);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_link(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	const struct fuse_link_in *arg = inarg;
	const void *name = PARAM(arg);

	_do_link(req, nodeid, inarg, name);
}

static void _do_create(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	const struct fuse_create_in *arg = op_in;
	const char *name = in_payload;

	if (req->se->op.create) {
		struct fuse_file_info fi;

		memset(&fi, 0, sizeof(fi));
		fi.flags = arg->flags;

		if (req->se->conn.proto_minor >= 12)
			req->ctx.umask = arg->umask;

		/* XXX: fuse_create_in::open_flags */

		req->se->op.create(req, nodeid, name, arg->mode, &fi);
	} else {
		fuse_reply_err(req, ENOSYS);
	}
}

static void do_create(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *inarg)
{
	const struct fuse_create_in *arg = (struct fuse_create_in *)inarg;
	void *payload = PARAM(arg);

	if (req->se->conn.proto_minor < 12)
		payload = (char *)inarg + sizeof(struct fuse_open_in);

	_do_create(req, nodeid, arg, payload);
}

static void _do_open(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
		     const void *in_payload)
{
	(void)in_payload;
	struct fuse_open_in *arg = (struct fuse_open_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;

	/* XXX: fuse_open_in::open_flags */

	if (req->se->op.open)
		req->se->op.open(req, nodeid, &fi);
	else if (req->se->conn.want_ext & FUSE_CAP_NO_OPEN_SUPPORT)
		fuse_reply_err(req, ENOSYS);
	else
		fuse_reply_open(req, &fi);
}

static void do_open(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_open(req, nodeid, inarg, NULL);
}

static void _do_read(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
		     const void *in_payload)
{
	(void)in_payload;
	struct fuse_read_in *arg = (struct fuse_read_in *)op_in;

	if (req->se->op.read) {
		struct fuse_file_info fi;

		memset(&fi, 0, sizeof(fi));
		fi.fh = arg->fh;
		if (req->se->conn.proto_minor >= 9) {
			fi.lock_owner = arg->lock_owner;
			fi.flags = arg->flags;
		}
		req->se->op.read(req, nodeid, arg->size, arg->offset, &fi);
	} else
		fuse_reply_err(req, ENOSYS);
}

static void do_read(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_read(req, nodeid, inarg, NULL);
}

static void _do_write(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	struct fuse_write_in *arg = (struct fuse_write_in *)op_in;
	const char *buf = in_payload;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.writepage = (arg->write_flags & FUSE_WRITE_CACHE) != 0;

	if (req->se->conn.proto_minor >= 9) {
		fi.lock_owner = arg->lock_owner;
		fi.flags = arg->flags;
	}

	if (req->se->op.write)
		req->se->op.write(req, nodeid, buf, arg->size, arg->offset,
				  &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_write(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_write_in *arg = (struct fuse_write_in *)inarg;
	const void *payload;

	if (req->se->conn.proto_minor < 9)
		payload = ((char *)arg) + FUSE_COMPAT_WRITE_IN_SIZE;
	else
		payload = PARAM(arg);

	_do_write(req, nodeid, arg, payload);
}

static void _do_write_buf(fuse_req_t req, const fuse_ino_t nodeid,
			  const void *op_in, struct fuse_bufvec *bufv)
{
	struct fuse_session *se = req->se;
	struct fuse_write_in *arg = (struct fuse_write_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.writepage = arg->write_flags & FUSE_WRITE_CACHE;

	if (se->conn.proto_minor >= 9) {
		fi.lock_owner = arg->lock_owner;
		fi.flags = arg->flags;
	}

	se->op.write_buf(req, nodeid, bufv, arg->offset, &fi);
}

static void do_write_buf(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *inarg, const struct fuse_buf *ibuf)
{
	struct fuse_session *se = req->se;
	struct fuse_bufvec bufv = {
		.buf[0] = *ibuf,
		.count = 1,
	};
	struct fuse_write_in *arg = (struct fuse_write_in *)inarg;

	if (se->conn.proto_minor < 9) {
		bufv.buf[0].mem = ((char *)arg) + FUSE_COMPAT_WRITE_IN_SIZE;
		bufv.buf[0].size -= sizeof(struct fuse_in_header) +
				    FUSE_COMPAT_WRITE_IN_SIZE;
		assert(!(bufv.buf[0].flags & FUSE_BUF_IS_FD));
	} else {
		if (!(bufv.buf[0].flags & FUSE_BUF_IS_FD))
			bufv.buf[0].mem = PARAM(arg);

		bufv.buf[0].size -= sizeof(struct fuse_in_header) +
				    sizeof(struct fuse_write_in);
	}
	if (bufv.buf[0].size < arg->size) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: %s: buffer size too small\n", __func__);
		fuse_reply_err(req, EIO);
		goto out;
	}
	bufv.buf[0].size = arg->size;

	_do_write_buf(req, nodeid, inarg, &bufv);

out:
	/* Need to reset the pipe if ->write_buf() didn't consume all data */
	if ((ibuf->flags & FUSE_BUF_IS_FD) && bufv.idx < bufv.count)
		fuse_ll_clear_pipe(se);
}

static void _do_flush(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)in_payload;
	struct fuse_flush_in *arg = (struct fuse_flush_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.flush = 1;
	if (req->se->conn.proto_minor >= 7)
		fi.lock_owner = arg->lock_owner;

	if (req->se->op.flush)
		req->se->op.flush(req, nodeid, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_flush(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_flush(req, nodeid, inarg, NULL);
}

static void _do_release(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_release_in *arg = op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;
	if (req->se->conn.proto_minor >= 8) {
		fi.flush = (arg->release_flags & FUSE_RELEASE_FLUSH) ? 1 : 0;
		fi.lock_owner = arg->lock_owner;
	}
	if (arg->release_flags & FUSE_RELEASE_FLOCK_UNLOCK) {
		fi.flock_release = 1;
		fi.lock_owner = arg->lock_owner;
	}

	if (req->se->op.release)
		req->se->op.release(req, nodeid, &fi);
	else
		fuse_reply_err(req, 0);
}

static void do_release(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *inarg)
{
	_do_release(req, nodeid, inarg, NULL);
}

static void _do_fsync(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_fsync_in *arg = op_in;
	struct fuse_file_info fi;
	int datasync = arg->fsync_flags & 1;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (req->se->op.fsync)
		req->se->op.fsync(req, nodeid, datasync, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_fsync(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_fsync(req, nodeid, inarg, NULL);
}

static void _do_opendir(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_open_in *arg = op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	/* XXX: fuse_open_in::open_flags */

	if (req->se->op.opendir)
		req->se->op.opendir(req, nodeid, &fi);
	else if (req->se->conn.want_ext & FUSE_CAP_NO_OPENDIR_SUPPORT)
		fuse_reply_err(req, ENOSYS);
	else
		fuse_reply_open(req, &fi);
}

static void do_opendir(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *inarg)
{
	_do_opendir(req, nodeid, inarg, NULL);
}

static void _do_readdir(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	(void)in_payload;
	struct fuse_read_in *arg = (struct fuse_read_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (req->se->op.readdir)
		req->se->op.readdir(req, nodeid, arg->size, arg->offset, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_readdir(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *inarg)
{
	_do_readdir(req, nodeid, inarg, NULL);
}

static void _do_readdirplus(fuse_req_t req, const fuse_ino_t nodeid,
			    const void *op_in, const void *in_payload)
{
	(void)in_payload;
	struct fuse_read_in *arg = (struct fuse_read_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (req->se->op.readdirplus)
		req->se->op.readdirplus(req, nodeid, arg->size, arg->offset, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_readdirplus(fuse_req_t req, const fuse_ino_t nodeid,
			   const void *inarg)
{
	_do_readdirplus(req, nodeid, inarg, NULL);
}

static void _do_releasedir(fuse_req_t req, const fuse_ino_t nodeid,
			   const void *op_in, const void *in_payload)
{
	(void)in_payload;
	struct fuse_release_in *arg = (struct fuse_release_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;

	if (req->se->op.releasedir)
		req->se->op.releasedir(req, nodeid, &fi);
	else
		fuse_reply_err(req, 0);
}

static void do_releasedir(fuse_req_t req, const fuse_ino_t nodeid,
			  const void *inarg)
{
	_do_releasedir(req, nodeid, inarg, NULL);
}

static void _do_fsyncdir(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *op_in, const void *in_payload)
{
	(void)in_payload;
	struct fuse_fsync_in *arg = (struct fuse_fsync_in *)op_in;
	struct fuse_file_info fi;
	int datasync = arg->fsync_flags & 1;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (req->se->op.fsyncdir)
		req->se->op.fsyncdir(req, nodeid, datasync, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}
static void do_fsyncdir(fuse_req_t req, const fuse_ino_t nodeid,
			const void *inarg)
{
	_do_fsyncdir(req, nodeid, inarg, NULL);
}

static void _do_statfs(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	(void) nodeid;
	(void)op_in;
	(void)in_payload;

	if (req->se->op.statfs)
		req->se->op.statfs(req, nodeid);
	else {
		struct statvfs buf = {
			.f_namemax = 255,
			.f_bsize = 512,
		};
		fuse_reply_statfs(req, &buf);
	}
}
static void do_statfs(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *inarg)
{
	_do_statfs(req, nodeid, inarg, NULL);
}

static void _do_setxattr(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *op_in, const void *in_payload)
{
	struct fuse_setxattr_in *arg = (struct fuse_setxattr_in *)op_in;
	const char *name = in_payload;
	const char *value = name + strlen(name) + 1;

	/* XXX:The API should be extended to support extra_flags/setxattr_flags */

	if (req->se->op.setxattr)
		req->se->op.setxattr(req, nodeid, name, value, arg->size,
				     arg->flags);
	else
		fuse_reply_err(req, ENOSYS);
}
static void do_setxattr(fuse_req_t req, const fuse_ino_t nodeid,
			const void *inarg)
{
	struct fuse_session *se = req->se;
	unsigned int xattr_ext = !!(se->conn.want & FUSE_CAP_SETXATTR_EXT);
	const struct fuse_setxattr_in *arg = inarg;
	char *payload = xattr_ext ? PARAM(arg) :
				    (char *)arg + FUSE_COMPAT_SETXATTR_IN_SIZE;

	_do_setxattr(req, nodeid, arg, payload);
}

static void _do_getxattr(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *op_in, const void *in_payload)
{
	const struct fuse_getxattr_in *arg = op_in;

	if (req->se->op.getxattr)
		req->se->op.getxattr(req, nodeid, in_payload, arg->size);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_getxattr(fuse_req_t req, const fuse_ino_t nodeid,
			const void *inarg)
{
	const struct fuse_getxattr_in *arg = inarg;
	const void *payload = PARAM(arg);

	_do_getxattr(req, nodeid, arg, payload);
}

static void _do_listxattr(fuse_req_t req, const fuse_ino_t nodeid,
			  const void *inarg, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_getxattr_in *arg = inarg;

	if (req->se->op.listxattr)
		req->se->op.listxattr(req, nodeid, arg->size);
	else
		fuse_reply_err(req, ENOSYS);
}
static void do_listxattr(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *inarg)
{
	_do_listxattr(req, nodeid, inarg, NULL);
}

static void _do_removexattr(fuse_req_t req, const fuse_ino_t nodeid,
			    const void *inarg, const void *in_payload)
{
	(void)inarg;
	const char *name = in_payload;

	if (req->se->op.removexattr)
		req->se->op.removexattr(req, nodeid, name);
	else
		fuse_reply_err(req, ENOSYS);
}
static void do_removexattr(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_removexattr(req, nodeid, NULL, inarg);
}

static void convert_fuse_file_lock(const struct fuse_file_lock *fl,
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

static void _do_getlk(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_lk_in *arg = op_in;
	struct fuse_file_info fi;
	struct flock flock;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.lock_owner = arg->owner;

	convert_fuse_file_lock(&arg->lk, &flock);
	if (req->se->op.getlk)
		req->se->op.getlk(req, nodeid, &fi, &flock);
	else
		fuse_reply_err(req, ENOSYS);
}
static void do_getlk(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_getlk(req, nodeid, inarg, NULL);
}

static void do_setlk_common(fuse_req_t req, const fuse_ino_t nodeid,
			    const void *op_in, int sleep)
{
	const struct fuse_lk_in *arg = op_in;
	struct fuse_file_info fi;
	struct flock flock;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.lock_owner = arg->owner;

	if (arg->lk_flags & FUSE_LK_FLOCK) {
		int op = 0;

		switch (arg->lk.type) {
		case F_RDLCK:
			op = LOCK_SH;
			break;
		case F_WRLCK:
			op = LOCK_EX;
			break;
		case F_UNLCK:
			op = LOCK_UN;
			break;
		}
		if (!sleep)
			op |= LOCK_NB;

		if (req->se->op.flock)
			req->se->op.flock(req, nodeid, &fi, op);
		else
			fuse_reply_err(req, ENOSYS);
	} else {
		convert_fuse_file_lock(&arg->lk, &flock);
		if (req->se->op.setlk)
			req->se->op.setlk(req, nodeid, &fi, &flock, sleep);
		else
			fuse_reply_err(req, ENOSYS);
	}
}

static void _do_setlk(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)in_payload;
	do_setlk_common(req, nodeid, op_in, 0);
}

static void do_setlk(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_setlk(req, nodeid, inarg, NULL);
}

static void _do_setlkw(fuse_req_t req, const fuse_ino_t nodeid,
		       const void *op_in, const void *in_payload)
{
	(void)in_payload;
	do_setlk_common(req, nodeid, op_in, 1);
}
static void do_setlkw(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_setlkw(req, nodeid, inarg, NULL);
}

static int find_interrupted(struct fuse_session *se, struct fuse_req *req)
{
	struct fuse_req *curr;

	for (curr = se->list.next; curr != &se->list; curr = curr->next) {
		if (curr->unique == req->u.i.unique) {
			fuse_interrupt_func_t func;
			void *data;

			curr->ref_cnt++;
			pthread_mutex_unlock(&se->lock);

			/* Ugh, ugly locking */
			pthread_mutex_lock(&curr->lock);
			pthread_mutex_lock(&se->lock);
			curr->interrupted = 1;
			func = curr->u.ni.func;
			data = curr->u.ni.data;
			pthread_mutex_unlock(&se->lock);
			if (func)
				func(curr, data);
			pthread_mutex_unlock(&curr->lock);

			pthread_mutex_lock(&se->lock);
			curr->ref_cnt--;
			if (!curr->ref_cnt) {
				destroy_req(curr);
			}

			return 1;
		}
	}
	for (curr = se->interrupts.next; curr != &se->interrupts;
	     curr = curr->next) {
		if (curr->u.i.unique == req->u.i.unique)
			return 1;
	}
	return 0;
}

static void _do_interrupt(fuse_req_t req, const fuse_ino_t nodeid,
			  const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_interrupt_in *arg = op_in;
	struct fuse_session *se = req->se;

	(void) nodeid;
	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "INTERRUPT: %llu\n",
			(unsigned long long) arg->unique);

	req->u.i.unique = arg->unique;

	pthread_mutex_lock(&se->lock);
	if (find_interrupted(se, req)) {
		fuse_chan_put(req->ch);
		req->ch = NULL;
		destroy_req(req);
	} else
		list_add_req(req, &se->interrupts);
	pthread_mutex_unlock(&se->lock);
}
static void do_interrupt(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_interrupt(req, nodeid, inarg, NULL);
}

static struct fuse_req *check_interrupt(struct fuse_session *se,
					struct fuse_req *req)
{
	struct fuse_req *curr;

	for (curr = se->interrupts.next; curr != &se->interrupts;
	     curr = curr->next) {
		if (curr->u.i.unique == req->unique) {
			req->interrupted = 1;
			list_del_req(curr);
			fuse_chan_put(curr->ch);
			curr->ch = NULL;
			destroy_req(curr);
			return NULL;
		}
	}
	curr = se->interrupts.next;
	if (curr != &se->interrupts) {
		list_del_req(curr);
		list_init_req(curr);
		return curr;
	} else
		return NULL;
}

static void _do_bmap(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
		     const void *in_payload)
{
	(void)in_payload;
	const struct fuse_bmap_in *arg = op_in;

	if (req->se->op.bmap)
		req->se->op.bmap(req, nodeid, arg->blocksize, arg->block);
	else
		fuse_reply_err(req, ENOSYS);
}
static void do_bmap(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_bmap(req, nodeid, inarg, NULL);
}

static void _do_ioctl(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	struct fuse_ioctl_in *arg = (struct fuse_ioctl_in *)op_in;
	unsigned int flags = arg->flags;
	const void *in_buf = in_payload;
	struct fuse_file_info fi;

	if (flags & FUSE_IOCTL_DIR &&
	    !(req->se->conn.want_ext & FUSE_CAP_IOCTL_DIR)) {
		fuse_reply_err(req, ENOTTY);
		return;
	}

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (sizeof(void *) == 4 && req->se->conn.proto_minor >= 16 &&
	    !(flags & FUSE_IOCTL_32BIT)) {
		req->flags.ioctl_64bit = 1;
	}

	if (req->se->op.ioctl)
		req->se->op.ioctl(req, nodeid, arg->cmd,
				 (void *)(uintptr_t)arg->arg, &fi, flags,
				 in_buf, arg->in_size, arg->out_size);
	else
		fuse_reply_err(req, ENOSYS);
}
static void do_ioctl(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	const struct fuse_ioctl_in *arg = inarg;
	void *in_buf = arg->in_size ? PARAM(arg) : NULL;

	_do_ioctl(req, nodeid, arg, in_buf);
}

void fuse_pollhandle_destroy(struct fuse_pollhandle *ph)
{
	free(ph);
}

static void _do_poll(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
		     const void *in_payload)
{
	(void)in_payload;
	struct fuse_poll_in *arg = (struct fuse_poll_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.poll_events = arg->events;

	if (req->se->op.poll) {
		struct fuse_pollhandle *ph = NULL;

		if (arg->flags & FUSE_POLL_SCHEDULE_NOTIFY) {
			ph = malloc(sizeof(struct fuse_pollhandle));
			if (ph == NULL) {
				fuse_reply_err(req, ENOMEM);
				return;
			}
			ph->kh = arg->kh;
			ph->se = req->se;
		}

		req->se->op.poll(req, nodeid, &fi, ph);
	} else {
		fuse_reply_err(req, ENOSYS);
	}
}

static void do_poll(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_poll(req, nodeid, inarg, NULL);
}

static void _do_fallocate(fuse_req_t req, const fuse_ino_t nodeid,
			  const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_fallocate_in *arg = op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (req->se->op.fallocate)
		req->se->op.fallocate(req, nodeid, arg->mode, arg->offset,
				      arg->length, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_fallocate(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *inarg)
{
	_do_fallocate(req, nodeid, inarg, NULL);
}

static void copy_file_range_common(fuse_req_t req, const fuse_ino_t nodeid_in,
				   const struct fuse_copy_file_range_in *arg)
{
	struct fuse_file_info fi_in, fi_out;

	memset(&fi_in, 0, sizeof(fi_in));
	fi_in.fh = arg->fh_in;

	memset(&fi_out, 0, sizeof(fi_out));
	fi_out.fh = arg->fh_out;

	if (req->se->op.copy_file_range)
		req->se->op.copy_file_range(req, nodeid_in, arg->off_in, &fi_in,
					    arg->nodeid_out, arg->off_out,
					    &fi_out, arg->len, arg->flags);
	else
		fuse_reply_err(req, ENOSYS);
}

static void _do_copy_file_range(fuse_req_t req, const fuse_ino_t nodeid_in,
				const void *op_in, const void *in_payload)
{
	const struct fuse_copy_file_range_in *arg = op_in;
	struct fuse_copy_file_range_in arg_tmp;

	(void) in_payload;
	/* fuse_write_out can only handle 32bit copy size */
	if (arg->len > 0xfffff000) {
		arg_tmp = *arg;
		arg_tmp.len = 0xfffff000;
		arg = &arg_tmp;
	}
	copy_file_range_common(req, nodeid_in, arg);
}

static void do_copy_file_range(fuse_req_t req, const fuse_ino_t nodeid_in,
			       const void *inarg)
{
	_do_copy_file_range(req, nodeid_in, inarg, NULL);
}

static void _do_copy_file_range_64(fuse_req_t req, const fuse_ino_t nodeid_in,
				   const void *op_in, const void *in_payload)
{
	(void) in_payload;
	req->flags.is_copy_file_range_64 = 1;
	/* Limit size on 32bit userspace to avoid conversion overflow */
	if (sizeof(size_t) == 4)
		_do_copy_file_range(req, nodeid_in, op_in, NULL);
	else
		copy_file_range_common(req, nodeid_in, op_in);
}

static void do_copy_file_range_64(fuse_req_t req, const fuse_ino_t nodeid_in,
			       const void *inarg)
{
	_do_copy_file_range_64(req, nodeid_in, inarg, NULL);
}

/*
 * Note that the uint64_t offset in struct fuse_lseek_in is derived from
 * linux kernel loff_t and is therefore signed.
 */
static void _do_lseek(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_lseek_in *arg = op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (req->se->op.lseek)
		req->se->op.lseek(req, nodeid, arg->offset, arg->whence, &fi);
	else
		fuse_reply_err(req, ENOSYS);
}

static void do_lseek(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_lseek(req, nodeid, inarg, NULL);
}

#ifdef HAVE_STATX
static void _do_statx(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)in_payload;
	const struct fuse_statx_in *arg = op_in;
	struct fuse_file_info *fip = NULL;
	struct fuse_file_info fi;

	if (arg->getattr_flags & FUSE_GETATTR_FH) {
		memset(&fi, 0, sizeof(fi));
		fi.fh = arg->fh;
		fip = &fi;
	}

	if (req->se->op.statx)
		req->se->op.statx(req, nodeid, arg->sx_flags, arg->sx_mask, fip);
	else
		fuse_reply_err(req, ENOSYS);
}
#else
static void _do_statx(fuse_req_t req, const fuse_ino_t nodeid,
		      const void *op_in, const void *in_payload)
{
	(void)in_payload;
	(void)req;
	(void)nodeid;
	(void)op_in;
}
#endif

static void do_statx(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_statx(req, nodeid, inarg, NULL);
}

static bool want_flags_valid(uint64_t capable, uint64_t want)
{
	uint64_t unknown_flags = want & (~capable);
	if (unknown_flags != 0) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: unknown connection 'want' flags: 0x%08llx\n",
			(unsigned long long)unknown_flags);
		return false;
	}
	return true;
}

/**
 * Get the wanted capability flags, converting from old format if necessary
 */
int fuse_convert_to_conn_want_ext(struct fuse_conn_info *conn)
{
	struct fuse_session *se = container_of(conn, struct fuse_session, conn);

	/*
	 * Convert want to want_ext if necessary.
	 * For the high level interface this function might be called
	 * twice, once from the high level interface and once from the
	 * low level interface. Both, with different want_ext_default and
	 * want_default values. In order to suppress a failure for the
	 * second call, we check if the lower 32 bits of want_ext are
	 * already set to the value of want.
	 */
	if (conn->want != se->conn_want &&
	    fuse_lower_32_bits(conn->want_ext) != conn->want) {
		if (conn->want_ext != se->conn_want_ext) {
			fuse_log(FUSE_LOG_ERR,
				 "%s: Both conn->want_ext and conn->want are set.\n"
				 "want=%x want_ext=%llx, se->want=%x se->want_ext=%llx\n",
				 __func__, conn->want,
				 (unsigned long long)conn->want_ext,
				 se->conn_want,
				 (unsigned long long)se->conn_want_ext);
			return -EINVAL;
		}

		/* high bits from want_ext, low bits from want */
		conn->want_ext = fuse_higher_32_bits(conn->want_ext) |
				 conn->want;
	}

	/* ensure there won't be a second conversion */
	conn->want = fuse_lower_32_bits(conn->want_ext);

	return 0;
}

bool fuse_set_feature_flag(struct fuse_conn_info *conn,
					 uint64_t flag)
{
	struct fuse_session *se = container_of(conn, struct fuse_session, conn);

	if (conn->capable_ext & flag) {
		conn->want_ext |= flag;
		se->conn_want_ext |= flag;
		conn->want  |= flag;
		se->conn_want |= flag;
		return true;
	}
	return false;
}

void fuse_unset_feature_flag(struct fuse_conn_info *conn,
					 uint64_t flag)
{
	struct fuse_session *se = container_of(conn, struct fuse_session, conn);

	conn->want_ext &= ~flag;
	se->conn_want_ext &= ~flag;
	conn->want  &= ~flag;
	se->conn_want &= ~flag;
}

bool fuse_get_feature_flag(struct fuse_conn_info *conn,
					     uint64_t flag)
{
	return conn->capable_ext & flag ? true : false;
}

/* Prevent bogus data races (bogus since "init" is called before
 * multi-threading becomes relevant */
static __attribute__((no_sanitize("thread"))) void
_do_init(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
	 const void *in_payload)
{
	(void)in_payload;
	const struct fuse_init_in *arg = op_in;
	struct fuse_init_out outarg;
	struct fuse_session *se = req->se;
	size_t bufsize = se->bufsize;
	size_t outargsize = sizeof(outarg);
	uint64_t inargflags = 0;
	uint64_t outargflags = 0;
	bool buf_reallocable = se->buf_reallocable;
	(void) nodeid;
	bool enable_io_uring = false;

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "INIT: %u.%u\n", arg->major, arg->minor);
		if (arg->major == 7 && arg->minor >= 6) {
			fuse_log(FUSE_LOG_DEBUG, "flags=0x%08x\n", arg->flags);
			fuse_log(FUSE_LOG_DEBUG, "max_readahead=0x%08x\n",
				arg->max_readahead);
		}
	}
	se->conn.proto_major = arg->major;
	se->conn.proto_minor = arg->minor;
	se->conn.capable_ext = 0;
	se->conn.want_ext = 0;

	memset(&outarg, 0, sizeof(outarg));
	outarg.major = FUSE_KERNEL_VERSION;
	outarg.minor = FUSE_KERNEL_MINOR_VERSION;

	if (arg->major < 7) {
		fuse_log(FUSE_LOG_ERR, "fuse: unsupported protocol version: %u.%u\n",
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
		if (arg->max_readahead < se->conn.max_readahead)
			se->conn.max_readahead = arg->max_readahead;
		inargflags = arg->flags;
		if (inargflags & FUSE_INIT_EXT)
			inargflags = inargflags | (uint64_t) arg->flags2 << 32;
		if (inargflags & FUSE_ASYNC_READ)
			se->conn.capable_ext |= FUSE_CAP_ASYNC_READ;
		if (inargflags & FUSE_POSIX_LOCKS)
			se->conn.capable_ext |= FUSE_CAP_POSIX_LOCKS;
		if (inargflags & FUSE_ATOMIC_O_TRUNC)
			se->conn.capable_ext |= FUSE_CAP_ATOMIC_O_TRUNC;
		if (inargflags & FUSE_EXPORT_SUPPORT)
			se->conn.capable_ext |= FUSE_CAP_EXPORT_SUPPORT;
		if (inargflags & FUSE_DONT_MASK)
			se->conn.capable_ext |= FUSE_CAP_DONT_MASK;
		if (inargflags & FUSE_FLOCK_LOCKS)
			se->conn.capable_ext |= FUSE_CAP_FLOCK_LOCKS;
		if (inargflags & FUSE_AUTO_INVAL_DATA)
			se->conn.capable_ext |= FUSE_CAP_AUTO_INVAL_DATA;
		if (inargflags & FUSE_DO_READDIRPLUS)
			se->conn.capable_ext |= FUSE_CAP_READDIRPLUS;
		if (inargflags & FUSE_READDIRPLUS_AUTO)
			se->conn.capable_ext |= FUSE_CAP_READDIRPLUS_AUTO;
		if (inargflags & FUSE_ASYNC_DIO)
			se->conn.capable_ext |= FUSE_CAP_ASYNC_DIO;
		if (inargflags & FUSE_WRITEBACK_CACHE)
			se->conn.capable_ext |= FUSE_CAP_WRITEBACK_CACHE;
		if (inargflags & FUSE_NO_OPEN_SUPPORT)
			se->conn.capable_ext |= FUSE_CAP_NO_OPEN_SUPPORT;
		if (inargflags & FUSE_PARALLEL_DIROPS)
			se->conn.capable_ext |= FUSE_CAP_PARALLEL_DIROPS;
		if (inargflags & FUSE_POSIX_ACL)
			se->conn.capable_ext |= FUSE_CAP_POSIX_ACL;
		if (inargflags & FUSE_HANDLE_KILLPRIV)
			se->conn.capable_ext |= FUSE_CAP_HANDLE_KILLPRIV;
		if (inargflags & FUSE_HANDLE_KILLPRIV_V2)
			se->conn.capable_ext |= FUSE_CAP_HANDLE_KILLPRIV_V2;
		if (inargflags & FUSE_CACHE_SYMLINKS)
			se->conn.capable_ext |= FUSE_CAP_CACHE_SYMLINKS;
		if (inargflags & FUSE_NO_OPENDIR_SUPPORT)
			se->conn.capable_ext |= FUSE_CAP_NO_OPENDIR_SUPPORT;
		if (inargflags & FUSE_EXPLICIT_INVAL_DATA)
			se->conn.capable_ext |= FUSE_CAP_EXPLICIT_INVAL_DATA;
		if (inargflags & FUSE_SETXATTR_EXT)
			se->conn.capable_ext |= FUSE_CAP_SETXATTR_EXT;
		if (!(inargflags & FUSE_MAX_PAGES)) {
			size_t max_bufsize =
				FUSE_DEFAULT_MAX_PAGES_PER_REQ * getpagesize()
				+ FUSE_BUFFER_HEADER_SIZE;
			if (bufsize > max_bufsize) {
				bufsize = max_bufsize;
			}
			buf_reallocable = false;
		}
		if (inargflags & FUSE_DIRECT_IO_ALLOW_MMAP)
			se->conn.capable_ext |= FUSE_CAP_DIRECT_IO_ALLOW_MMAP;
		if (arg->minor >= 38 || (inargflags & FUSE_HAS_EXPIRE_ONLY))
			se->conn.capable_ext |= FUSE_CAP_EXPIRE_ONLY;
		if (inargflags & FUSE_PASSTHROUGH)
			se->conn.capable_ext |= FUSE_CAP_PASSTHROUGH;
		if (inargflags & FUSE_NO_EXPORT_SUPPORT)
			se->conn.capable_ext |= FUSE_CAP_NO_EXPORT_SUPPORT;
		if (inargflags & FUSE_OVER_IO_URING)
			se->conn.capable_ext |= FUSE_CAP_OVER_IO_URING;

	} else {
		se->conn.max_readahead = 0;
	}

	if (se->conn.proto_minor >= 14) {
#ifdef HAVE_SPLICE
#ifdef HAVE_VMSPLICE
		if ((se->io == NULL) || (se->io->splice_send != NULL)) {
			se->conn.capable_ext |= FUSE_CAP_SPLICE_WRITE |
						FUSE_CAP_SPLICE_MOVE;
		}
#endif
		if ((se->io == NULL) || (se->io->splice_receive != NULL)) {
			se->conn.capable_ext |= FUSE_CAP_SPLICE_READ;
		}
#endif
	}
	if (se->conn.proto_minor >= 18)
		se->conn.capable_ext |= FUSE_CAP_IOCTL_DIR;

	/* Default settings for modern filesystems.
	 *
	 * Most of these capabilities were disabled by default in
	 * libfuse2 for backwards compatibility reasons. In libfuse3,
	 * we can finally enable them by default (as long as they're
	 * supported by the kernel).
	 */
#define LL_SET_DEFAULT(cond, cap)                     \
	if ((cond)) \
		fuse_set_feature_flag(&se->conn, cap)

	LL_SET_DEFAULT(1, FUSE_CAP_ASYNC_READ);
	LL_SET_DEFAULT(1, FUSE_CAP_AUTO_INVAL_DATA);
	LL_SET_DEFAULT(1, FUSE_CAP_ASYNC_DIO);
	LL_SET_DEFAULT(1, FUSE_CAP_IOCTL_DIR);
	LL_SET_DEFAULT(1, FUSE_CAP_ATOMIC_O_TRUNC);
	LL_SET_DEFAULT(se->op.write_buf, FUSE_CAP_SPLICE_READ);
	LL_SET_DEFAULT(se->op.getlk && se->op.setlk,
		       FUSE_CAP_POSIX_LOCKS);
	LL_SET_DEFAULT(se->op.flock, FUSE_CAP_FLOCK_LOCKS);
	LL_SET_DEFAULT(se->op.readdirplus, FUSE_CAP_READDIRPLUS);
	LL_SET_DEFAULT(se->op.readdirplus && se->op.readdir,
		       FUSE_CAP_READDIRPLUS_AUTO);
	LL_SET_DEFAULT(1, FUSE_CAP_OVER_IO_URING);

	/* This could safely become default, but libfuse needs an API extension
	 * to support it
	 * LL_SET_DEFAULT(1, FUSE_CAP_SETXATTR_EXT);
	 */

	se->conn.time_gran = 1;

	if (se->op.init) {
		// Apply the first 32 bits of capable_ext to capable
		se->conn.capable = fuse_lower_32_bits(se->conn.capable_ext);

		se->op.init(se->userdata, &se->conn);

		/*
		 * se->conn.want is 32-bit value and deprecated in favour of
		 * se->conn.want_ext
		 * Userspace might still use conn.want - we need to convert it
		 */
		fuse_convert_to_conn_want_ext(&se->conn);
	}

	if (!want_flags_valid(se->conn.capable_ext, se->conn.want_ext)) {
		fuse_reply_err(req, EPROTO);
		se->error = -EPROTO;
		fuse_session_exit(se);
		return;
	}

	unsigned max_read_mo = get_max_read(se->mo);
	if (se->conn.max_read != max_read_mo) {
		fuse_log(FUSE_LOG_ERR, "fuse: error: init() and fuse_session_new() "
			"requested different maximum read size (%u vs %u)\n",
			se->conn.max_read, max_read_mo);
		fuse_reply_err(req, EPROTO);
		se->error = -EPROTO;
		fuse_session_exit(se);
		return;
	}

	if (bufsize < FUSE_MIN_READ_BUFFER) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: warning: buffer size too small: %zu\n",
			 bufsize);
		bufsize = FUSE_MIN_READ_BUFFER;
	}

	if (buf_reallocable)
	    bufsize = UINT_MAX;
	se->conn.max_write = MIN(se->conn.max_write, bufsize - FUSE_BUFFER_HEADER_SIZE);
	se->bufsize = se->conn.max_write + FUSE_BUFFER_HEADER_SIZE;

	if (arg->flags & FUSE_MAX_PAGES) {
		outarg.flags |= FUSE_MAX_PAGES;
		outarg.max_pages = (se->conn.max_write - 1) / getpagesize() + 1;
	}
	outargflags = outarg.flags;
	/* Always enable big writes, this is superseded
	   by the max_write option */
	outargflags |= FUSE_BIG_WRITES;

	if (se->conn.want_ext & FUSE_CAP_ASYNC_READ)
		outargflags |= FUSE_ASYNC_READ;
	if (se->conn.want_ext & FUSE_CAP_POSIX_LOCKS)
		outargflags |= FUSE_POSIX_LOCKS;
	if (se->conn.want_ext & FUSE_CAP_ATOMIC_O_TRUNC)
		outargflags |= FUSE_ATOMIC_O_TRUNC;
	if (se->conn.want_ext & FUSE_CAP_EXPORT_SUPPORT)
		outargflags |= FUSE_EXPORT_SUPPORT;
	if (se->conn.want_ext & FUSE_CAP_DONT_MASK)
		outargflags |= FUSE_DONT_MASK;
	if (se->conn.want_ext & FUSE_CAP_FLOCK_LOCKS)
		outargflags |= FUSE_FLOCK_LOCKS;
	if (se->conn.want_ext & FUSE_CAP_AUTO_INVAL_DATA)
		outargflags |= FUSE_AUTO_INVAL_DATA;
	if (se->conn.want_ext & FUSE_CAP_READDIRPLUS)
		outargflags |= FUSE_DO_READDIRPLUS;
	if (se->conn.want_ext & FUSE_CAP_READDIRPLUS_AUTO)
		outargflags |= FUSE_READDIRPLUS_AUTO;
	if (se->conn.want_ext & FUSE_CAP_ASYNC_DIO)
		outargflags |= FUSE_ASYNC_DIO;
	if (se->conn.want_ext & FUSE_CAP_WRITEBACK_CACHE)
		outargflags |= FUSE_WRITEBACK_CACHE;
	if (se->conn.want_ext & FUSE_CAP_PARALLEL_DIROPS)
		outargflags |= FUSE_PARALLEL_DIROPS;
	if (se->conn.want_ext & FUSE_CAP_POSIX_ACL)
		outargflags |= FUSE_POSIX_ACL;
	if (se->conn.want_ext & FUSE_CAP_HANDLE_KILLPRIV)
		outargflags |= FUSE_HANDLE_KILLPRIV;
	if (se->conn.want_ext & FUSE_CAP_HANDLE_KILLPRIV_V2)
		outargflags |= FUSE_HANDLE_KILLPRIV_V2;
	if (se->conn.want_ext & FUSE_CAP_CACHE_SYMLINKS)
		outargflags |= FUSE_CACHE_SYMLINKS;
	if (se->conn.want_ext & FUSE_CAP_EXPLICIT_INVAL_DATA)
		outargflags |= FUSE_EXPLICIT_INVAL_DATA;
	if (se->conn.want_ext & FUSE_CAP_SETXATTR_EXT)
		outargflags |= FUSE_SETXATTR_EXT;
	if (se->conn.want_ext & FUSE_CAP_DIRECT_IO_ALLOW_MMAP)
		outargflags |= FUSE_DIRECT_IO_ALLOW_MMAP;
	if (se->conn.want_ext & FUSE_CAP_PASSTHROUGH) {
		outargflags |= FUSE_PASSTHROUGH;
		/*
		 * outarg.max_stack_depth includes the fuse stack layer,
		 * so it is one more than max_backing_stack_depth.
		 */
		outarg.max_stack_depth = se->conn.max_backing_stack_depth + 1;
	}
	if (se->conn.want_ext & FUSE_CAP_NO_EXPORT_SUPPORT)
		outargflags |= FUSE_NO_EXPORT_SUPPORT;
	if (se->uring.enable && se->conn.want_ext & FUSE_CAP_OVER_IO_URING) {
		outargflags |= FUSE_OVER_IO_URING;
		enable_io_uring = true;
	}

	if ((inargflags & FUSE_REQUEST_TIMEOUT) && se->conn.request_timeout) {
		outargflags |= FUSE_REQUEST_TIMEOUT;
		outarg.request_timeout = se->conn.request_timeout;
	}

	outarg.max_readahead = se->conn.max_readahead;
	outarg.max_write = se->conn.max_write;
	if (se->conn.proto_minor >= 13) {
		if (se->conn.max_background >= (1 << 16))
			se->conn.max_background = (1 << 16) - 1;
		if (se->conn.congestion_threshold > se->conn.max_background)
			se->conn.congestion_threshold = se->conn.max_background;
		if (!se->conn.congestion_threshold) {
			se->conn.congestion_threshold =
				se->conn.max_background * 3 / 4;
		}

		outarg.max_background = se->conn.max_background;
		outarg.congestion_threshold = se->conn.congestion_threshold;
	}
	if (se->conn.proto_minor >= 23)
		outarg.time_gran = se->conn.time_gran;

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "   INIT: %u.%u\n", outarg.major, outarg.minor);
		fuse_log(FUSE_LOG_DEBUG, "   flags=0x%08x\n", outarg.flags);
		fuse_log(FUSE_LOG_DEBUG, "   max_readahead=0x%08x\n",
			outarg.max_readahead);
		fuse_log(FUSE_LOG_DEBUG, "   max_write=0x%08x\n", outarg.max_write);
		fuse_log(FUSE_LOG_DEBUG, "   max_background=%i\n",
			outarg.max_background);
		fuse_log(FUSE_LOG_DEBUG, "   congestion_threshold=%i\n",
			outarg.congestion_threshold);
		fuse_log(FUSE_LOG_DEBUG, "   time_gran=%u\n",
			outarg.time_gran);
		if (se->conn.want_ext & FUSE_CAP_PASSTHROUGH)
			fuse_log(FUSE_LOG_DEBUG, "   max_stack_depth=%u\n",
				outarg.max_stack_depth);
	}
	if (arg->minor < 5)
		outargsize = FUSE_COMPAT_INIT_OUT_SIZE;
	else if (arg->minor < 23)
		outargsize = FUSE_COMPAT_22_INIT_OUT_SIZE;

	/* XXX: Add an option to make non-available io-uring fatal */
	if (enable_io_uring) {
		int ring_rc = fuse_uring_start(se);

		if (ring_rc != 0) {
			fuse_log(FUSE_LOG_INFO,
				 "fuse: failed to start io-uring: %s\n",
				 strerror(ring_rc));
			outargflags &= ~FUSE_OVER_IO_URING;
			enable_io_uring = false;
		}
	}

	if (inargflags & FUSE_INIT_EXT) {
		outargflags |= FUSE_INIT_EXT;
		outarg.flags2 = outargflags >> 32;
	}
	outarg.flags = outargflags;

	/*
	 * Has to be set before replying, as new kernel requests might
	 * immediately arrive and got_init is used for op-code sanity.
	 * Especially with external handlers, where we have no control
	 * over the thread scheduling.
	 */
	se->got_init = 1;
	send_reply_ok(req, &outarg, outargsize);
	if (enable_io_uring)
		fuse_uring_wake_ring_threads(se);
}

static __attribute__((no_sanitize("thread"))) void
do_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_init(req, nodeid, inarg, NULL);
}

static void _do_destroy(fuse_req_t req, const fuse_ino_t nodeid,
			const void *op_in, const void *in_payload)
{
	struct fuse_session *se = req->se;
	char *mountpoint;

	(void) nodeid;
	(void)op_in;
	(void)in_payload;

	mountpoint = atomic_exchange(&se->mountpoint, NULL);
	free(mountpoint);

	se->got_destroy = 1;
	se->got_init = 0;
	if (se->op.destroy)
		se->op.destroy(se->userdata);

	send_reply_ok(req, NULL, 0);
}

static void do_destroy(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_destroy(req, nodeid, inarg, NULL);
}

static void list_del_nreq(struct fuse_notify_req *nreq)
{
	struct fuse_notify_req *prev = nreq->prev;
	struct fuse_notify_req *next = nreq->next;
	prev->next = next;
	next->prev = prev;
}

static void list_add_nreq(struct fuse_notify_req *nreq,
			  struct fuse_notify_req *next)
{
	struct fuse_notify_req *prev = next->prev;
	nreq->next = next;
	nreq->prev = prev;
	prev->next = nreq;
	next->prev = nreq;
}

static void list_init_nreq(struct fuse_notify_req *nreq)
{
	nreq->next = nreq;
	nreq->prev = nreq;
}

static void do_notify_reply(fuse_req_t req, fuse_ino_t nodeid,
			    const void *inarg, const struct fuse_buf *buf)
{
	struct fuse_session *se = req->se;
	struct fuse_notify_req *nreq;
	struct fuse_notify_req *head;

	pthread_mutex_lock(&se->lock);
	head = &se->notify_list;
	for (nreq = head->next; nreq != head; nreq = nreq->next) {
		if (nreq->unique == req->unique) {
			list_del_nreq(nreq);
			break;
		}
	}
	pthread_mutex_unlock(&se->lock);

	if (nreq != head)
		nreq->reply(nreq, req, nodeid, inarg, buf);
}

static int send_notify_iov(struct fuse_session *se, int notify_code,
			   struct iovec *iov, int count)
{
	struct fuse_out_header out;
	struct fuse_req *req = NULL;

	if (!se->got_init)
		return -ENOTCONN;

	out.unique = 0;
	out.error = notify_code;
	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct fuse_out_header);

	return fuse_send_msg(se, NULL, iov, count, req);
}

int fuse_lowlevel_notify_poll(struct fuse_pollhandle *ph)
{
	if (ph != NULL) {
		struct fuse_notify_poll_wakeup_out outarg;
		struct iovec iov[2];

		outarg.kh = ph->kh;

		iov[1].iov_base = &outarg;
		iov[1].iov_len = sizeof(outarg);

		return send_notify_iov(ph->se, FUSE_NOTIFY_POLL, iov, 2);
	} else {
		return 0;
	}
}

int fuse_lowlevel_notify_inval_inode(struct fuse_session *se, fuse_ino_t ino,
				     off_t off, off_t len)
{
	struct fuse_notify_inval_inode_out outarg;
	struct iovec iov[2];

	if (!se)
		return -EINVAL;

	if (se->conn.proto_minor < 12)
		return -ENOSYS;

	outarg.ino = ino;
	outarg.off = off;
	outarg.len = len;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);

	return send_notify_iov(se, FUSE_NOTIFY_INVAL_INODE, iov, 2);
}

int fuse_lowlevel_notify_increment_epoch(struct fuse_session *se)
{
	struct iovec iov[1];

	if (!se)
		return -EINVAL;

	if (se->conn.proto_minor < 44)
		return -ENOSYS;

	return send_notify_iov(se, FUSE_NOTIFY_INC_EPOCH, iov, 1);
}

/**
 * Notify parent attributes and the dentry matching parent/name
 *
 * Underlying base function for fuse_lowlevel_notify_inval_entry() and
 * fuse_lowlevel_notify_expire_entry().
 *
 * @warning
 * Only checks if fuse_lowlevel_notify_inval_entry() is supported by
 * the kernel. All other flags will fall back to
 * fuse_lowlevel_notify_inval_entry() if not supported!
 * DO THE PROPER CHECKS IN THE DERIVED FUNCTION!
 *
 * @param se the session object
 * @param parent inode number
 * @param name file name
 * @param namelen strlen() of file name
 * @param flags flags to control if the entry should be expired or invalidated
 * @return zero for success, -errno for failure
*/
static int fuse_lowlevel_notify_entry(struct fuse_session *se, fuse_ino_t parent,
							const char *name, size_t namelen,
							enum fuse_notify_entry_flags flags)
{
	struct fuse_notify_inval_entry_out outarg;
	struct iovec iov[3];

	if (!se)
		return -EINVAL;

	if (se->conn.proto_minor < 12)
		return -ENOSYS;

	outarg.parent = parent;
	outarg.namelen = namelen;
	outarg.flags = 0;
	if (flags & FUSE_LL_EXPIRE_ONLY)
		outarg.flags |= FUSE_EXPIRE_ONLY;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);
	iov[2].iov_base = (void *)name;
	iov[2].iov_len = namelen + 1;

	return send_notify_iov(se, FUSE_NOTIFY_INVAL_ENTRY, iov, 3);
}

int fuse_lowlevel_notify_inval_entry(struct fuse_session *se, fuse_ino_t parent,
						 const char *name, size_t namelen)
{
	return fuse_lowlevel_notify_entry(se, parent, name, namelen, FUSE_LL_INVALIDATE);
}

int fuse_lowlevel_notify_expire_entry(struct fuse_session *se, fuse_ino_t parent,
							const char *name, size_t namelen)
{
	if (!se)
		return -EINVAL;

	if (!(se->conn.capable_ext & FUSE_CAP_EXPIRE_ONLY))
		return -ENOSYS;

	return fuse_lowlevel_notify_entry(se, parent, name, namelen, FUSE_LL_EXPIRE_ONLY);
}


int fuse_lowlevel_notify_delete(struct fuse_session *se,
				fuse_ino_t parent, fuse_ino_t child,
				const char *name, size_t namelen)
{
	struct fuse_notify_delete_out outarg;
	struct iovec iov[3];

	if (!se)
		return -EINVAL;

	if (se->conn.proto_minor < 18)
		return -ENOSYS;

	outarg.parent = parent;
	outarg.child = child;
	outarg.namelen = namelen;
	outarg.padding = 0;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);
	iov[2].iov_base = (void *)name;
	iov[2].iov_len = namelen + 1;

	return send_notify_iov(se, FUSE_NOTIFY_DELETE, iov, 3);
}

int fuse_lowlevel_notify_store(struct fuse_session *se, fuse_ino_t ino,
			       off_t offset, struct fuse_bufvec *bufv,
			       enum fuse_buf_copy_flags flags)
{
	struct fuse_out_header out;
	struct fuse_notify_store_out outarg;
	struct iovec iov[3];
	size_t size = fuse_buf_size(bufv);
	int res;
	struct fuse_req *req = NULL;

	if (!se)
		return -EINVAL;

	if (se->conn.proto_minor < 15)
		return -ENOSYS;

	out.unique = 0;
	out.error = FUSE_NOTIFY_STORE;

	outarg.nodeid = ino;
	outarg.offset = offset;
	outarg.size = size;
	outarg.padding = 0;

	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(out);
	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);

	res = fuse_send_data_iov(se, NULL, iov, 2, bufv, flags, req);
	if (res > 0)
		res = -res;

	return res;
}

struct fuse_retrieve_req {
	struct fuse_notify_req nreq;
	void *cookie;
};

static void fuse_ll_retrieve_reply(struct fuse_notify_req *nreq,
				   fuse_req_t req, fuse_ino_t ino,
				   const void *inarg,
				   const struct fuse_buf *ibuf)
{
	struct fuse_session *se = req->se;
	struct fuse_retrieve_req *rreq =
		container_of(nreq, struct fuse_retrieve_req, nreq);
	const struct fuse_notify_retrieve_in *arg = inarg;
	struct fuse_bufvec bufv = {
		.buf[0] = *ibuf,
		.count = 1,
	};

	if (!(bufv.buf[0].flags & FUSE_BUF_IS_FD))
		bufv.buf[0].mem = PARAM(arg);

	bufv.buf[0].size -= sizeof(struct fuse_in_header) +
		sizeof(struct fuse_notify_retrieve_in);

	if (bufv.buf[0].size < arg->size) {
		fuse_log(FUSE_LOG_ERR, "fuse: retrieve reply: buffer size too small\n");
		fuse_reply_none(req);
		goto out;
	}
	bufv.buf[0].size = arg->size;

	if (se->op.retrieve_reply) {
		se->op.retrieve_reply(req, rreq->cookie, ino,
					  arg->offset, &bufv);
	} else {
		fuse_reply_none(req);
	}
out:
	free(rreq);
	if ((ibuf->flags & FUSE_BUF_IS_FD) && bufv.idx < bufv.count)
		fuse_ll_clear_pipe(se);
}

int fuse_lowlevel_notify_retrieve(struct fuse_session *se, fuse_ino_t ino,
				  size_t size, off_t offset, void *cookie)
{
	struct fuse_notify_retrieve_out outarg;
	struct iovec iov[2];
	struct fuse_retrieve_req *rreq;
	int err;

	if (!se)
		return -EINVAL;

	if (se->conn.proto_minor < 15)
		return -ENOSYS;

	rreq = malloc(sizeof(*rreq));
	if (rreq == NULL)
		return -ENOMEM;

	pthread_mutex_lock(&se->lock);
	rreq->cookie = cookie;
	rreq->nreq.unique = se->notify_ctr++;
	rreq->nreq.reply = fuse_ll_retrieve_reply;
	list_add_nreq(&rreq->nreq, &se->notify_list);
	pthread_mutex_unlock(&se->lock);

	outarg.notify_unique = rreq->nreq.unique;
	outarg.nodeid = ino;
	outarg.offset = offset;
	outarg.size = size;
	outarg.padding = 0;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);

	err = send_notify_iov(se, FUSE_NOTIFY_RETRIEVE, iov, 2);
	if (err) {
		pthread_mutex_lock(&se->lock);
		list_del_nreq(&rreq->nreq);
		pthread_mutex_unlock(&se->lock);
		free(rreq);
	}

	return err;
}

void *fuse_req_userdata(fuse_req_t req)
{
	return req->se->userdata;
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
	return &req->ctx;
}

void fuse_req_interrupt_func(fuse_req_t req, fuse_interrupt_func_t func,
			     void *data)
{
	pthread_mutex_lock(&req->lock);
	pthread_mutex_lock(&req->se->lock);
	req->u.ni.func = func;
	req->u.ni.data = data;
	pthread_mutex_unlock(&req->se->lock);
	if (req->interrupted && func)
		func(req, data);
	pthread_mutex_unlock(&req->lock);
}

int fuse_req_interrupted(fuse_req_t req)
{
	int interrupted;

	pthread_mutex_lock(&req->se->lock);
	interrupted = req->interrupted;
	pthread_mutex_unlock(&req->se->lock);

	return interrupted;
}

bool fuse_req_is_uring(fuse_req_t req)
{
	return req->flags.is_uring;
}

#ifndef HAVE_URING
int fuse_req_get_payload(fuse_req_t req, char **payload, size_t *payload_sz,
			 void **mr)
{
	(void)req;
	(void)payload;
	(void)payload_sz;
	(void)mr;
	return -ENOTSUP;
}
#endif

static struct {
	void (*func)(fuse_req_t req, const fuse_ino_t node, const void *arg);
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
	[FUSE_TMPFILE]	   = { do_tmpfile,     "TMPFILE"     },
	[FUSE_INTERRUPT]   = { do_interrupt,   "INTERRUPT"   },
	[FUSE_BMAP]	   = { do_bmap,	       "BMAP"	     },
	[FUSE_IOCTL]	   = { do_ioctl,       "IOCTL"	     },
	[FUSE_POLL]	   = { do_poll,        "POLL"	     },
	[FUSE_FALLOCATE]   = { do_fallocate,   "FALLOCATE"   },
	[FUSE_DESTROY]	   = { do_destroy,     "DESTROY"     },
	[FUSE_NOTIFY_REPLY] = { (void *) 1,    "NOTIFY_REPLY" },
	[FUSE_BATCH_FORGET] = { do_batch_forget, "BATCH_FORGET" },
	[FUSE_READDIRPLUS] = { do_readdirplus,	"READDIRPLUS"},
	[FUSE_RENAME2]     = { do_rename2,      "RENAME2"    },
	[FUSE_COPY_FILE_RANGE] = { do_copy_file_range, "COPY_FILE_RANGE" },
	[FUSE_COPY_FILE_RANGE_64] = { do_copy_file_range_64, "COPY_FILE_RANGE_64" },
	[FUSE_LSEEK]	   = { do_lseek,       "LSEEK"	     },
	[FUSE_STATX]	   = { do_statx,       "STATX"	     },
	[CUSE_INIT]	   = { cuse_lowlevel_init, "CUSE_INIT"   },
};

static struct {
	void (*func)(fuse_req_t req, const fuse_ino_t ino, const void *op_in,
		     const void *op_payload);
	const char *name;
} fuse_ll_ops2[] __attribute__((unused)) = {
	[FUSE_LOOKUP]		= { _do_lookup,		"LOOKUP" },
	[FUSE_FORGET]		= { _do_forget,		"FORGET" },
	[FUSE_GETATTR]		= { _do_getattr,	"GETATTR" },
	[FUSE_SETATTR]		= { _do_setattr,	"SETATTR" },
	[FUSE_READLINK]		= { _do_readlink,	"READLINK" },
	[FUSE_SYMLINK]		= { _do_symlink,	"SYMLINK" },
	[FUSE_MKNOD]		= { _do_mknod,		"MKNOD" },
	[FUSE_MKDIR]		= { _do_mkdir,		"MKDIR" },
	[FUSE_UNLINK]		= { _do_unlink,		"UNLINK" },
	[FUSE_RMDIR]		= { _do_rmdir,		"RMDIR" },
	[FUSE_RENAME]		= { _do_rename,		"RENAME" },
	[FUSE_LINK]		= { _do_link,		"LINK" },
	[FUSE_OPEN]		= { _do_open,		"OPEN" },
	[FUSE_READ]		= { _do_read,		"READ" },
	[FUSE_WRITE]		= { _do_write,		"WRITE" },
	[FUSE_STATFS]		= { _do_statfs,		"STATFS" },
	[FUSE_RELEASE]		= { _do_release,	"RELEASE" },
	[FUSE_FSYNC]		= { _do_fsync,		"FSYNC" },
	[FUSE_SETXATTR]		= { _do_setxattr,	"SETXATTR" },
	[FUSE_GETXATTR]		= { _do_getxattr,	"GETXATTR" },
	[FUSE_LISTXATTR]	= { _do_listxattr,	"LISTXATTR" },
	[FUSE_REMOVEXATTR]	= { _do_removexattr,	"REMOVEXATTR" },
	[FUSE_FLUSH]		= { _do_flush,		"FLUSH" },
	[FUSE_INIT]		= { _do_init,		"INIT" },
	[FUSE_OPENDIR]		= { _do_opendir,	"OPENDIR" },
	[FUSE_READDIR]		= { _do_readdir,	"READDIR" },
	[FUSE_RELEASEDIR]	= { _do_releasedir,	"RELEASEDIR" },
	[FUSE_FSYNCDIR]		= { _do_fsyncdir,	"FSYNCDIR" },
	[FUSE_GETLK]		= { _do_getlk,		"GETLK" },
	[FUSE_SETLK]		= { _do_setlk,		"SETLK" },
	[FUSE_SETLKW]		= { _do_setlkw,		"SETLKW" },
	[FUSE_ACCESS]		= { _do_access,		"ACCESS" },
	[FUSE_CREATE]		= { _do_create,		"CREATE" },
	[FUSE_TMPFILE]		= { _do_tmpfile,	"TMPFILE" },
	[FUSE_INTERRUPT]	= { _do_interrupt,	"INTERRUPT" },
	[FUSE_BMAP]		= { _do_bmap,		"BMAP" },
	[FUSE_IOCTL]		= { _do_ioctl,		"IOCTL" },
	[FUSE_POLL]		= { _do_poll,		"POLL" },
	[FUSE_FALLOCATE]	= { _do_fallocate,	"FALLOCATE" },
	[FUSE_DESTROY]		= { _do_destroy,	"DESTROY" },
	[FUSE_NOTIFY_REPLY]	= { (void *)1,		"NOTIFY_REPLY" },
	[FUSE_BATCH_FORGET]	= { _do_batch_forget,	"BATCH_FORGET" },
	[FUSE_READDIRPLUS]	= { _do_readdirplus,	"READDIRPLUS" },
	[FUSE_RENAME2]		= { _do_rename2,	"RENAME2" },
	[FUSE_COPY_FILE_RANGE]	= { _do_copy_file_range, "COPY_FILE_RANGE" },
	[FUSE_COPY_FILE_RANGE_64]	= { _do_copy_file_range_64, "COPY_FILE_RANGE_64" },
	[FUSE_LSEEK]		= { _do_lseek,		"LSEEK" },
	[FUSE_STATX]		= { _do_statx,		"STATX" },
	[CUSE_INIT]		= { _cuse_lowlevel_init, "CUSE_INIT" },
};

/*
 * For ABI compatibility we cannot allow higher values than CUSE_INIT.
 * Without ABI compatibility we could use the size of the array.
 * #define FUSE_MAXOP (sizeof(fuse_ll_ops) / sizeof(fuse_ll_ops[0]))
 */
#define FUSE_MAXOP (CUSE_INIT + 1)


/**
 *
 * @return 0 if sanity is ok, error otherwise
 */
static inline int
fuse_req_opcode_sanity_ok(struct fuse_session *se, enum fuse_opcode in_op)
{
	int err = EIO;

	if (!se->got_init) {
		enum fuse_opcode expected;

		expected = se->cuse_data ? CUSE_INIT : FUSE_INIT;
		if (in_op != expected)
			return err;
	} else if (in_op == FUSE_INIT || in_op == CUSE_INIT)
		return err;

	return 0;
}

static inline void
fuse_session_in2req(struct fuse_req *req, struct fuse_in_header *in)
{
	req->unique = in->unique;
	req->ctx.uid = in->uid;
	req->ctx.gid = in->gid;
	req->ctx.pid = in->pid;
}

/**
 * Implement -o allow_root
 */
static inline int
fuse_req_check_allow_root(struct fuse_session *se, enum fuse_opcode in_op,
			  uid_t in_uid)
{
	int err = EACCES;

	if (se->deny_others && in_uid != se->owner && in_uid != 0 &&
		 in_op != FUSE_INIT && in_op != FUSE_READ &&
		 in_op != FUSE_WRITE && in_op != FUSE_FSYNC &&
		 in_op != FUSE_RELEASE && in_op != FUSE_READDIR &&
		 in_op != FUSE_FSYNCDIR && in_op != FUSE_RELEASEDIR &&
		 in_op != FUSE_NOTIFY_REPLY &&
		 in_op != FUSE_READDIRPLUS)
		return err;

	return 0;
}

static const char *opname(enum fuse_opcode opcode)
{
	if (opcode >= FUSE_MAXOP || !fuse_ll_ops[opcode].name)
		return "???";
	else
		return fuse_ll_ops[opcode].name;
}

static int fuse_ll_copy_from_pipe(struct fuse_bufvec *dst,
				  struct fuse_bufvec *src)
{
	ssize_t res = fuse_buf_copy(dst, src, 0);
	if (res < 0) {
		fuse_log(FUSE_LOG_ERR, "fuse: copy from pipe: %s\n", strerror(-res));
		return res;
	}
	if ((size_t)res < fuse_buf_size(dst)) {
		fuse_log(FUSE_LOG_ERR, "fuse: copy from pipe: short read\n");
		return -1;
	}
	return 0;
}

void fuse_session_process_buf(struct fuse_session *se,
			      const struct fuse_buf *buf)
{
	fuse_session_process_buf_internal(se, buf, NULL);
}

/* libfuse internal handler */
void fuse_session_process_buf_internal(struct fuse_session *se,
				  const struct fuse_buf *buf, struct fuse_chan *ch)
{
	const size_t write_header_size = sizeof(struct fuse_in_header) +
		sizeof(struct fuse_write_in);
	struct fuse_bufvec bufv = { .buf[0] = *buf, .count = 1 };
	struct fuse_bufvec tmpbuf = FUSE_BUFVEC_INIT(write_header_size);
	struct fuse_in_header *in;
	const void *inarg;
	struct fuse_req *req;
	void *mbuf = NULL;
	int err;
	int res;

	if (buf->flags & FUSE_BUF_IS_FD) {
		if (buf->size < tmpbuf.buf[0].size)
			tmpbuf.buf[0].size = buf->size;

		mbuf = malloc(tmpbuf.buf[0].size);
		if (mbuf == NULL) {
			fuse_log(FUSE_LOG_ERR, "fuse: failed to allocate header\n");
			goto clear_pipe;
		}
		tmpbuf.buf[0].mem = mbuf;

		res = fuse_ll_copy_from_pipe(&tmpbuf, &bufv);
		if (res < 0)
			goto clear_pipe;

		in = mbuf;
	} else {
		in = buf->mem;
	}

	trace_request_process(in->opcode, in->unique);

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG,
			"dev unique: %llu, opcode: %s (%i), nodeid: %llu, insize: %zu, pid: %u\n",
			(unsigned long long) in->unique,
			opname((enum fuse_opcode) in->opcode), in->opcode,
			(unsigned long long) in->nodeid, buf->size, in->pid);
	}

	req = fuse_ll_alloc_req(se);
	if (req == NULL) {
		struct fuse_out_header out = {
			.unique = in->unique,
			.error = -ENOMEM,
		};
		struct iovec iov = {
			.iov_base = &out,
			.iov_len = sizeof(struct fuse_out_header),
		};

		fuse_send_msg(se, ch, &iov, 1, NULL);
		goto clear_pipe;
	}

	fuse_session_in2req(req, in);
	req->ch = ch ? fuse_chan_get(ch) : NULL;

	err = fuse_req_opcode_sanity_ok(se, in->opcode);
	if (err)
		goto reply_err;

	err = fuse_req_check_allow_root(se, in->opcode, in->uid);
	if (err)
		goto reply_err;

	err = ENOSYS;
	if (in->opcode >= FUSE_MAXOP || !fuse_ll_ops[in->opcode].func)
		goto reply_err;
	/* Do not process interrupt request */
	if (se->conn.no_interrupt && in->opcode == FUSE_INTERRUPT) {
		if (se->debug)
			fuse_log(FUSE_LOG_DEBUG, "FUSE_INTERRUPT: reply to kernel to disable interrupt\n");
		goto reply_err;
	}
	if (!se->conn.no_interrupt && in->opcode != FUSE_INTERRUPT) {
		struct fuse_req *intr;
		pthread_mutex_lock(&se->lock);
		intr = check_interrupt(se, req);
		list_add_req(req, &se->list);
		pthread_mutex_unlock(&se->lock);
		if (intr)
			fuse_reply_err(intr, EAGAIN);
	}

	if ((buf->flags & FUSE_BUF_IS_FD) && write_header_size < buf->size &&
	    (in->opcode != FUSE_WRITE || !se->op.write_buf) &&
	    in->opcode != FUSE_NOTIFY_REPLY) {
		void *newmbuf;

		err = ENOMEM;
		newmbuf = realloc(mbuf, buf->size);
		if (newmbuf == NULL)
			goto reply_err;
		mbuf = newmbuf;

		tmpbuf = FUSE_BUFVEC_INIT(buf->size - write_header_size);
		tmpbuf.buf[0].mem = (char *)mbuf + write_header_size;

		res = fuse_ll_copy_from_pipe(&tmpbuf, &bufv);
		err = -res;
		if (res < 0)
			goto reply_err;

		in = mbuf;
	}

	inarg = (void *) &in[1];
	if (in->opcode == FUSE_WRITE && se->op.write_buf)
		do_write_buf(req, in->nodeid, inarg, buf);
	else if (in->opcode == FUSE_NOTIFY_REPLY)
		do_notify_reply(req, in->nodeid, inarg, buf);
	else
		fuse_ll_ops[in->opcode].func(req, in->nodeid, inarg);

out_free:
	free(mbuf);
	return;

reply_err:
	fuse_reply_err(req, err);
clear_pipe:
	if (buf->flags & FUSE_BUF_IS_FD)
		fuse_ll_clear_pipe(se);
	goto out_free;
}

void fuse_session_process_uring_cqe(struct fuse_session *se,
				    struct fuse_req *req,
				    struct fuse_in_header *in, void *op_in,
				    void *op_payload, size_t payload_len)
{
	int err;

	fuse_session_in2req(req, in);

	err = fuse_req_opcode_sanity_ok(se, in->opcode);
	if (err)
		goto reply_err;

	err = fuse_req_check_allow_root(se, in->opcode, in->uid);
	if (err)
		goto reply_err;

	err = ENOSYS;
	if (in->opcode >= FUSE_MAXOP || !fuse_ll_ops[in->opcode].func)
		goto reply_err;

	if (se->debug) {
		fuse_log(
			FUSE_LOG_DEBUG,
			"cqe unique: %llu, opcode: %s (%i), nodeid: %llu, insize: %zu, pid: %u\n",
			(unsigned long long)in->unique,
			opname((enum fuse_opcode)in->opcode), in->opcode,
			(unsigned long long)in->nodeid, payload_len, in->pid);
	}

	if (in->opcode == FUSE_WRITE && se->op.write_buf) {
		struct fuse_bufvec bufv = {
			.buf[0] = { .size = payload_len,
				    .flags = 0,
				    .mem = op_payload },
			.count = 1,
		};
		_do_write_buf(req, in->nodeid, op_in, &bufv);
	} else if (in->opcode == FUSE_NOTIFY_REPLY) {
		struct fuse_buf buf = { .size = payload_len,
					.mem = op_payload };
		do_notify_reply(req, in->nodeid, op_in, &buf);
	} else {
		fuse_ll_ops2[in->opcode].func(req, in->nodeid, op_in,
					      op_payload);
	}

	return;

reply_err:
	fuse_reply_err(req, err);
}

#define LL_OPTION(n,o,v) \
	{ n, offsetof(struct fuse_session, o), v }

static const struct fuse_opt fuse_ll_opts[] = {
	LL_OPTION("debug", debug, 1),
	LL_OPTION("-d", debug, 1),
	LL_OPTION("--debug", debug, 1),
	LL_OPTION("allow_root", deny_others, 1),
	LL_OPTION("io_uring", uring.enable, 1),
	LL_OPTION("io_uring_q_depth=%u", uring.q_depth, -1),
	FUSE_OPT_END
};

void fuse_lowlevel_version(void)
{
	printf("using FUSE kernel interface version %i.%i\n",
	       FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);
	fuse_mount_version();
}

void fuse_lowlevel_help(void)
{
	/* These are not all options, but the ones that are
	   potentially of interest to an end-user */
	printf(
"    -o allow_other         allow access by all users\n"
"    -o allow_root          allow access by root\n"
"    -o auto_unmount        auto unmount on process termination\n"
"    -o io_uring            enable io-uring\n"
"    -o io_uring_q_depth=<n> io-uring queue depth\n"
);
}

void fuse_session_destroy(struct fuse_session *se)
{
	struct fuse_ll_pipe *llp;

	if (se->got_init && !se->got_destroy) {
		if (se->op.destroy)
			se->op.destroy(se->userdata);
	}
	llp = pthread_getspecific(se->pipe_key);
	if (llp != NULL)
		fuse_ll_pipe_free(llp);
	pthread_key_delete(se->pipe_key);
	sem_destroy(&se->mt_finish);
	pthread_mutex_destroy(&se->mt_lock);
	pthread_mutex_destroy(&se->lock);
	free(se->cuse_data);
	if (se->fd != -1)
		close(se->fd);
	if (se->io != NULL)
		free(se->io);
	destroy_mount_opts(se->mo);
	free(se);
}


static void fuse_ll_pipe_destructor(void *data)
{
	struct fuse_ll_pipe *llp = data;
	fuse_ll_pipe_free(llp);
}

void fuse_buf_free(struct fuse_buf *buf)
{
	if (buf->mem == NULL)
		return;

	size_t write_header_sz =
		sizeof(struct fuse_in_header) + sizeof(struct fuse_write_in);

	char *ptr = (char *)buf->mem - pagesize + write_header_sz;
	free(ptr);
	buf->mem = NULL;
}

/*
 * This is used to allocate buffers that hold fuse requests
 */
static void *buf_alloc(size_t size, bool internal)
{
	/*
	 * For libfuse internal caller add in alignment. That cannot be done
	 * for an external caller, as it is not guaranteed that the external
	 * caller frees the raw pointer.
	 */
	if (internal) {
		size_t write_header_sz = sizeof(struct fuse_in_header) +
					 sizeof(struct fuse_write_in);
		size_t new_size = ROUND_UP(size + write_header_sz, pagesize);

		char *buf = aligned_alloc(pagesize, new_size);
		if (buf == NULL)
			return NULL;

		buf += pagesize - write_header_sz;

		return buf;
	} else {
		return malloc(size);
	}
}

/*
 *@param internal true if called from libfuse internal code
 */
static int _fuse_session_receive_buf(struct fuse_session *se,
				     struct fuse_buf *buf, struct fuse_chan *ch,
				     bool internal)
{
	int err;
	ssize_t res;
	size_t bufsize;
#ifdef HAVE_SPLICE
	struct fuse_ll_pipe *llp;
	struct fuse_buf tmpbuf;

pipe_retry:
	bufsize = se->bufsize;

	if (se->conn.proto_minor < 14 ||
	    !(se->conn.want_ext & FUSE_CAP_SPLICE_READ))
		goto fallback;

	llp = fuse_ll_get_pipe(se);
	if (llp == NULL)
		goto fallback;

	if (llp->size < bufsize) {
		if (llp->can_grow) {
			res = fcntl(llp->pipe[0], F_SETPIPE_SZ, bufsize);
			if (res == -1) {
				llp->can_grow = 0;
				res = grow_pipe_to_max(llp->pipe[0]);
				if (res > 0)
					llp->size = res;
				goto fallback;
			}
			llp->size = res;
		}
		if (llp->size < bufsize)
			goto fallback;
	}

	if (se->io != NULL && se->io->splice_receive != NULL) {
		res = se->io->splice_receive(ch ? ch->fd : se->fd, NULL,
					     llp->pipe[1], NULL, bufsize, 0,
					     se->userdata);
	} else {
		res = splice(ch ? ch->fd : se->fd, NULL, llp->pipe[1], NULL,
			     bufsize, 0);
	}
	err = errno;
	trace_request_receive(err);

	if (fuse_session_exited(se))
		return 0;

	if (res == -1) {
		if (err == ENODEV) {
			/* Filesystem was unmounted, or connection was aborted
			   via /sys/fs/fuse/connections */
			fuse_session_exit(se);
			return 0;
		}

		/* FUSE_INIT might have increased the required bufsize */
		if (err == EINVAL && bufsize < se->bufsize) {
			fuse_ll_clear_pipe(se);
			goto pipe_retry;
		}

		if (err != EINTR && err != EAGAIN)
			perror("fuse: splice from device");
		return -err;
	}

	if (res < sizeof(struct fuse_in_header)) {
		fuse_log(FUSE_LOG_ERR, "short splice from fuse device\n");
		return -EIO;
	}

	tmpbuf = (struct fuse_buf){
		.size = res,
		.flags = FUSE_BUF_IS_FD,
		.fd = llp->pipe[0],
	};

	/*
	 * Don't bother with zero copy for small requests.
	 * fuse_loop_mt() needs to check for FORGET so this more than
	 * just an optimization.
	 */
	if (res < sizeof(struct fuse_in_header) + sizeof(struct fuse_write_in) +
			  pagesize) {
		struct fuse_bufvec src = { .buf[0] = tmpbuf, .count = 1 };
		struct fuse_bufvec dst = { .count = 1 };

		if (!buf->mem) {
			buf->mem = buf_alloc(bufsize, internal);
			if (!buf->mem) {
				fuse_log(
					FUSE_LOG_ERR,
					"fuse: failed to allocate read buffer\n");
				return -ENOMEM;
			}
			buf->mem_size = bufsize;
		}
		buf->size = bufsize;
		buf->flags = 0;
		dst.buf[0] = *buf;

		res = fuse_buf_copy(&dst, &src, 0);
		if (res < 0) {
			fuse_log(FUSE_LOG_ERR, "fuse: copy from pipe: %s\n",
				 strerror(-res));
			fuse_ll_clear_pipe(se);
			return res;
		}
		if (res < tmpbuf.size) {
			fuse_log(FUSE_LOG_ERR,
				 "fuse: copy from pipe: short read\n");
			fuse_ll_clear_pipe(se);
			return -EIO;
		}
		assert(res == tmpbuf.size);

	} else {
		/* Don't overwrite buf->mem, as that would cause a leak */
		buf->fd = tmpbuf.fd;
		buf->flags = tmpbuf.flags;
	}
	buf->size = tmpbuf.size;

	return res;

fallback:
#endif
	bufsize = internal ? buf->mem_size : se->bufsize;
	if (!buf->mem) {
		bufsize = se->bufsize; /* might have changed */
		buf->mem = buf_alloc(bufsize, internal);
		if (!buf->mem) {
			fuse_log(FUSE_LOG_ERR,
				 "fuse: failed to allocate read buffer\n");
			return -ENOMEM;
		}

		if (internal)
			buf->mem_size = bufsize;
	}

restart:
	if (se->io != NULL) {
		/* se->io->read is never NULL if se->io is not NULL as
		specified by fuse_session_custom_io()*/
		res = se->io->read(ch ? ch->fd : se->fd, buf->mem, bufsize,
				   se->userdata);
	} else {
		res = read(ch ? ch->fd : se->fd, buf->mem, bufsize);
	}
	err = errno;
	trace_request_receive(err);

	if (fuse_session_exited(se))
		return 0;
	if (res == -1) {
		if (err == EINVAL && internal && se->bufsize > bufsize) {
			/* FUSE_INIT might have increased the required bufsize */
			bufsize = se->bufsize;
			void *newbuf = buf_alloc(bufsize, internal);
			if (!newbuf) {
				fuse_log(
					FUSE_LOG_ERR,
					"fuse: failed to (re)allocate read buffer\n");
				return -ENOMEM;
			}
			fuse_buf_free(buf);
			buf->mem = newbuf;
			buf->mem_size = bufsize;
			goto restart;
		}

		/* ENOENT means the operation was interrupted, it's safe
		   to restart */
		if (err == ENOENT)
			goto restart;

		if (err == ENODEV) {
			/* Filesystem was unmounted, or connection was aborted
			   via /sys/fs/fuse/connections */
			fuse_session_exit(se);
			return 0;
		}
		/* Errors occurring during normal operation: EINTR (read
		   interrupted), EAGAIN (nonblocking I/O), ENODEV (filesystem
		   umounted) */
		if (err != EINTR && err != EAGAIN)
			perror("fuse: reading device");
		return -err;
	}
	if ((size_t)res < sizeof(struct fuse_in_header)) {
		fuse_log(FUSE_LOG_ERR, "short read on fuse device\n");
		return -EIO;
	}

	buf->size = res;

	return res;
}

int fuse_session_receive_buf(struct fuse_session *se, struct fuse_buf *buf)
{
	return _fuse_session_receive_buf(se, buf, NULL, false);
}

/* libfuse internal handler */
int fuse_session_receive_buf_internal(struct fuse_session *se,
				      struct fuse_buf *buf,
				      struct fuse_chan *ch)
{
	/*
	 * if run internally thread buffers are from libfuse - we can
	 * reallocate them
	 */
	if (unlikely(!se->got_init) && !se->buf_reallocable)
		se->buf_reallocable = true;

	return _fuse_session_receive_buf(se, buf, ch, true);
}

struct fuse_session *
fuse_session_new_versioned(struct fuse_args *args,
			   const struct fuse_lowlevel_ops *op, size_t op_size,
			   struct libfuse_version *version, void *userdata)
{
	int err;
	struct fuse_session *se;
	struct mount_opts *mo;

	if (op == NULL || op_size == 0) {
		fuse_log(FUSE_LOG_ERR,
			 "fuse: warning: empty op list passed to fuse_session_new()\n");
		return NULL;
	}

	if (version == NULL) {
		fuse_log(FUSE_LOG_ERR, "fuse: warning: version not passed to fuse_session_new()\n");
		return NULL;
	}

	if (sizeof(struct fuse_lowlevel_ops) < op_size) {
		fuse_log(FUSE_LOG_ERR, "fuse: warning: library too old, some operations may not work\n");
		op_size = sizeof(struct fuse_lowlevel_ops);
	}

	if (args == NULL || args->argc == 0) {
		fuse_log(FUSE_LOG_ERR, "fuse: empty argv passed to fuse_session_new().\n");
		return NULL;
	}

	se = (struct fuse_session *) calloc(1, sizeof(struct fuse_session));
	if (se == NULL) {
		fuse_log(FUSE_LOG_ERR, "fuse: failed to allocate fuse object\n");
		goto out1;
	}
	se->fd = -1;
	se->conn.max_write = FUSE_DEFAULT_MAX_PAGES_LIMIT * getpagesize();
	se->bufsize = se->conn.max_write + FUSE_BUFFER_HEADER_SIZE;
	se->conn.max_readahead = UINT_MAX;

	/*
	 * Allow overriding with env, mostly to avoid the need to modify
	 * all tests. I.e. to test with and without io-uring being enabled.
	 */
	se->uring.enable = getenv("FUSE_URING_ENABLE") ?
				   atoi(getenv("FUSE_URING_ENABLE")) :
				   SESSION_DEF_URING_ENABLE;
	se->uring.q_depth = getenv("FUSE_URING_QUEUE_DEPTH") ?
				    atoi(getenv("FUSE_URING_QUEUE_DEPTH")) :
				    SESSION_DEF_URING_Q_DEPTH;

	/* Parse options */
	if(fuse_opt_parse(args, se, fuse_ll_opts, NULL) == -1)
		goto out2;
	if(se->deny_others) {
		/* Allowing access only by root is done by instructing
		 * kernel to allow access by everyone, and then restricting
		 * access to root and mountpoint owner in libfuse.
		 */
		// We may be adding the option a second time, but
		// that doesn't hurt.
		if(fuse_opt_add_arg(args, "-oallow_other") == -1)
			goto out2;
	}
	mo = parse_mount_opts(args);
	if (mo == NULL)
		goto out3;

	if(args->argc == 1 &&
	   args->argv[0][0] == '-') {
		fuse_log(FUSE_LOG_ERR, "fuse: warning: argv[0] looks like an option, but "
			"will be ignored\n");
	} else if (args->argc != 1) {
		int i;
		fuse_log(FUSE_LOG_ERR, "fuse: unknown option(s): `");
		for(i = 1; i < args->argc-1; i++)
			fuse_log(FUSE_LOG_ERR, "%s ", args->argv[i]);
		fuse_log(FUSE_LOG_ERR, "%s'\n", args->argv[i]);
		goto out4;
	}

	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "FUSE library version: %s\n", PACKAGE_VERSION);

	list_init_req(&se->list);
	list_init_req(&se->interrupts);
	list_init_nreq(&se->notify_list);
	se->notify_ctr = 1;
	pthread_mutex_init(&se->lock, NULL);
	sem_init(&se->mt_finish, 0, 0);
	pthread_mutex_init(&se->mt_lock, NULL);

	err = pthread_key_create(&se->pipe_key, fuse_ll_pipe_destructor);
	if (err) {
		fuse_log(FUSE_LOG_ERR, "fuse: failed to create thread specific key: %s\n",
			strerror(err));
		goto out5;
	}

	memcpy(&se->op, op, op_size);
	se->owner = getuid();
	se->userdata = userdata;

	se->mo = mo;

	/* Fuse server application should pass the version it was compiled
	 * against and pass it. If a libfuse version accidentally introduces an
	 * ABI incompatibility, it might be possible to 'fix' that at run time,
	 * by checking the version numbers.
	 */
	se->version = *version;

	return se;

out5:
	sem_destroy(&se->mt_finish);
	pthread_mutex_destroy(&se->mt_lock);
	pthread_mutex_destroy(&se->lock);
out4:
	fuse_opt_free_args(args);
out3:
	if (mo != NULL)
		destroy_mount_opts(mo);
out2:
	free(se);
out1:
	return NULL;
}

struct fuse_session *fuse_session_new_30(struct fuse_args *args,
					 const struct fuse_lowlevel_ops *op,
					 size_t op_size, void *userdata);
struct fuse_session *fuse_session_new_30(struct fuse_args *args,
					  const struct fuse_lowlevel_ops *op,
					  size_t op_size,
					  void *userdata)
{
	struct fuse_lowlevel_ops null_ops = { 0 };

	/* unknown version */
	struct libfuse_version version = { 0 };

	/*
	 * This function is the ABI interface function from fuse_session_new in
	 * compat.c. External libraries like "fuser" might call fuse_session_new()
	 * with NULL ops and then pass that session to fuse_session_mount().
	 * The actual FUSE operations are handled in their own library.
	 */
	if (op == NULL) {
		op = &null_ops;
		op_size = sizeof(null_ops);
	}

	return fuse_session_new_versioned(args, op, op_size, &version,
					  userdata);
}

FUSE_SYMVER("fuse_session_custom_io_317", "fuse_session_custom_io@@FUSE_3.17")
int fuse_session_custom_io_317(struct fuse_session *se,
				const struct fuse_custom_io *io, size_t op_size, int fd)
{
	if (sizeof(struct fuse_custom_io) < op_size) {
		fuse_log(FUSE_LOG_ERR, "fuse: warning: library too old, some operations may not work\n");
		op_size = sizeof(struct fuse_custom_io);
	}

	if (fd < 0) {
		fuse_log(FUSE_LOG_ERR, "Invalid file descriptor value %d passed to "
			"fuse_session_custom_io()\n", fd);
		return -EBADF;
	}
	if (io == NULL) {
		fuse_log(FUSE_LOG_ERR, "No custom IO passed to "
			"fuse_session_custom_io()\n");
		return -EINVAL;
	} else if (io->read == NULL || io->writev == NULL) {
		/* If the user provides their own file descriptor, we can't
		guarantee that the default behavior of the io operations made
		in libfuse will function properly. Therefore, we enforce the
		user to implement these io operations when using custom io. */
		fuse_log(FUSE_LOG_ERR, "io passed to fuse_session_custom_io() must "
			"implement both io->read() and io->writev\n");
		return -EINVAL;
	}

	se->io = calloc(1, sizeof(struct fuse_custom_io));
	if (se->io == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to allocate memory for custom io. "
			"Error: %s\n", strerror(errno));
		return -errno;
	}

	se->fd = fd;
	memcpy(se->io, io, op_size);
	return 0;
}

int fuse_session_custom_io_30(struct fuse_session *se,
			const struct fuse_custom_io *io, int fd);
FUSE_SYMVER("fuse_session_custom_io_30", "fuse_session_custom_io@FUSE_3.0")
int fuse_session_custom_io_30(struct fuse_session *se,
			const struct fuse_custom_io *io, int fd)
{
	return fuse_session_custom_io_317(se, io,
			offsetof(struct fuse_custom_io, clone_fd), fd);
}

int fuse_session_mount(struct fuse_session *se, const char *_mountpoint)
{
	int fd;
	char *mountpoint;

	if (_mountpoint == NULL) {
		fuse_log(FUSE_LOG_ERR, "Invalid null-ptr mountpoint!\n");
		return -1;
	}

	mountpoint = strdup(_mountpoint);
	if (mountpoint == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to allocate memory for mountpoint. Error: %s\n",
			strerror(errno));
		return -1;
	}

	/*
	 * Make sure file descriptors 0, 1 and 2 are open, otherwise chaos
	 * would ensue.
	 */
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

	/*
	 * To allow FUSE daemons to run without privileges, the caller may open
	 * /dev/fuse before launching the file system and pass on the file
	 * descriptor by specifying /dev/fd/N as the mount point. Note that the
	 * parent process takes care of performing the mount in this case.
	 */
	fd = fuse_mnt_parse_fuse_fd(mountpoint);
	if (fd != -1) {
		if (fcntl(fd, F_GETFD) == -1) {
			fuse_log(FUSE_LOG_ERR,
				"fuse: Invalid file descriptor /dev/fd/%u\n",
				fd);
			goto error_out;
		}
		se->fd = fd;
		return 0;
	}

	/* Open channel */
	fd = fuse_kern_mount(mountpoint, se->mo);
	if (fd == -1)
		goto error_out;
	se->fd = fd;

	/* Save mountpoint */
	se->mountpoint = mountpoint;

	return 0;

error_out:
	free(mountpoint);
	return -1;
}

int fuse_session_fd(struct fuse_session *se)
{
	return se->fd;
}

void fuse_session_unmount(struct fuse_session *se)
{
	if (se->mountpoint != NULL) {
		char *mountpoint = atomic_exchange(&se->mountpoint, NULL);

		fuse_kern_unmount(mountpoint, se->fd);
		se->fd = -1;
		free(mountpoint);
	}
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
	if (ret < 0) {
		ret = -EIO;
		goto out_free;
	}

	if ((size_t)ret == bufsize) {
		free(buf);
		bufsize *= 4;
		goto retry;
	}

	buf[ret] = '\0';
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
	(void) req; (void) size; (void) list;
	return -ENOSYS;
}
#endif

/* Prevent spurious data race warning - we don't care
 * about races for this flag */
__attribute__((no_sanitize_thread))
void fuse_session_exit(struct fuse_session *se)
{
	atomic_store_explicit(&se->mt_exited, 1, memory_order_relaxed);
	sem_post(&se->mt_finish);
}

__attribute__((no_sanitize_thread))
void fuse_session_reset(struct fuse_session *se)
{
	se->mt_exited = false;
	se->error = 0;
}

__attribute__((no_sanitize_thread))
int fuse_session_exited(struct fuse_session *se)
{
	bool exited =
		atomic_load_explicit(&se->mt_exited, memory_order_relaxed);

	return exited ? 1 : 0;
}
