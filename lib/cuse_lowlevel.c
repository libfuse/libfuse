/*
  CUSE: Character device in Userspace
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "cuse_lowlevel.h"
#include "fuse_kernel.h"
#include "fuse_i.h"
#include "fuse_opt.h"
#include "fuse_misc.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>

struct cuse_data {
	struct cuse_lowlevel_ops	clop;
	unsigned			max_read;
	unsigned			dev_major;
	unsigned			dev_minor;
	unsigned			flags;
	unsigned			dev_info_len;
	char				dev_info[];
};

static struct cuse_lowlevel_ops *req_clop(fuse_req_t req)
{
	return &req->f->cuse_data->clop;
}

static void cuse_fll_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	(void)ino;
	req_clop(req)->open(req, fi);
}

static void cuse_fll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	(void)ino;
	req_clop(req)->read(req, size, off, fi);
}

static void cuse_fll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			   size_t size, off_t off, struct fuse_file_info *fi)
{
	(void)ino;
	req_clop(req)->write(req, buf, size, off, fi);
}

static void cuse_fll_flush(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi)
{
	(void)ino;
	req_clop(req)->flush(req, fi);
}

static void cuse_fll_release(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	(void)ino;
	req_clop(req)->release(req, fi);
}

static void cuse_fll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			   struct fuse_file_info *fi)
{
	(void)ino;
	req_clop(req)->fsync(req, datasync, fi);
}

static void cuse_fll_ioctl(fuse_req_t req, fuse_ino_t ino, int cmd, void *arg,
		       struct fuse_file_info *fi, unsigned int flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	(void)ino;
	req_clop(req)->ioctl(req, cmd, arg, fi, flags, in_buf, in_bufsz,
			     out_bufsz);
}

static void cuse_fll_poll(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi, struct fuse_pollhandle *ph)
{
	(void)ino;
	req_clop(req)->poll(req, fi, ph);
}

static size_t cuse_pack_info(int argc, const char **argv, char *buf)
{
	size_t size = 0;
	int i;

	for (i = 0; i < argc; i++) {
		size_t len;

		len = strlen(argv[i]) + 1;
		size += len;
		if (buf) {
			memcpy(buf, argv[i], len);
			buf += len;
		}
	}

	return size;
}

static struct cuse_data *cuse_prep_data(const struct cuse_info *ci,
					const struct cuse_lowlevel_ops *clop)
{
	struct cuse_data *cd;
	size_t dev_info_len;

	dev_info_len = cuse_pack_info(ci->dev_info_argc, ci->dev_info_argv,
				      NULL);

	if (dev_info_len > CUSE_INIT_INFO_MAX) {
		fprintf(stderr, "cuse: dev_info (%zu) too large, limit=%u\n",
			dev_info_len, CUSE_INIT_INFO_MAX);
		return NULL;
	}

	cd = calloc(1, sizeof(*cd) + dev_info_len);
	if (!cd) {
		fprintf(stderr, "cuse: failed to allocate cuse_data\n");
		return NULL;
	}

	memcpy(&cd->clop, clop, sizeof(cd->clop));
	cd->max_read = 131072;
	cd->dev_major = ci->dev_major;
	cd->dev_minor = ci->dev_minor;
	cd->dev_info_len = dev_info_len;
	cd->flags = ci->flags;
	cuse_pack_info(ci->dev_info_argc, ci->dev_info_argv, cd->dev_info);

	return cd;
}

struct fuse_session *cuse_lowlevel_new(struct fuse_args *args,
				       const struct cuse_info *ci,
				       const struct cuse_lowlevel_ops *clop,
				       void *userdata)
{
	struct fuse_lowlevel_ops lop;
	struct cuse_data *cd;
	struct fuse_session *se;
	struct fuse_ll *ll;

	cd = cuse_prep_data(ci, clop);
	if (!cd)
		return NULL;

	memset(&lop, 0, sizeof(lop));
	lop.init	= clop->init;
	lop.destroy	= clop->destroy;
	lop.open	= clop->open		? cuse_fll_open		: NULL;
	lop.read	= clop->read		? cuse_fll_read		: NULL;
	lop.write	= clop->write		? cuse_fll_write	: NULL;
	lop.flush	= clop->flush		? cuse_fll_flush	: NULL;
	lop.release	= clop->release		? cuse_fll_release	: NULL;
	lop.fsync	= clop->fsync		? cuse_fll_fsync	: NULL;
	lop.ioctl	= clop->ioctl		? cuse_fll_ioctl	: NULL;
	lop.poll	= clop->poll		? cuse_fll_poll		: NULL;

	se = fuse_lowlevel_new_common(args, &lop, sizeof(lop), userdata);
	if (!se) {
		free(cd);
		return NULL;
	}
	ll = se->data;
	ll->cuse_data = cd;

	return se;
}

static int cuse_reply_init(fuse_req_t req, struct cuse_init_out *arg,
			   char *dev_info, unsigned dev_info_len)
{
	struct iovec iov[3];

	iov[1].iov_base = arg;
	iov[1].iov_len = sizeof(struct cuse_init_out);
	iov[2].iov_base = dev_info;
	iov[2].iov_len = dev_info_len;

	return fuse_send_reply_iov_nofree(req, 0, iov, 3);
}

void cuse_lowlevel_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_init_in *arg = (struct fuse_init_in *) inarg;
	struct cuse_init_out outarg;
	struct fuse_ll *f = req->f;
	struct cuse_data *cd = f->cuse_data;
	size_t bufsize = fuse_chan_bufsize(req->ch);
	struct cuse_lowlevel_ops *clop = req_clop(req);

	(void) nodeid;
	if (f->debug) {
		fprintf(stderr, "CUSE_INIT: %u.%u\n", arg->major, arg->minor);
		fprintf(stderr, "flags=0x%08x\n", arg->flags);
	}
	f->conn.proto_major = arg->major;
	f->conn.proto_minor = arg->minor;
	f->conn.capable = 0;
	f->conn.want = 0;

	if (arg->major < 7) {
		fprintf(stderr, "fuse: unsupported protocol version: %u.%u\n",
			arg->major, arg->minor);
		fuse_reply_err(req, EPROTO);
		return;
	}

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

	memset(&outarg, 0, sizeof(outarg));
	outarg.major = FUSE_KERNEL_VERSION;
	outarg.minor = FUSE_KERNEL_MINOR_VERSION;
	outarg.flags = cd->flags;
	outarg.max_read = cd->max_read;
	outarg.max_write = f->conn.max_write;
	outarg.dev_major = cd->dev_major;
	outarg.dev_minor = cd->dev_minor;

	if (f->debug) {
		fprintf(stderr, "   CUSE_INIT: %u.%u\n",
			outarg.major, outarg.minor);
		fprintf(stderr, "   flags=0x%08x\n", outarg.flags);
		fprintf(stderr, "   max_read=0x%08x\n", outarg.max_read);
		fprintf(stderr, "   max_write=0x%08x\n", outarg.max_write);
		fprintf(stderr, "   dev_major=%u\n", outarg.dev_major);
		fprintf(stderr, "   dev_minor=%u\n", outarg.dev_minor);
		fprintf(stderr, "   dev_info: %.*s\n", cd->dev_info_len,
			cd->dev_info);
	}

	cuse_reply_init(req, &outarg, cd->dev_info, cd->dev_info_len);

	if (clop->init_done)
		clop->init_done(f->userdata);

	fuse_free_req(req);
}

struct fuse_session *cuse_lowlevel_setup(int argc, char *argv[],
					 const struct cuse_info *ci,
					 const struct cuse_lowlevel_ops *clop,
					 int *multithreaded, void *userdata)
{
	const char *devname = "/dev/cuse";
	static const struct fuse_opt kill_subtype_opts[] = {
		FUSE_OPT_KEY("subtype=",  FUSE_OPT_KEY_DISCARD),
		FUSE_OPT_END
	};
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_chan *ch;
	int fd;
	int foreground;
	int res;

	res = fuse_parse_cmdline(&args, NULL, multithreaded, &foreground);
	if (res == -1)
		goto err_args;

	res = fuse_opt_parse(&args, NULL, kill_subtype_opts, NULL);
	if (res == -1)
		goto err_args;

	/*
	 * Make sure file descriptors 0, 1 and 2 are open, otherwise chaos
	 * would ensue.
	 */
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

	se = cuse_lowlevel_new(&args, ci, clop, userdata);
	fuse_opt_free_args(&args);
	if (se == NULL)
		goto err_args;

	fd = open(devname, O_RDWR);
	if (fd == -1) {
		if (errno == ENODEV || errno == ENOENT)
			fprintf(stderr, "fuse: device not found, try 'modprobe cuse' first\n");
		else
			fprintf(stderr, "fuse: failed to open %s: %s\n",
				devname, strerror(errno));
		goto err_se;
	}

	ch = fuse_kern_chan_new(fd);
	if (!ch) {
		close(fd);
		goto err_se;
	}

	fuse_session_add_chan(se, ch);

	res = fuse_set_signal_handlers(se);
	if (res == -1)
		goto err_se;

	res = fuse_daemonize(foreground);
	if (res == -1)
		goto err_sig;

	return se;

err_sig:
	fuse_remove_signal_handlers(se);
err_se:
	fuse_session_destroy(se);
err_args:
	fuse_opt_free_args(&args);
	return NULL;
}

void cuse_lowlevel_teardown(struct fuse_session *se)
{
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);
}

int cuse_lowlevel_main(int argc, char *argv[], const struct cuse_info *ci,
		       const struct cuse_lowlevel_ops *clop, void *userdata)
{
	struct fuse_session *se;
	int multithreaded;
	int res;

	se = cuse_lowlevel_setup(argc, argv, ci, clop, &multithreaded,
				 userdata);
	if (se == NULL)
		return 1;

	if (multithreaded)
		res = fuse_session_loop_mt(se);
	else
		res = fuse_session_loop(se);

	cuse_lowlevel_teardown(se);
	if (res == -1)
		return 1;

	return 0;
}
