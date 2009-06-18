/*
  CUSE example: Character device in Userspace
  Copyright (C) 2008-2009  SUSE Linux Products GmbH
  Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` cusexmp.c -o cusexmp
*/

#define FUSE_USE_VERSION 29

#include <cuse_lowlevel.h>
#include <fuse_opt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "fioc.h"

static void *cusexmp_buf;
static size_t cusexmp_size;

static const char *usage =
"usage: cusexmp [options]\n"
"\n"
"options:\n"
"    --help|-h             print this help message\n"
"    --maj=MAJ|-M MAJ      device major number\n"
"    --min=MIN|-m MIN      device minor number\n"
"    --name=NAME|-n NAME   device name (mandatory)\n"
"\n";

static int cusexmp_resize(size_t new_size)
{
	void *new_buf;

	if (new_size == cusexmp_size)
		return 0;

	new_buf = realloc(cusexmp_buf, new_size);
	if (!new_buf && new_size)
		return -ENOMEM;

	if (new_size > cusexmp_size)
		memset(new_buf + cusexmp_size, 0, new_size - cusexmp_size);

	cusexmp_buf = new_buf;
	cusexmp_size = new_size;

	return 0;
}

static int cusexmp_expand(size_t new_size)
{
	if (new_size > cusexmp_size)
		return cusexmp_resize(new_size);
	return 0;
}

static void cusexmp_open(fuse_req_t req, struct fuse_file_info *fi)
{
	fuse_reply_open(req, fi);
}

static void cusexmp_read(fuse_req_t req, size_t size, off_t off,
			 struct fuse_file_info *fi)
{
	(void)fi;

	if (off >= cusexmp_size)
		off = cusexmp_size;
	if (size > cusexmp_size - off)
		size = cusexmp_size - off;

	fuse_reply_buf(req, cusexmp_buf + off, size);
}

static void cusexmp_write(fuse_req_t req, const char *buf, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	(void)fi;

	if (cusexmp_expand(off + size)) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	memcpy(cusexmp_buf + off, buf, size);
	fuse_reply_write(req, size);
}

static void fioc_do_rw(fuse_req_t req, void *addr, const void *in_buf,
		       size_t in_bufsz, size_t out_bufsz, int is_read)
{
	const struct fioc_rw_arg *arg;
	struct iovec in_iov[2], out_iov[3], iov[3];
	size_t cur_size;

	/* read in arg */
	in_iov[0].iov_base = addr;
	in_iov[0].iov_len = sizeof(*arg);
	if (!in_bufsz) {
		fuse_reply_ioctl_retry(req, in_iov, 1, NULL, 0);
		return;
	}
	arg = in_buf;
	in_buf += sizeof(*arg);
	in_bufsz -= sizeof(*arg);

	/* prepare size outputs */
	out_iov[0].iov_base =
		addr + (unsigned long)&(((struct fioc_rw_arg *)0)->prev_size);
	out_iov[0].iov_len = sizeof(arg->prev_size);

	out_iov[1].iov_base =
		addr + (unsigned long)&(((struct fioc_rw_arg *)0)->new_size);
	out_iov[1].iov_len = sizeof(arg->new_size);

	/* prepare client buf */
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

	/* we're all set */
	cur_size = cusexmp_size;
	iov[0].iov_base = &cur_size;
	iov[0].iov_len = sizeof(cur_size);

	iov[1].iov_base = &cusexmp_size;
	iov[1].iov_len = sizeof(cusexmp_size);

	if (is_read) {
		size_t off = arg->offset;
		size_t size = arg->size;

		if (off >= cusexmp_size)
			off = cusexmp_size;
		if (size > cusexmp_size - off)
			size = cusexmp_size - off;

		iov[2].iov_base = cusexmp_buf + off;
		iov[2].iov_len = size;
		fuse_reply_ioctl_iov(req, size, iov, 3);
	} else {
		if (cusexmp_expand(arg->offset + in_bufsz)) {
			fuse_reply_err(req, ENOMEM);
			return;
		}

		memcpy(cusexmp_buf + arg->offset, in_buf, in_bufsz);
		fuse_reply_ioctl_iov(req, in_bufsz, iov, 2);
	}
}

static void cusexmp_ioctl(fuse_req_t req, int cmd, void *arg,
			  struct fuse_file_info *fi, unsigned flags,
			  const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	int is_read = 0;

	(void)fi;

	if (flags & FUSE_IOCTL_COMPAT) {
		fuse_reply_err(req, ENOSYS);
		return;
	}

	switch (cmd) {
	case FIOC_GET_SIZE:
		if (!out_bufsz) {
			struct iovec iov = { arg, sizeof(size_t) };

			fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
		} else
			fuse_reply_ioctl(req, 0, &cusexmp_size,
					 sizeof(cusexmp_size));
		break;

	case FIOC_SET_SIZE:
		if (!in_bufsz) {
			struct iovec iov = { arg, sizeof(size_t) };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else {
			cusexmp_resize(*(size_t *)in_buf);
			fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;

	case FIOC_READ:
		is_read = 1;
	case FIOC_WRITE:
		fioc_do_rw(req, arg, in_buf, in_bufsz, out_bufsz, is_read);
		break;

	default:
		fuse_reply_err(req, EINVAL);
	}
}

struct cusexmp_param {
	unsigned		major;
	unsigned		minor;
	char			*dev_name;
	int			is_help;
};

#define CUSEXMP_OPT(t, p) { t, offsetof(struct cusexmp_param, p), 1 }

static const struct fuse_opt cusexmp_opts[] = {
	CUSEXMP_OPT("-M %u",		major),
	CUSEXMP_OPT("--maj=%u",		major),
	CUSEXMP_OPT("-m %u",		minor),
	CUSEXMP_OPT("--min=%u",		minor),
	CUSEXMP_OPT("-n %s",		dev_name),
	CUSEXMP_OPT("--name=%s",	dev_name),
	FUSE_OPT_KEY("-h",		0),
	FUSE_OPT_KEY("--help",		0),
	FUSE_OPT_END
};

static int cusexmp_process_arg(void *data, const char *arg, int key,
			       struct fuse_args *outargs)
{
	struct cusexmp_param *param = data;

	(void)outargs;
	(void)arg;

	switch (key) {
	case 0:
		param->is_help = 1;
		fprintf(stderr, usage);
		return fuse_opt_add_arg(outargs, "-ho");
	default:
		return 1;
	}
}

static const struct cuse_lowlevel_ops cusexmp_clop = {
	.open		= cusexmp_open,
	.read		= cusexmp_read,
	.write		= cusexmp_write,
	.ioctl		= cusexmp_ioctl,
};

int main(int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct cusexmp_param param = { 0, 0, NULL, 0 };
	char dev_name[128] = "DEVNAME=";
	const char *dev_info_argv[] = { dev_name };
	struct cuse_info ci;

	if (fuse_opt_parse(&args, &param, cusexmp_opts, cusexmp_process_arg)) {
		printf("failed to parse option\n");
		return 1;
	}

	if (!param.is_help) {
		if (!param.dev_name) {
			fprintf(stderr, "Error: device name missing\n");
			return 1;
		}
		strncat(dev_name, param.dev_name, sizeof(dev_name) - 9);
	}

	memset(&ci, 0, sizeof(ci));
	ci.dev_major = param.major;
	ci.dev_minor = param.minor;
	ci.dev_info_argc = 1;
	ci.dev_info_argv = dev_info_argv;
	ci.flags = CUSE_UNRESTRICTED_IOCTL;

	return cuse_lowlevel_main(args.argc, args.argv, &ci, &cusexmp_clop,
				  NULL);
}
