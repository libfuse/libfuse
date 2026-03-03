/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2026 Oracle.

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/** @file
 *
 * minimal example filesystem using low-level API and systemd service api
 *
 * Compile with:
 *
 *     gcc -Wall service_ll.c `pkg-config fuse3 --cflags --libs` -o service_ll
 *
 * Note: If the pkg-config command fails due to the absence of the fuse3.pc
 *     file, you should configure the path to the fuse3.pc file in the
 *     PKG_CONFIG_PATH variable.
 *
 * ## Source code ##
 * \include service_ll.c
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fuse_lowlevel.h>
#include <fuse_service.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <linux/stat.h>

struct service_ll {
	struct fuse_session *se;
	char *device;
	uint64_t isize;
	uint64_t blocks;
	struct fuse_service *service;
	int fusedev_fd;
	int fd;
	mode_t mode;

	/* really booleans */
	int debug;
	int ro;
	int allow_dio;
	int sync;

	int dev_index;
	unsigned int blocksize;

	struct timespec atime;
	struct timespec mtime;

	pthread_mutex_t lock;
};

static struct service_ll ll = {
	.fd = -1,
	.allow_dio = 1,
	.mode = S_IFREG | 0444,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};
static const char *file_name = "svc_bdev";

struct service_ll_stat {
	struct fuse_entry_param entry;
};

static inline uint64_t round_up(uint64_t b, unsigned int align)
{
	unsigned int m;

	if (align == 0)
		return b;
	m = b % align;
	if (m)
		b += align - m;
	return b;
}

static inline uint64_t round_down(uint64_t b, unsigned int align)
{
	unsigned int m;

	if (align == 0)
		return b;
	m = b % align;
	return b - m;
}

static inline uint64_t howmany(uint64_t b, unsigned int align)
{
	unsigned int m;

	if (align == 0)
		return b;
	m = (b % align) ? 1 : 0;
	return (b / align) + m;
}

static inline uint64_t b_to_fsbt(uint64_t off)
{
	return off / ll.blocksize;
}

static inline uint64_t b_to_fsb(uint64_t off)
{
	return (off + ll.blocksize - 1) / ll.blocksize;
}

static inline uint64_t fsb_to_b(uint64_t fsb)
{
	return fsb * ll.blocksize;
}

static int service_stat(fuse_ino_t ino, struct service_ll_stat *llstat)
{
	struct fuse_entry_param *entry = &llstat->entry;
	struct stat *stbuf = &entry->attr;

	stbuf->st_ino = ino;
	switch (ino) {
	case 1:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		break;

	case 2:
		stbuf->st_mode = ll.mode;
		stbuf->st_nlink = 1;
		stbuf->st_size = ll.isize;
		stbuf->st_blksize = ll.blocksize;
		stbuf->st_blocks = howmany(ll.isize, 512);
		stbuf->st_atim = ll.atime;
		stbuf->st_mtim = ll.mtime;
		break;

	default:
		return ENOENT;
	}

	entry->generation = ino + 1;
	entry->attr_timeout = 0.0;
	entry->entry_timeout = 0.0;
	entry->ino = ino;

	return 0;
}

#if defined(STATX_BASIC_STATS)
static inline void service_set_statx_attr(struct statx *stx,
					    uint64_t statx_flag, int set)
{
	if (set)
		stx->stx_attributes |= statx_flag;
	stx->stx_attributes_mask |= statx_flag;
}

static void service_statx_directio(struct statx *stx)
{
	struct statx devx;
	int ret;

	ret = statx(ll.fd, "", AT_EMPTY_PATH, STATX_DIOALIGN, &devx);
	if (ret)
		return;
	if (!(devx.stx_mask & STATX_DIOALIGN))
		return;

	stx->stx_mask |= STATX_DIOALIGN;
	stx->stx_dio_mem_align = devx.stx_dio_mem_align;
	stx->stx_dio_offset_align = devx.stx_dio_offset_align;
}

static int service_statx(fuse_ino_t ino, int statx_mask, struct statx *stx)
{
	(void)statx_mask;

	stx->stx_mask = STATX_BASIC_STATS;
	stx->stx_ino = ino;
	switch (ino) {
	case 1:
		stx->stx_mode = S_IFDIR | 0755;
		stx->stx_nlink = 2;
		break;

	case 2:
		stx->stx_mode = ll.mode;
		stx->stx_nlink = 1;
		stx->stx_size = ll.isize;
		stx->stx_blksize = ll.blocksize;
		stx->stx_blocks = howmany(ll.isize, 512);
		stx->stx_atime.tv_sec = ll.atime.tv_sec;
		stx->stx_atime.tv_nsec = ll.atime.tv_nsec;
		stx->stx_mtime.tv_sec = ll.mtime.tv_sec;
		stx->stx_mtime.tv_nsec = ll.mtime.tv_nsec;
		break;

	default:
		return ENOENT;
	}

	service_set_statx_attr(stx, STATX_ATTR_IMMUTABLE, ll.ro);
	service_statx_directio(stx);

	return 0;
}

static void service_ll_statx(fuse_req_t req, fuse_ino_t ino, int flags,
			       int mask, struct fuse_file_info *fi)
{
	struct statx stx = { };
	int ret = 0;

	(void)flags;
	(void)fi;

	pthread_mutex_lock(&ll.lock);
	ret = service_statx(ino, mask, &stx);
	pthread_mutex_unlock(&ll.lock);
	if (ret)
		fuse_reply_err(req, ret);
	else
		fuse_reply_statx(req, 0, &stx, 0.0);
}
#else
# define service_ll_statx		NULL
#endif /* STATX_BASIC_STATS */

static void service_ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct statvfs buf;

	(void)ino;

	pthread_mutex_lock(&ll.lock);
	buf.f_bsize = ll.blocksize;
	buf.f_frsize = 0;

	buf.f_blocks = ll.blocks;
	buf.f_bfree = 0;
	buf.f_bavail = 0;
	buf.f_files = 1;
	buf.f_ffree = 0;
	buf.f_favail = 0;
	buf.f_fsid = 0x50C00L;
	buf.f_flag = 0;
	if (ll.ro)
		buf.f_flag |= ST_RDONLY;
	buf.f_namemax = 255;
	pthread_mutex_unlock(&ll.lock);

	fuse_reply_statfs(req, &buf);
}

static void service_ll_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;

	conn->time_gran = 1;
}

static void service_ll_getattr(fuse_req_t req, fuse_ino_t ino,
				 struct fuse_file_info *fi)
{
	struct service_ll_stat llstat;
	int ret;

	(void) fi;

	memset(&llstat, 0, sizeof(llstat));
	pthread_mutex_lock(&ll.lock);
	ret = service_stat(ino, &llstat);
	pthread_mutex_unlock(&ll.lock);
	if (ret)
		fuse_reply_err(req, ret);
	else
		fuse_reply_attr(req, &llstat.entry.attr,
				llstat.entry.attr_timeout);
}

static void service_ll_setattr(fuse_req_t req, fuse_ino_t ino,
				 struct stat *attr, int to_set,
				 struct fuse_file_info *fi)
{
	pthread_mutex_lock(&ll.lock);
	if (to_set & FUSE_SET_ATTR_MODE)
		ll.mode = attr->st_mode;
	if (to_set & FUSE_SET_ATTR_ATIME)
		ll.atime = attr->st_atim;
	if (to_set & FUSE_SET_ATTR_MTIME)
		ll.mtime = attr->st_mtim;
	pthread_mutex_unlock(&ll.lock);

	service_ll_getattr(req, ino, fi);
}

static void service_ll_lookup(fuse_req_t req, fuse_ino_t parent,
				const char *name)
{
	struct service_ll_stat llstat;
	int ret = ENOENT;

	if (parent != 1 || strcmp(name, file_name) != 0)
		goto enoent;

	memset(&llstat, 0, sizeof(llstat));
	pthread_mutex_lock(&ll.lock);
	ret = service_stat(2, &llstat);
	pthread_mutex_unlock(&ll.lock);
	if (ret)
		goto enoent;

	fuse_reply_entry(req, &llstat.entry);
	return;

enoent:
	fuse_reply_err(req, ret);
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

#define max(x, y) ((x) > (y) ? (x) : (y))
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

static void service_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
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
		dirbuf_add(req, &b, file_name, 2);
		reply_buf_limited(req, b.p, b.size, off, size);
		free(b.p);
	}
}

static void service_ll_open(fuse_req_t req, fuse_ino_t ino,
			      struct fuse_file_info *fi)
{
	if (ino != 2)
		fuse_reply_err(req, EISDIR);
	else if (ll.ro && (fi->flags & O_ACCMODE) != O_RDONLY)
		fuse_reply_err(req, EACCES);
	else
		fuse_reply_open(req, fi);
}

static void service_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			       struct fuse_file_info *fp)
{
	int ret = 0;

	(void)datasync;
	(void)fp;

	if (ino == 2) {
		ret = fsync(ll.fd);
		if (ret)
			ret = -errno;
	}

	fuse_reply_err(req, ret);
}

static void service_ll_read(fuse_req_t req, fuse_ino_t ino, size_t count,
			    off_t pos, struct fuse_file_info *fp)
{
	void *buf = NULL;
	ssize_t got;
	int ret;

	if (ino != 2) {
		ret = EIO;
		goto out_reply;
	}

	if (ll.debug)
		fprintf(stderr, "%s: pos 0x%llx count 0x%llx\n",
			__func__,
			(unsigned long long)pos,
			(unsigned long long)count);

	if (!ll.allow_dio && fp->direct_io) {
		ret = ENOSYS;
		goto out_reply;
	}

	buf = malloc(count);
	if (!buf) {
		ret = ENOMEM;
		goto out_reply;
	}

	got = pread(ll.fd, buf, count, pos);
	if (got < 0) {
		ret = -errno;
		goto out_reply;
	}

	fuse_reply_buf(req, buf, got);
	goto out_buf;

out_reply:
	fuse_reply_err(req, ret);
out_buf:
	free(buf);
}

static void service_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			     size_t count, off_t pos,
			     struct fuse_file_info *fp)
{
	ssize_t got;
	int ret;

	if (ino != 2) {
		ret = EIO;
		goto out_reply;
	}

	if (ll.debug)
		fprintf(stderr, "%s: pos 0x%llx count 0x%llx\n",
			__func__,
			(unsigned long long)pos,
			(unsigned long long)count);

	if (!ll.allow_dio && fp->direct_io) {
		ret = ENOSYS;
		goto out_reply;
	}

	if (pos >= ll.isize) {
		ret = EFBIG;
		goto out_reply;
	}

	if (pos >= ll.isize - count)
		count = ll.isize - pos;

	got = pwrite(ll.fd, buf, count, pos);
	if (got < 0) {
		ret = -errno;
		goto out_reply;
	}

	if (ll.sync) {
		ret = fsync(ll.fd);
		if (ret < 0) {
			ret = -errno;
			goto out_reply;
		}
	}

	fuse_reply_write(req, got);
	return;

out_reply:
	fuse_reply_err(req, ret);
}

static const struct fuse_lowlevel_ops service_ll_oper = {
	.init		= service_ll_init,
	.lookup		= service_ll_lookup,
	.getattr	= service_ll_getattr,
	.setattr	= service_ll_setattr,
	.readdir	= service_ll_readdir,
	.open		= service_ll_open,
	.fsync		= service_ll_fsync,
	.statfs		= service_ll_statfs,
	.statx		= service_ll_statx,
	.read		= service_ll_read,
	.write		= service_ll_write,
};

enum {
	SERVICE_LL_SIZE,
	SERVICE_LL_BLOCKSIZE,
};

#define SERVICE_LL_OPT(t, p, v) { t, offsetof(struct service_ll, p), v }

static struct fuse_opt service_ll_opts[] = {
	SERVICE_LL_OPT("debug",		debug,			1),
	SERVICE_LL_OPT("ro",		ro,			1),
	SERVICE_LL_OPT("rw",		ro,			0),
	SERVICE_LL_OPT("dio",		allow_dio,		1),
	SERVICE_LL_OPT("nodio",		allow_dio,		0),
	SERVICE_LL_OPT("sync",		sync,			1),
	SERVICE_LL_OPT("nosync",	sync,			0),
	FUSE_OPT_KEY("size=%s",		SERVICE_LL_SIZE),
	FUSE_OPT_KEY("blocksize=%s",	SERVICE_LL_BLOCKSIZE),
	FUSE_OPT_END
};

static unsigned long long parse_num_blocks2(const char *arg, int log_block_size)
{
	char *p;
	unsigned long long num;

	num = strtoull(arg, &p, 0);

	if (p[0] && p[1])
		return 0;

	switch (*p) {		/* Using fall-through logic */
	case 'T': case 't':
		num <<= 10;
		/* fallthrough */
	case 'G': case 'g':
		num <<= 10;
		/* fallthrough */
	case 'M': case 'm':
		num <<= 10;
		/* fallthrough */
	case 'K': case 'k':
		if (log_block_size < 0)
			num <<= 10;
		else
			num >>= log_block_size;
		break;
	case 's':
		if (log_block_size < 0)
			num <<= 9;
		else
			num >>= (1+log_block_size);
		break;
	case '\0':
		break;
	default:
		return 0;
	}
	return num;
}

static int service_ll_opt_proc(void *data, const char *arg, int key,
				 struct fuse_args *outargs)
{
	(void)data;
	(void)outargs;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		if (!ll.device) {
			ll.device = strdup(arg);
			return 0;
		}
		return 1;
	case SERVICE_LL_BLOCKSIZE:
		ll.blocksize = parse_num_blocks2(arg + 10, -1);
		if (ll.blocksize < 1 || ll.blocksize > INT32_MAX ||
		    (ll.blocksize & (ll.blocksize - 1)) != 0) {
			fprintf(stderr,
 "%s: block size must be power of two between 1 block and 2GB.\n",
				arg + 10);
			return -1;
		}

		/* do not pass through to libfuse */
		return 0;
	case SERVICE_LL_SIZE:
		ll.isize = parse_num_blocks2(arg + 5, -1);
		if (ll.isize < 1 || (ll.isize & 511) != 0) {
			fprintf(stderr,
 "%s: size must be multiple of 512 and larger than zero.\n\n",
				arg + 5);
			return -1;
		}

		/* do not pass through to libfuse */
		return 0;
	}

	return 1;
}

static int service_get_config(void)
{
	int open_flags = (ll.ro ? O_RDONLY : O_RDWR) | O_EXCL;
	int ret;

again:
	if (ll.blocksize)
		ret = fuse_service_request_blockdev(ll.service, ll.device,
						    open_flags, 0, 0,
						    ll.blocksize);
	else
		ret = fuse_service_request_file(ll.service, ll.device,
						open_flags, 0, 0);
	if (ret)
		return ret;

	ret = fuse_service_receive_file(ll.service, ll.device, &ll.fd);
	if (ret)
		return ret;

	if (ll.fd < 0 &&
	    (errno == EPERM || errno == EACCES) &&
	    (open_flags & O_ACCMODE) != O_RDONLY) {
		open_flags = O_RDONLY | O_EXCL;
		goto again;
	}

	if (ll.fd < 0) {
		printf("%s: opening device: %s.\n", ll.device,
		       strerror(errno));
		return -1;
	}

	ret = fuse_service_finish_file_requests(ll.service);
	if (ret)
		return ret;

	ll.fusedev_fd = fuse_service_take_fusedev(ll.service);
	return 0;
}


int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;
	struct fuse_loop_config *config;
	struct stat statbuf;
	unsigned long long bdev_size;
	int lbasize;
	int ret = -1;

	if (fuse_service_accept(&ll.service) != 0) {
		printf("service acceptance failed\n");
		return 1;
	}
	if (!fuse_service_accepted(ll.service)) {
		printf("service not accepted\n");
		return 1;
	}
	fuse_service_append_args(ll.service, &args);

	if (fuse_opt_parse(&args, &ll, service_ll_opts,
			   service_ll_opt_proc) != 0) {
		printf("parsing existing cli options failed\n");
		return 1;
	}
	if (fuse_service_parse_cmdline_opts(&args, &opts) != 0) {
		printf("parsing service cli options failed\n");
		return 1;
	}

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

	if (opts.mountpoint == NULL || !ll.device) {
		printf("usage: %s [options] <device> <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}

	ret = service_get_config();
	if (ret) {
		printf("could not get service config: %s\n", strerror(-errno));
		ret = -1;
		goto err_out1;
	}

	if (!ll.blocksize)
		ll.blocksize = sysconf(_SC_PAGESIZE);

	ret = fstat(ll.fd, &statbuf);
	if (ret) {
		perror(ll.device);
		ret = -1;
		goto err_out1;
	}

	if (S_ISBLK(statbuf.st_mode)) {
		ret = ioctl(ll.fd, BLKSSZGET, &lbasize);
		if (ret) {
			perror(ll.device);
			ret = -1;
			goto err_out1;
		}

		ret = ioctl(ll.fd, BLKGETSIZE64, &bdev_size);
		if (ret) {
			perror(ll.device);
			ret = -1;
			goto err_out1;
		}
	} else {
		lbasize = statbuf.st_blksize;
		bdev_size = statbuf.st_size;
	}
	if (lbasize > ll.blocksize) {
		fprintf(stderr,
 "%s: lba size %u smaller than blocksize %u\n",
		       ll.device, lbasize, ll.blocksize);
		ret = -1;
		goto err_out1;
	}
	if (ll.isize % ll.blocksize > 0) {
		fprintf(stderr,
 "%s: size parameter %llu not congruent with blocksize %u\n",
			ll.device, (unsigned long long)ll.isize,
			ll.blocksize);
		ret = -1;
		goto err_out1;
	}
	if (ll.isize > bdev_size) {
		fprintf(stderr,
 "%s: block device size %llu smaller than size param %llu\n",
			ll.device, bdev_size,
			(unsigned long long)ll.isize);
		ret = -1;
		goto err_out1;
	}
	if (!ll.isize)
		ll.isize = bdev_size;
	ll.isize = round_down(ll.isize, ll.blocksize);
	ll.blocks = ll.isize / ll.blocksize;

	ll.se = fuse_session_new(&args, &service_ll_oper,
				 sizeof(service_ll_oper), NULL);
	if (ll.se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(ll.se) != 0)
	    goto err_out2;

	if (fuse_service_session_mount(ll.service, ll.se, &opts) != 0) {
		printf("%s: could not mount fuse filesystem: %s\n",
		       ll.device, strerror(errno));
		ret = -1;
		goto err_out3;
	}

	fuse_service_send_goodbye(ll.service, 0);
	fuse_service_release(ll.service);

	fuse_daemonize(opts.foreground);

	/* Block until ctrl+c or fusermount -u */
	if (opts.singlethread)
		ret = fuse_session_loop(ll.se);
	else {
		config = fuse_loop_cfg_create();
		fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
		fuse_loop_cfg_set_max_threads(config, opts.max_threads);
		ret = fuse_session_loop_mt(ll.se, config);
		fuse_loop_cfg_destroy(config);
		config = NULL;
	}

	fuse_session_unmount(ll.se);
err_out3:
	fuse_remove_signal_handlers(ll.se);
err_out2:
	fuse_session_destroy(ll.se);
err_out1:
	fuse_service_destroy(&ll.service);
	free(opts.mountpoint);
	free(ll.device);
	close(ll.fd);
	fuse_opt_free_args(&args);
	return fuse_service_exit(ret);
}
