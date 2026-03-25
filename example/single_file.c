/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Oracle.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#ifdef __linux__
#include <linux/fs.h>
#include <linux/stat.h>
#endif

#define FUSE_USE_VERSION (FUSE_MAKE_VERSION(3, 19))

#include "fuse_lowlevel.h"
#include "fuse.h"
#include "fuse_service.h"
#define USE_SINGLE_FILE_LL_API
#define USE_SINGLE_FILE_HL_API
#include "single_file.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)
#endif

struct dirbuf {
	char *p;
	size_t size;
};

struct single_file_stat {
	struct fuse_entry_param entry;
};

#define SINGLE_FILE_INO		(FUSE_ROOT_ID + 1)

static const char *single_file_name = "single_file";
static bool single_file_name_set;
static struct timespec startup_time;

struct single_file single_file = {
	.backing_fd = -1,
	.allow_dio = true,
	.mode = S_IFREG | 0444,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static fuse_ino_t single_file_path_to_ino(const char *path)
{
	if (strcmp(path, "/") == 0)
		return FUSE_ROOT_ID;
	if (strcmp(path + 1, single_file_name) == 0)
		return SINGLE_FILE_INO;
	return 0;
}

static fuse_ino_t single_open_file_path_to_ino(const struct fuse_file_info *fi,
					       const char *path)
{
	if (fi)
		return fi->fh;
	return single_file_path_to_ino(path);
}

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

int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
		      off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off,
				      min(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

bool is_single_file_child(fuse_ino_t parent, const char *name)
{
	return  parent == FUSE_ROOT_ID &&
		strcmp(name, single_file_name) == 0;
}

bool is_single_file_ino(fuse_ino_t ino)
{
	return ino == SINGLE_FILE_INO;
}

bool is_single_open_file_path(const struct fuse_file_info *fi, const char *name)
{
	if (fi)
		return is_single_file_ino(fi->fh);
	return name[0] == '/' && strcmp(name + 1, single_file_name) == 0;
}

void single_file_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			    off_t off, struct fuse_file_info *fi)
{
	struct dirbuf b;

	(void) fi;

	switch (ino) {
	case FUSE_ROOT_ID:
		break;
	case SINGLE_FILE_INO:
		fuse_reply_err(req, ENOTDIR);
		return;
	default:
		fuse_reply_err(req, ENOENT);
		return;
	}

	memset(&b, 0, sizeof(b));
	dirbuf_add(req, &b, ".", FUSE_ROOT_ID);
	dirbuf_add(req, &b, "..", FUSE_ROOT_ID);
	dirbuf_add(req, &b, single_file_name, SINGLE_FILE_INO);
	reply_buf_limited(req, b.p, b.size, off, size);
	free(b.p);
}

int single_file_hl_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi,
			   enum fuse_readdir_flags flags)
{
	struct stat stbuf;
	fuse_ino_t ino = single_open_file_path_to_ino(fi, path);

	memset(&stbuf, 0, sizeof(stbuf));

	(void) offset;
	(void) flags;

	switch (ino) {
	case FUSE_ROOT_ID:
		break;
	case SINGLE_FILE_INO:
		return -ENOTDIR;
	default:
		return -ENOENT;
	}

	stbuf.st_ino = FUSE_ROOT_ID;
	filler(buf, ".", &stbuf, 0, FUSE_FILL_DIR_DEFAULTS);
	filler(buf, "..", &stbuf, 0, FUSE_FILL_DIR_DEFAULTS);

	stbuf.st_ino = SINGLE_FILE_INO;
	filler(buf, single_file_name, &stbuf, 0, FUSE_FILL_DIR_DEFAULTS);

	return 0;
}

static bool sf_stat(fuse_ino_t ino, struct single_file_stat *llstat)
{
	struct fuse_entry_param *entry = &llstat->entry;
	struct stat *stbuf = &entry->attr;

	if (ino == FUSE_ROOT_ID) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		stbuf->st_atim = startup_time;
		stbuf->st_mtim = startup_time;
		stbuf->st_ctim = startup_time;
	} else if (ino == SINGLE_FILE_INO) {
		stbuf->st_mode = single_file.mode;
		stbuf->st_nlink = 1;
		stbuf->st_size = single_file.isize;
		stbuf->st_blksize = single_file.blocksize;
		stbuf->st_blocks = howmany(single_file.isize, 512);
		stbuf->st_atim = single_file.atime;
		stbuf->st_mtim = single_file.mtime;
		stbuf->st_ctim = single_file.ctime;
	} else {
		return false;
	}
	stbuf->st_ino = ino;

	entry->generation = ino + 1;
	entry->attr_timeout = 0.0;
	entry->entry_timeout = 0.0;
	entry->ino = ino;

	return true;
}

#if defined(STATX_BASIC_STATS)
static inline void sf_set_statx_attr(struct statx *stx,
				     uint64_t statx_flag, int set)
{
	if (set)
		stx->stx_attributes |= statx_flag;
	stx->stx_attributes_mask |= statx_flag;
}

static void sf_statx_directio(struct statx *stx)
{
	struct statx devx;
	int ret;

	ret = statx(single_file.backing_fd, "", AT_EMPTY_PATH, STATX_DIOALIGN,
		    &devx);
	if (ret)
		return;
	if (!(devx.stx_mask & STATX_DIOALIGN))
		return;

	stx->stx_mask |= STATX_DIOALIGN;
	stx->stx_dio_mem_align = devx.stx_dio_mem_align;
	stx->stx_dio_offset_align = devx.stx_dio_offset_align;
}

static bool sf_statx(fuse_ino_t ino, int statx_mask, struct statx *stx)
{
	(void)statx_mask;

	if (ino == FUSE_ROOT_ID) {
		stx->stx_mask = STATX_BASIC_STATS | STATX_BTIME;
		stx->stx_mode = S_IFDIR | 0555;
		stx->stx_nlink = 2;
		stx->stx_atime.tv_sec = startup_time.tv_sec;
		stx->stx_atime.tv_nsec = startup_time.tv_nsec;
		stx->stx_mtime.tv_sec = startup_time.tv_sec;
		stx->stx_mtime.tv_nsec = startup_time.tv_nsec;
		stx->stx_ctime.tv_sec = startup_time.tv_sec;
		stx->stx_ctime.tv_nsec = startup_time.tv_nsec;
		stx->stx_btime.tv_sec = startup_time.tv_sec;
		stx->stx_btime.tv_nsec = startup_time.tv_nsec;
	} else if (ino == SINGLE_FILE_INO) {
		stx->stx_mask = STATX_BASIC_STATS | STATX_BTIME;
		stx->stx_mode = single_file.mode;
		stx->stx_nlink = 1;
		stx->stx_size = single_file.isize;
		stx->stx_blksize = single_file.blocksize;
		stx->stx_blocks = howmany(single_file.isize, 512);
		stx->stx_atime.tv_sec = single_file.atime.tv_sec;
		stx->stx_atime.tv_nsec = single_file.atime.tv_nsec;
		stx->stx_mtime.tv_sec = single_file.mtime.tv_sec;
		stx->stx_mtime.tv_nsec = single_file.mtime.tv_nsec;
		stx->stx_ctime.tv_sec = single_file.ctime.tv_sec;
		stx->stx_ctime.tv_nsec = single_file.ctime.tv_nsec;
		stx->stx_btime.tv_sec = startup_time.tv_sec;
		stx->stx_btime.tv_nsec = startup_time.tv_nsec;
	} else {
		return false;
	}
	stx->stx_ino = ino;

	sf_set_statx_attr(stx, STATX_ATTR_IMMUTABLE, single_file.ro);
	sf_statx_directio(stx);

	return true;
}

void single_file_ll_statx(fuse_req_t req, fuse_ino_t ino, int flags, int mask,
			  struct fuse_file_info *fi)
{
	struct statx stx = { };
	bool filled;

	(void)flags;
	(void)fi;

	pthread_mutex_lock(&single_file.lock);
	filled = sf_statx(ino, mask, &stx);
	pthread_mutex_unlock(&single_file.lock);
	if (!filled)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_statx(req, 0, &stx, 0.0);
}

int single_file_hl_statx(const char *path, int statx_flags, int statx_mask,
			 struct statx *stx, struct fuse_file_info *fi)
{
	(void)statx_flags;
	fuse_ino_t ino = single_open_file_path_to_ino(fi, path);
	bool filled;

	if (!ino)
		return -ENOENT;

	pthread_mutex_lock(&single_file.lock);
	filled = sf_statx(ino, statx_mask, stx);
	pthread_mutex_unlock(&single_file.lock);

	return filled ? 0 : -ENOENT;
}
#else
void single_file_ll_statx(fuse_req_t req, fuse_ino_t ino, int flags, int mask,
			  struct fuse_file_info *fi)
{
	fuse_reply_err(req, ENOSYS);
}

int single_file_hl_statx(const char *path, int statx_flags, int statx_mask,
			 struct statx *stx, struct fuse_file_info *fi)
{
	return -ENOSYS;
}
#endif /* STATX_BASIC_STATS */

static void single_file_statfs(struct statvfs *buf)
{
	pthread_mutex_lock(&single_file.lock);
	buf->f_bsize = single_file.blocksize;
	buf->f_frsize = 0;

	buf->f_blocks = single_file.blocks;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = 1;
	buf->f_ffree = 0;
	buf->f_favail = 0;
	buf->f_fsid = 0x50C00L;
	buf->f_flag = 0;
	if (single_file.ro)
		buf->f_flag |= ST_RDONLY;
	buf->f_namemax = 255;
	pthread_mutex_unlock(&single_file.lock);
}

void single_file_ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct statvfs buf;

	(void)ino;

	single_file_statfs(&buf);
	fuse_reply_statfs(req, &buf);
}

int single_file_hl_statfs(const char *path, struct statvfs *buf)
{
	(void)path;

	single_file_statfs(buf);
	return 0;
}

void single_file_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi)
{
	struct single_file_stat llstat;
	bool filled;

	(void) fi;

	memset(&llstat, 0, sizeof(llstat));
	pthread_mutex_lock(&single_file.lock);
	filled = sf_stat(ino, &llstat);
	pthread_mutex_unlock(&single_file.lock);
	if (!filled)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &llstat.entry.attr,
				llstat.entry.attr_timeout);
}

int single_file_hl_getattr(const char *path, struct stat *stbuf,
			   struct fuse_file_info *fi)
{
	struct single_file_stat llstat;
	fuse_ino_t ino = single_open_file_path_to_ino(fi, path);
	bool filled;

	if (!ino)
		return -ENOENT;

	memset(&llstat, 0, sizeof(llstat));
	pthread_mutex_lock(&single_file.lock);
	filled = sf_stat(ino, &llstat);
	pthread_mutex_unlock(&single_file.lock);

	if (!filled)
		return -ENOENT;

	memcpy(stbuf, &llstat.entry.attr, sizeof(*stbuf));
	return 0;
}

static void get_now(struct timespec *now)
{
#ifdef CLOCK_REALTIME
	if (!clock_gettime(CLOCK_REALTIME, now))
		return;
#endif

	now->tv_sec = time(NULL);
	now->tv_nsec = 0;
}

void single_file_ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			    int to_set, struct fuse_file_info *fi)
{
	struct timespec now;

	if (ino != SINGLE_FILE_INO)
		goto deny;
	if (to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID |
		      FUSE_SET_ATTR_SIZE))
		goto deny;
	if (single_file.ro)
		goto deny;

	get_now(&now);

	pthread_mutex_lock(&single_file.lock);
	if (to_set & FUSE_SET_ATTR_MODE)
		single_file.mode = (single_file.mode & S_IFMT) |
				   (attr->st_mode & ~S_IFMT);
	if (to_set & FUSE_SET_ATTR_ATIME) {
		if (to_set & FUSE_SET_ATTR_ATIME_NOW)
			single_file.atime = now;
		else
			single_file.atime = attr->st_atim;
	}
	if (to_set & FUSE_SET_ATTR_MTIME) {
		if (to_set & FUSE_SET_ATTR_MTIME_NOW)
			single_file.mtime = now;
		else
			single_file.mtime = attr->st_mtim;
	}
	if (to_set & FUSE_SET_ATTR_CTIME)
		single_file.ctime = attr->st_mtim;
	else
		single_file.ctime = now;
	pthread_mutex_unlock(&single_file.lock);

	single_file_ll_getattr(req, ino, fi);
	return;
deny:
	fuse_reply_err(req, EPERM);
}

int single_file_hl_chmod(const char *path, mode_t mode,
			 struct fuse_file_info *fi)
{
	fuse_ino_t ino = single_open_file_path_to_ino(fi, path);

	if (!ino)
		return -ENOENT;
	if (ino != SINGLE_FILE_INO)
		return -EPERM;
	if (single_file.ro)
		return -EPERM;

	pthread_mutex_lock(&single_file.lock);
	single_file.mode = (single_file.mode & S_IFMT) | (mode & ~S_IFMT);
	pthread_mutex_unlock(&single_file.lock);

	return 0;
}

static void set_time(const struct timespec *ctv, struct timespec *tv)
{
	switch (ctv->tv_nsec) {
	case UTIME_OMIT:
		return;
	case UTIME_NOW:
		get_now(tv);
		break;
	default:
		memcpy(tv, ctv, sizeof(*tv));
		break;
	}
}

int single_file_hl_utimens(const char *path, const struct timespec ctv[2],
			   struct fuse_file_info *fi)
{
	fuse_ino_t ino = single_open_file_path_to_ino(fi, path);

	if (!ino)
		return -ENOENT;
	if (ino != SINGLE_FILE_INO)
		return -EPERM;
	if (single_file.ro)
		return -EPERM;

	pthread_mutex_lock(&single_file.lock);
	set_time(&ctv[0], &single_file.atime);
	set_time(&ctv[1], &single_file.mtime);
	get_now(&single_file.ctime);
	pthread_mutex_unlock(&single_file.lock);

	return 0;
}

int single_file_hl_chown(const char *path, uid_t owner, gid_t group,
			 struct fuse_file_info *fi)
{
	(void)path;
	(void)owner;
	(void)group;
	(void)fi;

	return -EPERM;
}

int single_file_hl_truncate(const char *path, off_t len,
			    struct fuse_file_info *fi)
{
	(void)path;
	(void)len;
	(void)fi;

	return -EPERM;
}

void single_file_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct single_file_stat llstat;
	bool filled;

	if (!is_single_file_child(parent, name)) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	memset(&llstat, 0, sizeof(llstat));
	pthread_mutex_lock(&single_file.lock);
	filled = sf_stat(SINGLE_FILE_INO, &llstat);
	pthread_mutex_unlock(&single_file.lock);
	if (!filled)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_entry(req, &llstat.entry);
}

void single_file_ll_open(fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi)
{
	if (ino != SINGLE_FILE_INO)
		fuse_reply_err(req, EISDIR);
	else if (single_file.ro && (fi->flags & O_ACCMODE) != O_RDONLY)
		fuse_reply_err(req, EROFS);
	else
		fuse_reply_open(req, fi);
}

int single_file_hl_opendir(const char *path, struct fuse_file_info *fi)
{
	fuse_ino_t ino = single_file_path_to_ino(path);

	if (!ino)
		return -ENOENT;
	if (ino == SINGLE_FILE_INO)
		return -ENOTDIR;

	fi->fh = ino;
	return 0;
}

int single_file_hl_open(const char *path, struct fuse_file_info *fi)
{
	fuse_ino_t ino = single_file_path_to_ino(path);

	if (!ino)
		return -ENOENT;
	if (ino != SINGLE_FILE_INO)
		return -EISDIR;
	if (single_file.ro && (fi->flags & O_ACCMODE) != O_RDONLY)
		return -EROFS;

	fi->fh = ino;
	return 0;
}

void single_file_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			  struct fuse_file_info *fi)
{
	int ret = 0;

	(void)datasync;
	(void)fi;

	if (ino == SINGLE_FILE_INO) {
		ret = fsync(single_file.backing_fd);
		if (ret)
			ret = errno;
	}

	fuse_reply_err(req, ret);
}

int single_file_hl_fsync(const char *path, int datasync,
			 struct fuse_file_info *fi)
{
	fuse_ino_t ino = single_open_file_path_to_ino(fi, path);

	(void)datasync;

	if (!ino)
		return -ENOENT;

	if (ino == SINGLE_FILE_INO) {
		int ret = fsync(single_file.backing_fd);

		if (ret)
			return -errno;
	}

	return 0;
}

unsigned long long parse_num_blocks(const char *arg, int log_block_size)
{
	char *p;
	unsigned long long num;

	num = strtoull(arg, &p, 0);

	if (p[0] && p[1])
		return 0;

	switch (*p) {
	case 'T': case 't':
		num <<= 10;
		fallthrough;
	case 'G': case 'g':
		num <<= 10;
		fallthrough;
	case 'M': case 'm':
		num <<= 10;
		fallthrough;
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

static int single_file_set_blocksize(const char *arg)
{
	unsigned long long l = parse_num_blocks(arg, -1);

	if (l < 512 || l > INT32_MAX || (l & (l - 1)) != 0) {
		fprintf(stderr, "%s: block size must be power of two between 512 and 2G.\n",
			arg);
		return -1;
	}

	/* do not pass through to libfuse */
	single_file.blocksize = l;
	return 0;
}

static int single_file_set_size(const char *arg)
{
	unsigned long long l = parse_num_blocks(arg, -1);

	if (l < 1 || (l & 511) != 0 || l > INT64_MAX) {
		fprintf(stderr, "%s: size must be multiple of 512 and larger than zero.\n",
			arg);
		return -1;
	}

	/* do not pass through to libfuse */
	single_file.isize = l;
	return 0;
}

int single_file_opt_proc(void *data, const char *arg, int key,
			 struct fuse_args *outargs)
{
	(void)data;
	(void)outargs;

	switch (key) {
	case SINGLE_FILE_RO:
		/* pass through to libfuse */
		single_file.ro = true;
		return 1;
	case SINGLE_FILE_RW:
		/* pass through to libfuse */
		single_file.ro = false;
		return 1;
	case SINGLE_FILE_REQUIRE_BDEV:
		single_file.require_bdev = true;
		return 0;
	case SINGLE_FILE_DIO:
		single_file.allow_dio = true;
		return 0;
	case SINGLE_FILE_NODIO:
		single_file.allow_dio = false;
		return 0;
	case SINGLE_FILE_SYNC:
		single_file.sync = true;
		return 0;
	case SINGLE_FILE_NOSYNC:
		single_file.sync = false;
		return 0;
	case SINGLE_FILE_BLOCKSIZE:
		return single_file_set_blocksize(arg + 10);
	case SINGLE_FILE_SIZE:
		return single_file_set_size(arg + 5);
	}

	return 1;
}

int single_file_service_open(struct fuse_service *sf, const char *path)
{
	int open_flags = single_file.ro ? O_RDONLY : O_RDWR;
	int fd;
	int ret;

again:
	if (single_file.require_bdev)
		ret = fuse_service_request_blockdev(sf, path,
						    open_flags | O_EXCL, 0, 0,
						    single_file.blocksize);
	else
		ret = fuse_service_request_file(sf, path, open_flags | O_EXCL,
						0, 0);
	if (ret)
		return ret;

	if (!single_file.ro && open_flags == O_RDONLY)
		single_file.ro = true;

	ret = fuse_service_receive_file(sf, path, &fd);
	if (ret)
		return ret;

	/* downgrade from rw to ro if necessary */
	if ((fd == -EPERM || fd == -EACCES || fd == -EROFS) &&
	    open_flags == O_RDWR) {
		open_flags = O_RDONLY;
		goto again;
	}

	if (fd < 0) {
		fprintf(stderr, "%s: opening file: %s.\n",
			path, strerror(-fd));
		return -1;
	}

	single_file.backing_fd = fd;
	return 0;
}

int single_file_check_write(off_t pos, size_t *count)
{
	if (pos >= single_file.isize)
		return -EFBIG;

	if (*count > single_file.isize)
		*count = single_file.isize;
	if (pos >= single_file.isize - *count)
		*count = single_file.isize - pos;

	return 0;
}

void single_file_check_read(off_t pos, size_t *count)
{
	int ret = single_file_check_write(pos, count);

	if (ret)
		*count = 0;
}

ssize_t single_file_pwrite(const char *buf, size_t count, off_t pos)
{
	ssize_t processed = 0;
	ssize_t got;

	while ((got = pwrite(single_file.backing_fd, buf, count, pos)) > 0) {
		processed += got;
		pos += got;
		buf += got;
		count -= got;
	}

	if (processed > 0) {
		struct timespec now;

		if (single_file.sync) {
			int ret = fsync(single_file.backing_fd);

			if (ret < 0)
				return -errno;
		}

		get_now(&now);

		pthread_mutex_lock(&single_file.lock);
		single_file.ctime = now;
		pthread_mutex_unlock(&single_file.lock);

		return processed;
	}

	if (got < 0)
		return -errno;
	return 0;
}

ssize_t single_file_pread(char *buf, size_t count, off_t pos)
{
	ssize_t processed = 0;
	ssize_t got;

	while ((got = pread(single_file.backing_fd, buf, count, pos)) > 0) {
		processed += got;
		pos += got;
		buf += got;
		count -= got;
	}

	if (processed)
		return processed;
	if (got < 0)
		return -errno;
	return 0;
}

int single_file_configure(const char *device, const char *filename)
{
	struct stat stbuf;
	unsigned long long backing_size;
	unsigned int proposed_blocksize;
	int lbasize;
	int ret;

	ret = fstat(single_file.backing_fd, &stbuf);
	if (ret) {
		perror(device);
		return -1;
	}
	lbasize = stbuf.st_blksize;
	backing_size = stbuf.st_size;

	if (S_ISBLK(stbuf.st_mode)) {
#ifdef BLKSSZGET
		ret = ioctl(single_file.backing_fd, BLKSSZGET, &lbasize);
		if (ret) {
			perror(device);
			return -1;
		}
#endif

#ifdef BLKGETSIZE64
		ret = ioctl(single_file.backing_fd, BLKGETSIZE64, &backing_size);
		if (ret) {
			perror(device);
			return -1;
		}
#endif
	}

	if (backing_size == 0) {
		fprintf(stderr, "%s: backing file size zero?\n", device);
		return -1;
	}

	if (lbasize == 0) {
		fprintf(stderr, "%s: blocksize zero?\n", device);
		return -1;
	}

	proposed_blocksize = single_file.blocksize ? single_file.blocksize :
						     sysconf(_SC_PAGESIZE);
	if (lbasize > proposed_blocksize) {
		fprintf(stderr, "%s: lba size %d smaller than blocksize %u\n",
			device, lbasize, proposed_blocksize);
		return -1;
	}

	if (single_file.isize % proposed_blocksize > 0) {
		fprintf(stderr, "%s: size parameter %llu not congruent with blocksize %u\n",
			device, (unsigned long long)single_file.isize,
			proposed_blocksize);
		return -1;
	}

	if (single_file.isize > backing_size) {
		fprintf(stderr, "%s: file size %llu smaller than size param %llu\n",
			device, backing_size,
			(unsigned long long)single_file.isize);
		return -1;
	}

	if (!single_file.blocksize)
		single_file.blocksize = proposed_blocksize;
	if (!single_file.isize)
		single_file.isize = backing_size;

	single_file.isize = round_down(single_file.isize, single_file.blocksize);
	single_file.blocks = single_file.isize / single_file.blocksize;

	return single_file_configure_simple(filename);
}

int single_file_configure_simple(const char *filename)
{
	if (!single_file.blocksize)
		single_file.blocksize = sysconf(_SC_PAGESIZE);

	if (filename) {
		char *n = strdup(filename);

		if (!n) {
			perror(filename);
			return -1;
		}

		if (single_file_name_set)
			free((void *)single_file_name);
		single_file_name = n;
		single_file_name_set = true;
	}

	get_now(&startup_time);
	single_file.atime = startup_time;
	single_file.mtime = startup_time;

	if (!single_file.ro)
		single_file.mode |= 0220;

	return 0;
}

void single_file_close(void)
{
	close(single_file.backing_fd);
	single_file.backing_fd = -1;

	if (single_file_name_set)
		free((void *)single_file_name);
	single_file_name_set = false;
}
