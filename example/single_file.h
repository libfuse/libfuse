/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Oracle.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */
#ifndef FUSE_SINGLE_FILE_H_
#define FUSE_SINGLE_FILE_H_

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

struct single_file {
	int backing_fd;

	int64_t isize;
	uint64_t blocks;

	mode_t mode;

	bool ro;
	bool allow_dio;
	bool sync;
	bool require_bdev;

	unsigned int blocksize;

	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;

	pthread_mutex_t lock;
};

extern struct single_file single_file;

static inline uint64_t b_to_fsbt(uint64_t off)
{
	return off / single_file.blocksize;
}

static inline uint64_t b_to_fsb(uint64_t off)
{
	return (off + single_file.blocksize - 1) / single_file.blocksize;
}

static inline uint64_t fsb_to_b(uint64_t fsb)
{
	return fsb * single_file.blocksize;
}

enum single_file_opt_keys {
	SINGLE_FILE_RO = 171717, /* how many options could we possibly have? */
	SINGLE_FILE_RW,
	SINGLE_FILE_REQUIRE_BDEV,
	SINGLE_FILE_DIO,
	SINGLE_FILE_NODIO,
	SINGLE_FILE_SYNC,
	SINGLE_FILE_NOSYNC,
	SINGLE_FILE_SIZE,
	SINGLE_FILE_BLOCKSIZE,

	SINGLE_FILE_NR_KEYS,
};

#define SINGLE_FILE_OPT_KEYS \
	FUSE_OPT_KEY("ro",		SINGLE_FILE_RO), \
	FUSE_OPT_KEY("rw",		SINGLE_FILE_RW), \
	FUSE_OPT_KEY("require_bdev",	SINGLE_FILE_REQUIRE_BDEV), \
	FUSE_OPT_KEY("dio",		SINGLE_FILE_DIO), \
	FUSE_OPT_KEY("nodio",		SINGLE_FILE_NODIO), \
	FUSE_OPT_KEY("sync",		SINGLE_FILE_SYNC), \
	FUSE_OPT_KEY("nosync",		SINGLE_FILE_NOSYNC), \
	FUSE_OPT_KEY("size=%s",		SINGLE_FILE_SIZE), \
	FUSE_OPT_KEY("blocksize=%s",	SINGLE_FILE_BLOCKSIZE)

int single_file_opt_proc(void *data, const char *arg, int key,
			 struct fuse_args *outargs);

unsigned long long parse_num_blocks(const char *arg, int log_block_size);

struct fuse_service;
int single_file_service_open(struct fuse_service *sf, const char *path);

void single_file_check_read(off_t pos, size_t *count);
int single_file_check_write(off_t pos, size_t *count);

int single_file_configure(const char *device, const char *filename);
int single_file_configure_simple(const char *filename);
void single_file_close(void);

ssize_t single_file_pwrite(const char *buf, size_t count, off_t pos);
ssize_t single_file_pread(char *buf, size_t count, off_t pos);

/* low-level fuse operation handlers */

#ifdef USE_SINGLE_FILE_LL_API
bool is_single_file_child(fuse_ino_t parent, const char *name);
bool is_single_file_ino(fuse_ino_t ino);

void single_file_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
				off_t off, struct fuse_file_info *fi);

void single_file_ll_statfs(fuse_req_t req, fuse_ino_t ino);

void single_file_ll_statx(fuse_req_t req, fuse_ino_t ino, int flags, int mask,
		       struct fuse_file_info *fi);

void single_file_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi);
void single_file_ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			 int to_set, struct fuse_file_info *fi);

void single_file_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
void single_file_ll_open(fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);

void single_file_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			  struct fuse_file_info *fi);

int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
		      off_t off, size_t maxsize);
#endif

/* high-level fuse operation handlers */

#ifdef USE_SINGLE_FILE_HL_API
bool is_single_open_file_path(const struct fuse_file_info *fi, const char *name);

int single_file_hl_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi,
			   enum fuse_readdir_flags flags);

int single_file_hl_statfs(const char *path, struct statvfs *buf);

int single_file_hl_statx(const char *path, int statx_flags, int statx_mask,
			 struct statx *stx, struct fuse_file_info *fi);

int single_file_hl_getattr(const char *path, struct stat *stbuf,
			   struct fuse_file_info *fi);
int single_file_hl_chmod(const char *path, mode_t mode,
			 struct fuse_file_info *fi);
int single_file_hl_utimens(const char *path, const struct timespec ctv[2],
			   struct fuse_file_info *fi);
int single_file_hl_chown(const char *path, uid_t owner, gid_t group,
			 struct fuse_file_info *fi);
int single_file_hl_truncate(const char *path, off_t len,
			    struct fuse_file_info *fi);

int single_file_hl_opendir(const char *path, struct fuse_file_info *fi);
int single_file_hl_open(const char *path, struct fuse_file_info *fi);

int single_file_hl_fsync(const char *path, int datasync,
			 struct fuse_file_info *fi);
#endif

#if !defined(USE_SINGLE_FILE_LL_API) && !defined(USE_SINGLE_FILE_HL_API)
# warning USE_SINGLE_FILE_[HL]L_API not defined!
#endif

#endif /* FUSE_SINGLE_FILE_H_ */
