struct fuse_mkdir_in_compat5 {
	__u32	mode;
};

struct fuse_setattr_in_compat5 {
	__u32	valid;
	struct fuse_attr attr;
};

struct fuse_open_out_compat5 {
	__u64	fh;
	__u32	open_flags;
};

struct fuse_write_out_compat5 {
	__u32	size;
};

struct fuse_getxattr_out_compat5 {
	__u32	size;
};

struct fuse_in_header_compat5 {
	__u32	len;
	__u32	opcode;
	__u64	unique;
	__u64	nodeid;
	__u32	uid;
	__u32	gid;
	__u32	pid;
};

struct fuse_dirent_compat5 {
	__u64	ino;
	__u32	namelen;
	__u32	type;
	char name[0];
};

#define FUSE_NAME_OFFSET_COMPAT5 ((unsigned) ((struct fuse_dirent_compat5 *) 0)->name)
#define FUSE_DIRENT_SIZE_COMPAT5(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET_COMPAT5 + (d)->namelen)
