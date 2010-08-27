/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

/* these definitions provide source compatibility to prior versions.
   Do not include this file directly! */

struct fuse_lowlevel_ops_compat25 {
	void (*init) (void *userdata);
	void (*destroy) (void *userdata);
	void (*lookup) (fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*forget) (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup);
	void (*getattr) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);
	void (*setattr) (fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			 int to_set, struct fuse_file_info *fi);
	void (*readlink) (fuse_req_t req, fuse_ino_t ino);
	void (*mknod) (fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, dev_t rdev);
	void (*mkdir) (fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode);
	void (*unlink) (fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*rmdir) (fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*symlink) (fuse_req_t req, const char *link, fuse_ino_t parent,
			 const char *name);
	void (*rename) (fuse_req_t req, fuse_ino_t parent, const char *name,
			fuse_ino_t newparent, const char *newname);
	void (*link) (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
		      const char *newname);
	void (*open) (fuse_req_t req, fuse_ino_t ino,
		      struct fuse_file_info *fi);
	void (*read) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		      struct fuse_file_info *fi);
	void (*write) (fuse_req_t req, fuse_ino_t ino, const char *buf,
		       size_t size, off_t off, struct fuse_file_info *fi);
	void (*flush) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi);
	void (*release) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);
	void (*fsync) (fuse_req_t req, fuse_ino_t ino, int datasync,
		       struct fuse_file_info *fi);
	void (*opendir) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);
	void (*readdir) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			 struct fuse_file_info *fi);
	void (*releasedir) (fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi);
	void (*fsyncdir) (fuse_req_t req, fuse_ino_t ino, int datasync,
			  struct fuse_file_info *fi);
	void (*statfs) (fuse_req_t req);
	void (*setxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  const char *value, size_t size, int flags);
	void (*getxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  size_t size);
	void (*listxattr) (fuse_req_t req, fuse_ino_t ino, size_t size);
	void (*removexattr) (fuse_req_t req, fuse_ino_t ino, const char *name);
	void (*access) (fuse_req_t req, fuse_ino_t ino, int mask);
	void (*create) (fuse_req_t req, fuse_ino_t parent, const char *name,
			mode_t mode, struct fuse_file_info *fi);
};

struct fuse_session *fuse_lowlevel_new_compat25(struct fuse_args *args,
				const struct fuse_lowlevel_ops_compat25 *op,
				size_t op_size, void *userdata);

size_t fuse_dirent_size(size_t namelen);

char *fuse_add_dirent(char *buf, const char *name, const struct stat *stbuf,
		      off_t off);

#if !defined(__FreeBSD__) && !defined(__NetBSD__)

#include <sys/statfs.h>

struct fuse_lowlevel_ops_compat {
	void (*init) (void *userdata);
	void (*destroy) (void *userdata);
	void (*lookup) (fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*forget) (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup);
	void (*getattr) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info_compat *fi);
	void (*setattr) (fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			 int to_set, struct fuse_file_info_compat *fi);
	void (*readlink) (fuse_req_t req, fuse_ino_t ino);
	void (*mknod) (fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, dev_t rdev);
	void (*mkdir) (fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode);
	void (*unlink) (fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*rmdir) (fuse_req_t req, fuse_ino_t parent, const char *name);
	void (*symlink) (fuse_req_t req, const char *link, fuse_ino_t parent,
			 const char *name);
	void (*rename) (fuse_req_t req, fuse_ino_t parent, const char *name,
			fuse_ino_t newparent, const char *newname);
	void (*link) (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
		      const char *newname);
	void (*open) (fuse_req_t req, fuse_ino_t ino,
		      struct fuse_file_info_compat *fi);
	void (*read) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		      struct fuse_file_info_compat *fi);
	void (*write) (fuse_req_t req, fuse_ino_t ino, const char *buf,
		       size_t size, off_t off, struct fuse_file_info_compat *fi);
	void (*flush) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info_compat *fi);
	void (*release) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info_compat *fi);
	void (*fsync) (fuse_req_t req, fuse_ino_t ino, int datasync,
		       struct fuse_file_info_compat *fi);
	void (*opendir) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info_compat *fi);
	void (*readdir) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			 struct fuse_file_info_compat *fi);
	void (*releasedir) (fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info_compat *fi);
	void (*fsyncdir) (fuse_req_t req, fuse_ino_t ino, int datasync,
			  struct fuse_file_info_compat *fi);
	void (*statfs) (fuse_req_t req);
	void (*setxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  const char *value, size_t size, int flags);
	void (*getxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  size_t size);
	void (*listxattr) (fuse_req_t req, fuse_ino_t ino, size_t size);
	void (*removexattr) (fuse_req_t req, fuse_ino_t ino, const char *name);
	void (*access) (fuse_req_t req, fuse_ino_t ino, int mask);
	void (*create) (fuse_req_t req, fuse_ino_t parent, const char *name,
			mode_t mode, struct fuse_file_info_compat *fi);
};

int fuse_reply_statfs_compat(fuse_req_t req, const struct statfs *stbuf);

int fuse_reply_open_compat(fuse_req_t req,
			   const struct fuse_file_info_compat *fi);

struct fuse_session *fuse_lowlevel_new_compat(const char *opts,
				const struct fuse_lowlevel_ops_compat *op,
				size_t op_size, void *userdata);

#endif /* __FreeBSD__ || __NetBSD__ */

struct fuse_chan_ops_compat24 {
	int (*receive)(struct fuse_chan *ch, char *buf, size_t size);
	int (*send)(struct fuse_chan *ch, const struct iovec iov[],
		    size_t count);
	void (*destroy)(struct fuse_chan *ch);
};

struct fuse_chan *fuse_chan_new_compat24(struct fuse_chan_ops_compat24 *op,
					 int fd, size_t bufsize, void *data);

int fuse_chan_receive(struct fuse_chan *ch, char *buf, size_t size);
struct fuse_chan *fuse_kern_chan_new(int fd);
