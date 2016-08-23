/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 * @tableofcontents
 *
 * fusexmp.c - FUSE: Filesystem in Userspace
 *
 * \section section_compile compiling this example
 *
 * gcc -Wall fusexmp.c `pkg-config fuse3 --cflags --libs` -o fusexmp
 *
 * \section section_source the complete source
 * \include fusexmp.c
 */


#define FUSE_USE_VERSION 30

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

struct xmp_data {
	int acls;
};

static int xmp_setacl(const char *path, enum posix_acl_type type,
		      struct fuse_acl *acl);
static int xmp_getacl(const char *path, enum posix_acl_type type,
		      struct fuse_acl **acl);

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	(void) flags;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_acl_mknod(const char *path, mode_t *pmode, bool is_dir,
			 struct fuse_acl **default_acl,
			 struct fuse_acl **access_acl)
{
	struct fuse_acl *p = NULL, *d = NULL, *a = NULL;
	char *tmp, *parent_path;
	int res;

	tmp = strdup(path);
	if (!tmp)
		return -errno;
	parent_path = dirname(tmp);
	res = xmp_getacl(parent_path, POSIX_ACL_TYPE_DEFAULT, &p);
	free(tmp);
	if (res == -ENODATA)
		goto out;
	if (res)
		return res;
	res = fuse_acl_mknod(p, pmode, is_dir, &d, &a);
	free(p);
	if (res)
		return res;

out:
	*access_acl = a;
	*default_acl = d;
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	struct xmp_data *xmp = fuse_get_context()->private_data;
	int res;
	struct fuse_acl *default_acl = NULL, *access_acl = NULL;

	if (xmp->acls) {
		res = xmp_acl_mknod(path, &mode, false, &default_acl,
				    &access_acl);
		if (res)
			return res;
	}

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1) {
		res = -errno;
		goto out;
	}

	if (default_acl) {
		res = xmp_setacl(path, POSIX_ACL_TYPE_DEFAULT, default_acl);
		if (res)
			goto out;
	}
	if (access_acl) {
		res = xmp_setacl(path, POSIX_ACL_TYPE_ACCESS, access_acl);
		if (res)
			goto out;
	}

out:
	free(default_acl);
	free(access_acl);
	return res;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	struct xmp_data *xmp = fuse_get_context()->private_data;
	struct fuse_acl *default_acl = NULL, *access_acl = NULL;
	int res;

	if (xmp->acls) {
		res = xmp_acl_mknod(path, &mode, true, &default_acl,
				    &access_acl);
		if (res)
			return res;
	}

	res = mkdir(path, mode);
	if (res == -1) {
		res = -errno;
		goto out;
	}

	if (default_acl) {
		res = xmp_setacl(path, POSIX_ACL_TYPE_DEFAULT, default_acl);
		if (res)
			goto out;
	}
	if (access_acl) {
		res = xmp_setacl(path, POSIX_ACL_TYPE_ACCESS, access_acl);
		if (res)
			goto out;
	}

out:
	free(default_acl);
	free(access_acl);
	return res;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

	if (flags)
		return -EINVAL;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	struct xmp_data *xmp = fuse_get_context()->private_data;
	int res;

	if (xmp->acls) {
		struct fuse_acl *acl;
		res = xmp_getacl(path, POSIX_ACL_TYPE_ACCESS, &acl);
		if (!res) {
			res = fuse_acl_chmod(acl, mode);
			if (!res)
				res = xmp_setacl(path, POSIX_ACL_TYPE_ACCESS, acl);
			free(acl);
			if (res)
				return res;
		} else if (res != -ENODATA) {
			return res;
		}
	}

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}

/*
 * Data of ACL xattrs is the same as standard posix ACLs, but use
 * different xattr names so that the underlying filesystem doesn't
 * treat them as ACLs.
 */
#define XMP_ACCESS_ACL_XATTR	"user.fusexmp_acl_access"
#define XMP_DEFAULT_ACL_XATTR	"user.fusexmp_acl_default"

static int xmp_setacl(const char *path, enum posix_acl_type type,
		      struct fuse_acl *acl)
{
	struct xmp_data *xmp = fuse_get_context()->private_data;
	const char *name;
	struct posix_acl_xattr *xattr;
	ssize_t size;
	uint32_t mode;
	int ret = 0;

	if (!xmp->acls)
		return -ENOSYS;

	switch (type) {
	case POSIX_ACL_TYPE_ACCESS:
		name = XMP_ACCESS_ACL_XATTR;
		if (acl) {
			ret = fuse_acl_equiv_mode(acl, &mode);
			if (ret < 0)
				return ret;
		}
		break;
	case POSIX_ACL_TYPE_DEFAULT:
		name = XMP_DEFAULT_ACL_XATTR;
		break;
	default:
		return -EINVAL;
	}

	if (!acl)
		return xmp_removexattr(path, name);

	size = fuse_acl_to_xattr(acl, &xattr);
	if (size < 0)
		return (int)size;
	ret = xmp_setxattr(path, name, (char *)xattr, size, 0);
	if (!ret && type == POSIX_ACL_TYPE_ACCESS) {
		/* Don't use xmp_chmod() as it will try to update the ACL */
		if (chmod(path, mode) == -1)
			ret = -errno;
	}
	free(xattr);
	return ret;
}

static int xmp_getacl(const char *path, enum posix_acl_type type,
		      struct fuse_acl **acl)
{
	struct xmp_data *xmp = fuse_get_context()->private_data;
	const char *name;
	ssize_t size;
	struct posix_acl_xattr *xattr;
	int ret;

	if (!xmp->acls)
		return -ENODATA;

	switch (type) {
	case POSIX_ACL_TYPE_ACCESS:
		name = XMP_ACCESS_ACL_XATTR;
		break;
	case POSIX_ACL_TYPE_DEFAULT:
		name = XMP_DEFAULT_ACL_XATTR;
		break;
	default:
		return -EINVAL;
	}

	size = lgetxattr(path, name, NULL, 0);
	if (size == -1)
		return -errno;
	xattr = malloc(size);
	if (!xattr)
		return -ENOMEM;

	size = lgetxattr(path, name, xattr, size);
	if (size == -1)
		ret = -errno;
	else
		ret = fuse_acl_from_xattr(xattr, size, acl);
	free(xattr);
	return ret;
}
#else
static int xmp_setacl(const char *path, enum posix_acl_type type,
		      struct fuse_acl *acl)
{
	return -ENOSYS;
}


static int xmp_getacl(const char *path, enum posix_acl_type type,
		      struct fuse_acl **acl)
{
	return -ENODATA;
}
#endif /* HAVE_SETXATTR */

static void *xmp_init(struct fuse_conn_info *conn)
{
	struct xmp_data *xmp = fuse_get_context()->private_data;
	xmp->acls = (conn->want & FUSE_CAP_POSIX_ACL) != 0;
	return xmp;
}

static struct fuse_operations xmp_oper = {
	.init		= xmp_init,
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
	.setacl		= xmp_setacl,
	.getacl		= xmp_getacl,
#endif
};

int main(int argc, char *argv[])
{
	struct xmp_data xmp = {0,};
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, &xmp);
}
