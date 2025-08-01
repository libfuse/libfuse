/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2017       Nikolaus Rath <Nikolaus@rath.org>
  Copyright (C) 2018       Valve, Inc

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/** @file
 *
 * This is a "high-performance" version of passthrough_ll.c. While
 * passthrough_ll.c is designed to be as simple as possible, this
 * example intended to be as efficient and correct as possible.
 *
 * passthrough_hp.cc mirrors a specified "source" directory under a
 * specified the mountpoint with as much fidelity and performance as
 * possible.
 *
 * If --nocache is specified, the source directory may be changed
 * directly even while mounted and the filesystem will continue
 * to work correctly.
 *
 * Without --nocache, the source directory is assumed to be modified
 * only through the passthrough filesystem. This enables much better
 * performance, but if changes are made directly to the source, they
 * may not be immediately visible under the mountpoint and further
 * access to the mountpoint may result in incorrect behavior,
 * including data-loss.
 *
 * On its own, this filesystem fulfills no practical purpose. It is
 * intended as a template upon which additional functionality can be
 * built.
 *
 * Unless --nocache is specified, is only possible to write to files
 * for which the mounting user has read permissions. This is because
 * the writeback cache requires the kernel to be able to issue read
 * requests for all files (which the passthrough filesystem cannot
 * satisfy if it can't read the file in the underlying filesystem).
 *
 * ## Source code ##
 * \include passthrough_hp.cc
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 12)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// C includes
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#ifdef __FreeBSD__
#include <fcntl.h>
#include <sys/user.h>
#endif

// C++ includes
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include "cxxopts.hpp"
#include <mutex>
#include <syslog.h>

#include "passthrough_helpers.h"

using namespace std;

#define SFS_DEFAULT_THREADS "-1" // take libfuse value as default
#define SFS_DEFAULT_CLONE_FD "0"

/* We are re-using pointers to our `struct sfs_inode` and `struct
   sfs_dirp` elements as inodes and file handles. This means that we
   must be able to store pointer a pointer in both a fuse_ino_t
   variable and a uint64_t variable (used for file handles). */
static_assert(sizeof(fuse_ino_t) >= sizeof(void *),
	      "void* must fit into fuse_ino_t");
static_assert(sizeof(fuse_ino_t) >= sizeof(uint64_t),
	      "fuse_ino_t must be at least 64 bits");

/* Forward declarations */
struct Inode;
static Inode &get_inode(fuse_ino_t ino);
static void forget_one(fuse_ino_t ino, uint64_t n);

// Uniquely identifies a file in the source directory tree. This could
// be simplified to just ino_t since we require the source directory
// not to contain any mountpoints. This hasn't been done yet in case
// we need to reconsider this constraint (but relaxing this would have
// the drawback that we can no longer reuse inode numbers, and thus
// readdir() would need to do a full lookup() in order to report the
// right inode number).
typedef std::pair<ino_t, dev_t> SrcId;

// Define a hash function for SrcId
namespace std
{
template <> struct hash<SrcId> {
	size_t operator()(const SrcId &id) const
	{
		return hash<ino_t>{}(id.first) ^ hash<dev_t>{}(id.second);
	}
};
}

// Maps files in the source directory tree to inodes
typedef std::unordered_map<SrcId, Inode> InodeMap;

struct Inode {
	int fd{ -1 };
	dev_t src_dev{ 0 };
	ino_t src_ino{ 0 };
	int generation{ 0 };
	int backing_id{ 0 };
	uint64_t nopen{ 0 };
	uint64_t nlookup{ 0 };
	std::mutex m;

	// Delete copy constructor and assignments. We could implement
	// move if we need it.
	Inode() = default;
	Inode(const Inode &) = delete;
	Inode(Inode &&inode) = delete;
	Inode &operator=(Inode &&inode) = delete;
	Inode &operator=(const Inode &) = delete;

	~Inode()
	{
		if (fd > 0)
			close(fd);
	}
};

struct Fs {
	// Must be acquired *after* any Inode.m locks.
	std::mutex mutex;
	InodeMap inodes; // protected by mutex
	Inode root;
	double timeout;
	bool debug;
	bool debug_fuse;
	bool foreground;
	std::string source;
	size_t blocksize;
	dev_t src_dev;
	bool nosplice;
	bool nocache;
	size_t num_threads;
	bool clone_fd;

	std::string fuse_mount_options;
	bool direct_io;
	bool passthrough;
};
static Fs fs{};

#define FUSE_BUF_COPY_FLAGS                 \
	(fs.nosplice ? FUSE_BUF_NO_SPLICE : \
		       static_cast<fuse_buf_copy_flags>(FUSE_BUF_SPLICE_MOVE))

static Inode &get_inode(fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return fs.root;

	Inode *inode = reinterpret_cast<Inode *>(ino);
	if (inode->fd == -1) {
		cerr << "INTERNAL ERROR: Unknown inode " << ino << endl;
		abort();
	}
	return *inode;
}

static int get_fs_fd(fuse_ino_t ino)
{
	int fd = get_inode(ino).fd;
	return fd;
}

static void sfs_init(void *userdata, fuse_conn_info *conn)
{
	(void)userdata;

	if (!fuse_set_feature_flag(conn, FUSE_CAP_PASSTHROUGH))
		fs.passthrough = false;

	/* Passthrough and writeback cache are conflicting modes */
	if (fs.timeout && !fs.passthrough)
		fuse_set_feature_flag(conn, FUSE_CAP_WRITEBACK_CACHE);

	fuse_set_feature_flag(conn, FUSE_CAP_FLOCK_LOCKS);

	if (fs.nosplice) {
		// FUSE_CAP_SPLICE_READ is enabled in libfuse3 by default,
		// see do_init() in fuse_lowlevel.c
		// Just unset all, in case FUSE_CAP_SPLICE_WRITE or
		// FUSE_CAP_SPLICE_MOVE would also get enabled by default.
		fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_READ);
		fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_WRITE);
		fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_MOVE);
	} else {
		fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_WRITE);
		fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_READ);
		fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_MOVE);
	}

	/* This is a local file system - no network coherency needed */
	fuse_set_feature_flag(conn, FUSE_CAP_DIRECT_IO_ALLOW_MMAP);

	/* Disable NFS export support, which also disabled name_to_handle_at.
	 * Goal is to make xfstests that test name_to_handle_at to fail with
	 * the right error code (EOPNOTSUPP) than to open_by_handle_at to fail with
	 * ESTALE and let those test fail.
	 * Perfect NFS export support is not possible with this FUSE filesystem needs
	 * more kernel work, in order to passthrough nfs handle encode/decode to
	 * fuse-server/daemon.
	 */
	fuse_set_feature_flag(conn, FUSE_CAP_NO_EXPORT_SUPPORT);

	/* Disable the receiving and processing of FUSE_INTERRUPT requests */
	conn->no_interrupt = 1;

	/* Try a large IO by default */
	conn->max_write = 4 * 1024 * 1024;
}

static void sfs_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	struct stat attr;
	int fd = fi ? fi->fh : get_inode(ino).fd;

	auto res = fstatat(fd, "", &attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	fuse_reply_attr(req, &attr, fs.timeout);
}

static int with_fd_path(int fd, const std::function<int(const char*)>& f)
{
#ifdef __FreeBSD__
    struct kinfo_file kf;
    kf.kf_structsize = sizeof(kf);
    int ret = fcntl(fd, F_KINFO, &kf);
    if (ret == -1)
        return ret;
    return f (kf.kf_path);
#else // Linux
    char procname[64];
    sprintf(procname, "/proc/self/fd/%i", fd);
    return f(procname);
#endif
}
static void do_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		       int valid, struct fuse_file_info *fi)
{
	Inode &inode = get_inode(ino);
	int ifd = inode.fd;
	int res;

	if (valid & FUSE_SET_ATTR_MODE) {
		if (fi) {
			res = fchmod(fi->fh, attr->st_mode);
		} else {
			res = with_fd_path(ifd, [attr](const char* procname) {
				return chmod(procname, attr->st_mode);
			});
		}
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
		uid_t uid = (valid & FUSE_SET_ATTR_UID) ?
				    attr->st_uid :
				    static_cast<uid_t>(-1);
		gid_t gid = (valid & FUSE_SET_ATTR_GID) ?
				    attr->st_gid :
				    static_cast<gid_t>(-1);

		res = fchownat(ifd, "", uid, gid,
			       AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
		if (res == -1)
			goto out_err;
	}
	if (valid & FUSE_SET_ATTR_SIZE) {
		if (fi) {
			res = ftruncate(fi->fh, attr->st_size);
		} else {
			res = with_fd_path(ifd, [attr](const char* procname) {
				return truncate(procname, attr->st_size);
			});
		}
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		struct timespec tv[2];

		tv[0].tv_sec = 0;
		tv[1].tv_sec = 0;
		tv[0].tv_nsec = UTIME_OMIT;
		tv[1].tv_nsec = UTIME_OMIT;

		if (valid & FUSE_SET_ATTR_ATIME_NOW)
			tv[0].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_ATIME)
			tv[0] = attr->st_atim;

		if (valid & FUSE_SET_ATTR_MTIME_NOW)
			tv[1].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_MTIME)
			tv[1] = attr->st_mtim;

		if (fi)
			res = futimens(fi->fh, tv);
		else {
#ifdef HAVE_UTIMENSAT
			res = with_fd_path(ifd, [&tv](const char* procname) {
				return utimensat(AT_FDCWD, procname, tv, 0);
			});
#else
			res = -1;
			errno = EOPNOTSUPP;
#endif
		}
		if (res == -1)
			goto out_err;
	}
	return sfs_getattr(req, ino, fi);

out_err:
	fuse_reply_err(req, errno);
}

static void sfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			int valid, fuse_file_info *fi)
{
	(void)ino;
	do_setattr(req, ino, attr, valid, fi);
}

static int do_lookup(fuse_ino_t parent, const char *name, fuse_entry_param *e)
{
	if (fs.debug)
		cerr << "DEBUG: lookup(): name=" << name
		     << ", parent=" << parent << endl;
	memset(e, 0, sizeof(*e));
	e->attr_timeout = fs.timeout;
	e->entry_timeout = fs.timeout;

	auto newfd = openat(get_fs_fd(parent), name, O_PATH | O_NOFOLLOW);
	if (newfd == -1)
		return errno;

	auto res = fstatat(newfd, "", &e->attr,
			   AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		auto saveerr = errno;
		close(newfd);
		if (fs.debug)
			cerr << "DEBUG: lookup(): fstatat failed" << endl;
		return saveerr;
	}

	if (e->attr.st_dev != fs.src_dev) {
		cerr << "WARNING: Mountpoints in the source directory tree will be hidden."
		     << endl;
		return ENOTSUP;
	} else if (e->attr.st_ino == FUSE_ROOT_ID) {
		cerr << "ERROR: Source directory tree must not include inode "
		     << FUSE_ROOT_ID << endl;
		return EIO;
	}

	SrcId id{ e->attr.st_ino, e->attr.st_dev };
	unique_lock<mutex> fs_lock{ fs.mutex };
	Inode *inode_p;
	try {
		inode_p = &fs.inodes[id];
	} catch (std::bad_alloc &) {
		return ENOMEM;
	}
	e->ino = reinterpret_cast<fuse_ino_t>(inode_p);
	Inode &inode{ *inode_p };
	e->generation = inode.generation;

	if (inode.fd == -ENOENT) { // found unlinked inode
		if (fs.debug)
			cerr << "DEBUG: lookup(): inode " << e->attr.st_ino
			     << " recycled; generation=" << inode.generation
			     << endl;
		/* fallthrough to new inode but keep existing inode.nlookup */
	}

	if (inode.fd > 0) { // found existing inode
		fs_lock.unlock();
		if (fs.debug)
			cerr << "DEBUG: lookup(): inode " << e->attr.st_ino
			     << " (userspace) already known; fd = " << inode.fd
			     << endl;
		lock_guard<mutex> g{ inode.m };

		inode.nlookup++;
		if (fs.debug)
			cerr << "DEBUG:" << __func__ << ":" << __LINE__ << " "
			     << "inode " << inode.src_ino << " count "
			     << inode.nlookup << endl;

		close(newfd);
	} else { // no existing inode
		/* This is just here to make Helgrind happy. It violates the
		 * lock ordering requirement (inode.m must be acquired before
		 * fs.mutex), but this is of no consequence because at this
		 * point no other thread has access to the inode mutex
		 */
		lock_guard<mutex> g{ inode.m };
		inode.src_ino = e->attr.st_ino;
		inode.src_dev = e->attr.st_dev;

		inode.nlookup++;
		if (fs.debug)
			cerr << "DEBUG:" << __func__ << ":" << __LINE__ << " "
			     << "inode " << inode.src_ino << " count "
			     << inode.nlookup << endl;

		inode.fd = newfd;
		fs_lock.unlock();

		if (fs.debug)
			cerr << "DEBUG: lookup(): created userspace inode "
			     << e->attr.st_ino << "; fd = " << inode.fd << endl;
	}

	return 0;
}

static void sfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fuse_entry_param e{};
	auto err = do_lookup(parent, name, &e);
	if (err == ENOENT) {
		e.attr_timeout = fs.timeout;
		e.entry_timeout = fs.timeout;
		e.ino = e.attr.st_ino = 0;
		fuse_reply_entry(req, &e);
	} else if (err) {
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors."
			     << endl;
		fuse_reply_err(req, err);
	} else {
		fuse_reply_entry(req, &e);
	}
}

static void mknod_symlink(fuse_req_t req, fuse_ino_t parent, const char *name,
			  mode_t mode, dev_t rdev, const char *link)
{
	int res;
	Inode &inode_p = get_inode(parent);
	auto saverr = ENOMEM;

	if (S_ISDIR(mode))
		res = mkdirat(inode_p.fd, name, mode);
	else if (S_ISLNK(mode))
		res = symlinkat(link, inode_p.fd, name);
	else
		res = mknodat(inode_p.fd, name, mode, rdev);
	saverr = errno;
	if (res == -1)
		goto out;

	fuse_entry_param e;
	saverr = do_lookup(parent, name, &e);
	if (saverr)
		goto out;

	fuse_reply_entry(req, &e);
	return;

out:
	if (saverr == ENFILE || saverr == EMFILE)
		cerr << "ERROR: Reached maximum number of file descriptors."
		     << endl;
	fuse_reply_err(req, saverr);
}

static void sfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode, dev_t rdev)
{
	mknod_symlink(req, parent, name, mode, rdev, nullptr);
}

static void sfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode)
{
	mknod_symlink(req, parent, name, S_IFDIR | mode, 0, nullptr);
}

static void sfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
			const char *name)
{
	mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}

static void sfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
		     const char *name)
{
	Inode &inode = get_inode(ino);
	Inode &inode_p = get_inode(parent);
	fuse_entry_param e{};

	e.attr_timeout = fs.timeout;
	e.entry_timeout = fs.timeout;

	char procname[64];
	sprintf(procname, "/proc/self/fd/%i", inode.fd);
	auto res =
		linkat(AT_FDCWD, procname, inode_p.fd, name, AT_SYMLINK_FOLLOW);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}

	res = fstatat(inode.fd, "", &e.attr,
		      AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	e.ino = reinterpret_cast<fuse_ino_t>(&inode);
	{
		lock_guard<mutex> g{ inode.m };
		inode.nlookup++;
		if (fs.debug)
			cerr << "DEBUG:" << __func__ << ":" << __LINE__ << " "
			     << "inode " << inode.src_ino << " count "
			     << inode.nlookup << endl;
	}

	fuse_reply_entry(req, &e);
	return;
}

static void sfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	Inode &inode_p = get_inode(parent);
	lock_guard<mutex> g{ inode_p.m };
	auto res = unlinkat(inode_p.fd, name, AT_REMOVEDIR);
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void sfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		       fuse_ino_t newparent, const char *newname,
		       unsigned int flags)
{
	Inode &inode_p = get_inode(parent);
	Inode &inode_np = get_inode(newparent);
	if (flags) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	auto res = renameat(inode_p.fd, name, inode_np.fd, newname);
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void sfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	Inode &inode_p = get_inode(parent);
	// Release inode.fd before last unlink like nfsd EXPORT_OP_CLOSE_BEFORE_UNLINK
	// to test reused inode numbers.
	// Skip this when inode has an open file and when writeback cache is enabled.
	if (!fs.timeout) {
		fuse_entry_param e;
		auto err = do_lookup(parent, name, &e);
		if (err) {
			fuse_reply_err(req, err);
			return;
		}
		if (e.attr.st_nlink == 1) {
			Inode &inode = get_inode(e.ino);
			lock_guard<mutex> g{ inode.m };
			if (inode.fd > 0 && !inode.nopen) {
				if (fs.debug)
					cerr << "DEBUG: unlink: release inode "
					     << e.attr.st_ino
					     << "; fd=" << inode.fd << endl;
				lock_guard<mutex> g_fs{ fs.mutex };
				close(inode.fd);
				inode.fd = -ENOENT;
				inode.generation++;
			}
		}

		// decrease the ref which lookup above had increased
		forget_one(e.ino, 1);
	}
	auto res = unlinkat(inode_p.fd, name, 0);
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void forget_one(fuse_ino_t ino, uint64_t n)
{
	Inode &inode = get_inode(ino);
	unique_lock<mutex> l{ inode.m };

	if (n > inode.nlookup) {
		cerr << "INTERNAL ERROR: Negative lookup count for inode "
		     << inode.src_ino << endl;
		abort();
	}
	inode.nlookup -= n;

	if (fs.debug)
		cerr << "DEBUG:" << __func__ << ":" << __LINE__ << " "
		     << "inode " << inode.src_ino << " count " << inode.nlookup
		     << endl;

	if (!inode.nlookup) {
		if (fs.debug)
			cerr << "DEBUG: forget: cleaning up inode "
			     << inode.src_ino << endl;
		{
			lock_guard<mutex> g_fs{ fs.mutex };
			l.unlock();
			fs.inodes.erase({ inode.src_ino, inode.src_dev });
		}
	} else if (fs.debug)
		cerr << "DEBUG: forget: inode " << inode.src_ino
		     << " lookup count now " << inode.nlookup << endl;
}

static void sfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	forget_one(ino, nlookup);
	fuse_reply_none(req);
}

static void sfs_forget_multi(fuse_req_t req, size_t count,
			     fuse_forget_data *forgets)
{
	for (int i = 0; i < count; i++)
		forget_one(forgets[i].ino, forgets[i].nlookup);
	fuse_reply_none(req);
}

static void sfs_readlink(fuse_req_t req, fuse_ino_t ino)
{
	Inode &inode = get_inode(ino);
	char buf[PATH_MAX + 1];
	auto res = readlinkat(inode.fd, "", buf, sizeof(buf));
	if (res == -1)
		fuse_reply_err(req, errno);
	else if (res == sizeof(buf))
		fuse_reply_err(req, ENAMETOOLONG);
	else {
		buf[res] = '\0';
		fuse_reply_readlink(req, buf);
	}
}

struct DirHandle {
	DIR *dp{ nullptr };
	off_t offset;

	DirHandle() = default;
	DirHandle(const DirHandle &) = delete;
	DirHandle &operator=(const DirHandle &) = delete;

	~DirHandle()
	{
		if (dp)
			closedir(dp);
	}
};

static DirHandle *get_dir_handle(fuse_file_info *fi)
{
	return reinterpret_cast<DirHandle *>(fi->fh);
}

static void sfs_opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	Inode &inode = get_inode(ino);
	auto d = new (nothrow) DirHandle;
	if (d == nullptr) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	// Make Helgrind happy - it can't know that there's an implicit
	// synchronization due to the fact that other threads cannot
	// access d until we've called fuse_reply_*.
	lock_guard<mutex> g{ inode.m };

	auto fd = openat(inode.fd, ".", O_RDONLY);
	if (fd == -1)
		goto out_errno;

	// On success, dir stream takes ownership of fd, so we
	// do not have to close it.
	d->dp = fdopendir(fd);
	if (d->dp == nullptr)
		goto out_errno;

	d->offset = 0;

	fi->fh = reinterpret_cast<uint64_t>(d);
	if (fs.timeout) {
		fi->keep_cache = 1;
		fi->cache_readdir = 1;
	}
	fuse_reply_open(req, fi);
	return;

out_errno:
	auto error = errno;
	delete d;
	if (error == ENFILE || error == EMFILE)
		cerr << "ERROR: Reached maximum number of file descriptors."
		     << endl;
	fuse_reply_err(req, error);
}

static bool is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' &&
	       (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static void do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t offset, fuse_file_info *fi, const int plus)
{
	auto d = get_dir_handle(fi);
	Inode &inode = get_inode(ino);
	lock_guard<mutex> g{ inode.m };
	char *p;
	auto rem = size;
	int err = 0, count = 0;

	if (fs.debug)
		cerr << "DEBUG: readdir(): started with offset " << offset
		     << endl;

	auto buf = new (nothrow) char[size];
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}
	p = buf;

	if (offset != d->offset) {
		if (fs.debug)
			cerr << "DEBUG: readdir(): seeking to " << offset
			     << endl;
		seekdir(d->dp, offset);
		d->offset = offset;
	}

	while (1) {
		bool did_lookup = false;
		struct dirent *entry;
		errno = 0;
		entry = readdir(d->dp);
		if (!entry) {
			if (errno) {
				err = errno;
				if (fs.debug)
					warn("DEBUG: readdir(): readdir failed with");
				goto error;
			}
			break; // End of stream
		}
		d->offset = entry->d_off;

		fuse_entry_param e{};
		size_t entsize;
		if (plus) {
			if (is_dot_or_dotdot(entry->d_name)) {
				/* fuse kernel ignores attributes for these and also does
				 * not increase lookup count (see fuse_direntplus_link)
				 */
				e.attr.st_ino = entry->d_ino;
				e.attr.st_mode = entry->d_type << 12;
			} else {
				err = do_lookup(ino, entry->d_name, &e);
				if (err)
					goto error;
				did_lookup = true;
			}
			entsize = fuse_add_direntry_plus(
				req, p, rem, entry->d_name, &e, entry->d_off);
		} else {
			e.attr.st_ino = entry->d_ino;
			e.attr.st_mode = entry->d_type << 12;
			entsize = fuse_add_direntry(req, p, rem, entry->d_name,
						    &e.attr, entry->d_off);
		}

		if (entsize > rem) {
			if (fs.debug)
				cerr << "DEBUG: readdir(): buffer full, returning data. "
				     << endl;
			if (did_lookup)
				forget_one(e.ino, 1);
			break;
		}

		p += entsize;
		rem -= entsize;
		count++;
		if (fs.debug) {
			cerr << "DEBUG: readdir(): added to buffer: "
			     << entry->d_name << ", ino " << e.attr.st_ino
			     << ", offset " << entry->d_off << endl;
		}
	}
	err = 0;
error:

	// If there's an error, we can only signal it if we haven't stored
	// any entries yet - otherwise we'd end up with wrong lookup
	// counts for the entries that are already in the buffer. So we
	// return what we've collected until that point.
	if (err && rem == size) {
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors."
			     << endl;
		fuse_reply_err(req, err);
	} else {
		if (fs.debug)
			cerr << "DEBUG: readdir(): returning " << count
			     << " entries, curr offset " << d->offset << endl;
		fuse_reply_buf(req, buf, size - rem);
	}
	delete[] buf;
	return;
}

static void sfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			off_t offset, fuse_file_info *fi)
{
	// operation logging is done in readdir to reduce code duplication
	do_readdir(req, ino, size, offset, fi, 0);
}

static void sfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			    off_t offset, fuse_file_info *fi)
{
	// operation logging is done in readdir to reduce code duplication
	do_readdir(req, ino, size, offset, fi, 1);
}

static void sfs_releasedir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	(void)ino;
	auto d = get_dir_handle(fi);
	delete d;
	fuse_reply_err(req, 0);
}

static void do_passthrough_open(fuse_req_t req, fuse_ino_t ino, int fd,
				fuse_file_info *fi)
{
	Inode &inode = get_inode(ino);
	/* Setup a shared backing file on first open of an inode */
	if (inode.backing_id) {
		if (fs.debug)
			cerr << "DEBUG: reusing shared backing file "
			     << inode.backing_id << " for inode " << ino
			     << endl;
		fi->backing_id = inode.backing_id;
	} else if (!(inode.backing_id = fuse_passthrough_open(req, fd))) {
		cerr << "DEBUG: fuse_passthrough_open failed for inode " << ino
		     << ", disabling rw passthrough." << endl;
		fs.passthrough = false;
	} else {
		if (fs.debug)
			cerr << "DEBUG: setup shared backing file "
			     << inode.backing_id << " for inode " << ino
			     << endl;
		fi->backing_id = inode.backing_id;
	}
	/* open in passthrough mode must drop old page cache */
	if (fi->backing_id)
		fi->keep_cache = false;
}

static void sfs_create_open_flags(fuse_file_info *fi)
{
	if (fs.direct_io)
		fi->direct_io = 1;

	/*
	 * fi->direct_io (FOPEN_DIRECT_IO) is set to benefit from
	 * parallel_direct_writes, which kernel cannot do for plain O_DIRECT.
	 * However, passthrough is preferred, but which is not possible when
	 * FOPEN_DIRECT_IO is set.
	 */
	if (!fs.passthrough) {
		if (fi->flags & O_DIRECT)
			fi->direct_io = 1;
	}

	/* parallel_direct_writes feature depends on direct_io features.
	 * To make parallel_direct_writes valid, need set fi->direct_io
	 * in current function.
	 */
	fi->parallel_direct_writes = 1;

	fi->keep_cache = (fs.timeout != 0);
	fi->noflush = (fs.timeout == 0 && (fi->flags & O_ACCMODE) == O_RDONLY);
}

static void sfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, fuse_file_info *fi)
{
	Inode &inode_p = get_inode(parent);

	auto fd = openat(inode_p.fd, name, (fi->flags | O_CREAT) & ~O_NOFOLLOW,
			 mode);
	if (fd == -1) {
		auto err = errno;
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors."
			     << endl;
		fuse_reply_err(req, err);
		return;
	}

	fi->fh = fd;
	fuse_entry_param e;
	auto err = do_lookup(parent, name, &e);
	if (err) {
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors."
			     << endl;
		fuse_reply_err(req, err);
		return;
	}

	Inode &inode = get_inode(e.ino);
	lock_guard<mutex> g{ inode.m };
	inode.nopen++;

	sfs_create_open_flags(fi);

	if (fs.passthrough)
		do_passthrough_open(req, e.ino, fd, fi);
	fuse_reply_create(req, &e, fi);
}

#ifdef O_TMPFILE
static Inode *create_new_inode(int fd, fuse_entry_param *e)
{
	memset(e, 0, sizeof(*e));
	e->attr_timeout = fs.timeout;
	e->entry_timeout = fs.timeout;

	auto res =
		fstatat(fd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		if (fs.debug)
			cerr << "DEBUG: lookup(): fstatat failed" << endl;
		return NULL;
	}

	SrcId id{ e->attr.st_ino, e->attr.st_dev };
	unique_lock<mutex> fs_lock{ fs.mutex };
	Inode *p_inode;
	try {
		p_inode = &fs.inodes[id];
	} catch (std::bad_alloc &) {
		return NULL;
	}

	e->ino = reinterpret_cast<fuse_ino_t>(p_inode);
	e->generation = p_inode->generation;

	lock_guard<mutex> g{ p_inode->m };
	p_inode->src_ino = e->attr.st_ino;
	p_inode->src_dev = e->attr.st_dev;

	p_inode->nlookup++;
	if (fs.debug)
		cerr << "DEBUG:" << __func__ << ":" << __LINE__ << " "
		     << "inode " << p_inode->src_ino << " count "
		     << p_inode->nlookup << endl;

	p_inode->fd = fd;
	fs_lock.unlock();

	if (fs.debug)
		cerr << "DEBUG: lookup(): created userspace inode "
		     << e->attr.st_ino << "; fd = " << p_inode->fd << endl;
	return p_inode;
}

static void sfs_tmpfile(fuse_req_t req, fuse_ino_t parent, mode_t mode,
			fuse_file_info *fi)
{
	Inode &parent_inode = get_inode(parent);

	auto fd = openat(parent_inode.fd, ".",
			 (fi->flags | O_TMPFILE) & ~O_NOFOLLOW, mode);
	if (fd == -1) {
		auto err = errno;
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors."
			     << endl;
		fuse_reply_err(req, err);
		return;
	}

	fi->fh = fd;
	fuse_entry_param e;

	Inode *inode = create_new_inode(dup(fd), &e);
	if (inode == NULL) {
		auto err = errno;
		cerr << "ERROR: could not create new inode." << endl;
		close(fd);
		fuse_reply_err(req, err);
		return;
	}

	lock_guard<mutex> g{ inode->m };

	sfs_create_open_flags(fi);

	if (fs.passthrough)
		do_passthrough_open(req, e.ino, fd, fi);

	fuse_reply_create(req, &e, fi);
}
#endif
static void sfs_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
			 fuse_file_info *fi)
{
	(void)ino;
	int res;
	int fd = dirfd(get_dir_handle(fi)->dp);
	if (datasync)
		res = fdatasync(fd);
	else
		res = fsync(fd);
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void sfs_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	Inode &inode = get_inode(ino);

	/* With writeback cache, kernel may send read requests even
       when userspace opened write-only */
	if (fs.timeout && (fi->flags & O_ACCMODE) == O_WRONLY) {
		fi->flags &= ~O_ACCMODE;
		fi->flags |= O_RDWR;
	}

	/* With writeback cache, O_APPEND is handled by the kernel.  This
	 * breaks atomicity (since the file may change in the underlying
	 * filesystem, so that the kernel's idea of the end of the file
	 * isn't accurate anymore). However, no process should modify the
	 * file in the underlying filesystem once it has been read, so
	 * this is not a problem.
	 */
	if (fs.timeout && fi->flags & O_APPEND)
		fi->flags &= ~O_APPEND;

	/* Unfortunately we cannot use inode.fd, because this was opened
       with O_PATH (so it doesn't allow read/write access). */
	auto fd = with_fd_path(inode.fd, [fi](const char* buf) {
		return open(buf, fi->flags & ~O_NOFOLLOW);
	});
	if (fd == -1) {
		auto err = errno;
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors."
			     << endl;
		fuse_reply_err(req, err);
		return;
	}

	lock_guard<mutex> g{ inode.m };
	inode.nopen++;

	sfs_create_open_flags(fi);

	fi->fh = fd;
	if (fs.passthrough)
		do_passthrough_open(req, ino, fd, fi);
	fuse_reply_open(req, fi);
}

static void sfs_release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	Inode &inode = get_inode(ino);
	lock_guard<mutex> g{ inode.m };
	inode.nopen--;

	/* Close the shared backing file on last file close of an inode */
	if (inode.backing_id && !inode.nopen) {
		if (fuse_passthrough_close(req, inode.backing_id) < 0) {
			cerr << "DEBUG: fuse_passthrough_close failed for inode "
			     << ino << " backing file " << inode.backing_id
			     << endl;
		} else if (fs.debug) {
			cerr << "DEBUG: closed backing file "
			     << inode.backing_id << " for inode " << ino
			     << endl;
		}
		inode.backing_id = 0;
	}

	close(fi->fh);
	fuse_reply_err(req, 0);
}

static void sfs_flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	(void)ino;
	auto res = close(dup(fi->fh));
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void sfs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
		      fuse_file_info *fi)
{
	(void)ino;
	int res;
	if (datasync)
		res = fdatasync(fi->fh);
	else
		res = fsync(fi->fh);
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void do_read(fuse_req_t req, size_t size, off_t off, fuse_file_info *fi)
{
	fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
	buf.buf[0].flags =
		static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
	buf.buf[0].fd = fi->fh;
	buf.buf[0].pos = off;

	fuse_reply_data(req, &buf, FUSE_BUF_COPY_FLAGS);
}

static void sfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		     fuse_file_info *fi)
{
	(void)ino;
	if (fs.passthrough && !fs.direct_io) {
		cerr << "ERROR: fuse_passthrough read failed." << endl;
		fuse_reply_err(req, EIO);
		return;
	}
	do_read(req, size, off, fi);
}

static void do_write_buf(fuse_req_t req, size_t size, off_t off,
			 fuse_bufvec *in_buf, fuse_file_info *fi)
{
	fuse_bufvec out_buf = FUSE_BUFVEC_INIT(size);
	out_buf.buf[0].flags =
		static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
	out_buf.buf[0].fd = fi->fh;
	out_buf.buf[0].pos = off;

	auto res = fuse_buf_copy(&out_buf, in_buf, FUSE_BUF_COPY_FLAGS);
	if (res < 0)
		fuse_reply_err(req, -res);
	else
		fuse_reply_write(req, (size_t)res);
}

static void sfs_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *in_buf,
			  off_t off, fuse_file_info *fi)
{
	(void)ino;
	if (fs.passthrough && !fs.direct_io) {
		cerr << "ERROR: fuse_passthrough write failed." << endl;
		fuse_reply_err(req, EIO);
		return;
	}
	auto size{ fuse_buf_size(in_buf) };
	do_write_buf(req, size, off, in_buf, fi);
}

static void sfs_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct statvfs stbuf;

	auto res = fstatvfs(get_fs_fd(ino), &stbuf);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_statfs(req, &stbuf);
}

static void sfs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
			  off_t offset, off_t length, fuse_file_info *fi)
{
	(void)ino;

	auto err = -do_fallocate(fi->fh, mode, offset, length);

	fuse_reply_err(req, err);
}

static void sfs_flock(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi,
		      int op)
{
	(void)ino;
	auto res = flock(fi->fh, op);
	fuse_reply_err(req, res == -1 ? errno : 0);
}

#ifdef HAVE_SETXATTR
static void sfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			 size_t size)
{
	char *value = nullptr;
	Inode &inode = get_inode(ino);
	ssize_t ret;
	int saverr;

	char procname[64];
	sprintf(procname, "/proc/self/fd/%i", inode.fd);

	if (size) {
		value = new (nothrow) char[size];
		if (value == nullptr) {
			saverr = ENOMEM;
			goto out;
		}

		ret = getxattr(procname, name, value, size);
		if (ret == -1)
			goto out_err;
		saverr = 0;
		if (ret == 0)
			goto out;

		fuse_reply_buf(req, value, ret);
	} else {
		ret = getxattr(procname, name, nullptr, 0);
		if (ret == -1)
			goto out_err;

		fuse_reply_xattr(req, ret);
	}
out_free:
	delete[] value;
	return;

out_err:
	saverr = errno;
out:
	fuse_reply_err(req, saverr);
	goto out_free;
}

static void sfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	char *value = nullptr;
	Inode &inode = get_inode(ino);
	ssize_t ret;
	int saverr;

	char procname[64];
	sprintf(procname, "/proc/self/fd/%i", inode.fd);

	if (size) {
		value = new (nothrow) char[size];
		if (value == nullptr) {
			saverr = ENOMEM;
			goto out;
		}

		ret = listxattr(procname, value, size);
		if (ret == -1)
			goto out_err;
		saverr = 0;
		if (ret == 0)
			goto out;

		fuse_reply_buf(req, value, ret);
	} else {
		ret = listxattr(procname, nullptr, 0);
		if (ret == -1)
			goto out_err;

		fuse_reply_xattr(req, ret);
	}
out_free:
	delete[] value;
	return;
out_err:
	saverr = errno;
out:
	fuse_reply_err(req, saverr);
	goto out_free;
}

static void sfs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			 const char *value, size_t size, int flags)
{
	Inode &inode = get_inode(ino);
	ssize_t ret;
	int saverr;

	char procname[64];
	sprintf(procname, "/proc/self/fd/%i", inode.fd);

	ret = setxattr(procname, name, value, size, flags);
	saverr = ret == -1 ? errno : 0;

	fuse_reply_err(req, saverr);
}

static void sfs_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	char procname[64];
	Inode &inode = get_inode(ino);
	ssize_t ret;
	int saverr;

	sprintf(procname, "/proc/self/fd/%i", inode.fd);
	ret = removexattr(procname, name);
	saverr = ret == -1 ? errno : 0;

	fuse_reply_err(req, saverr);
}
#endif

static void assign_operations(fuse_lowlevel_ops &sfs_oper)
{
	sfs_oper.init = sfs_init;
	sfs_oper.lookup = sfs_lookup;
	sfs_oper.mkdir = sfs_mkdir;
	sfs_oper.mknod = sfs_mknod;
	sfs_oper.symlink = sfs_symlink;
	sfs_oper.link = sfs_link;
	sfs_oper.unlink = sfs_unlink;
	sfs_oper.rmdir = sfs_rmdir;
	sfs_oper.rename = sfs_rename;
	sfs_oper.forget = sfs_forget;
	sfs_oper.forget_multi = sfs_forget_multi;
	sfs_oper.getattr = sfs_getattr;
	sfs_oper.setattr = sfs_setattr;
	sfs_oper.readlink = sfs_readlink;
	sfs_oper.opendir = sfs_opendir;
	sfs_oper.readdir = sfs_readdir;
	sfs_oper.readdirplus = sfs_readdirplus;
	sfs_oper.releasedir = sfs_releasedir;
	sfs_oper.fsyncdir = sfs_fsyncdir;
	sfs_oper.create = sfs_create;
#ifdef O_TMPFILE
	sfs_oper.tmpfile = sfs_tmpfile;
#endif
	sfs_oper.open = sfs_open;
	sfs_oper.release = sfs_release;
	sfs_oper.flush = sfs_flush;
	sfs_oper.fsync = sfs_fsync;
	sfs_oper.read = sfs_read;
	sfs_oper.write_buf = sfs_write_buf;
	sfs_oper.statfs = sfs_statfs;
	sfs_oper.fallocate = sfs_fallocate;
	sfs_oper.flock = sfs_flock;
#ifdef HAVE_SETXATTR
	sfs_oper.setxattr = sfs_setxattr;
	sfs_oper.getxattr = sfs_getxattr;
	sfs_oper.listxattr = sfs_listxattr;
	sfs_oper.removexattr = sfs_removexattr;
#endif
}

static void print_usage(char *prog_name)
{
	cout << "Usage: " << prog_name << " --help\n"
	     << "       " << prog_name << " [options] <source> <mountpoint>\n";
}

static cxxopts::ParseResult parse_wrapper(cxxopts::Options &parser, int &argc,
					  char **&argv)
{
	try {
		return parser.parse(argc, argv);
	} catch (cxxopts::option_not_exists_exception &exc) {
		std::cout << argv[0] << ": " << exc.what() << std::endl;
		print_usage(argv[0]);
		exit(2);
	}
}

static void string_split(std::string s, std::vector<std::string> &out,
			 std::string delimiter)
{
	size_t pos_start = 0, pos_end, delim_len = delimiter.length();
	std::string token;

	while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
		token = s.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		out.push_back(token);
	}

	out.push_back(s.substr(pos_start));
}

static std::string string_join(const std::vector<std::string> &elems,
			       char delim)
{
	std::ostringstream out;
	for (auto ii = elems.begin(); ii != elems.end(); ++ii) {
		out << (*ii);
		if (ii + 1 != elems.end()) {
			out << delim;
		}
	}
	return out.str();
}

static cxxopts::ParseResult parse_options(int argc, char **argv)
{
	cxxopts::Options opt_parser(argv[0]);
	std::vector<std::string> mount_options;
	opt_parser.add_options()("debug", "Enable filesystem debug messages")(
		"debug-fuse", "Enable libfuse debug messages")(
		"foreground", "Run in foreground")("help", "Print help")(
		"nocache", "Disable attribute all caching")(
		"nosplice", "Do not use splice(2) to transfer data")(
		"nopassthrough", "Do not use pass-through mode for read/write")(
		"single", "Run single-threaded")(
		"o",
		"Mount options (see mount.fuse(5) - only use if you know what "
		"you are doing)",
		cxxopts::value(mount_options))(
		"num-threads", "Number of libfuse worker threads",
		cxxopts::value<int>()->default_value(SFS_DEFAULT_THREADS))(
		"clone-fd", "use separate fuse device fd for each thread")(
		"direct-io", "enable fuse kernel internal direct-io");

	// FIXME: Find a better way to limit the try clause to just
	// opt_parser.parse() (cf. https://github.com/jarro2783/cxxopts/issues/146)
	auto options = parse_wrapper(opt_parser, argc, argv);

	if (options.count("help")) {
		print_usage(argv[0]);
		// Strip everything before the option list from the
		// default help string.
		auto help = opt_parser.help();
		std::cout << std::endl
			  << "options:"
			  << help.substr(help.find("\n\n") + 1, string::npos);
		std::cout << "\nFuse lowlevel options:\n";
		fuse_lowlevel_help();
		exit(0);

	} else if (argc != 3) {
		std::cout << argv[0] << ": invalid number of arguments\n";
		print_usage(argv[0]);
		exit(2);
	}

	fs.debug = options.count("debug") != 0;
	fs.debug_fuse = options.count("debug-fuse") != 0;

	fs.foreground = options.count("foreground") != 0;
	if (fs.debug || fs.debug_fuse)
		fs.foreground = true;

	fs.nosplice = options.count("nosplice") != 0;
	fs.passthrough = options.count("nopassthrough") == 0;
	fs.num_threads = options["num-threads"].as<int>();
	fs.clone_fd = options.count("clone-fd");
	fs.direct_io = options.count("direct-io");

	char *resolved_path = realpath(argv[1], NULL);
	if (resolved_path == NULL)
		warn("WARNING: realpath() failed with");
	fs.source = std::string{ resolved_path };
	free(resolved_path);

	std::vector<std::string> flattened_mount_opts;
	for (auto opt : mount_options) {
		string_split(opt, flattened_mount_opts, ",");
	}

	bool found_fsname = false;
	for (auto opt : flattened_mount_opts) {
		if (opt.find("fsname=") == 0) {
			found_fsname = true;
			continue;
		}

		/* Filter out some obviously incorrect options. */
		if (opt == "fd") {
			std::cout << argv[0]
				  << ": Unsupported mount option: " << opt
				  << "\n";
			print_usage(argv[0]);
			exit(2);
		}
	}
	if (!found_fsname) {
		flattened_mount_opts.push_back("fsname=" + fs.source);
	}
	flattened_mount_opts.push_back("default_permissions");
	fs.fuse_mount_options = string_join(flattened_mount_opts, ',');
	return options;
}

static void maximize_fd_limit()
{
	struct rlimit lim {};
	auto res = getrlimit(RLIMIT_NOFILE, &lim);
	if (res != 0) {
		warn("WARNING: getrlimit() failed with");
		return;
	}
	lim.rlim_cur = lim.rlim_max;
	res = setrlimit(RLIMIT_NOFILE, &lim);
	if (res != 0)
		warn("WARNING: setrlimit() failed with");
}

int main(int argc, char *argv[])
{
	struct fuse_loop_config *loop_config = NULL;

	// Parse command line options
	auto options{ parse_options(argc, argv) };

	// We need an fd for every dentry in our the filesystem that the
	// kernel knows about. This is way more than most processes need,
	// so try to get rid of any resource softlimit.
	maximize_fd_limit();

	// Initialize filesystem root
	fs.root.fd = -1;
	fs.root.nlookup = 9999;
	fs.timeout = options.count("nocache") ? 0 : 86400.0;

	struct stat stat;
	auto ret = lstat(fs.source.c_str(), &stat);
	if (ret == -1)
		err(1, "ERROR: failed to stat source (\"%s\")",
		    fs.source.c_str());
	if (!S_ISDIR(stat.st_mode))
		errx(1, "ERROR: source is not a directory");
	fs.src_dev = stat.st_dev;

	fs.root.fd = open(fs.source.c_str(), O_PATH);
	if (fs.root.fd == -1)
		err(1, "ERROR: open(\"%s\", O_PATH)", fs.source.c_str());

	// Initialize fuse
	fuse_args args = FUSE_ARGS_INIT(0, nullptr);
	if (fuse_opt_add_arg(&args, argv[0]) || fuse_opt_add_arg(&args, "-o") ||
	    fuse_opt_add_arg(&args, fs.fuse_mount_options.c_str()) ||
	    (fs.debug_fuse && fuse_opt_add_arg(&args, "-odebug")))
		errx(3, "ERROR: Out of memory adding arguments");

	ret = -1;
	fuse_lowlevel_ops sfs_oper{};
	assign_operations(sfs_oper);
	auto se = fuse_session_new(&args, &sfs_oper, sizeof(sfs_oper), &fs);
	if (se == nullptr)
		goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;

	if (fuse_set_fail_signal_handlers(se) != 0)
		goto err_out2;

	// Don't apply umask, use modes exactly as specified
	umask(0);

	// Mount and run main loop
	loop_config = fuse_loop_cfg_create();

	if (fs.num_threads != -1)
		fuse_loop_cfg_set_max_threads(loop_config, fs.num_threads);

	fuse_loop_cfg_set_clone_fd(loop_config, fs.clone_fd);

	if (fuse_session_mount(se, argv[2]) != 0)
		goto err_out3;

	fuse_daemonize(fs.foreground);

	if (!fs.foreground)
		fuse_log_enable_syslog("passthrough-hp", LOG_PID | LOG_CONS,
				       LOG_DAEMON);

	if (options.count("single"))
		ret = fuse_session_loop(se);
	else
		ret = fuse_session_loop_mt(se, loop_config);

	fuse_session_unmount(se);

err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:

	fuse_loop_cfg_destroy(loop_config);
	fuse_opt_free_args(&args);

	if (!fs.foreground)
		fuse_log_close_syslog();

	return ret ? 1 : 0;
}
