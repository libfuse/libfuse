/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#ifdef KERNEL_2_6
#include <linux/gfp.h>
#else
#include <linux/mm.h>
#endif
#include <linux/sched.h>
#ifdef KERNEL_2_6_8_PLUS
#include <linux/namei.h>
#endif

static inline unsigned long time_to_jiffies(unsigned long sec,
					    unsigned long nsec)
{
	struct timespec ts = {sec, nsec};
	return jiffies + timespec_to_jiffies(&ts);
}

static void fuse_lookup_init(struct fuse_req *req, struct inode *dir,
			     struct dentry *entry,
			     struct fuse_entry_out *outarg)
{
	req->in.h.opcode = FUSE_LOOKUP;
	req->in.h.nodeid = get_node_id(dir);
	req->inode = dir;
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_entry_out);
	req->out.args[0].value = outarg;
}

static int fuse_dentry_revalidate(struct dentry *entry, struct nameidata *nd)
{
	if (!entry->d_inode || is_bad_inode(entry->d_inode))
		return 0;
	else if (time_after(jiffies, entry->d_time)) {
		int err;
		int version;
		struct fuse_entry_out outarg;
		struct inode *inode = entry->d_inode;
		struct fuse_inode *fi = get_fuse_inode(inode);
		struct fuse_conn *fc = get_fuse_conn(inode);
		struct fuse_req *req = fuse_get_request_nonint(fc);
		if (!req)
			return 0;

		fuse_lookup_init(req, entry->d_parent->d_inode, entry, &outarg);
		request_send_nonint(fc, req);
		version = req->out.h.unique;
		err = req->out.h.error;
		fuse_put_request(fc, req);
		if (err || outarg.nodeid != get_node_id(inode) ||
		    (outarg.attr.mode ^ inode->i_mode) & S_IFMT)
			return 0;

		fuse_change_attributes(inode, &outarg.attr);
		inode->i_version = version;
		entry->d_time = time_to_jiffies(outarg.entry_valid,
						outarg.entry_valid_nsec);
		fi->i_time = time_to_jiffies(outarg.attr_valid,
					     outarg.attr_valid_nsec);
	}
	return 1;
}
#ifndef KERNEL_2_6
static int fuse_dentry_revalidate_2_4(struct dentry *entry, int flags)
{
	return fuse_dentry_revalidate(entry, NULL);
}
#endif

static struct dentry_operations fuse_dentry_operations = {
#ifdef KERNEL_2_6
	.d_revalidate	= fuse_dentry_revalidate,
#else
	.d_revalidate	= fuse_dentry_revalidate_2_4,
#endif
};

static int fuse_lookup_iget(struct inode *dir, struct dentry *entry,
			    struct inode **inodep)
{
	int err;
	int version;
	struct fuse_entry_out outarg;
	struct inode *inode = NULL;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req;

	if (entry->d_name.len > FUSE_NAME_MAX)
		return -ENAMETOOLONG;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	fuse_lookup_init(req, dir, entry, &outarg);
	request_send(fc, req);
	version = req->out.h.unique;
	err = req->out.h.error;
	if (!err) {
		inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
				  &outarg.attr, version);
		if (!inode) {
			fuse_send_forget(fc, req, outarg.nodeid, version);
			return -ENOMEM;
		}
	}
	fuse_put_request(fc, req);
	if (err && err != -ENOENT)
		return err;

	if (inode) {
		struct fuse_inode *fi = get_fuse_inode(inode);
		entry->d_time =	time_to_jiffies(outarg.entry_valid,
						outarg.entry_valid_nsec);
		fi->i_time = time_to_jiffies(outarg.attr_valid,
					     outarg.attr_valid_nsec);
	}

	entry->d_op = &fuse_dentry_operations;
	*inodep = inode;
	return 0;
}

void fuse_invalidate_attr(struct inode *inode)
{
	get_fuse_inode(inode)->i_time = jiffies - 1;
}

static void fuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	entry->d_time = jiffies - 1;
}

static int create_new_entry(struct fuse_conn *fc, struct fuse_req *req,
			    struct inode *dir, struct dentry *entry,
			    int mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	struct fuse_inode *fi;
	int version;
	int err;

	req->in.h.nodeid = get_node_id(dir);
	req->inode = dir;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	version = req->out.h.unique;
	err = req->out.h.error;
	if (err) {
		fuse_put_request(fc, req);
		return err;
	}
	inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, version);
	if (!inode) {
		fuse_send_forget(fc, req, outarg.nodeid, version);
		return -ENOMEM;
	}
	fuse_put_request(fc, req);

	/* Don't allow userspace to do really stupid things... */
	if ((inode->i_mode ^ mode) & S_IFMT) {
		iput(inode);
		return -EIO;
	}

	entry->d_time = time_to_jiffies(outarg.entry_valid,
					outarg.entry_valid_nsec);

	fi = get_fuse_inode(inode);
	fi->i_time = time_to_jiffies(outarg.attr_valid,
				     outarg.attr_valid_nsec);

	d_instantiate(entry, inode);
	fuse_invalidate_attr(dir);
	return 0;
}

static int fuse_mknod(struct inode *dir, struct dentry *entry, int mode,
		      dev_t rdev)
{
	struct fuse_mknod_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	req->in.h.opcode = FUSE_MKNOD;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, mode);
}

static int fuse_create(struct inode *dir, struct dentry *entry, int mode,
		       struct nameidata *nd)
{
	return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_mkdir(struct inode *dir, struct dentry *entry, int mode)
{
	struct fuse_mkdir_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	req->in.h.opcode = FUSE_MKDIR;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, S_IFDIR);
}

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	unsigned len = strlen(link) + 1;
	struct fuse_req *req;

	if (len > FUSE_SYMLINK_MAX)
		return -ENAMETOOLONG;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	req->in.h.opcode = FUSE_SYMLINK;
	req->in.numargs = 2;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->in.args[1].size = len;
	req->in.args[1].value = link;
	return create_new_entry(fc, req, dir, entry, S_IFLNK);
}

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	req->in.h.opcode = FUSE_UNLINK;
	req->in.h.nodeid = get_node_id(dir);
	req->inode = dir;
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		struct inode *inode = entry->d_inode;

		/* Set nlink to zero so the inode can be cleared, if
                   the inode does have more links this will be
                   discovered at the next lookup/getattr */
		inode->i_nlink = 0;
		fuse_invalidate_attr(inode);
		fuse_invalidate_attr(dir);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	req->in.h.opcode = FUSE_RMDIR;
	req->in.h.nodeid = get_node_id(dir);
	req->inode = dir;
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		entry->d_inode->i_nlink = 0;
		fuse_invalidate_attr(dir);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rename(struct inode *olddir, struct dentry *oldent,
		       struct inode *newdir, struct dentry *newent)
{
	int err;
	struct fuse_rename_in inarg;
	struct fuse_conn *fc = get_fuse_conn(olddir);
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.newdir = get_node_id(newdir);
	req->in.h.opcode = FUSE_RENAME;
	req->in.h.nodeid = get_node_id(olddir);
	req->inode = olddir;
	req->inode2 = newdir;
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = oldent->d_name.len + 1;
	req->in.args[1].value = oldent->d_name.name;
	req->in.args[2].size = newent->d_name.len + 1;
	req->in.args[2].value = newent->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		fuse_invalidate_attr(olddir);
		if (olddir != newdir)
			fuse_invalidate_attr(newdir);
	} else if (err == -EINTR) {
		/* If request was interrupted, DEITY only knows if the
		   rename actually took place.  If the invalidation
		   fails (e.g. some process has CWD under the renamed
		   directory), then there can be inconsistency between
		   the dcache and the real filesystem.  Tough luck. */
		fuse_invalidate_entry(oldent);
		if (newent->d_inode)
			fuse_invalidate_entry(newent);
	}

	return err;
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	req->in.h.opcode = FUSE_LINK;
	req->inode2 = inode;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = newent->d_name.len + 1;
	req->in.args[1].value = newent->d_name.name;
	err = create_new_entry(fc, req, newdir, newent, inode->i_mode);
	/* Contrary to "normal" filesystems it can happen that link
	   makes two "logical" inodes point to the same "physical"
	   inode.  We invalidate the attributes of the old one, so it
	   will reflect changes in the backing inode (link count,
	   etc.)
	*/
	if (!err || err == -EINTR)
		fuse_invalidate_attr(inode);
	return err;
}

int fuse_do_getattr(struct inode *inode)
{
	int err;
	struct fuse_attr_out arg;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	req->in.h.opcode = FUSE_GETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(arg);
	req->out.args[0].value = &arg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if ((inode->i_mode ^ arg.attr.mode) & S_IFMT) {
#ifndef FUSE_MAINLINE
			if (get_node_id(inode) != FUSE_ROOT_ID)
				make_bad_inode(inode);
#else
			make_bad_inode(inode);
#endif
			err = -EIO;
		} else {
			struct fuse_inode *fi = get_fuse_inode(inode);
			fuse_change_attributes(inode, &arg.attr);
			fi->i_time = time_to_jiffies(arg.attr_valid,
						     arg.attr_valid_nsec);
		}
	}
	return err;
}

static int fuse_revalidate(struct dentry *entry)
{
	struct inode *inode = entry->d_inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (get_node_id(inode) == FUSE_ROOT_ID) {
		if (!(fc->flags & FUSE_ALLOW_OTHER) &&
		    current->fsuid != fc->user_id &&
		    (!(fc->flags & FUSE_ALLOW_ROOT) ||
		     !capable(CAP_DAC_OVERRIDE)))
			return -EACCES;
	} else if (time_before_eq(jiffies, fi->i_time))
		return 0;

	return fuse_do_getattr(inode);
}

static int fuse_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!(fc->flags & FUSE_ALLOW_OTHER) && current->fsuid != fc->user_id &&
	    (!(fc->flags & FUSE_ALLOW_ROOT) || !capable(CAP_DAC_OVERRIDE)))
		return -EACCES;
	else if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
#ifdef KERNEL_2_6_10_PLUS
		int err = generic_permission(inode, mask, NULL);
#else
		int err = vfs_permission(inode, mask);
#endif

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */
		if (err == -EACCES) {
		 	err = fuse_do_getattr(inode);
			if (!err)
#ifdef KERNEL_2_6_10_PLUS
				err = generic_permission(inode, mask, NULL);
#else
				err = vfs_permission(inode, mask);
#endif
		}

		/* FIXME: Need some mechanism to revoke permissions:
		   currently if the filesystem suddenly changes the
		   file mode, we will not be informed about it, and
		   continue to allow access to the file/directory.

		   This is actually not so grave, since the user can
		   simply keep access to the file/directory anyway by
		   keeping it open... */

		return err;
	} else {
		int mode = inode->i_mode;
		if ((mask & MAY_WRITE) && IS_RDONLY(inode) &&
                    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
                        return -EROFS;
		if ((mask & MAY_EXEC) && !S_ISDIR(mode) && !(mode & S_IXUGO))
			return -EACCES;
		return 0;
	}
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 void *dstbuf, filldir_t filldir)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		int over;
		if (dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;

		over = filldir(dstbuf, dirent->name, dirent->namelen,
			       file->f_pos, dirent->ino, dirent->type);
		if (over)
			break;

		buf += reclen;
		file->f_pos += reclen;
		nbytes -= reclen;
	}

	return 0;
}

static inline size_t fuse_send_readdir(struct fuse_req *req, struct file *file,
				       struct inode *inode, loff_t pos,
				       size_t count)
{
	return fuse_send_read_common(req, file, inode, pos, count, 1);
}

static int fuse_readdir(struct file *file, void *dstbuf, filldir_t filldir)
{
	int err;
	size_t nbytes;
	struct page *page;
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_request_nonint(fc);
	if (!req)
		return -EINTR;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}
	req->num_pages = 1;
	req->pages[0] = page;
	nbytes = fuse_send_readdir(req, file, inode, file->f_pos, PAGE_SIZE);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err)
		err = parse_dirfile(page_address(page), nbytes, file, dstbuf,
				    filldir);

	__free_page(page);
	return err;
}

static char *read_link(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_request(fc);
	char *link;

	if (!req)
		return ERR_PTR(-ERESTARTNOINTR);

	link = (char *) __get_free_page(GFP_KERNEL);
	if (!link) {
		link = ERR_PTR(-ENOMEM);
		goto out;
	}
	req->in.h.opcode = FUSE_READLINK;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = PAGE_SIZE - 1;
	req->out.args[0].value = link;
	request_send(fc, req);
	if (req->out.h.error) {
		free_page((unsigned long) link);
		link = ERR_PTR(req->out.h.error);
	} else
		link[req->out.args[0].size] = '\0';
 out:
	fuse_put_request(fc, req);
	return link;
}

static void free_link(char *link)
{
	if (!IS_ERR(link))
		free_page((unsigned long) link);
}

#ifdef KERNEL_2_6_8_PLUS
static int fuse_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, read_link(dentry));
	return 0;
}

static void fuse_put_link(struct dentry *dentry, struct nameidata *nd)
{
	free_link(nd_get_link(nd));
}
#else
static int fuse_readlink(struct dentry *dentry, char __user *buffer,
			 int buflen)
{
	int ret;
	char *link;

	link = read_link(dentry);
	ret = vfs_readlink(dentry, buffer, buflen, link);
	free_link(link);
	return ret;
}

static int fuse_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int ret;
	char *link;

	link = read_link(dentry);
	ret = vfs_follow_link(nd, link);
	free_link(link);
	return ret;
}
#endif

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, 1);
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	return fuse_release_common(inode, file, 1);
}

static unsigned iattr_to_fattr(struct iattr *iattr, struct fuse_attr *fattr)
{
	unsigned ivalid = iattr->ia_valid;
	unsigned fvalid = 0;

	memset(fattr, 0, sizeof(*fattr));

	if (ivalid & ATTR_MODE)
		fvalid |= FATTR_MODE,   fattr->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		fvalid |= FATTR_UID,    fattr->uid = iattr->ia_uid;
	if (ivalid & ATTR_GID)
		fvalid |= FATTR_GID,    fattr->gid = iattr->ia_gid;
	if (ivalid & ATTR_SIZE)
		fvalid |= FATTR_SIZE,   fattr->size = iattr->ia_size;
	/* You can only _set_ these together (they may change by themselves) */
	if ((ivalid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME)) {
		fvalid |= FATTR_ATIME | FATTR_MTIME;
#ifdef KERNEL_2_6
		fattr->atime = iattr->ia_atime.tv_sec;
		fattr->mtime = iattr->ia_mtime.tv_sec;
#else
		fattr->atime = iattr->ia_atime;
		fattr->mtime = iattr->ia_mtime;
#endif
	}

	return fvalid;
}

static int fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	int err;
	int is_truncate = 0;

	if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
		err = inode_change_ok(inode, attr);
		if (err)
			return err;
	}

	if (attr->ia_valid & ATTR_SIZE) {
		unsigned long limit;
		is_truncate = 1;
#ifdef KERNEL_2_6_10_PLUS
		limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;
#else
		limit = current->rlim[RLIMIT_FSIZE].rlim_cur;
#endif
		if (limit != RLIM_INFINITY && attr->ia_size > (loff_t) limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
	}

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.valid = iattr_to_fattr(attr, &inarg.attr);
	req->in.h.opcode = FUSE_SETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
#ifndef FUSE_MAINLINE
			if (get_node_id(inode) != FUSE_ROOT_ID)
				make_bad_inode(inode);
#else
			make_bad_inode(inode);
#endif
			err = -EIO;
		} else {
			if (is_truncate) {
				loff_t origsize = i_size_read(inode);
				i_size_write(inode, outarg.attr.size);
				if (origsize > outarg.attr.size)
					vmtruncate(inode, outarg.attr.size);
			}
			fuse_change_attributes(inode, &outarg.attr);
			fi->i_time = time_to_jiffies(outarg.attr_valid,
						     outarg.attr_valid_nsec);
		}
	} else if (err == -EINTR)
		fuse_invalidate_attr(inode);

	return err;
}

#ifdef KERNEL_2_6
static int fuse_getattr(struct vfsmount *mnt, struct dentry *entry,
			struct kstat *stat)
{
	struct inode *inode = entry->d_inode;
	int err = fuse_revalidate(entry);
	if (!err)
		generic_fillattr(inode, stat);

	return err;
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry,
				  struct nameidata *nd)
{
	struct inode *inode;
	int err = fuse_lookup_iget(dir, entry, &inode);
	if (err)
		return ERR_PTR(err);
	return d_splice_alias(inode, entry);
}
#else /* KERNEL_2_6 */
static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry)
{
	struct inode *inode;
	struct dentry *alias;

	int err = fuse_lookup_iget(dir, entry, &inode);
	if (err)
		return ERR_PTR(err);

	if (inode && S_ISDIR(inode->i_mode) &&
	    (alias = d_find_alias(inode)) != NULL) {
		dput(alias);
		iput(inode);
		return ERR_PTR(-EIO);
	}

	d_add(entry, inode);
	return NULL;
}

static int fuse_mknod_2_4(struct inode *dir, struct dentry *entry, int mode,
			  int rdev)
{
	return fuse_mknod(dir, entry, mode, rdev);
}

static int fuse_create_2_4(struct inode *dir, struct dentry *entry, int mode)
{
	return fuse_create(dir, entry, mode, NULL);
}

static int fuse_permission_2_4(struct inode *inode, int mask)
{
	return fuse_permission(inode, mask, NULL);
}
#endif /* KERNEL_2_6 */

#ifdef HAVE_KERNEL_XATTR
#ifdef KERNEL_2_6
static int fuse_setxattr(struct dentry *entry, const char *name,
			 const void *value, size_t size, int flags)
#else
static int fuse_setxattr(struct dentry *entry, const char *name,
			 void *value, size_t size, int flags)
#endif
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_setxattr_in inarg;
	int err;

	if (size > FUSE_XATTR_SIZE_MAX)
		return -E2BIG;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	req->in.h.opcode = FUSE_SETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	req->in.args[2].size = size;
	req->in.args[2].value = value;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	return err;
}

static ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_GETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	/* This is really two different operations rolled into one */
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = value;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}
	request_send(fc, req);
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_getxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static ssize_t fuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_LISTXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	/* This is really two different operations rolled into one */
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = list;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}
	request_send(fc, req);
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_listxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static int fuse_removexattr(struct dentry *entry, const char *name)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	int err;

	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTNOINTR;

	req->in.h.opcode = FUSE_REMOVEXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->inode = inode;
	req->in.numargs = 1;
	req->in.args[0].size = strlen(name) + 1;
	req->in.args[0].value = name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	return err;
}
#endif

static struct inode_operations fuse_dir_inode_operations = {
	.lookup		= fuse_lookup,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename		= fuse_rename,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
#ifdef KERNEL_2_6
	.create		= fuse_create,
	.mknod		= fuse_mknod,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
#else
	.create		= fuse_create_2_4,
	.mknod		= fuse_mknod_2_4,
	.permission	= fuse_permission_2_4,
	.revalidate	= fuse_revalidate,
#endif
#ifdef HAVE_KERNEL_XATTR
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#endif
};

static struct file_operations fuse_dir_operations = {
	.read		= generic_read_dir,
	.readdir	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
};

static struct inode_operations fuse_common_inode_operations = {
	.setattr	= fuse_setattr,
#ifdef KERNEL_2_6
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
#else
	.permission	= fuse_permission_2_4,
	.revalidate	= fuse_revalidate,
#endif
#ifdef HAVE_KERNEL_XATTR
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#endif
};

static struct inode_operations fuse_symlink_inode_operations = {
	.setattr	= fuse_setattr,
	.follow_link	= fuse_follow_link,
#ifdef KERNEL_2_6_8_PLUS
	.put_link	= fuse_put_link,
	.readlink	= generic_readlink,
#else
	.readlink	= fuse_readlink,
#endif
#ifdef KERNEL_2_6
	.getattr	= fuse_getattr,
#else
	.revalidate	= fuse_revalidate,
#endif
#ifdef HAVE_KERNEL_XATTR
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#endif
};

void fuse_init_common(struct inode *inode)
{
	inode->i_op = &fuse_common_inode_operations;
}

void fuse_init_dir(struct inode *inode)
{
	inode->i_op = &fuse_dir_inode_operations;
	inode->i_fop = &fuse_dir_operations;
}

void fuse_init_symlink(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
}
