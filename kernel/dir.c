/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>

static struct inode_operations fuse_dir_inode_operations;
static struct inode_operations fuse_file_inode_operations;
static struct inode_operations fuse_symlink_inode_operations;

static struct file_operations fuse_dir_operations;

static struct dentry_operations fuse_dentry_operations;

#ifndef KERNEL_2_6
#define new_decode_dev(x) (x)
#define new_encode_dev(x) (x)
#endif

static void change_attributes(struct inode *inode, struct fuse_attr *attr)
{
	if (S_ISREG(inode->i_mode) && i_size_read(inode) != attr->size) {
#ifdef KERNEL_2_6
		invalidate_inode_pages(inode->i_mapping);
#else
		invalidate_inode_pages(inode);
#endif
	}

	inode->i_mode    = (inode->i_mode & S_IFMT) + (attr->mode & 07777);
	inode->i_nlink   = attr->nlink;
	inode->i_uid     = attr->uid;
	inode->i_gid     = attr->gid;
	i_size_write(inode, attr->size);
	inode->i_blksize = PAGE_CACHE_SIZE;
	inode->i_blocks  = attr->blocks;
#ifdef KERNEL_2_6
	inode->i_atime.tv_sec   = attr->atime;
	inode->i_atime.tv_nsec  = attr->atimensec;
	inode->i_mtime.tv_sec   = attr->mtime;
	inode->i_mtime.tv_nsec  = attr->mtimensec;
	inode->i_ctime.tv_sec   = attr->ctime;
	inode->i_ctime.tv_nsec  = attr->ctimensec;
#else
	inode->i_atime   = attr->atime;
	inode->i_mtime   = attr->mtime;
	inode->i_ctime   = attr->ctime;
#endif
}

static void fuse_init_inode(struct inode *inode, struct fuse_attr *attr)
{
	inode->i_mode = attr->mode & S_IFMT;
	i_size_write(inode, attr->size);
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &fuse_file_inode_operations;
		fuse_init_file_inode(inode);
	}
	else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &fuse_dir_inode_operations;
		inode->i_fop = &fuse_dir_operations;
	}
	else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &fuse_symlink_inode_operations;
	}
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) || 
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)){
		inode->i_op = &fuse_file_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   new_decode_dev(attr->rdev));
	} else
		printk("fuse_init_inode: bad file type: %o\n", inode->i_mode);
}

struct inode *fuse_iget(struct super_block *sb, ino_t ino, int generation,
			struct fuse_attr *attr, int version)
{
	struct inode *inode;

	inode = iget(sb, ino);
	if (inode) {
		if (!INO_FI(inode)) {
			struct fuse_inode *fi = fuse_inode_alloc();
			if (!fi) {
				iput(inode);
				inode = NULL;
				goto out;
			}
			INO_FI(inode) = fi;
			inode->i_generation = generation;
			fuse_init_inode(inode, attr);
		} else if (inode->i_generation != generation)
			printk("fuse_iget: bad generation for ino %lu\n", ino);

		change_attributes(inode, attr);
		inode->i_version = version;
	}
 out:

	return inode;
}

static int fuse_send_lookup(struct fuse_conn *fc, struct fuse_req *req,
			    struct inode *dir, struct dentry *entry, 
			    struct fuse_entry_out *outarg, int *version)
{
	req->in.h.opcode = FUSE_LOOKUP;
	req->in.h.ino = dir->i_ino;
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_entry_out);
	req->out.args[0].value = outarg;
	request_send(fc, req);
	*version = req->out.h.unique;
	return req->out.h.error;
}

static int fuse_do_lookup(struct inode *dir, struct dentry *entry,
			  struct fuse_entry_out *outarg, int *version)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_req *req;
	int err;

	if (entry->d_name.len > FUSE_NAME_MAX)
		return -ENAMETOOLONG;
	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	err = fuse_send_lookup(fc, req, dir, entry, outarg, version);
	fuse_put_request(fc, req);
	return err;
}

static inline unsigned long time_to_jiffies(unsigned long sec,
					    unsigned long nsec)
{
	/* prevent wrapping of jiffies */
	if (sec + 1 >= LONG_MAX / HZ)
		return 0;
	
	return jiffies + sec * HZ + nsec / (1000000000 / HZ);
}

static int fuse_lookup_iget(struct inode *dir, struct dentry *entry,
			    struct inode **inodep)
{
	struct fuse_conn *fc = INO_FC(dir);
	int err;
	struct fuse_entry_out outarg;
	int version;
	struct inode *inode = NULL;
	struct fuse_req *req;

	if (entry->d_name.len > FUSE_NAME_MAX)
		return -ENAMETOOLONG;
	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	err = fuse_send_lookup(fc, req, dir, entry, &outarg, &version);
	if (!err) {
		inode = fuse_iget(dir->i_sb, outarg.ino, outarg.generation,
				  &outarg.attr, version);
		if (!inode) {
			fuse_send_forget(fc, req, outarg.ino, version);
			return -ENOMEM;
		}
	} 
	fuse_put_request(fc, req);
	if (err && err != -ENOENT)
		return err;

	if (inode) {
		struct fuse_inode *fi = INO_FI(inode);
		entry->d_time =	time_to_jiffies(outarg.entry_valid,
						outarg.entry_valid_nsec);
		fi->i_time = time_to_jiffies(outarg.attr_valid,
					     outarg.attr_valid_nsec);
	}

	entry->d_op = &fuse_dentry_operations;
	*inodep = inode;
	return 0;
}

static void fuse_invalidate_attr(struct inode *inode)
{
	struct fuse_inode *fi = INO_FI(inode);
	fi->i_time = jiffies - 1;
}

static int lookup_new_entry(struct fuse_conn *fc, struct fuse_req *req,
			    struct inode *dir, struct dentry *entry,
			    struct fuse_entry_out *outarg, int version,
			    int mode)
{
	struct inode *inode;
	struct fuse_inode *fi;
	inode = fuse_iget(dir->i_sb, outarg->ino, outarg->generation, 
			  &outarg->attr, version);
	if (!inode) {
		fuse_send_forget(fc, req, outarg->ino, version);
		return -ENOMEM;
	}
	fuse_put_request(fc, req);

	/* Don't allow userspace to do really stupid things... */
	if ((inode->i_mode ^ mode) & S_IFMT) {
		iput(inode);
		printk("fuse_mknod: inode has wrong type\n");
		return -EINVAL;
	}

	entry->d_time = time_to_jiffies(outarg->entry_valid,
					outarg->entry_valid_nsec);

	fi = INO_FI(inode);
	fi->i_time = time_to_jiffies(outarg->attr_valid,
				     outarg->attr_valid_nsec);

	d_instantiate(entry, inode);
	fuse_invalidate_attr(dir);
	return 0;
}


static int _fuse_mknod(struct inode *dir, struct dentry *entry, int mode,
		      dev_t rdev)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_req *req = fuse_get_request(fc);
	struct fuse_mknod_in inarg;
	struct fuse_entry_out outarg;
	int err;

	if (!req)
		return -ERESTARTSYS;

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	req->in.h.opcode = FUSE_MKNOD;
	req->in.h.ino = dir->i_ino;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err)
		err = lookup_new_entry(fc, req, dir, entry, &outarg,
				       req->out.h.unique, mode);
	else
		fuse_put_request(fc, req);
	return err;
}

static int _fuse_create(struct inode *dir, struct dentry *entry, int mode)
{
	return _fuse_mknod(dir, entry, mode, 0);
}


static int fuse_mkdir(struct inode *dir, struct dentry *entry, int mode)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_req *req = fuse_get_request(fc);
	struct fuse_mkdir_in inarg;
	struct fuse_entry_out outarg;
	int err;

	if (!req)
		return -ERESTARTSYS;

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	req->in.h.opcode = FUSE_MKDIR;
	req->in.h.ino = dir->i_ino;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err)
		err = lookup_new_entry(fc, req, dir, entry, &outarg,
				       req->out.h.unique, S_IFDIR);
	else
		fuse_put_request(fc, req);
	return err;
}

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_req *req;
	struct fuse_entry_out outarg;
	unsigned int len = strlen(link) + 1;
	int err;
	
	if (len > FUSE_SYMLINK_MAX)
		return -ENAMETOOLONG;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	req->in.h.opcode = FUSE_SYMLINK;
	req->in.h.ino = dir->i_ino;
	req->in.numargs = 2;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->in.args[1].size = len;
	req->in.args[1].value = link;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err)
		err = lookup_new_entry(fc, req, dir, entry, &outarg,
				       req->out.h.unique, S_IFLNK);
	else
		fuse_put_request(fc, req);
	return err;
}

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_req *req = fuse_get_request(fc);
	int err;
	
	if (!req)
		return -ERESTARTSYS;

	req->in.h.opcode = FUSE_UNLINK;
	req->in.h.ino = dir->i_ino;
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err) {
		struct inode *inode = entry->d_inode;
		
		/* Set nlink to zero so the inode can be cleared, if
                   the inode does have more links this will be
                   discovered at the next lookup/getattr */
		inode->i_nlink = 0;
		fuse_invalidate_attr(inode);
		fuse_invalidate_attr(dir);
	}
	fuse_put_request(fc, req);
	return err;
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_req *req = fuse_get_request(fc);
	int err;
	
	if (!req)
		return -ERESTARTSYS;

	req->in.h.opcode = FUSE_RMDIR;
	req->in.h.ino = dir->i_ino;
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err) {
		entry->d_inode->i_nlink = 0;
		fuse_invalidate_attr(dir);
	}
	fuse_put_request(fc, req);
	return err;
}

static int fuse_rename(struct inode *olddir, struct dentry *oldent,
		       struct inode *newdir, struct dentry *newent)
{
	struct fuse_conn *fc = INO_FC(olddir);
	struct fuse_req *req = fuse_get_request(fc);
	struct fuse_rename_in inarg;
	int err;

	if (!req)
		return -ERESTARTSYS;

	memset(&inarg, 0, sizeof(inarg));
	inarg.newdir = newdir->i_ino;
	req->in.h.opcode = FUSE_RENAME;
	req->in.h.ino = olddir->i_ino;
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
	}
	return err;
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req = fuse_get_request(fc);
	struct fuse_link_in inarg;
	struct fuse_entry_out outarg;
	int err;

	if (!req)
		return -ERESTARTSYS;

	memset(&inarg, 0, sizeof(inarg));
	inarg.newdir = newdir->i_ino;
	req->in.h.opcode = FUSE_LINK;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = newent->d_name.len + 1;
	req->in.args[1].value = newent->d_name.name;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err) {
		/* Invalidate old entry, so attributes are refreshed */
		d_invalidate(entry);
		err = lookup_new_entry(fc, req, newdir, newent, &outarg,
				       req->out.h.unique, inode->i_mode);
	} else
		fuse_put_request(fc, req);
	return err;
}

int fuse_do_getattr(struct inode *inode)
{
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req = fuse_get_request(fc);
	struct fuse_attr_out arg;
	int err;

	if (!req)
		return -ERESTARTSYS;

	req->in.h.opcode = FUSE_GETATTR;
	req->in.h.ino = inode->i_ino;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(arg);
	req->out.args[0].value = &arg;
	request_send(fc, req);
	err = req->out.h.error;	
	if (!err) {
		change_attributes(inode, &arg.attr);
		fi->i_time = time_to_jiffies(arg.attr_valid,
					     arg.attr_valid_nsec);
	}
	fuse_put_request(fc, req);
	return err;
}

static int fuse_revalidate(struct dentry *entry)
{
	struct inode *inode = entry->d_inode;
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_conn *fc = INO_FC(inode);

	if (inode->i_ino == FUSE_ROOT_INO) {
		if (!(fc->flags & FUSE_ALLOW_OTHER) &&
		    current->fsuid != fc->uid &&
		    (!(fc->flags & FUSE_ALLOW_ROOT) ||
		     current->fsuid != 0))
			return -EACCES;
	} else if (!fi->i_time || time_before_eq(jiffies, fi->i_time))
		return 0;

	return fuse_do_getattr(inode);
}

static int _fuse_permission(struct inode *inode, int mask)
{
	struct fuse_conn *fc = INO_FC(inode);

	if (!(fc->flags & FUSE_ALLOW_OTHER) && current->fsuid != fc->uid &&
	    (!(fc->flags & FUSE_ALLOW_ROOT) || current->fsuid != 0))
		return -EACCES;
	else if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
		int err = vfs_permission(inode, mask);

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */

		if (err == -EACCES) {
		 	err = fuse_do_getattr(inode);
			if (!err)
			 	err = vfs_permission(inode, mask);
		}

		/* FIXME: Need some mechanism to revoke permissions:
		   currently if the filesystem suddenly changes the
		   file mode, we will not be informed abot that, and
		   continue to allow access to the file/directory.
		   
		   This is actually not so grave, since the user can
		   simply keep access to the file/directory anyway by
		   keeping it open... */

		return err;
	} else
		return 0;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 void *dstbuf, filldir_t filldir)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		int over;
		if (dirent->namelen > NAME_MAX) {
			printk("fuse_readdir: name too long\n");
			return -EPROTO;
		}
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

static int fuse_checkdir(struct file *cfile, struct file *file)
{
	struct inode *inode;
	if (!cfile) {
		printk("fuse_getdir: invalid file\n");
		return -EPROTO;
	}
	inode = cfile->f_dentry->d_inode;
	if (!S_ISREG(inode->i_mode)) {
		printk("fuse_getdir: not a regular file\n");
		fput(cfile);
		return -EPROTO;
	}
	
	file->private_data = cfile;
	return 0;
}

static int fuse_getdir(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req = fuse_get_request(fc);
	struct fuse_getdir_out_i outarg;
	int err;

	if (!req)
		return -ERESTARTSYS;

	req->in.h.opcode = FUSE_GETDIR;
	req->in.h.ino = inode->i_ino;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_getdir_out);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;	
	if (!err)
		err = fuse_checkdir(outarg.file, file);
	fuse_put_request(fc, req);
	return err;
}

#define DIR_BUFSIZE 2048
static int fuse_readdir(struct file *file, void *dstbuf, filldir_t filldir)
{
	struct file *cfile = file->private_data;
	char *buf;
	int ret;

	if (!cfile) {
		ret = fuse_getdir(file);
		if (ret)
			return ret;

		cfile = file->private_data;
	}

	buf = kmalloc(DIR_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	
	ret = kernel_read(cfile, file->f_pos, buf, DIR_BUFSIZE);
	if (ret < 0)
		printk("fuse_readdir: failed to read container file\n");
	else 
		ret = parse_dirfile(buf, ret, file, dstbuf, filldir);

	kfree(buf);	
	return ret;
}

static char *read_link(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req = fuse_get_request(fc);
	char *link;

	if (!req)
		return ERR_PTR(-ERESTARTSYS);

	link = (char *) __get_free_page(GFP_KERNEL);
	if (!link) {
		link = ERR_PTR(-ENOMEM);
		goto out;
	}
	req->in.h.opcode = FUSE_READLINK;
	req->in.h.ino = inode->i_ino;
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

static int fuse_readlink(struct dentry *dentry, char *buffer, int buflen)
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

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	struct file *cfile = file->private_data;

	if (cfile)
		fput(cfile);

	return 0;
}

static unsigned int iattr_to_fattr(struct iattr *iattr,
				   struct fuse_attr *fattr)
{
	unsigned int ivalid = iattr->ia_valid;
	unsigned int fvalid = 0;
	
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
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
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

		limit = current->rlim[RLIMIT_FSIZE].rlim_cur;
		if (limit != RLIM_INFINITY && attr->ia_size > limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		//fuse_sync_inode(inode);
	}

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	if (is_truncate)
		down_write(&fi->write_sem);

	memset(&inarg, 0, sizeof(inarg));
	inarg.valid = iattr_to_fattr(attr, &inarg.attr);
	req->in.h.opcode = FUSE_SETATTR;
	req->in.h.ino = inode->i_ino;
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
		if (is_truncate) {
			loff_t origsize = i_size_read(inode);
			i_size_write(inode, outarg.attr.size);
			up_write(&fi->write_sem);
			if (origsize > outarg.attr.size)
				vmtruncate(inode, outarg.attr.size);
		}
		change_attributes(inode, &outarg.attr);
		fi->i_time = time_to_jiffies(outarg.attr_valid,
					     outarg.attr_valid_nsec);
	} else if (is_truncate)
		up_write(&fi->write_sem);
		
	return err;
}

static int _fuse_dentry_revalidate(struct dentry *entry)
{
	if (!entry->d_inode)
		return 0;
	else if (entry->d_time && time_after(jiffies, entry->d_time)) {
		struct inode *inode = entry->d_inode;
		struct fuse_inode *fi = INO_FI(inode);
		struct fuse_entry_out outarg;
		int version;
		int ret;
		
		ret = fuse_do_lookup(entry->d_parent->d_inode, entry, &outarg,
				     &version);
		if (ret)
			return 0;
		
		if (outarg.ino != inode->i_ino)
			return 0;
		
		change_attributes(inode, &outarg.attr);
		inode->i_version = version;
		entry->d_time = time_to_jiffies(outarg.entry_valid,
						outarg.entry_valid_nsec);
		fi->i_time = time_to_jiffies(outarg.attr_valid,
					     outarg.attr_valid_nsec);
	}
	return 1;
}

#ifdef KERNEL_2_6

#define fuse_mknod _fuse_mknod

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

static int fuse_create(struct inode *dir, struct dentry *entry, int mode,
		       struct nameidata *nd)
{
	return _fuse_create(dir, entry, mode);
}

static int fuse_permission(struct inode *inode, int mask,
			    struct nameidata *nd)
{
	return _fuse_permission(inode, mask);
}

static int fuse_dentry_revalidate(struct dentry *entry, struct nameidata *nd)
{
	return _fuse_dentry_revalidate(entry);
}

#else /* KERNEL_2_6 */

#define fuse_create _fuse_create
#define fuse_permission _fuse_permission

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
		printk("fuse: cannot assign an existing directory\n");
		return ERR_PTR(-EPROTO);
	}

	d_add(entry, inode);
	return NULL;
}

static int fuse_mknod(struct inode *dir, struct dentry *entry, int mode,
		      int rdev)
{
	return _fuse_mknod(dir, entry, mode, rdev);
}

static int fuse_dentry_revalidate(struct dentry *entry, int flags)
{
	return _fuse_dentry_revalidate(entry);
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
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req;
	struct fuse_setxattr_in inarg;
	int err;

	if (size > FUSE_XATTR_SIZE_MAX)
		return -E2BIG;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	req->in.h.opcode = FUSE_SETXATTR;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	req->in.args[2].size = size;
	req->in.args[2].value = value;
	request_send(fc, req);
	err = req->out.h.error;
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	fuse_put_request(fc, req);
	return err;
}

static ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_GETXATTR;
	req->in.h.ino = inode->i_ino;
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
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_LISTXATTR;
	req->in.h.ino = inode->i_ino;
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
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req;
	int err;
	
	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	req->in.h.opcode = FUSE_REMOVEXATTR;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 1;
	req->in.args[0].size = strlen(name) + 1;
	req->in.args[0].value = name;
	request_send(fc, req);
	err = req->out.h.error;
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	fuse_put_request(fc, req);
	return err;
}

#endif

static struct inode_operations fuse_dir_inode_operations =
{
	.lookup		= fuse_lookup,
	.create		= fuse_create,
	.mknod		= fuse_mknod,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename		= fuse_rename,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
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

static struct file_operations fuse_dir_operations = {
	.read		= generic_read_dir,
	.readdir	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
};

static struct inode_operations fuse_file_inode_operations = {
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
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

static struct inode_operations fuse_symlink_inode_operations =
{
	.setattr	= fuse_setattr,
	.readlink	= fuse_readlink,
	.follow_link	= fuse_follow_link,
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

static struct dentry_operations fuse_dentry_operations = {
	.d_revalidate	= fuse_dentry_revalidate,
};

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
