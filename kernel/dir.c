/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/slab.h>
#include <linux/file.h>

static struct inode_operations fuse_dir_inode_operations;
static struct inode_operations fuse_file_inode_operations;
static struct inode_operations fuse_symlink_inode_operations;

static struct file_operations fuse_dir_operations;

static struct dentry_operations fuse_dentry_opertations;

/* FIXME: This should be user configurable */
#define FUSE_REVALIDATE_TIME (1 * HZ)

static void change_attributes(struct inode *inode, struct fuse_attr *attr)
{
	if(S_ISREG(inode->i_mode) && inode->i_size != attr->size)
		invalidate_inode_pages(inode);

	inode->i_mode    = (inode->i_mode & S_IFMT) + (attr->mode & 07777);
	inode->i_nlink   = attr->nlink;
	inode->i_uid     = attr->uid;
	inode->i_gid     = attr->gid;
	inode->i_size    = attr->size;
	inode->i_blksize = attr->blksize;
	inode->i_blocks  = attr->blocks;
	inode->i_atime   = attr->atime;
	inode->i_mtime   = attr->mtime;
	inode->i_ctime   = attr->ctime;
}

static void fuse_init_inode(struct inode *inode, struct fuse_attr *attr)
{
	inode->i_mode = attr->mode & S_IFMT;
	inode->i_size = attr->size;
	if(S_ISREG(inode->i_mode)) {
		inode->i_op = &fuse_file_inode_operations;
		fuse_init_file_inode(inode);
	}
	else if(S_ISDIR(inode->i_mode)) {
		inode->i_op = &fuse_dir_inode_operations;
		inode->i_fop = &fuse_dir_operations;
	}
	else if(S_ISLNK(inode->i_mode)) {
		inode->i_op = &fuse_symlink_inode_operations;
	}
	else {
		inode->i_op = &fuse_file_inode_operations;
		init_special_inode(inode, inode->i_mode, attr->rdev);
	}
	inode->u.generic_ip = inode;
}

struct inode *fuse_iget(struct super_block *sb, ino_t ino,
			struct fuse_attr *attr, int version)
{
	struct inode *inode;

	inode = iget(sb, ino);
	if(inode) {
		if(!inode->u.generic_ip)
			fuse_init_inode(inode, attr);
		
		change_attributes(inode, attr);
		inode->i_version = version;
	}

	return inode;
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry)
{
	int ret;
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_lookup_out arg;
	struct inode *inode;

	in.h.opcode = FUSE_LOOKUP;
	in.h.ino = dir->i_ino;
	in.argsize = entry->d_name.len + 1;
	in.arg = entry->d_name.name;
	out.argsize = sizeof(arg);
	out.arg = &arg;
	request_send(fc, &in, &out);
	
	inode = NULL;
	if(!out.h.error) {
		ret = -ENOMEM;
		inode = fuse_iget(dir->i_sb, arg.ino, &arg.attr, out.h.unique);
		if(!inode) 
			goto err;
	}
	else if(out.h.error != -ENOENT) {
		ret = out.h.error;
		goto err;
	}

	entry->d_time = jiffies;
	entry->d_op = &fuse_dentry_opertations;
	d_add(entry, inode);

	return NULL;

  err:
	return ERR_PTR(ret);
}

/* create needs to return a positive entry, so this is actually an
   mknod+lookup */
static int fuse_mknod(struct inode *dir, struct dentry *entry, int mode,
		      int rdev)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_mknod_in *inarg;
	unsigned int insize;
	struct fuse_mknod_out outarg;
	struct inode *inode;
	
	insize = offsetof(struct fuse_mknod_in, name) + entry->d_name.len + 1;
	inarg = kmalloc(insize, GFP_KERNEL);
	if(!inarg)
		return -ENOMEM;
	
	inarg->mode = mode;
	inarg->rdev = rdev;
	strcpy(inarg->name, entry->d_name.name);

	in.h.opcode = FUSE_MKNOD;
	in.h.ino = dir->i_ino;
	in.argsize = insize;
	in.arg = inarg;
	out.argsize = sizeof(outarg);
	out.arg = &outarg;
	request_send(fc, &in, &out);
	kfree(inarg);

	if(out.h.error) 
		return out.h.error;

	inode = fuse_iget(dir->i_sb, outarg.ino, &outarg.attr, out.h.unique);
	if(!inode) 
		return -ENOMEM;

	d_instantiate(entry, inode);
	return 0;
}


static int fuse_create(struct inode *dir, struct dentry *entry, int mode)
{
	return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_mkdir(struct inode *dir, struct dentry *entry, int mode)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_mkdir_in *inarg;
	unsigned int insize;
	
	insize = offsetof(struct fuse_mkdir_in, name) + entry->d_name.len + 1;
	inarg = kmalloc(insize, GFP_KERNEL);
	if(!inarg)
		return -ENOMEM;
	
	inarg->mode = mode;
	strcpy(inarg->name, entry->d_name.name);

	in.h.opcode = FUSE_MKDIR;
	in.h.ino = dir->i_ino;
	in.argsize = insize;
	in.arg = inarg;
	request_send(fc, &in, &out);
	kfree(inarg);

	return out.h.error;
}

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	char *inarg;
	unsigned int insize;
	
	insize = entry->d_name.len + 1 + strlen(link) + 1;
	inarg = kmalloc(insize, GFP_KERNEL);
	if(!inarg)
		return -ENOMEM;
	
	strcpy(inarg, entry->d_name.name);
	strcpy(inarg + entry->d_name.len + 1, link);

	in.h.opcode = FUSE_SYMLINK;
	in.h.ino = dir->i_ino;
	in.argsize = insize;
	in.arg = inarg;
	request_send(fc, &in, &out);
	kfree(inarg);
	
	return out.h.error;
}

static int fuse_remove(struct inode *dir, struct dentry *entry, 
		       enum fuse_opcode op)
{
	struct fuse_conn *fc = INO_FC(dir);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;

	in.h.opcode = op;
	in.h.ino = dir->i_ino;
	in.argsize = entry->d_name.len + 1;
	in.arg = entry->d_name.name;
	request_send(fc, &in, &out);
	return out.h.error;
}

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	return fuse_remove(dir, entry, FUSE_UNLINK);
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	return fuse_remove(dir, entry, FUSE_RMDIR);
}

static int fuse_rename(struct inode *olddir, struct dentry *oldent,
		       struct inode *newdir, struct dentry *newent)
{
	struct fuse_conn *fc = INO_FC(olddir);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_rename_in *inarg;
	unsigned int oldnamsize = oldent->d_name.len + 1;
	unsigned int newnamsize = newent->d_name.len + 1;
	unsigned int insize;
	
	insize = offsetof(struct fuse_rename_in, names) + oldnamsize +
		newnamsize;
	inarg = kmalloc(insize, GFP_KERNEL);
	if(!inarg)
		return -ENOMEM;
	
	inarg->newdir = newdir->i_ino;
	strcpy(inarg->names, oldent->d_name.name);
	strcpy(inarg->names + oldnamsize, newent->d_name.name);

	in.h.opcode = FUSE_RENAME;
	in.h.ino = olddir->i_ino;
	in.argsize = insize;
	in.arg = inarg;
	request_send(fc, &in, &out);
	kfree(inarg);

	return out.h.error;
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_link_in *inarg;
	unsigned int insize;
	
	insize = offsetof(struct fuse_link_in, name) + newent->d_name.len + 1;
	inarg = kmalloc(insize, GFP_KERNEL);
	if(!inarg)
		return -ENOMEM;
	
	inarg->newdir = newdir->i_ino;
	strcpy(inarg->name, newent->d_name.name);

	in.h.opcode = FUSE_LINK;
	in.h.ino = inode->i_ino;
	in.argsize = insize;
	in.arg = inarg;
	request_send(fc, &in, &out);
	kfree(inarg);

	return out.h.error;
}

static int fuse_permission(struct inode *inode, int mask)
{
	struct fuse_conn *fc = INO_FC(inode);

	/* (too) simple protection */
	if(current->fsuid == fc->uid)
		return 0;
	else
		return -EACCES;
}

static int fuse_revalidate(struct dentry *entry)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_getattr_out arg;
	
	if(inode->i_ino != FUSE_ROOT_INO && 
	   time_before_eq(jiffies, entry->d_time + FUSE_REVALIDATE_TIME))
		return 0;

	in.h.opcode = FUSE_GETATTR;
	in.h.ino = inode->i_ino;
	out.argsize = sizeof(arg);
	out.arg = &arg;
	request_send(fc, &in, &out);
	
	if(!out.h.error)
		change_attributes(inode, &arg.attr);
	
	return out.h.error;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 void *dstbuf, filldir_t filldir)
{
	while(nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		int over;
		if(dirent->namelen > NAME_MAX) {
			printk("fuse_readdir: name too long\n");
			return -EPROTO;
		}
		if(reclen > nbytes)
			break;

		over = filldir(dstbuf, dirent->name, dirent->namelen,
			      file->f_pos, dirent->ino, dirent->type);
		if(over)
			break;

		buf += reclen;
		file->f_pos += reclen;
		nbytes -= reclen;
	}

	return 0;
}

#define DIR_BUFSIZE 2048
static int fuse_readdir(struct file *file, void *dstbuf, filldir_t filldir)
{
	struct file *cfile = file->private_data;
	char *buf;
	int ret;
	
	buf = kmalloc(DIR_BUFSIZE, GFP_KERNEL);
	if(!buf)
		return -ENOMEM;

	ret = kernel_read(cfile, file->f_pos, buf, DIR_BUFSIZE);
	if(ret < 0)
		printk("fuse_readdir: failed to read container file\n");
	else 
		ret = parse_dirfile(buf, ret, file, dstbuf, filldir);

	kfree(buf);	
	return ret;
}

static int read_link(struct dentry *dentry, char **bufp)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	unsigned long page;

	page = __get_free_page(GFP_KERNEL);
	if(!page)
		return -ENOMEM;

	in.h.opcode = FUSE_READLINK;
	in.h.ino = inode->i_ino;
	out.arg = (void *) page;
	out.argsize = PAGE_SIZE - 1;
	out.argvar = 1;
	request_send(fc, &in, &out);
	if(out.h.error) {
		free_page(page);
		return out.h.error;
	}

	*bufp = (char *) page;
	(*bufp)[out.argsize] = '\0';
	return 0;
}

static void free_link(char *link)
{
	free_page((unsigned long) link);
}

static int fuse_readlink(struct dentry *dentry, char *buffer, int buflen)
{
	int ret;
	char *link;

	ret = read_link(dentry, &link);
	if(ret)
		return ret;

	ret = vfs_readlink(dentry, buffer, buflen, link);
	free_link(link);
	return ret;
}

static int fuse_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int ret;
	char *link;

	ret = read_link(dentry, &link);
	if(ret)
		return ret;

	ret = vfs_follow_link(nd, link);
	free_link(link);
	return ret;
}

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_getdir_out outarg;

	if(!(file->f_flags & O_DIRECTORY))
		return 0;
	
	in.h.opcode = FUSE_GETDIR;
	in.h.ino = inode->i_ino;
	out.argsize = sizeof(outarg);
	out.arg = &outarg;
	request_send(fc, &in, &out);
	if(!out.h.error) {
		struct file *cfile = outarg.file;
		struct inode *inode;
		if(!cfile) {
			printk("fuse_getdir: invalid file\n");
			return -EPROTO;
		}
		inode = cfile->f_dentry->d_inode;
		if(!S_ISREG(inode->i_mode)) {
			printk("fuse_getdir: not a regular file\n");
			fput(cfile);
			return -EPROTO;
		}

		file->private_data = cfile;
	}

	return out.h.error;
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	struct file *cfile = file->private_data;

	if(cfile)
		fput(cfile);

	return 0;
}

static unsigned int iattr_to_fattr(struct iattr *iattr,
				   struct fuse_attr *fattr)
{
	unsigned int ivalid = iattr->ia_valid;
	unsigned int fvalid = 0;
	
	memset(fattr, 0, sizeof(*fattr));
	
	if(ivalid & ATTR_MODE)
		fvalid |= FATTR_MODE,   fattr->mode = iattr->ia_mode;
	if(ivalid & ATTR_UID)
		fvalid |= FATTR_UID,    fattr->uid = iattr->ia_uid;
	if(ivalid & ATTR_GID)
		fvalid |= FATTR_GID,    fattr->gid = iattr->ia_gid;
	if(ivalid & ATTR_SIZE)
		fvalid |= FATTR_SIZE,   fattr->size = iattr->ia_size;
	/* You can only _set_ these together (they may change by themselves) */
	if((ivalid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME)) {
		fvalid |= FATTR_UTIME;
		fattr->atime = iattr->ia_atime;
		fattr->mtime = iattr->ia_mtime;
	}

	return fvalid;
}

static int fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_setattr_in inarg;
	struct fuse_setattr_out outarg;

	inarg.valid = iattr_to_fattr(attr, &inarg.attr);
	
	in.h.opcode = FUSE_SETATTR;
	in.h.ino = inode->i_ino;
	in.argsize = sizeof(inarg);
	in.arg = &inarg;
	out.argsize = sizeof(outarg);
	out.arg = &outarg;
	request_send(fc, &in, &out);

	if(!out.h.error) {
		if(attr->ia_valid & ATTR_SIZE &&
		   outarg.attr.size < inode->i_size)
			vmtruncate(inode, outarg.attr.size);

		change_attributes(inode, &outarg.attr);
	} 
	return out.h.error;
}

static int fuse_dentry_revalidate(struct dentry *entry, int flags)
{
	if(!entry->d_inode)
		return 0;
	else if(!(flags & LOOKUP_CONTINUE) && 
		time_after(jiffies, entry->d_time + FUSE_REVALIDATE_TIME))
		return 0;
	else
		return 1;
}

static struct inode_operations fuse_dir_inode_operations =
{
	lookup:		fuse_lookup,
	create:         fuse_create,
	mknod:          fuse_mknod,
	mkdir:          fuse_mkdir,
	symlink:        fuse_symlink,
	unlink:         fuse_unlink,
	rmdir:          fuse_rmdir,
	rename:         fuse_rename,
	link:           fuse_link,
	setattr:	fuse_setattr,
	permission:	fuse_permission,
	revalidate:	fuse_revalidate,
};

static struct file_operations fuse_dir_operations = {
	read:		generic_read_dir,
	readdir:	fuse_readdir,
	open:		fuse_dir_open,
	release:	fuse_dir_release,
};

static struct inode_operations fuse_file_inode_operations = {
	setattr:	fuse_setattr,
	permission:	fuse_permission,
	revalidate:	fuse_revalidate,
};

static struct inode_operations fuse_symlink_inode_operations =
{
	setattr:	fuse_setattr,
	readlink:	fuse_readlink,
	follow_link:	fuse_follow_link,
	revalidate:	fuse_revalidate,
};

static struct dentry_operations fuse_dentry_opertations = {
	d_revalidate:	fuse_dentry_revalidate,
};

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
