/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/slab.h>

static void change_attributes(struct inode *inode, struct fuse_attr *attr)
{
	inode->i_mode    = attr->mode;
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

static void init_inode(struct inode *inode, struct fuse_attr *attr)
{
	change_attributes(inode, attr);
	
	if(S_ISREG(inode->i_mode))
		fuse_file_init(inode);
	else if(S_ISDIR(inode->i_mode))
		fuse_dir_init(inode);
	else if(S_ISLNK(inode->i_mode))
		fuse_symlink_init(inode);
	else {
		fuse_special_init(inode);
		init_special_inode(inode, inode->i_mode, attr->rdev);
	}
}


static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry)
{
	struct fuse_conn *fc = dir->i_sb->u.generic_sbp;
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
	
	if(out.h.result) {
		/* Negative dentries are not hashed */
		if(out.h.result == -ENOENT)
			return NULL;
		else
			return ERR_PTR(out.h.result);
	}

	inode = iget(dir->i_sb, arg.ino);
	if(!inode) 
		return ERR_PTR(-ENOMEM);

	init_inode(inode, &arg.attr);
	d_add(entry, inode);
	return NULL;
}

static int fuse_mknod(struct inode *dir, struct dentry *entry, int mode,
		      int rdev)
{
	struct fuse_conn *fc = dir->i_sb->u.generic_sbp;
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
	if(out.h.result)
		return out.h.result;

	inode = iget(dir->i_sb, outarg.ino);
	if(!inode) 
		return -ENOMEM;

	init_inode(inode, &outarg.attr);
	d_add(entry, inode);
	return 0;
}

static int fuse_create(struct inode *dir, struct dentry *entry, int mode)
{
	return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_permission(struct inode *inode, int mask)
{

	return 0;
}

static int fuse_revalidate(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_getattr_out arg;
	
	in.h.opcode = FUSE_GETATTR;
	in.h.ino = inode->i_ino;
	out.argsize = sizeof(arg);
	out.arg = &arg;
	request_send(fc, &in, &out);
	
	if(out.h.result == 0)
		change_attributes(inode, &arg.attr);

	return out.h.result;
}


#define DIR_BUFSIZE 2048

static int fuse_readdir(struct file *file, void *dstbuf, filldir_t filldir)
{
	struct file *cfile = file->private_data;
	char *buf;
	char *p;
	int ret;
	size_t nbytes;
	
	buf = kmalloc(DIR_BUFSIZE, GFP_KERNEL);
	if(!buf)
		return -ENOMEM;

	ret = kernel_read(cfile, file->f_pos, buf, DIR_BUFSIZE);
	if(ret < 0) {
		printk("fuse_readdir: failed to read container file\n");
		goto out;
	}
	nbytes = ret;
	p = buf;
	ret = 0;
	while(nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) p;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		int over;
		if(dirent->namelen > NAME_MAX) {
			printk("fuse_readdir: name too long\n");
			ret = -EPROTO;
			goto out;
		}
		if(reclen > nbytes)
			break;

		over = filldir(dstbuf, dirent->name, dirent->namelen,
			      file->f_pos, dirent->ino, dirent->type);
		if(over)
			break;

		p += reclen;
		file->f_pos += reclen;
		nbytes -= reclen;
	}

  out:
	kfree(buf);	
	return ret;
}



static int read_link(struct dentry *dentry, char **bufp)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
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
	if(out.h.result) {
		free_page(page);
		return out.h.result;
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
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_getdir_out outarg;

	if(!(file->f_flags & O_DIRECTORY))
		return -EISDIR;
	
	in.h.opcode = FUSE_GETDIR;
	in.h.ino = inode->i_ino;
	out.argsize = sizeof(outarg);
	out.arg = &outarg;
	request_send(fc, &in, &out);
	if(out.h.result == 0) {
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

	return out.h.result;
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	struct file *cfile = file->private_data;

	if(!cfile)
		BUG();
	
	fput(cfile);

	return 0;
}

static struct inode_operations fuse_dir_inode_operations =
{
	lookup:		fuse_lookup,
	create:         fuse_create,
	mknod:          fuse_mknod,
#if 0

	link:           fuse_link,
	unlink:         fuse_unlink,
	symlink:        fuse_symlink,
	mkdir:          fuse_mkdir,
	rmdir:          fuse_rmdir,
	rename:         fuse_rename,
#endif
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
	permission:	fuse_permission,
        revalidate:	fuse_revalidate,
};

static struct inode_operations fuse_special_inode_operations = {
	permission:	fuse_permission,
        revalidate:	fuse_revalidate,
};

static struct file_operations fuse_file_operations = {
};

static struct inode_operations fuse_symlink_inode_operations =
{
	readlink:	fuse_readlink,
	follow_link:	fuse_follow_link,
        revalidate:	fuse_revalidate,
};

void fuse_dir_init(struct inode *inode)
{
	inode->i_op = &fuse_dir_inode_operations;
	inode->i_fop = &fuse_dir_operations;
}

void fuse_file_init(struct inode *inode)
{
	inode->i_op = &fuse_file_inode_operations;
	inode->i_fop = &fuse_file_operations;
}

void fuse_symlink_init(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
}

void fuse_special_init(struct inode *inode)
{
	inode->i_op = &fuse_special_inode_operations;
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
