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
	else
		init_special_inode(inode, inode->i_mode, attr->rdev);
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry)
{
	struct fuse_conn *fc = dir->i_sb->u.generic_sbp;
	struct fuse_inparam in;
	struct fuse_outparam out;
	struct inode *inode;
	
	in.opcode = FUSE_LOOKUP;
	in.ino = dir->i_ino;
	strcpy(in.u.lookup.name, entry->d_name.name);

	request_send(fc, &in, &out);
	
	if(out.result)
		return ERR_PTR(out.result);

	inode = iget(dir->i_sb, out.u.lookup.ino);
	if(!inode) 
		return ERR_PTR(-ENOMEM);

	init_inode(inode, &out.u.lookup.attr);

	d_add(entry, inode);
	return NULL;
}

static int fuse_permission(struct inode *inode, int mask)
{

	return 0;
}

static int fuse_revalidate(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
	struct fuse_inparam in;
	struct fuse_outparam out;
	
	in.opcode = FUSE_GETATTR;
	in.ino = inode->i_ino;

	request_send(fc, &in, &out);
	
	if(out.result == 0)
		change_attributes(inode, &out.u.getattr.attr);

	return out.result;
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
		int err;
		if(dirent->namelen > NAME_MAX) {
			printk("fuse_readdir: name too long\n");
			ret = -EPROTO;
			goto out;
		}
		if(reclen > nbytes)
			break;

		err = filldir(dstbuf, dirent->name, dirent->namelen,
			      file->f_pos, dirent->ino, dirent->type);
		if(err) {
			ret = err;
			break;
		}
		p += reclen;
		file->f_pos += reclen;
		nbytes -= reclen;
		ret ++;
	}

  out:
	kfree(buf);	
	return ret;
}



static int read_link(struct dentry *dentry, char **bufp)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
	struct fuse_in in;
	struct fuse_out out;
	unsigned long page;

	page = __get_free_page(GFP_KERNEL);
	if(!page)
		return -ENOMEM;

	in.c.opcode = FUSE_READLINK;
	in.c.ino = inode->i_ino;
	in.argsize = 0;
	out.arg = (void *) page;
	out.argsize = PAGE_SIZE;
	
	request_send(fc, &in, &out);
	if(out.c.result) {
		__free_page(page);
		return out.c.result;
	}

	*bufp = (char *) page;
	(*bufp)[PAGE_SIZE - 1] = 0;
	return 0;
}

static void free_link(char *link)
{
	__free_page((unsigned long) link);
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

static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
	struct fuse_inparam in;
	struct fuse_outparam out;
	struct file *cfile = NULL;
	
	in.opcode = FUSE_OPEN;
	in.ino = inode->i_ino;
	in.u.open.flags = file->f_flags & ~O_EXCL;

	request_send(fc, &in, &out);
	
	if(out.result == 0) {
		struct inode *inode;
		cfile = out.u.open_internal.file;
		if(!cfile) {
			printk("fuse_open: invalid container file\n");
			return -EPROTO;
		}
		inode = cfile->f_dentry->d_inode;
		if(!S_ISREG(inode->i_mode)) {
			printk("fuse_open: container is not a regular file\n");
			fput(cfile);
			return -EPROTO;
		}

		file->private_data = cfile;
	}

	return out.result;
}

static int fuse_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
	struct file *cfile = file->private_data;
	struct fuse_inparam in;
	struct fuse_outparam out;

	if(cfile)
		fput(cfile);

	in.opcode = FUSE_RELEASE;
	request_send(fc, &in, &out);

	return out.result;
}

static struct inode_operations fuse_dir_inode_operations =
{
	lookup:		fuse_lookup,
	permission:	fuse_permission,
        revalidate:	fuse_revalidate,
};

static struct file_operations fuse_dir_operations = {
	read:		generic_read_dir,
	readdir:	fuse_readdir,
	open:		fuse_open,
	release:	fuse_release,
};

static struct inode_operations fuse_file_inode_operations =
{
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

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
