/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/


#include "fuse_i.h"

#include <linux/module.h>
#include <linux/kernel.h>

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry)
{
	printk(KERN_DEBUG "fuse_lookup: %li\n", dir->i_ino);

	return NULL;
}

static int fuse_permission(struct inode *inode, int mask)
{
	printk(KERN_DEBUG "fuse_permission: %li, 0%o\n", inode->i_ino, mask);

	return 0;
}

static int fuse_revalidate(struct dentry *dentry)
{
	printk(KERN_DEBUG "fuse_revalidate: %li\n",
	       dentry->d_inode->i_ino);
	
	return 0;
}
static int fuse_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	printk(KERN_DEBUG "fuse_readdir: %li\n",
	       file->f_dentry->d_inode->i_ino);
	
	return 0;
}

static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = inode->i_sb->u.generic_sbp;
	struct fuse_inparam in;
	struct fuse_outparam out;
	
	printk(KERN_DEBUG "fuse_open: %li\n", inode->i_ino);

	in.opcode = FUSE_OPEN;
	in.u.open.ino = inode->i_ino;
	in.u.open.flags = file->f_flags & ~O_EXCL;

	request_send(fc, &in, &out, 0);

	printk(KERN_DEBUG "  fuse_open: <%i> %i\n", out.result, out.u.open.fd);

	return out.result;
}

static int fuse_release(struct inode *inode, struct file *file)
{
	printk(KERN_DEBUG "fuse_release: %li\n", inode->i_ino);

	return 0;
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

void fuse_dir_init(struct inode *inode)
{
	inode->i_op = &fuse_dir_inode_operations;
	inode->i_fop = &fuse_dir_operations;
}


/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
