/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/


#include "fuse.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp_lock.h>
#include <linux/sched.h>
#include <linux/file.h>

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
	printk(KERN_DEBUG "fuse_open: %li\n", inode->i_ino);

	return 0;
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
