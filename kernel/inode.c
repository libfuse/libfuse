/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#ifdef KERNEL_2_6
#include <linux/statfs.h>
#endif

#define FUSE_SUPER_MAGIC 0x65735546

#ifndef KERNEL_2_6
#define kstatfs statfs
#endif

static void fuse_read_inode(struct inode *inode)
{
	/* No op */
}

static void fuse_clear_inode(struct inode *inode)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in *in = NULL;
	struct fuse_forget_in *inarg = NULL;
	unsigned int s = sizeof(struct fuse_in) + sizeof(struct fuse_forget_in);
	
	if(fc == NULL)
		return;

	in = kmalloc(s, GFP_NOFS);
	if(!in)
		return;
	memset(in, 0, s);
	inarg = (struct fuse_forget_in *) (in + 1);
	inarg->version = inode->i_version;
		
	in->h.opcode = FUSE_FORGET;
	in->h.ino = inode->i_ino;
	in->numargs = 1;
	in->args[0].size = sizeof(struct fuse_forget_in);
	in->args[0].value = inarg;
		
	if(!request_send_noreply(fc, in))
		return;

	kfree(in);
}

static void fuse_put_super(struct super_block *sb)
{
	struct fuse_conn *fc = SB_FC(sb);

	spin_lock(&fuse_lock);
	fc->sb = NULL;
	fc->uid = 0;
	fc->flags = 0;
	/* Flush all readers on this fs */
	wake_up_all(&fc->waitq);
	fuse_release_conn(fc);
	SB_FC(sb) = NULL;
	spin_unlock(&fuse_lock);
}

static void convert_fuse_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr)
{
	stbuf->f_type    = FUSE_SUPER_MAGIC;
	stbuf->f_bsize   = attr->block_size;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = stbuf->f_bavail = attr->blocks_free;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->files_free;
	/* Is this field necessary?  Most filesystems ignore it...
	stbuf->f_fsid.val[0] = (FUSE_SUPER_MAGIC>>16)&0xffff;
	stbuf->f_fsid.val[1] =  FUSE_SUPER_MAGIC     &0xffff; */
	stbuf->f_namelen = attr->namelen;
}

static int fuse_statfs(struct super_block *sb, struct kstatfs *buf)
{
	struct fuse_conn *fc = SB_FC(sb);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_statfs_out outarg;
        
	in.numargs = 0;
	in.h.opcode = FUSE_STATFS;
	out.numargs = 1;
	out.args[0].size = sizeof(outarg);
	out.args[0].value = &outarg;
	request_send(fc, &in, &out);
	if(!out.h.error)
		convert_fuse_statfs(buf, &outarg.st);
	
	return out.h.error;
}

static struct fuse_conn *get_conn(struct fuse_mount_data *d)
{
	struct fuse_conn *fc = NULL;
	struct file *file;
	struct inode *ino;

	if(d == NULL) {
		printk("fuse_read_super: Bad mount data\n");
		return NULL;
	}

	if(d->version != FUSE_KERNEL_VERSION) {
		printk("fuse_read_super: Bad version: %i\n", d->version);
		return NULL;
	}

	file = fget(d->fd);
	ino = NULL;
	if(file)
		ino = file->f_dentry->d_inode;
	
	if(!ino || !proc_fuse_dev || proc_fuse_dev->low_ino != ino->i_ino) {
		printk("fuse_read_super: Bad file: %i\n", d->fd);
		goto out;
	}

	fc = file->private_data;

  out:
	fput(file);
	return fc;

}

static struct inode *get_root_inode(struct super_block *sb, unsigned int mode)
{
	struct fuse_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.mode = mode;
	return fuse_iget(sb, 1, &attr, 0);
}


#ifdef KERNEL_2_6

static struct dentry *fuse_get_dentry(struct super_block *sb, void *vobjp)
{
	__u32 *objp = vobjp;
	unsigned long ino = objp[0];
	/* __u32 generation = objp[1]; */
	struct inode *inode;
	struct dentry *entry;

	if(ino == 0)
		return ERR_PTR(-ESTALE);

	inode = ilookup(sb, ino);
	if(!inode)
		return ERR_PTR(-ESTALE);

	entry = d_alloc_anon(inode);
	if(!entry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	return entry;
}

static struct export_operations fuse_export_operations = {
	.get_dentry	= fuse_get_dentry,
};
#endif

static struct super_operations fuse_super_operations = {
	.read_inode	= fuse_read_inode,
	.clear_inode	= fuse_clear_inode,
	.put_super	= fuse_put_super,
	.statfs		= fuse_statfs,
};

static int fuse_read_super(struct super_block *sb, void *data, int silent)
{	
	struct fuse_conn *fc;
	struct inode *root;
	struct fuse_mount_data *d = data;

        sb->s_blocksize = PAGE_CACHE_SIZE;
        sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
        sb->s_magic = FUSE_SUPER_MAGIC;
        sb->s_op = &fuse_super_operations;
#ifdef KERNEL_2_6
	sb->s_export_op = &fuse_export_operations;
#endif

	fc = get_conn(d);
	if(fc == NULL)
		return -EINVAL;
	spin_lock(&fuse_lock);
	if(fc->sb != NULL) {
		printk("fuse_read_super: connection already mounted\n");
		spin_unlock(&fuse_lock);
		return -EINVAL;
	}
	fc->sb = sb;
	fc->flags = d->flags;
	fc->uid = d->uid;
	spin_unlock(&fuse_lock);
	
	/* fc is needed in fuse_init_file_inode which could be called
           from get_root_inode */
	SB_FC(sb) = fc;

	root = get_root_inode(sb, d->rootmode);
	if(root == NULL) {
		printk("fuse_read_super: failed to get root inode\n");
		return -EINVAL;
	}

	sb->s_root = d_alloc_root(root);
	if(!sb->s_root)
		return -EINVAL;

	return 0;
}

#ifdef KERNEL_2_6
static struct super_block *fuse_get_sb(struct file_system_type *fs_type,
				       int flags, const char *dev_name,
				       void *raw_data)
{
        return get_sb_nodev(fs_type, flags, raw_data, fuse_read_super);
}

static struct file_system_type fuse_fs_type = {
        .owner          = THIS_MODULE,
        .name           = "fuse",
        .get_sb         = fuse_get_sb,
        .kill_sb        = kill_anon_super,
        .fs_flags       = 0
};
#else
static struct super_block *fuse_read_super_compat(struct super_block *sb,
						  void *data, int silent)
{
	int err = fuse_read_super(sb, data, silent);
	if(err)
		return NULL;
	else
		return sb;
}

static DECLARE_FSTYPE(fuse_fs_type, "fuse", fuse_read_super_compat, 0);
#endif

int fuse_fs_init()
{
	int res;

	res = register_filesystem(&fuse_fs_type);
	if(res)
		printk("fuse: failed to register filesystem\n");

	return res;
}

void fuse_fs_cleanup()
{
	unregister_filesystem(&fuse_fs_type);
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
