/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#ifdef KERNEL_2_6
#include <linux/parser.h>
#include <linux/statfs.h>
#else
#include "compat/parser.h"
#endif


static int user_allow_other;
static kmem_cache_t *fuse_inode_cachep;

#ifdef KERNEL_2_6
#include <linux/moduleparam.h>
module_param(user_allow_other, int, 0);
#else
MODULE_PARM(user_allow_other, "i");
#endif

MODULE_PARM_DESC(user_allow_other, "Allow non root user to specify the \"allow_other\" or \"allow_root\" mount options");


#define FUSE_SUPER_MAGIC 0x65735546

#ifndef KERNEL_2_6
#define kstatfs statfs
#endif

#ifndef FS_SAFE
#define FS_SAFE 0
#endif

#ifndef MAX_LFS_FILESIZE
#define MAX_LFS_FILESIZE (((u64)PAGE_CACHE_SIZE << (BITS_PER_LONG-1))-1) 
#endif

struct fuse_mount_data {
	int fd;
	unsigned int rootmode;
	unsigned int uid;
	unsigned int flags;
	unsigned int max_read;
};

struct fuse_inode *fuse_inode_alloc(void)
{
	struct fuse_inode *fi;

	fi = kmem_cache_alloc(fuse_inode_cachep, SLAB_KERNEL);
	if (fi) {
		memset(fi, 0, sizeof(*fi));
		fi->forget_req = fuse_request_alloc();
		if (!fi->forget_req) {
			kmem_cache_free(fuse_inode_cachep, fi);
			fi = NULL;
		} else {
			init_rwsem(&fi->write_sem);
			INIT_LIST_HEAD(&fi->write_files);
		}
	}

	return fi;
}

static void fuse_inode_free(struct fuse_inode *fi)
{
	BUG_ON(!list_empty(&fi->write_files));
	if (fi->forget_req)
		fuse_request_free(fi->forget_req);
	kmem_cache_free(fuse_inode_cachep, fi);
}

static void fuse_read_inode(struct inode *inode)
{
	/* No op */
}

void fuse_send_forget(struct fuse_conn *fc, struct fuse_req *req, ino_t ino,
		      int version)
{
	struct fuse_forget_in *inarg = &req->misc.forget_in;
	inarg->version = version;
	req->in.h.opcode = FUSE_FORGET;
	req->in.h.ino = ino;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_forget_in);
	req->in.args[0].value = inarg;
	request_send_noreply(fc, req);
}

static void fuse_clear_inode(struct inode *inode)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	
	if (fi) {
		if (fc) {
			fuse_send_forget(fc, fi->forget_req, inode->i_ino,
					 inode->i_version);
			fi->forget_req = NULL;
		}
		fuse_inode_free(fi);
	}
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
	stbuf->f_bsize   = attr->bsize;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = attr->bfree;
	stbuf->f_bavail  = attr->bavail;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->ffree;
	stbuf->f_namelen = attr->namelen;
	/* fsid is left zero */
}

static int fuse_statfs(struct super_block *sb, struct kstatfs *buf)
{
	struct fuse_conn *fc = SB_FC(sb);
	struct fuse_req *req;
	struct fuse_statfs_out outarg;
	int err;

        req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	req->in.numargs = 0;
	req->in.h.opcode = FUSE_STATFS;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err)
		convert_fuse_statfs(buf, &outarg.st);
	fuse_put_request(fc, req);
	return err;
}

enum { opt_fd,
       opt_rootmode,
       opt_uid,
       opt_default_permissions, 
       opt_allow_other,
       opt_allow_root,
       opt_kernel_cache,
       opt_large_read,
       opt_direct_io,
       opt_max_read,
       opt_err };

static match_table_t tokens = {
	{opt_fd, "fd=%u"},
	{opt_rootmode, "rootmode=%o"},
	{opt_uid, "uid=%u"},
	{opt_default_permissions, "default_permissions"},
	{opt_allow_other, "allow_other"},
	{opt_allow_root, "allow_root"},
	{opt_kernel_cache, "kernel_cache"},
	{opt_large_read, "large_read"},
	{opt_direct_io, "direct_io"},
	{opt_max_read, "max_read=%u" },
	{opt_err, NULL}
};

static int parse_fuse_opt(char *opt, struct fuse_mount_data *d)
{
	char *p;
	memset(d, 0, sizeof(struct fuse_mount_data));
	d->fd = -1;
	d->max_read = ~0;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		int value;
		substring_t args[MAX_OPT_ARGS];
		if (!*p)
			continue;
		
		token = match_token(p, tokens, args);
		switch (token) {
		case opt_fd:
			if (match_int(&args[0], &value))
				return 0;
			d->fd = value;
			break;

		case opt_rootmode:
			if (match_octal(&args[0], &value))
				return 0;
			d->rootmode = value;
			break;
			
		case opt_uid:
			if (match_int(&args[0], &value))
				return 0;
			d->uid = value;
			break;
			
		case opt_default_permissions:
			d->flags |= FUSE_DEFAULT_PERMISSIONS;
			break;

		case opt_allow_other:
			d->flags |= FUSE_ALLOW_OTHER;
			break;

		case opt_allow_root:
			d->flags |= FUSE_ALLOW_ROOT;
			break;

		case opt_kernel_cache:
			d->flags |= FUSE_KERNEL_CACHE;
			break;
			
		case opt_large_read:
#ifndef KERNEL_2_6
			d->flags |= FUSE_LARGE_READ;
#else
			{
				static int warned = 0;
				if (!warned) {
					printk("fuse: large_read option is deprecated for 2.6 kernels\n");
					warned = 1;
				}
			}
#endif
			break;
			
		case opt_direct_io:
			d->flags |= FUSE_DIRECT_IO;
			break;

		case opt_max_read:
			if (match_int(&args[0], &value))
				return 0;
			d->max_read = value;
			break;

		default:
			return 0;
		}
	}
	if (d->fd == -1)
		return 0;

	return 1;
}

static int fuse_show_options(struct seq_file *m, struct vfsmount *mnt)
{
	struct fuse_conn *fc = SB_FC(mnt->mnt_sb);

	seq_printf(m, ",uid=%u", fc->uid);
	if (fc->flags & FUSE_DEFAULT_PERMISSIONS)
		seq_puts(m, ",default_permissions");
	if (fc->flags & FUSE_ALLOW_OTHER)
		seq_puts(m, ",allow_other");
	if (fc->flags & FUSE_ALLOW_ROOT)
		seq_puts(m, ",allow_root");
	if (fc->flags & FUSE_KERNEL_CACHE)
		seq_puts(m, ",kernel_cache");
#ifndef KERNEL_2_6
	if (fc->flags & FUSE_LARGE_READ)
		seq_puts(m, ",large_read");
#endif
	if (fc->flags & FUSE_DIRECT_IO)
		seq_puts(m, ",direct_io");
	if (fc->max_read != ~0)
		seq_printf(m, ",max_read=%u", fc->max_read);
	return 0;
}

static struct fuse_conn *get_conn(struct file *file, struct super_block *sb)
{
	struct fuse_conn *fc;
	struct inode *ino;

	ino = file->f_dentry->d_inode;
	if (!ino || !proc_fuse_dev || proc_fuse_dev->low_ino != ino->i_ino) {
		printk("FUSE: bad communication file descriptor\n");
		return NULL;
	}
	fc = file->private_data;
	if (fc->sb != NULL) {
		printk("fuse_read_super: connection already mounted\n");
		return NULL;
	}
	fc->sb = sb;
	return fc;
}

static struct inode *get_root_inode(struct super_block *sb, unsigned int mode)
{
	struct fuse_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.mode = mode;
	return fuse_iget(sb, 1, 0, &attr, 0);
}


#ifdef KERNEL_2_6

static struct dentry *fuse_get_dentry(struct super_block *sb, void *vobjp)
{
	__u32 *objp = vobjp;
	unsigned long ino = objp[0];
	__u32 generation = objp[1];
	struct inode *inode;
	struct dentry *entry;

	if (ino == 0)
		return ERR_PTR(-ESTALE);

	inode = ilookup(sb, ino);
	if (!inode || inode->i_generation != generation)
		return ERR_PTR(-ESTALE);

	entry = d_alloc_anon(inode);
	if (!entry) {
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
	.show_options	= fuse_show_options,
};

static int fuse_read_super(struct super_block *sb, void *data, int silent)
{	
	struct fuse_conn *fc;
	struct inode *root;
	struct fuse_mount_data d;
	struct file *file;

	if (!parse_fuse_opt((char *) data, &d))
		return -EINVAL;

	if (!user_allow_other &&
	    (d.flags & (FUSE_ALLOW_OTHER | FUSE_ALLOW_ROOT)) &&
	    current->uid != 0)
		return -EPERM;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = FUSE_SUPER_MAGIC;
	sb->s_op = &fuse_super_operations;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
#ifdef KERNEL_2_6
	sb->s_export_op = &fuse_export_operations;
#endif

	file = fget(d.fd);
	if (!file)
		return -EINVAL;

	spin_lock(&fuse_lock);
	fc = get_conn(file, sb);
	spin_unlock(&fuse_lock);
	fput(file);
	if (fc == NULL)
		return -EINVAL;

	fc->flags = d.flags;
	fc->uid = d.uid;
	fc->max_read = d.max_read;
	fc->max_write = FUSE_MAX_IN / 2;
	
	/* fc is needed in fuse_init_file_inode which could be called
	   from get_root_inode */
	SB_FC(sb) = fc;

	root = get_root_inode(sb, d.rootmode);
	if (root == NULL) {
		printk("fuse_read_super: failed to get root inode\n");
		goto err;
	}

	sb->s_root = d_alloc_root(root);
	if (!sb->s_root) {
		iput(root);
		goto err;
	}

	return 0;

 err:
	spin_lock(&fuse_lock);
	fc->sb = NULL;
	fuse_release_conn(fc);
	spin_unlock(&fuse_lock);
	SB_FC(sb) = NULL;
	return -EINVAL;
}

#ifdef KERNEL_2_6
static struct super_block *fuse_get_sb(struct file_system_type *fs_type,
				       int flags, const char *dev_name,
				       void *raw_data)
{
	return get_sb_nodev(fs_type, flags, raw_data, fuse_read_super);
}

static struct file_system_type fuse_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuse",
	.get_sb		= fuse_get_sb,
	.kill_sb	= kill_anon_super,
	.fs_flags	= FS_SAFE,
};
#else
static struct super_block *fuse_read_super_compat(struct super_block *sb,
						  void *data, int silent)
{
	int err = fuse_read_super(sb, data, silent);
	if (err)
		return NULL;
	else
		return sb;
}

static DECLARE_FSTYPE(fuse_fs_type, "fuse", fuse_read_super_compat, 0);
#endif

int fuse_fs_init()
{
	int err;

	err = register_filesystem(&fuse_fs_type);
	if (err)
		printk("fuse: failed to register filesystem\n");
	else {
		fuse_inode_cachep = kmem_cache_create("fuse_inode",
						      sizeof(struct fuse_inode),
						      0, 0, NULL, NULL);
		if (!fuse_inode_cachep) {
			unregister_filesystem(&fuse_fs_type);
			err = -ENOMEM;
		}
	}

	return err;
}

void fuse_fs_cleanup()
{
	unregister_filesystem(&fuse_fs_type);
	kmem_cache_destroy(fuse_inode_cachep);
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
