/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#ifdef KERNEL_2_6
#include <linux/parser.h>
#include <linux/statfs.h>
#else
#include "compat/parser.h"
#endif

MODULE_AUTHOR("Miklos Szeredi <miklos@szeredi.hu>");
MODULE_DESCRIPTION("Filesystem in Userspace");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

static kmem_cache_t *fuse_inode_cachep;
#ifdef KERNEL_2_6
static struct subsystem connections_subsys;

struct fuse_conn_attr {
	struct attribute attr;
	ssize_t (*show)(struct fuse_conn *, char *);
	ssize_t (*store)(struct fuse_conn *, const char *, size_t);
};
#endif

#define FUSE_SUPER_MAGIC 0x65735546

#ifndef KERNEL_2_6
#define kstatfs statfs
#endif
#ifndef MAX_LFS_FILESIZE
#define MAX_LFS_FILESIZE (((u64)PAGE_CACHE_SIZE << (BITS_PER_LONG-1))-1)
#endif
struct fuse_mount_data {
	int fd;
	unsigned rootmode;
	unsigned user_id;
	unsigned group_id;
	unsigned fd_present : 1;
	unsigned rootmode_present : 1;
	unsigned user_id_present : 1;
	unsigned group_id_present : 1;
	unsigned flags;
	unsigned max_read;
};

static struct inode *fuse_alloc_inode(struct super_block *sb)
{
	struct inode *inode;
	struct fuse_inode *fi;

	inode = kmem_cache_alloc(fuse_inode_cachep, SLAB_KERNEL);
	if (!inode)
		return NULL;

#ifndef KERNEL_2_6
	inode->u.generic_ip = NULL;
#endif
	fi = get_fuse_inode(inode);
	fi->i_time = jiffies - 1;
	fi->nodeid = 0;
	fi->nlookup = 0;
	fi->forget_req = fuse_request_alloc();
	if (!fi->forget_req) {
		kmem_cache_free(fuse_inode_cachep, inode);
		return NULL;
	}

	return inode;
}

static void fuse_destroy_inode(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	if (fi->forget_req)
		fuse_request_free(fi->forget_req);
	kmem_cache_free(fuse_inode_cachep, inode);
}

static void fuse_read_inode(struct inode *inode)
{
	/* No op */
}

void fuse_send_forget(struct fuse_conn *fc, struct fuse_req *req,
		      unsigned long nodeid, u64 nlookup)
{
	struct fuse_forget_in *inarg = &req->misc.forget_in;
	inarg->nlookup = nlookup;
	req->in.h.opcode = FUSE_FORGET;
	req->in.h.nodeid = nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_forget_in);
	req->in.args[0].value = inarg;
	request_send_noreply(fc, req);
}

static void fuse_clear_inode(struct inode *inode)
{
	if (inode->i_sb->s_flags & MS_ACTIVE) {
		struct fuse_conn *fc = get_fuse_conn(inode);
		struct fuse_inode *fi = get_fuse_inode(inode);
		fuse_send_forget(fc, fi->forget_req, fi->nodeid, fi->nlookup);
		fi->forget_req = NULL;
	}
}

void fuse_change_attributes(struct inode *inode, struct fuse_attr *attr)
{
	if (S_ISREG(inode->i_mode) && i_size_read(inode) != attr->size)
#ifdef KERNEL_2_6
		invalidate_inode_pages(inode->i_mapping);
#else
		invalidate_inode_pages(inode);
#endif

	inode->i_ino     = attr->ino;
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
		fuse_init_common(inode);
		fuse_init_file_inode(inode);
	} else if (S_ISDIR(inode->i_mode))
		fuse_init_dir(inode);
	else if (S_ISLNK(inode->i_mode))
		fuse_init_symlink(inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		fuse_init_common(inode);
		init_special_inode(inode, inode->i_mode,
				   new_decode_dev(attr->rdev));
	} else
		BUG();
}

#ifdef KERNEL_2_6
static int fuse_inode_eq(struct inode *inode, void *_nodeidp)
{
	unsigned long nodeid = *(unsigned long *) _nodeidp;
	if (get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

static int fuse_inode_set(struct inode *inode, void *_nodeidp)
{
	unsigned long nodeid = *(unsigned long *) _nodeidp;
	get_fuse_inode(inode)->nodeid = nodeid;
	return 0;
}

struct inode *fuse_iget(struct super_block *sb, unsigned long nodeid,
			int generation, struct fuse_attr *attr)
{
	struct inode *inode;
	struct fuse_inode *fi;
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	int retried = 0;

 retry:
	inode = iget5_locked(sb, nodeid, fuse_inode_eq, fuse_inode_set, &nodeid);
	if (!inode)
		return NULL;

	if ((inode->i_state & I_NEW)) {
#ifdef KERNEL_2_6_8_PLUS
		inode->i_flags |= S_NOATIME|S_NOCMTIME;
#else
		inode->i_flags |= S_NOATIME;
#endif
		inode->i_generation = generation;
		inode->i_data.backing_dev_info = &fc->bdi;
		fuse_init_inode(inode, attr);
		unlock_new_inode(inode);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		BUG_ON(retried);
		/* Inode has changed type, any I/O on the old should fail */
		make_bad_inode(inode);
		iput(inode);
		retried = 1;
		goto retry;
	}

	fi = get_fuse_inode(inode);
	fi->nlookup ++;
	fuse_change_attributes(inode, attr);
	return inode;
}
#else
static int fuse_inode_eq(struct inode *inode, unsigned long ino, void *_nodeidp){
	unsigned long nodeid = *(unsigned long *) _nodeidp;
	if (inode->u.generic_ip && get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

struct inode *fuse_iget(struct super_block *sb, unsigned long nodeid,
			int generation, struct fuse_attr *attr)
{
	struct inode *inode;
	struct fuse_inode *fi;
	int retried = 0;

 retry:
	inode = iget4(sb, attr->ino, fuse_inode_eq, &nodeid);
	if (!inode)
		return NULL;

	if (!inode->u.generic_ip) {
		get_fuse_inode(inode)->nodeid = nodeid;
		inode->u.generic_ip = inode;
		inode->i_generation = generation;
		fuse_init_inode(inode, attr);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		BUG_ON(retried);
		/* Inode has changed type, any I/O on the old should fail */
		remove_inode_hash(inode);
		make_bad_inode(inode);
		iput(inode);
		retried = 1;
		goto retry;
	}

	fi = get_fuse_inode(inode);
	fi->nlookup ++;
	fuse_change_attributes(inode, attr);
	return inode;
}
#endif

static void fuse_umount_begin(struct super_block *sb)
{
	fuse_abort_conn(get_fuse_conn_super(sb));
}

static void fuse_put_super(struct super_block *sb)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);

	down_write(&fc->sbput_sem);
	while (!list_empty(&fc->background))
		fuse_release_background(fc,
					list_entry(fc->background.next,
						   struct fuse_req, bg_entry));

	spin_lock(&fc->lock);
	fc->mounted = 0;
	fc->connected = 0;
	spin_unlock(&fc->lock);
	up_write(&fc->sbput_sem);
	/* Flush all readers on this fs */
	kill_fasync(&fc->fasync, SIGIO, POLL_IN);
	wake_up_all(&fc->waitq);
#ifdef KERNEL_2_6
	kobject_del(&fc->kobj);
#endif
	kobject_put(&fc->kobj);
}

static void convert_fuse_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr)
{
	stbuf->f_type    = FUSE_SUPER_MAGIC;
	stbuf->f_bsize   = attr->bsize;
#ifdef KERNEL_2_6
	stbuf->f_frsize  = attr->frsize;
#endif
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
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct fuse_req *req;
	struct fuse_statfs_out outarg;
	int err;

        req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	memset(&outarg, 0, sizeof(outarg));
	req->in.numargs = 0;
	req->in.h.opcode = FUSE_STATFS;
	req->out.numargs = 1;
	req->out.args[0].size =
		fc->minor < 4 ? FUSE_COMPAT_STATFS_SIZE : sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err)
		convert_fuse_statfs(buf, &outarg.st);
	fuse_put_request(fc, req);
	return err;
}

enum {
	OPT_FD,
	OPT_ROOTMODE,
	OPT_USER_ID,
	OPT_GROUP_ID,
	OPT_DEFAULT_PERMISSIONS,
	OPT_ALLOW_OTHER,
#ifndef KERNEL_2_6
	OPT_LARGE_READ,
#endif
	OPT_MAX_READ,
	OPT_ERR
};

static match_table_t tokens = {
	{OPT_FD,			"fd=%u"},
	{OPT_ROOTMODE,			"rootmode=%o"},
	{OPT_USER_ID,			"user_id=%u"},
	{OPT_GROUP_ID,			"group_id=%u"},
	{OPT_DEFAULT_PERMISSIONS,	"default_permissions"},
	{OPT_ALLOW_OTHER,		"allow_other"},
#ifndef KERNEL_2_6
	{OPT_LARGE_READ,		"large_read"},
#endif
	{OPT_MAX_READ,			"max_read=%u"},
	{OPT_ERR,			NULL}
};

static int parse_fuse_opt(char *opt, struct fuse_mount_data *d)
{
	char *p;
	memset(d, 0, sizeof(struct fuse_mount_data));
	d->max_read = ~0;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		int value;
		substring_t args[MAX_OPT_ARGS];
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case OPT_FD:
			if (match_int(&args[0], &value))
				return 0;
			d->fd = value;
			d->fd_present = 1;
			break;

		case OPT_ROOTMODE:
			if (match_octal(&args[0], &value))
				return 0;
			d->rootmode = value;
			d->rootmode_present = 1;
			break;

		case OPT_USER_ID:
			if (match_int(&args[0], &value))
				return 0;
			d->user_id = value;
			d->user_id_present = 1;
			break;

		case OPT_GROUP_ID:
			if (match_int(&args[0], &value))
				return 0;
			d->group_id = value;
			d->group_id_present = 1;
			break;

		case OPT_DEFAULT_PERMISSIONS:
			d->flags |= FUSE_DEFAULT_PERMISSIONS;
			break;

		case OPT_ALLOW_OTHER:
			d->flags |= FUSE_ALLOW_OTHER;
			break;

#ifndef KERNEL_2_6
		case OPT_LARGE_READ:
			d->flags |= FUSE_LARGE_READ;
			break;
#endif
		case OPT_MAX_READ:
			if (match_int(&args[0], &value))
				return 0;
			d->max_read = value;
			break;

		default:
			return 0;
		}
	}

	if (!d->fd_present || !d->rootmode_present ||
	    !d->user_id_present || !d->group_id_present)
		return 0;

	return 1;
}

static int fuse_show_options(struct seq_file *m, struct vfsmount *mnt)
{
	struct fuse_conn *fc = get_fuse_conn_super(mnt->mnt_sb);

	seq_printf(m, ",user_id=%u", fc->user_id);
	seq_printf(m, ",group_id=%u", fc->group_id);
	if (fc->flags & FUSE_DEFAULT_PERMISSIONS)
		seq_puts(m, ",default_permissions");
	if (fc->flags & FUSE_ALLOW_OTHER)
		seq_puts(m, ",allow_other");
#ifndef KERNEL_2_6
	if (fc->flags & FUSE_LARGE_READ)
		seq_puts(m, ",large_read");
#endif
	if (fc->max_read != ~0)
		seq_printf(m, ",max_read=%u", fc->max_read);
	return 0;
}

static void fuse_conn_release(struct kobject *kobj)
{
	struct fuse_conn *fc = get_fuse_conn_kobj(kobj);

	while (!list_empty(&fc->unused_list)) {
		struct fuse_req *req;
		req = list_entry(fc->unused_list.next, struct fuse_req, list);
		list_del(&req->list);
		fuse_request_free(req);
	}
	kfree(fc);
}

#ifndef HAVE_KZALLOC
static void *kzalloc(size_t size, int flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif
static struct fuse_conn *new_conn(void)
{
	struct fuse_conn *fc;

	fc = kzalloc(sizeof(*fc), GFP_KERNEL);
	if (fc) {
		int i;
		spin_lock_init(&fc->lock);
		init_waitqueue_head(&fc->waitq);
		INIT_LIST_HEAD(&fc->pending);
		INIT_LIST_HEAD(&fc->processing);
		INIT_LIST_HEAD(&fc->io);
		INIT_LIST_HEAD(&fc->unused_list);
		INIT_LIST_HEAD(&fc->background);
		sema_init(&fc->outstanding_sem, 1); /* One for INIT */
		init_rwsem(&fc->sbput_sem);
#ifdef KERNEL_2_6
		kobj_set_kset_s(fc, connections_subsys);
		kobject_init(&fc->kobj);
#else
		atomic_set(&fc->kobj.count, 1);
		fc->kobj.release = fuse_conn_release;
#endif
		atomic_set(&fc->num_waiting, 0);
		for (i = 0; i < FUSE_MAX_OUTSTANDING; i++) {
			struct fuse_req *req = fuse_request_alloc();
			if (!req) {
				kobject_put(&fc->kobj);
				return NULL;
			}
			list_add(&req->list, &fc->unused_list);
		}
#ifdef KERNEL_2_6_6_PLUS
		fc->bdi.ra_pages = (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE;
		fc->bdi.unplug_io_fn = default_unplug_io_fn;
#endif
		fc->reqctr = 0;
	}
	return fc;
}

static struct inode *get_root_inode(struct super_block *sb, unsigned mode)
{
	struct fuse_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.mode = mode;
	attr.ino = FUSE_ROOT_ID;
	return fuse_iget(sb, 1, 0, &attr);
}
#ifndef FUSE_MAINLINE
#ifdef KERNEL_2_6
static struct dentry *fuse_get_dentry(struct super_block *sb, void *vobjp)
{
	__u32 *objp = vobjp;
	unsigned long nodeid = objp[0];
	__u32 generation = objp[1];
	struct inode *inode;
	struct dentry *entry;

	if (nodeid == 0)
		return ERR_PTR(-ESTALE);

	inode = ilookup5(sb, nodeid, fuse_inode_eq, &nodeid);
	if (!inode)
		return ERR_PTR(-ESTALE);
	if (inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	entry = d_alloc_anon(inode);
	if (!entry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	return entry;
}

static int fuse_encode_fh(struct dentry *dentry, __u32 *fh, int *max_len,
			  int connectable)
{
	struct inode *inode = dentry->d_inode;
	int len = *max_len;
	int type = 1;

	if (len < 2 || (connectable && len < 4))
		return 255;

	len = 2;
	fh[0] = get_fuse_inode(inode)->nodeid;
	fh[1] = inode->i_generation;
	if (connectable && !S_ISDIR(inode->i_mode)) {
		struct inode *parent;

		spin_lock(&dentry->d_lock);
		parent = dentry->d_parent->d_inode;
		fh[2] = get_fuse_inode(parent)->nodeid;
		fh[3] = parent->i_generation;
		spin_unlock(&dentry->d_lock);
		len = 4;
		type = 2;
	}
	*max_len = len;
	return type;
}

static struct export_operations fuse_export_operations = {
	.get_dentry	= fuse_get_dentry,
	.encode_fh      = fuse_encode_fh,
};
#endif
#endif

static struct super_operations fuse_super_operations = {
	.alloc_inode    = fuse_alloc_inode,
	.destroy_inode  = fuse_destroy_inode,
	.read_inode	= fuse_read_inode,
	.clear_inode	= fuse_clear_inode,
	.put_super	= fuse_put_super,
	.umount_begin	= fuse_umount_begin,
	.statfs		= fuse_statfs,
	.show_options	= fuse_show_options,
};

static void process_init_reply(struct fuse_conn *fc, struct fuse_req *req)
{
	int i;
	struct fuse_init_out *arg = &req->misc.init_out;

	if (req->out.h.error || arg->major != FUSE_KERNEL_VERSION)
		fc->conn_error = 1;
	else {
#ifdef KERNEL_2_6
		unsigned long ra_pages;

		if (arg->minor >= 6) {
			ra_pages = arg->max_readahead / PAGE_CACHE_SIZE;
			if (arg->flags & FUSE_ASYNC_READ)
				fc->async_read = 1;
		} else
			ra_pages = fc->max_read / PAGE_CACHE_SIZE;

		fc->bdi.ra_pages = min(fc->bdi.ra_pages, ra_pages);
#endif
		fc->minor = arg->minor;
		fc->max_write = arg->minor < 5 ? 4096 : arg->max_write;
	}

	/* After INIT reply is received other requests can go
	   out.  So do (FUSE_MAX_OUTSTANDING - 1) number of
	   up()s on outstanding_sem.  The last up() is done in
	   fuse_putback_request() */
	for (i = 1; i < FUSE_MAX_OUTSTANDING; i++)
		up(&fc->outstanding_sem);

	fuse_put_request(fc, req);
}

static void fuse_send_init(struct fuse_conn *fc)
{
	/* This is called from fuse_read_super() so there's guaranteed
	   to be exactly one request available */
	struct fuse_req *req = fuse_get_request(fc);
	struct fuse_init_in *arg = &req->misc.init_in;

	arg->major = FUSE_KERNEL_VERSION;
	arg->minor = FUSE_KERNEL_MINOR_VERSION;
#ifdef KERNEL_2_6
	arg->max_readahead = fc->bdi.ra_pages * PAGE_CACHE_SIZE;
	arg->flags |= FUSE_ASYNC_READ;
#endif
	req->in.h.opcode = FUSE_INIT;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*arg);
	req->in.args[0].value = arg;
	req->out.numargs = 1;
	/* Variable length arguement used for backward compatibility
	   with interface version < 7.5.  Rest of init_out is zeroed
	   by do_get_request(), so a short reply is not a problem */
	req->out.argvar = 1;
	req->out.args[0].size = sizeof(struct fuse_init_out);
	req->out.args[0].value = &req->misc.init_out;
	req->end = process_init_reply;
	request_send_background(fc, req);
}

#ifdef KERNEL_2_6
static unsigned long long conn_id(void)
{
	/* BKL is held for ->get_sb() */
	static unsigned long long ctr = 1;
	return ctr++;
}
#endif

static int fuse_fill_super(struct super_block *sb, void *data, int silent)
{
	struct fuse_conn *fc;
	struct inode *root;
	struct fuse_mount_data d;
	struct file *file;
	struct dentry *root_dentry;
	int err;

	if (!parse_fuse_opt((char *) data, &d))
		return -EINVAL;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = FUSE_SUPER_MAGIC;
	sb->s_op = &fuse_super_operations;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
#ifndef FUSE_MAINLINE
#ifdef KERNEL_2_6
	sb->s_export_op = &fuse_export_operations;
#endif
#endif

	file = fget(d.fd);
	if (!file)
		return -EINVAL;

	if (file->f_op != &fuse_dev_operations)
		return -EINVAL;

	/* Setting file->private_data can't race with other mount()
	   instances, since BKL is held for ->get_sb() */
	if (file->private_data)
		return -EINVAL;

	fc = new_conn();
	if (!fc)
		return -ENOMEM;

	fc->flags = d.flags;
	fc->user_id = d.user_id;
	fc->group_id = d.group_id;
	fc->max_read = d.max_read;

	/* Used by get_root_inode() */
	sb->s_fs_info = fc;

	err = -ENOMEM;
	root = get_root_inode(sb, d.rootmode);
	if (!root)
		goto err;

	root_dentry = d_alloc_root(root);
	if (!root_dentry) {
		iput(root);
		goto err;
	}

#ifdef KERNEL_2_6
	err = kobject_set_name(&fc->kobj, "%llu", conn_id());
	if (err)
		goto err_put_root;

	err = kobject_add(&fc->kobj);
	if (err)
		goto err_put_root;
#endif

	sb->s_root = root_dentry;
	fc->mounted = 1;
	fc->connected = 1;
	kobject_get(&fc->kobj);
	file->private_data = fc;
	/*
	 * atomic_dec_and_test() in fput() provides the necessary
	 * memory barrier for file->private_data to be visible on all
	 * CPUs after this
	 */
	fput(file);

	fuse_send_init(fc);

	return 0;

#ifdef KERNEL_2_6
 err_put_root:
	dput(root_dentry);
#endif
 err:
	fput(file);
	kobject_put(&fc->kobj);
	return err;
}

#ifdef KERNEL_2_6
static struct super_block *fuse_get_sb(struct file_system_type *fs_type,
				       int flags, const char *dev_name,
				       void *raw_data)
{
	return get_sb_nodev(fs_type, flags, raw_data, fuse_fill_super);
}

static struct file_system_type fuse_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuse",
	.get_sb		= fuse_get_sb,
	.kill_sb	= kill_anon_super,
};
#else
static struct super_block *fuse_read_super_compat(struct super_block *sb,
						  void *data, int silent)
{
	int err = fuse_fill_super(sb, data, silent);
	if (err)
		return NULL;
	else
		return sb;
}

static DECLARE_FSTYPE(fuse_fs_type, "fuse", fuse_read_super_compat, 0);
#endif

#ifdef KERNEL_2_6
static ssize_t fuse_conn_waiting_show(struct fuse_conn *fc, char *page)
{
	return sprintf(page, "%i\n", atomic_read(&fc->num_waiting));
}

static ssize_t fuse_conn_abort_store(struct fuse_conn *fc, const char *page,
				     size_t count)
{
	fuse_abort_conn(fc);
	return count;
}

#ifndef __ATTR
#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE },	\
	.show	= _show,					\
	.store	= _store,					\
}
#endif
static struct fuse_conn_attr fuse_conn_waiting =
	__ATTR(waiting, 0400, fuse_conn_waiting_show, NULL);
static struct fuse_conn_attr fuse_conn_abort =
	__ATTR(abort, 0600, NULL, fuse_conn_abort_store);

static struct attribute *fuse_conn_attrs[] = {
	&fuse_conn_waiting.attr,
	&fuse_conn_abort.attr,
	NULL,
};

static ssize_t fuse_conn_attr_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *page)
{
	struct fuse_conn_attr *fca =
		container_of(attr, struct fuse_conn_attr, attr);

	if (fca->show)
		return fca->show(get_fuse_conn_kobj(kobj), page);
	else
		return -EACCES;
}

static ssize_t fuse_conn_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *page, size_t count)
{
	struct fuse_conn_attr *fca =
		container_of(attr, struct fuse_conn_attr, attr);

	if (fca->store)
		return fca->store(get_fuse_conn_kobj(kobj), page, count);
	else
		return -EACCES;
}

static struct sysfs_ops fuse_conn_sysfs_ops = {
	.show	= &fuse_conn_attr_show,
	.store	= &fuse_conn_attr_store,
};

static struct kobj_type ktype_fuse_conn = {
	.release	= fuse_conn_release,
	.sysfs_ops	= &fuse_conn_sysfs_ops,
	.default_attrs	= fuse_conn_attrs,
};

#ifndef HAVE_FS_SUBSYS
static decl_subsys(fs, NULL, NULL);
#endif
static decl_subsys(fuse, NULL, NULL);
static decl_subsys(connections, &ktype_fuse_conn, NULL);
#endif /* KERNEL_2_6 */

static void fuse_inode_init_once(void *foo, kmem_cache_t *cachep,
				 unsigned long flags)
{
	struct inode * inode = foo;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR)
		inode_init_once(inode);
}

static int __init fuse_fs_init(void)
{
	int err;

	err = register_filesystem(&fuse_fs_type);
	if (err)
		printk("fuse: failed to register filesystem\n");
	else {
		fuse_inode_cachep = kmem_cache_create("fuse_inode",
						      sizeof(struct fuse_inode),
						      0, SLAB_HWCACHE_ALIGN,
						      fuse_inode_init_once, NULL);
		if (!fuse_inode_cachep) {
			unregister_filesystem(&fuse_fs_type);
			err = -ENOMEM;
		}
	}

	return err;
}

static void fuse_fs_cleanup(void)
{
	unregister_filesystem(&fuse_fs_type);
	kmem_cache_destroy(fuse_inode_cachep);
}

#ifdef KERNEL_2_6
static int fuse_sysfs_init(void)
{
	int err;

#ifndef HAVE_FS_SUBSYS
	err = subsystem_register(&fs_subsys);
	if (err)
		return err;
#endif
	kset_set_kset_s(&fuse_subsys, fs_subsys);
	err = subsystem_register(&fuse_subsys);
	if (err)
		goto out_err;

	kset_set_kset_s(&connections_subsys, fuse_subsys);
	err = subsystem_register(&connections_subsys);
	if (err)
		goto out_fuse_unregister;

	return 0;

 out_fuse_unregister:
	subsystem_unregister(&fuse_subsys);
 out_err:
#ifndef HAVE_FS_SUBSYS
	subsystem_unregister(&fs_subsys);
#endif
	return err;
}

static void fuse_sysfs_cleanup(void)
{
	subsystem_unregister(&connections_subsys);
	subsystem_unregister(&fuse_subsys);
#ifndef HAVE_FS_SUBSYS
	subsystem_unregister(&fs_subsys);
#endif
}
#else /* KERNEL_2_6 */
static int fuse_sysfs_init(void)
{
	return 0;
}
static void fuse_sysfs_cleanup(void)
{
}
#endif /* KERNEL_2_6 */

static int __init fuse_init(void)
{
	int res;

	printk("fuse init (API version %i.%i)\n",
	       FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);
#ifndef FUSE_MAINLINE
	printk("fuse distribution version: %s\n", FUSE_VERSION);
#endif

	res = fuse_fs_init();
	if (res)
		goto err;

	res = fuse_dev_init();
	if (res)
		goto err_fs_cleanup;

	res = fuse_sysfs_init();
	if (res)
		goto err_dev_cleanup;

	return 0;

 err_dev_cleanup:
	fuse_dev_cleanup();
 err_fs_cleanup:
	fuse_fs_cleanup();
 err:
	return res;
}

static void __exit fuse_exit(void)
{
	printk(KERN_DEBUG "fuse exit\n");

	fuse_sysfs_cleanup();
	fuse_fs_cleanup();
	fuse_dev_cleanup();
}

module_init(fuse_init);
module_exit(fuse_exit);
