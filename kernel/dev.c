/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#ifdef KERNEL_2_6
#include <linux/kobject.h>
#else
#include <linux/proc_fs.h>
#endif
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/file.h>

static kmem_cache_t *fuse_req_cachep;

static inline struct fuse_conn *fuse_get_conn(struct file *file)
{
	struct fuse_conn *fc;
	spin_lock(&fuse_lock);
	fc = file->private_data;
	if (fc && !fc->sb)
		fc = NULL;
	spin_unlock(&fuse_lock);
	return fc;
}

struct fuse_req *fuse_request_alloc(void)
{
	struct fuse_req *req = kmem_cache_alloc(fuse_req_cachep, SLAB_KERNEL);
	if (req) {
		memset(req, 0, sizeof(*req));
		INIT_LIST_HEAD(&req->list);
		init_waitqueue_head(&req->waitq);
	}
	return req;
}

void fuse_request_free(struct fuse_req *req)
{
	kmem_cache_free(fuse_req_cachep, req);
}

/* Called with fuse_lock held.  Releases, and then reaquires it. */
static void request_wait_answer(struct fuse_req *req)
{
	spin_unlock(&fuse_lock);
	wait_event(req->waitq, req->finished);
	spin_lock(&fuse_lock);
}

static int get_unique(struct fuse_conn *fc)
{
	fc->reqctr++;
	if (fc->reqctr == 0)
		fc->reqctr = 1;
	return fc->reqctr;
}

void fuse_reset_request(struct fuse_req *req)
{
	int preallocated = req->preallocated;
	
	memset(req, 0, sizeof(*req));
	INIT_LIST_HEAD(&req->list);
	init_waitqueue_head(&req->waitq);
	req->preallocated = preallocated;
}

static struct fuse_req *do_get_request(struct fuse_conn *fc)
{
	struct fuse_req *req;

	spin_lock(&fuse_lock);
	BUG_ON(list_empty(&fc->unused_list));
	req = list_entry(fc->unused_list.next, struct fuse_req, list);
	list_del_init(&req->list);
	spin_unlock(&fuse_lock);
	fuse_reset_request(req);
	req->in.h.uid = current->fsuid;
	req->in.h.gid = current->fsgid;
	req->in.h.pid = current->pid;
	return req;
}

struct fuse_req *fuse_get_request(struct fuse_conn *fc)
{
	if (down_interruptible(&fc->unused_sem))
		return NULL;
	return  do_get_request(fc);
}

struct fuse_req *fuse_get_request_nonint(struct fuse_conn *fc)
{
	down(&fc->unused_sem);
	return do_get_request(fc);
}

struct fuse_req *fuse_get_request_nonblock(struct fuse_conn *fc)
{
	if (down_trylock(&fc->unused_sem))
		return NULL;
	return  do_get_request(fc);
}

void fuse_put_request(struct fuse_conn *fc, struct fuse_req *req)
{
	if (!req->preallocated)
		fuse_request_free(req);
	else {
		spin_lock(&fuse_lock);
		list_add(&req->list, &fc->unused_list);
		spin_unlock(&fuse_lock);
		up(&fc->unused_sem);
	}
}

/* Must be called with fuse_lock held, and unlocks it */
static void request_end(struct fuse_conn *fc, struct fuse_req *req)
{
	fuse_reqend_t endfunc = req->end;

	if (!endfunc) {
		wake_up(&req->waitq);
		spin_unlock(&fuse_lock);
	} else {
		spin_unlock(&fuse_lock);
		endfunc(fc, req);
	}
}

void request_send(struct fuse_conn *fc, struct fuse_req *req)
{
	req->isreply = 1;
	req->end = NULL;
		
	spin_lock(&fuse_lock);
	req->out.h.error = -ENOTCONN;
	if (fc->file) {
		req->in.h.unique = get_unique(fc);		
		list_add_tail(&req->list, &fc->pending);
		wake_up(&fc->waitq);
		request_wait_answer(req);
		list_del(&req->list);
	}
	spin_unlock(&fuse_lock);
}

void request_send_noreply(struct fuse_conn *fc, struct fuse_req *req)
{
	req->isreply = 0;

	spin_lock(&fuse_lock);
	if (fc->file) {
		list_add_tail(&req->list, &fc->pending);
		wake_up(&fc->waitq);
		spin_unlock(&fuse_lock);
	} else {
		spin_unlock(&fuse_lock);
		fuse_put_request(fc, req);
	}
}

void request_send_async(struct fuse_conn *fc, struct fuse_req *req, 
			fuse_reqend_t end)
{
	req->end = end;
	req->isreply = 1;
	
	spin_lock(&fuse_lock);
	if (fc->file) {
		req->in.h.unique = get_unique(fc);
		list_add_tail(&req->list, &fc->pending);
		wake_up(&fc->waitq);
		spin_unlock(&fuse_lock);
	} else {
		req->out.h.error = -ENOTCONN;
		request_end(fc, req);
	}
}

static void request_wait(struct fuse_conn *fc)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue_exclusive(&fc->waitq, &wait);
	while (fc->sb && list_empty(&fc->pending)) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (signal_pending(current))
			break;

		spin_unlock(&fuse_lock);
		schedule();
		spin_lock(&fuse_lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&fc->waitq, &wait);
}

static inline int copy_in_page(char __user *buf, struct page *page,
			       unsigned offset, unsigned count)
{
	char *tmpbuf = kmap(page);
	int err = copy_to_user(buf, tmpbuf + offset, count);
	kunmap(page);
	return err;
}

static int copy_in_pages(struct fuse_req *req, size_t nbytes, char __user *buf)
{
	unsigned i;
	unsigned offset = req->page_offset;
	unsigned count = min(nbytes, (unsigned) PAGE_SIZE - offset);
	for (i = 0; i < req->num_pages && nbytes; i++) {
		struct page *page = req->pages[i];
		if (page && copy_in_page(buf, page, offset, count))
			return -EFAULT;
		nbytes -= count;
		buf += count;
		count = min(nbytes, (unsigned) PAGE_SIZE);
		offset = 0;
	}
	return 0;
}

static inline int copy_in_one(struct fuse_req *req, size_t argsize,
			      const void *val, int islast, char __user *buf,
			      size_t nbytes)
{
	if (nbytes < argsize) {
		printk("fuse_dev_read: buffer too small\n");
		return -EINVAL;
	}
	if (islast && req->in.argpages) 
		return copy_in_pages(req, argsize, buf);
	else if (argsize && copy_to_user(buf, val, argsize))
		return -EFAULT;
	else
		return 0;
}

static int copy_in_args(struct fuse_req *req, char __user *buf, size_t nbytes)
{
	int i;
	int err;
	struct fuse_in *in = &req->in;
	size_t orignbytes = nbytes;
	unsigned argsize;
	
	argsize = sizeof(in->h);
	err = copy_in_one(req, argsize, &in->h, 0, buf, nbytes);
	if (err)
		return err;

	buf += argsize;
	nbytes -= argsize;

	for (i = 0; i < in->numargs; i++) {
		struct fuse_in_arg *arg = &in->args[i];
		int islast = (i == in->numargs - 1);
		err = copy_in_one(req, arg->size, arg->value, islast, buf, 
				  nbytes);
		if (err)
			return err;

		buf += arg->size;
		nbytes -= arg->size;
	}

	return orignbytes - nbytes;
}

static ssize_t fuse_dev_read(struct file *file, char __user *buf,
			     size_t nbytes, loff_t *off)
{
	ssize_t ret;
	struct fuse_conn *fc;
	struct fuse_req *req = NULL;

	spin_lock(&fuse_lock);
	fc = file->private_data;
	if (!fc) {
		spin_unlock(&fuse_lock);
		return -EPERM;
	}
	request_wait(fc);
	if (!fc->sb)
		fc = NULL;
	else if (!list_empty(&fc->pending)) {
		req = list_entry(fc->pending.next, struct fuse_req, list);
		list_del_init(&req->list);
	}
	spin_unlock(&fuse_lock);
	if (!fc)
		return -ENODEV;
	if (req == NULL)
		return -EINTR;

	ret = copy_in_args(req, buf, nbytes);
	spin_lock(&fuse_lock);
	if (req->isreply) {
		if (ret < 0) {
			req->out.h.error = -EPROTO;
			req->finished = 1;
		} else
			list_add_tail(&req->list, &fc->processing);
		if (ret < 0)
			/* Unlocks fuse_lock: */
			request_end(fc, req);
		else
			spin_unlock(&fuse_lock);
	} else {
		spin_unlock(&fuse_lock);
		fuse_put_request(fc, req);
	}
	return ret;
}

static struct fuse_req *request_find(struct fuse_conn *fc, unsigned unique)
{
	struct list_head *entry;
	struct fuse_req *req = NULL;

	list_for_each(entry, &fc->processing) {
		struct fuse_req *tmp;
		tmp = list_entry(entry, struct fuse_req, list);
		if (tmp->in.h.unique == unique) {
			req = tmp;
			break;
		}
	}

	return req;
}

static void process_getdir(struct fuse_req *req)
{
	struct fuse_getdir_out_i *arg = req->out.args[0].value;
	arg->file = fget(arg->fd);
}

static inline int copy_out_page(const char __user *buf, struct page *page,
				unsigned offset, unsigned count, int zeroing)
{
	int err = 0;
	char *tmpbuf = kmap(page);
	if (count < PAGE_SIZE && zeroing)
		memset(tmpbuf, 0, PAGE_SIZE);
	if (count)
		err = copy_from_user(tmpbuf + offset, buf, count);
	flush_dcache_page(page);
	kunmap(page);
	return err;
}

static int copy_out_pages(struct fuse_req *req, size_t nbytes,
			  const char __user *buf)
{
	unsigned i;
	unsigned offset = req->page_offset;
	unsigned zeroing = req->out.page_zeroing;
	unsigned count = min(nbytes, (unsigned) PAGE_SIZE - offset);

	for (i = 0; i < req->num_pages && (zeroing || nbytes); i++) {
		struct page *page = req->pages[i];
		if (page && copy_out_page(buf, page, offset, count, zeroing))
		    return -EFAULT;
		nbytes -= count;
		buf += count;
		count = min(nbytes, (unsigned) PAGE_SIZE);
		offset = 0;
	}
	return 0;
}

static inline int copy_out_one(struct fuse_req *req, struct fuse_out_arg *arg,
			       int islast, const char __user *buf, size_t nbytes)
{
	if (nbytes < arg->size) {
		if (!islast || !req->out.argvar) {
			printk("fuse_dev_write: write is short\n");
			return -EINVAL;
		}
		arg->size = nbytes;
	}
	if (islast && req->out.argpages)
		return copy_out_pages(req, arg->size, buf);
	else if (arg->size && copy_from_user(arg->value, buf, arg->size))
		return -EFAULT;
	else
		return 0;
}

static int copy_out_args(struct fuse_req *req, const char __user *buf,
			 size_t nbytes)
{
	struct fuse_out *out = &req->out;
	int i;

	buf += sizeof(struct fuse_out_header);
	nbytes -= sizeof(struct fuse_out_header);
		
	if (!out->h.error) {
		for (i = 0; i < out->numargs; i++) {
			struct fuse_out_arg *arg = &out->args[i];
			int islast = (i == out->numargs - 1);
			int err = copy_out_one(req, arg, islast, buf, nbytes);
			if (err)
				return err;
			buf += arg->size;
			nbytes -= arg->size;
		}
	}
	if (nbytes != 0) {
		printk("fuse_dev_write: write is long\n");
		return -EINVAL;
	}

	return 0;
}

static inline int copy_out_header(struct fuse_out_header *oh,
				  const char __user *buf, size_t nbytes)
{
	if (nbytes < sizeof(struct fuse_out_header)) {
		printk("fuse_dev_write: write is short\n");
		return -EINVAL;
	}
	if (copy_from_user(oh, buf, sizeof(struct fuse_out_header)))
		return -EFAULT;

	return 0;
}

static int fuse_invalidate(struct fuse_conn *fc, struct fuse_user_header *uh)
{
	int err;
	down(&fc->sb_sem);
	err = -ENODEV;
	if (fc->sb) {
		struct inode *inode;
#ifdef KERNEL_2_6
		inode = fuse_ilookup(fc->sb, uh->nodeid);
#else
		inode = fuse_ilookup(fc->sb, uh->ino, uh->nodeid);
#endif
		err = -ENOENT;
		if (inode) {
			fuse_sync_inode(inode);
#ifdef KERNEL_2_6
			invalidate_inode_pages(inode->i_mapping);
#else
			invalidate_inode_pages(inode);
#endif
			iput(inode);
			err = 0;
		}
	}
	up(&fc->sb_sem);

	return err;
}

static int fuse_user_request(struct fuse_conn *fc, const char __user *buf,
			     size_t nbytes)
{
	struct fuse_user_header uh;
	int err;

	if (nbytes < sizeof(struct fuse_user_header)) {
		printk("fuse_dev_write: write is short\n");
		return -EINVAL;
	}

	if (copy_from_user(&uh, buf, sizeof(struct fuse_user_header)))
		return -EFAULT;
	
	switch (uh.opcode) {
	case FUSE_INVALIDATE:
		err = fuse_invalidate(fc, &uh);
		break;

	default:
		err = -ENOSYS;
	}
	return err;
}
    
static ssize_t fuse_dev_write(struct file *file, const char __user *buf,
			      size_t nbytes, loff_t *off)
{
	int err;
	struct fuse_conn *fc = fuse_get_conn(file);
	struct fuse_req *req;
	struct fuse_out_header oh;
	
	if (!fc)
		return -ENODEV;

	err = copy_out_header(&oh, buf, nbytes);
	if (err)
		return err;

	if (!oh.unique)	{
		err = fuse_user_request(fc, buf, nbytes);
		goto out;
	}     

        if (oh.error <= -1000 || oh.error > 0) {
                printk("fuse_dev_write: bad error value\n");
                return -EINVAL;
        }

	spin_lock(&fuse_lock);
	req = request_find(fc, oh.unique);
	if (req != NULL)
		list_del_init(&req->list);
	spin_unlock(&fuse_lock);
	if (!req)
		return -ENOENT;

	req->out.h = oh;
	err = copy_out_args(req, buf, nbytes);

	spin_lock(&fuse_lock);
	if (err)
		req->out.h.error = -EPROTO;
	else {
		/* fget() needs to be done in this context */
		if (req->in.h.opcode == FUSE_GETDIR && !oh.error)
			process_getdir(req);
	}	
	req->finished = 1;
	/* Unlocks fuse_lock: */
	request_end(fc, req);

 out:
	if (!err)
		return nbytes;
	else
		return err;
}

static unsigned fuse_dev_poll(struct file *file, poll_table *wait)
{
	struct fuse_conn *fc = fuse_get_conn(file);
	unsigned mask = POLLOUT | POLLWRNORM;

	if (!fc)
		return -ENODEV;

	poll_wait(file, &fc->waitq, wait);

	spin_lock(&fuse_lock);
	if (!list_empty(&fc->pending))
                mask |= POLLIN | POLLRDNORM;
	spin_unlock(&fuse_lock);

	return mask;
}

static void end_requests(struct fuse_conn *fc, struct list_head *head)
{
	while (!list_empty(head)) {
		struct fuse_req *req;
		req = list_entry(head->next, struct fuse_req, list);
		list_del_init(&req->list);
		if (req->isreply) {
			req->out.h.error = -ECONNABORTED;
			req->finished = 1;
			/* Unlocks fuse_lock: */
			request_end(fc, req);
			spin_lock(&fuse_lock);
		} else {
			spin_unlock(&fuse_lock);
			fuse_put_request(fc, req);
			spin_lock(&fuse_lock);
		}
	}
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc;

	spin_lock(&fuse_lock);
	fc = file->private_data;
	if (fc) {
		fc->file = NULL;
		end_requests(fc, &fc->pending);
		end_requests(fc, &fc->processing);
		fuse_release_conn(fc);
	}
	spin_unlock(&fuse_lock);
	return 0;
}

struct file_operations fuse_dev_operations = {
	.owner		= THIS_MODULE,
	.read		= fuse_dev_read,
	.write		= fuse_dev_write,
	.poll		= fuse_dev_poll,
	.release	= fuse_dev_release,
};

#ifdef KERNEL_2_6
#ifndef HAVE_FS_SUBSYS
static decl_subsys(fs, NULL, NULL);
#endif
static decl_subsys(fuse, NULL, NULL);

static ssize_t version_show(struct subsystem *subsys, char *buf)
{
	return sprintf(buf, "%i.%i\n", FUSE_KERNEL_VERSION,
		       FUSE_KERNEL_MINOR_VERSION);
}
static struct subsys_attribute fuse_attr_version = __ATTR_RO(version);

static int __init fuse_version_init(void)
{
	int err;

#ifndef HAVE_FS_SUBSYS
	subsystem_register(&fs_subsys);
#endif
	kset_set_kset_s(&fuse_subsys, fs_subsys);
	err = subsystem_register(&fuse_subsys);
	if (err)
		return err;
	err = subsys_create_file(&fuse_subsys, &fuse_attr_version);
	if (err) {
		subsystem_unregister(&fuse_subsys);
#ifndef HAVE_FS_SUBSYS
		subsystem_unregister(&fs_subsys);
#endif
		return err;
	}
	return 0;
}

static void fuse_version_clean(void)
{
	subsys_remove_file(&fuse_subsys, &fuse_attr_version);
	subsystem_unregister(&fuse_subsys);
#ifndef HAVE_FS_SUBSYS
	subsystem_unregister(&fs_subsys);
#endif	
}
#else
static struct proc_dir_entry *proc_fs_fuse;

static int read_version(char *page, char **start, off_t off, int count,
			int *eof, void *data)
{
	char *s = page;
	s += sprintf(s, "%i.%i\n", FUSE_KERNEL_VERSION,
		     FUSE_KERNEL_MINOR_VERSION);
	return s - page;
}

static int fuse_version_init(void)
{
	proc_fs_fuse = proc_mkdir("fuse", proc_root_fs);
	if (proc_fs_fuse) {
		struct proc_dir_entry *de;

		de = create_proc_entry("version", S_IFREG | 0444, proc_fs_fuse);
		if (de) {
			de->owner = THIS_MODULE;
			de->read_proc = read_version;
		}
	}
	return 0;
}

static void fuse_version_clean(void)
{
	if (proc_fs_fuse) {
		remove_proc_entry("version", proc_fs_fuse);
		remove_proc_entry("fuse", proc_root_fs);
	}
}
#endif

static struct miscdevice fuse_miscdevice = {
	.minor = FUSE_MINOR,
	.name  = "fuse",
	.fops = &fuse_dev_operations,
};

int __init fuse_dev_init(void)
{
	int err;
	err = fuse_version_init();
	if (err)
		goto out;

	err = -ENOMEM;
	fuse_req_cachep = kmem_cache_create("fuser_request",
					    sizeof(struct fuse_req),
					    0, 0, NULL, NULL);
	if (!fuse_req_cachep)
		goto out_version_clean;
	

	err = misc_register(&fuse_miscdevice);
	if (err)
		goto out_cache_clean;

	return 0;

 out_cache_clean:
	kmem_cache_destroy(fuse_req_cachep);
 out_version_clean:
	fuse_version_clean();
 out:
	return err;
}

void fuse_dev_cleanup(void)
{
	misc_deregister(&fuse_miscdevice);
	kmem_cache_destroy(fuse_req_cachep);
	fuse_version_clean();
}
