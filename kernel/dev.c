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
#include <linux/uio.h>
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

static inline void fuse_request_init(struct fuse_req *req)
{
	memset(req, 0, sizeof(*req));
	INIT_LIST_HEAD(&req->list);
	init_waitqueue_head(&req->waitq);
	atomic_set(&req->count, 1);
}

struct fuse_req *fuse_request_alloc(void)
{
	struct fuse_req *req = kmem_cache_alloc(fuse_req_cachep, SLAB_KERNEL);
	if (req)
		fuse_request_init(req);
	return req;
}

void fuse_request_free(struct fuse_req *req)
{
	kmem_cache_free(fuse_req_cachep, req);
}

#ifdef KERNEL_2_6
static inline void block_sigs(sigset_t *oldset)
{
	sigset_t sigmask;

	siginitsetinv(&sigmask, sigmask(SIGKILL));
	sigprocmask(SIG_BLOCK, &sigmask, oldset);
}

static inline void restore_sigs(sigset_t *oldset)
{
	sigprocmask(SIG_SETMASK, oldset, NULL);
}
#else
static inline void block_sigs(sigset_t *oldset)
{
	spin_lock_irq(&current->sigmask_lock);
	*oldset = current->blocked;
	siginitsetinv(&current->blocked, sigmask(SIGKILL) & ~oldset->sig[0]);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);
}

static inline void restore_sigs(sigset_t *oldset)
{
	spin_lock_irq(&current->sigmask_lock);
	current->blocked = *oldset;
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);
}
#endif

void fuse_reset_request(struct fuse_req *req)
{
	int preallocated = req->preallocated;
	BUG_ON(atomic_read(&req->count) != 1);
	fuse_request_init(req);
	req->preallocated = preallocated;
}

static void __fuse_get_request(struct fuse_req *req)
{
	atomic_inc(&req->count);
}

/* Must be called with > 1 refcount */
static void __fuse_put_request(struct fuse_req *req)
{
	BUG_ON(atomic_read(&req->count) < 2);
	atomic_dec(&req->count);
}

static struct fuse_req *do_get_request(struct fuse_conn *fc)
{
	struct fuse_req *req;

	spin_lock(&fuse_lock);
	BUG_ON(list_empty(&fc->unused_list));
	req = list_entry(fc->unused_list.next, struct fuse_req, list);
	list_del_init(&req->list);
	spin_unlock(&fuse_lock);
	fuse_request_init(req);
	req->preallocated = 1;
	req->in.h.uid = current->fsuid;
	req->in.h.gid = current->fsgid;
	req->in.h.pid = current->pid;
	return req;
}

struct fuse_req *fuse_get_request(struct fuse_conn *fc)
{
	if (down_interruptible(&fc->outstanding_sem))
		return NULL;
	return  do_get_request(fc);
}

struct fuse_req *fuse_get_request_nonint(struct fuse_conn *fc)
{
	int intr;
	sigset_t oldset;

	block_sigs(&oldset);
	intr = down_interruptible(&fc->outstanding_sem);
	restore_sigs(&oldset);
	return intr ? NULL : do_get_request(fc);
}

void fuse_putback_request(struct fuse_conn *fc, struct fuse_req *req)
{
	if (!req->preallocated)
		fuse_request_free(req);

	spin_lock(&fuse_lock);
	if (req->preallocated)
		list_add(&req->list, &fc->unused_list);

	if (fc->outstanding_debt)
		fc->outstanding_debt--;
	else
		up(&fc->outstanding_sem);
	spin_unlock(&fuse_lock);
}

void fuse_put_request(struct fuse_conn *fc, struct fuse_req *req)
{
	if (atomic_dec_and_test(&req->count))
		fuse_putback_request(fc, req);
}

/* Called with fuse_lock, unlocks it */
static void request_end(struct fuse_conn *fc, struct fuse_req *req)
{
	int putback;
	req->finished = 1;
	putback = atomic_dec_and_test(&req->count);
	spin_unlock(&fuse_lock);
	if (req->background) {
		if (req->inode)
			iput(req->inode);
		if (req->inode2)
			iput(req->inode2);
		if (req->file)
			fput(req->file);
	}
	wake_up(&req->waitq);
	if (putback)
		fuse_putback_request(fc, req);
}

static int request_wait_answer_nonint(struct fuse_req *req)
{
	int err;
	sigset_t oldset;
	block_sigs(&oldset);
	err = wait_event_interruptible(req->waitq, req->finished);
	restore_sigs(&oldset);
	return err;
}

static void background_request(struct fuse_req *req)
{
	/* Need to get hold of the inode(s) and/or file used in the
	   request, so FORGET and RELEASE are not sent too early */
	req->background = 1;
	if (req->inode)
		req->inode = igrab(req->inode);
	if (req->inode2)
		req->inode2 = igrab(req->inode2);
	if (req->file)
		get_file(req->file);
}

/* Called with fuse_lock held.  Releases, and then reacquires it. */
static void request_wait_answer(struct fuse_req *req, int interruptible)
{
	int intr;

	spin_unlock(&fuse_lock);
	if (interruptible)
		intr = wait_event_interruptible(req->waitq, req->finished);
	else
		intr = request_wait_answer_nonint(req);
	spin_lock(&fuse_lock);
	if (intr && interruptible && req->sent) {
		/* If request is already in userspace, only allow KILL
		   signal to interrupt */
		spin_unlock(&fuse_lock);
		intr = request_wait_answer_nonint(req);
		spin_lock(&fuse_lock);
	}
	if (!intr)
		return;

	if (!interruptible || req->sent)
		req->out.h.error = -EINTR;
	else
		req->out.h.error = -ERESTARTNOINTR;

	req->interrupted = 1;
	if (req->locked) {
		/* This is uninterruptible sleep, because data is
		   being copied to/from the buffers of req.  During
		   locked state, there musn't be any filesystem
		   operation (e.g. page fault), since that could lead
		   to deadlock */
		spin_unlock(&fuse_lock);
		wait_event(req->waitq, !req->locked);
		spin_lock(&fuse_lock);
	}
	if (!req->sent && !list_empty(&req->list)) {
		list_del(&req->list);
		__fuse_put_request(req);
	} else if (req->sent)
		background_request(req);
}

static unsigned len_args(unsigned numargs, struct fuse_arg *args)
{
	unsigned nbytes = 0;
	unsigned i;

	for (i = 0; i < numargs; i++)
		nbytes += args[i].size;

	return nbytes;
}

static void queue_request(struct fuse_conn *fc, struct fuse_req *req)
{
	fc->reqctr++;
	/* zero is special */
	if (fc->reqctr == 0)
		fc->reqctr = 1;
	req->in.h.unique = fc->reqctr;
	req->in.h.len = sizeof(struct fuse_in_header) + 
		len_args(req->in.numargs, (struct fuse_arg *) req->in.args);
	if (!req->preallocated) {
		/* decrease outstanding_sem, but without blocking... */
		if (down_trylock(&fc->outstanding_sem))
			fc->outstanding_debt++;
	}
	list_add_tail(&req->list, &fc->pending);
	wake_up(&fc->waitq);
}

static void request_send_wait(struct fuse_conn *fc, struct fuse_req *req,
			      int interruptible)
{
	req->isreply = 1;
	spin_lock(&fuse_lock);
	req->out.h.error = -ENOTCONN;
	if (fc->file) {
		queue_request(fc, req);
		/* acquire extra reference, since request is still needed
		   after request_end() */
		__fuse_get_request(req);

		request_wait_answer(req, interruptible);
	}
	spin_unlock(&fuse_lock);
}

void request_send(struct fuse_conn *fc, struct fuse_req *req)
{
	request_send_wait(fc, req, 1);
}

void request_send_nonint(struct fuse_conn *fc, struct fuse_req *req)
{
	request_send_wait(fc, req, 0);
}

void request_send_nowait(struct fuse_conn *fc, struct fuse_req *req)
{
	spin_lock(&fuse_lock);
	if (fc->file) {
		queue_request(fc, req);
		spin_unlock(&fuse_lock);
	} else {
		req->out.h.error = -ENOTCONN;
		request_end(fc, req);
	}
}

void request_send_noreply(struct fuse_conn *fc, struct fuse_req *req)
{
	req->isreply = 0;
	request_send_nowait(fc, req);
}

void request_send_background(struct fuse_conn *fc, struct fuse_req *req)
{
	req->isreply = 1;
	background_request(req);
	request_send_nowait(fc, req);
}

static inline int lock_request(struct fuse_req *req)
{
	int err = 0;
	if (req) {
		spin_lock(&fuse_lock);
		if (req->interrupted)
			err = -ENOENT;
		else
			req->locked = 1;
		spin_unlock(&fuse_lock);
	}
	return err;
}

static inline void unlock_request(struct fuse_req *req)
{
	if (req) {
		spin_lock(&fuse_lock);
		req->locked = 0;
		if (req->interrupted)
			wake_up(&req->waitq);
		spin_unlock(&fuse_lock);
	}
}


/* Why all this complex one-page-at-a-time copying needed instead of
   just copy_to/from_user()?  The reason is that blocking on a page
   fault must be avoided while the request is locked.  This is because
   if servicing that pagefault happens to be done by this filesystem,
   an unbreakable deadlock can occur.  So the code is careful to allow
   request interruption during get_user_pages(), and only lock the
   request while doing kmapped copying, which cannot block.
 */

struct fuse_copy_state {
	int write;
	struct fuse_req *req;
	const struct iovec *iov;
	unsigned long nr_segs;
	unsigned long seglen;
	unsigned long addr;
	struct page *pg;
	void *mapaddr;
	void *buf;
	unsigned len;
};

static unsigned fuse_copy_init(struct fuse_copy_state *cs, int write,
			       struct fuse_req *req, const struct iovec *iov,
			       unsigned long nr_segs)
{
	unsigned i;
	unsigned nbytes;

	memset(cs, 0, sizeof(*cs));
	cs->write = write;
	cs->req = req;
	cs->iov = iov;
	cs->nr_segs = nr_segs;

	nbytes = 0;
	for (i = 0; i < nr_segs; i++)
		nbytes += iov[i].iov_len;

	return nbytes;
}

static inline void fuse_copy_finish(struct fuse_copy_state *cs)
{
	if (cs->mapaddr) {
		kunmap_atomic(cs->mapaddr, KM_USER0);
		if (cs->write) {
			flush_dcache_page(cs->pg);
			set_page_dirty_lock(cs->pg);
		}
		put_page(cs->pg);
		cs->mapaddr = NULL;
	}
}

static int fuse_copy_fill(struct fuse_copy_state *cs)
{
	unsigned long offset;
	int err;

	unlock_request(cs->req);
	fuse_copy_finish(cs);
	if (!cs->seglen) {
		BUG_ON(!cs->nr_segs);
		cs->seglen = cs->iov[0].iov_len;
		cs->addr = (unsigned long) cs->iov[0].iov_base;
		cs->iov ++;
		cs->nr_segs --;
	}
	down_read(&current->mm->mmap_sem);
	err = get_user_pages(current, current->mm, cs->addr, 1, cs->write, 0,
			     &cs->pg, NULL);
	up_read(&current->mm->mmap_sem);
	if (err < 0)
		return err;
	BUG_ON(err != 1);
	offset = cs->addr % PAGE_SIZE;
	cs->mapaddr = kmap_atomic(cs->pg, KM_USER0);
	cs->buf = cs->mapaddr + offset;
	cs->len = min(PAGE_SIZE - offset, cs->seglen);
	cs->seglen -= cs->len;
	cs->addr += cs->len;

	return lock_request(cs->req);
}

static inline int fuse_copy_do(struct fuse_copy_state *cs, void **val,
			       unsigned *size)
{
	unsigned ncpy = min(*size, cs->len);
	if (val) {
		if (cs->write)
			memcpy(cs->buf, *val, ncpy);
		else
			memcpy(*val, cs->buf, ncpy);
		*val += ncpy;
	}
	*size -= ncpy;
	cs->len -= ncpy;
	cs->buf += ncpy;
	return ncpy;
}

static inline int fuse_copy_page(struct fuse_copy_state *cs, struct page *page,
				 unsigned offset, unsigned count, int zeroing)
{
	if (page && zeroing && count < PAGE_SIZE) {
		void *mapaddr = kmap_atomic(page, KM_USER1);
		memset(mapaddr, 0, PAGE_SIZE);
		kunmap_atomic(mapaddr, KM_USER1);
	}
	while (count) {
		int err;
		if (!cs->len && (err = fuse_copy_fill(cs)))
			return err;
		if (page) {
			void *mapaddr = kmap_atomic(page, KM_USER1);
			void *buf = mapaddr + offset;
			offset += fuse_copy_do(cs, &buf, &count);
			kunmap_atomic(mapaddr, KM_USER1);
		} else
			offset += fuse_copy_do(cs, NULL, &count);
	}
	if (page && !cs->write)
		flush_dcache_page(page);
	return 0;
}

static int fuse_copy_pages(struct fuse_copy_state *cs, unsigned nbytes,
			   int zeroing)
{
	unsigned i;
	struct fuse_req *req = cs->req;
	unsigned offset = req->page_offset;
	unsigned count = min(nbytes, (unsigned) PAGE_SIZE - offset);

	for (i = 0; i < req->num_pages && nbytes; i++) {
		struct page *page = req->pages[i];
		int err = fuse_copy_page(cs, page, offset, count, zeroing);
		if (err)
			return err;

		nbytes -= count;
		count = min(nbytes, (unsigned) PAGE_SIZE);
		offset = 0;
	}
	return 0;
}

static int fuse_copy_one(struct fuse_copy_state *cs, void *val, unsigned size)
{
	while (size) {
		int err;
		if (!cs->len && (err = fuse_copy_fill(cs)))
			return err;
		fuse_copy_do(cs, &val, &size);
	}
	return 0;
}

static int fuse_copy_args(struct fuse_copy_state *cs, unsigned numargs,
			  unsigned argpages, struct fuse_arg *args,
			  int zeroing)
{
	int err = 0;
	unsigned i;

	for (i = 0; !err && i < numargs; i++)  {
		struct fuse_arg *arg = &args[i];
		if (i == numargs - 1 && argpages)
			err = fuse_copy_pages(cs, arg->size, zeroing);
		else
			err = fuse_copy_one(cs, arg->value, arg->size);
	}
	return err;
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

static ssize_t fuse_dev_readv(struct file *file, const struct iovec *iov,
			      unsigned long nr_segs, loff_t *off)
{
	int err;
	struct fuse_conn *fc;
	struct fuse_req *req;
	struct fuse_in *in;
	struct fuse_copy_state cs;
	unsigned nbytes;
	unsigned reqsize;

	spin_lock(&fuse_lock);
	fc = file->private_data;
	err = -EPERM;
	if (!fc)
		goto err_unlock;
	request_wait(fc);
	err = -ENODEV;
	if (!fc->sb)
		goto err_unlock;
	err = -ERESTARTSYS;
	if (list_empty(&fc->pending))
		goto err_unlock;

	req = list_entry(fc->pending.next, struct fuse_req, list);
	list_del_init(&req->list);
	spin_unlock(&fuse_lock);

	in = &req->in;
	reqsize = req->in.h.len;
	nbytes = fuse_copy_init(&cs, 1, req, iov, nr_segs);
	err = -EINVAL;
	if (nbytes >= reqsize) {
		err = fuse_copy_one(&cs, &in->h, sizeof(in->h));
		if (!err)
			err = fuse_copy_args(&cs, in->numargs, in->argpages,
					     (struct fuse_arg *) in->args, 0);
	}
	fuse_copy_finish(&cs);

	spin_lock(&fuse_lock);
	req->locked = 0;
	if (!err && req->interrupted)
		err = -ENOENT;
	if (err) {
		if (!req->interrupted)
			req->out.h.error = -EIO;
		request_end(fc, req);
		return err;
	}
	if (!req->isreply)
		request_end(fc, req);
	else {
		req->sent = 1;
		list_add_tail(&req->list, &fc->processing);
		spin_unlock(&fuse_lock);
	}
	return reqsize;

 err_unlock:
	spin_unlock(&fuse_lock);
	return err;
}

static ssize_t fuse_dev_read(struct file *file, char __user *buf,
			     size_t nbytes, loff_t *off)
{
	struct iovec iov;
	iov.iov_len = nbytes;
	iov.iov_base = buf;
	return fuse_dev_readv(file, &iov, 1, off);
}

static struct fuse_req *request_find(struct fuse_conn *fc, unsigned unique)
{
	struct list_head *entry;

	list_for_each(entry, &fc->processing) {
		struct fuse_req *req;
		req = list_entry(entry, struct fuse_req, list);
		if (req->in.h.unique == unique)
			return req;
	}
	return NULL;
}

/* fget() needs to be done in this context */
static void process_getdir(struct fuse_req *req)
{
	struct fuse_getdir_out_i *arg = req->out.args[0].value;
	arg->file = fget(arg->fd);
}

static int copy_out_args(struct fuse_copy_state *cs, struct fuse_out *out,
			 unsigned nbytes)
{
	unsigned reqsize = sizeof(struct fuse_out_header);

	if (out->h.error)
		return nbytes != reqsize ? -EINVAL : 0;

	reqsize += len_args(out->numargs, out->args);

	if (reqsize < nbytes || (reqsize > nbytes && !out->argvar))
		return -EINVAL;
	else if (reqsize > nbytes) {
		struct fuse_arg *lastarg = &out->args[out->numargs-1];
		unsigned diffsize = reqsize - nbytes;
		if (diffsize > lastarg->size)
			return -EINVAL;
		lastarg->size -= diffsize;
	}
	return fuse_copy_args(cs, out->numargs, out->argpages, out->args,
			      out->page_zeroing);
}

static ssize_t fuse_dev_writev(struct file *file, const struct iovec *iov,
			       unsigned long nr_segs, loff_t *off)
{
	int err;
	unsigned nbytes;
	struct fuse_req *req;
	struct fuse_out_header oh;
	struct fuse_copy_state cs;
	struct fuse_conn *fc = fuse_get_conn(file);
	if (!fc)
		return -ENODEV;

	nbytes = fuse_copy_init(&cs, 0, NULL, iov, nr_segs);
	if (nbytes < sizeof(struct fuse_out_header))
		return -EINVAL;

	err = fuse_copy_one(&cs, &oh, sizeof(oh));
	if (err)
		goto err_finish;
	err = -EINVAL;
	if (!oh.unique || oh.error <= -1000 || oh.error > 0 || 
	    oh.len != nbytes)
		goto err_finish;

	spin_lock(&fuse_lock);
	req = request_find(fc, oh.unique);
	err = -EINVAL;
	if (!req)
		goto err_unlock;

	list_del_init(&req->list);
	if (req->interrupted) {
		request_end(fc, req);
		fuse_copy_finish(&cs);
		return -ENOENT;
	}
	req->out.h = oh;
	req->locked = 1;
	cs.req = req;
	spin_unlock(&fuse_lock);

	err = copy_out_args(&cs, &req->out, nbytes);
	fuse_copy_finish(&cs);

	spin_lock(&fuse_lock);
	req->locked = 0;
	if (!err) {
		if (req->interrupted)
			err = -ENOENT;
		else if (req->in.h.opcode == FUSE_GETDIR && !oh.error)
			process_getdir(req);
	} else if (!req->interrupted)
		req->out.h.error = -EIO;
	request_end(fc, req);

	return err ? err : nbytes;

 err_unlock:
	spin_unlock(&fuse_lock);
 err_finish:
	fuse_copy_finish(&cs);
	return err;
}

static ssize_t fuse_dev_write(struct file *file, const char __user *buf,
			      size_t nbytes, loff_t *off)
{
	struct iovec iov;
	iov.iov_len = nbytes;
	iov.iov_base = (char __user *) buf;
	return fuse_dev_writev(file, &iov, 1, off);
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
		req->out.h.error = -ECONNABORTED;
		request_end(fc, req);
		spin_lock(&fuse_lock);
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
	.readv		= fuse_dev_readv,
	.write		= fuse_dev_write,
	.writev		= fuse_dev_writev,
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
