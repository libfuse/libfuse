/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/file.h>

/* If more requests are outstanding, then the operation will block */
#define MAX_OUTSTANDING 10

static struct proc_dir_entry *proc_fs_fuse;
struct proc_dir_entry *proc_fuse_dev;
static kmem_cache_t *fuse_req_cachep;

static struct fuse_req *request_new(void)
{
	struct fuse_req *req;

	req = (struct fuse_req *) kmem_cache_alloc(fuse_req_cachep, SLAB_NOFS);
	if(req) {
		INIT_LIST_HEAD(&req->list);
		req->issync = 0;
		req->locked = 0;
		req->interrupted = 0;
		req->sent = 0;
		req->finished = 0;
		req->in = NULL;
		req->out = NULL;
		init_waitqueue_head(&req->waitq);
	}

	return req;
}

static void request_free(struct fuse_req *req)
{
	kmem_cache_free(fuse_req_cachep, req);
}

static int request_restartable(enum fuse_opcode opcode)
{
	switch(opcode) {
	case FUSE_LOOKUP:
	case FUSE_GETATTR:
	case FUSE_READLINK:
	case FUSE_GETDIR:
	case FUSE_OPEN:
	case FUSE_READ:
	case FUSE_WRITE:
		return 1;

	default:
		return 0;
	}
}

/* Called with fuse_lock held.  Releases, and then reaquires it. */
static void request_wait_answer(struct fuse_req *req)
{
	int intr;
	
	spin_unlock(&fuse_lock);
	intr = wait_event_interruptible(req->waitq, req->finished);
	spin_lock(&fuse_lock);
	if(!intr)
		return;

	/* Request interrupted... Wait for it to be unlocked */
	if(req->locked) {
		req->interrupted = 1;
		spin_unlock(&fuse_lock);
		wait_event(req->waitq, !req->locked);
		spin_lock(&fuse_lock);
	}
	
	/* Operations which modify the filesystem cannot safely be
	   restarted, because it is uncertain whether the operation has
	   completed or not... */
	if(req->sent && !request_restartable(req->in->h.opcode))
		req->out->h.error = -EINTR;
	else
		req->out->h.error = -ERESTARTSYS;
}

static int get_unique(struct fuse_conn *fc)
{
	do fc->reqctr++;
	while(!fc->reqctr);
	return fc->reqctr;
}

/* Must be called with fuse_lock held, and unlocks it */
static void request_end(struct fuse_conn *fc, struct fuse_req *req)
{
	fuse_reqend_t endfunc = req->end;

	if(!endfunc) {
		wake_up(&req->waitq);
		spin_unlock(&fuse_lock);
	} else {
		spin_unlock(&fuse_lock);
		endfunc(fc, req->in, req->out, req->data);
		request_free(req);
		up(&fc->outstanding);
	}
}

void request_send(struct fuse_conn *fc, struct fuse_in *in,
		  struct fuse_out *out)
{
	struct fuse_req *req;

	out->h.error = -ERESTARTSYS;
	if(down_interruptible(&fc->outstanding))
		return;

	out->h.error = -ENOMEM;
	req = request_new();
	if(req) {
		req->in = in;
		req->out = out;
		req->issync = 1;
		req->end = NULL;
		
		spin_lock(&fuse_lock);
		out->h.error = -ENOTCONN;
		if(fc->file) {
			in->h.unique = get_unique(fc);		
			list_add_tail(&req->list, &fc->pending);
			wake_up(&fc->waitq);
			request_wait_answer(req);
			list_del(&req->list);
		}
		spin_unlock(&fuse_lock);
		request_free(req);
	}

	up(&fc->outstanding);
}


static inline void destroy_request(struct fuse_req *req)
{
	if(req) {
		kfree(req->in);
		request_free(req);
	}
}

/* This one is currently only used for sending FORGET and RELEASE,
   which are kernel initiated request.  So the outstanding semaphore
   is not used.  */
int request_send_noreply(struct fuse_conn *fc, struct fuse_in *in)
{
	struct fuse_req *req;

	req = request_new();
	if(!req)
		return -ENOMEM;

	req->in = in;
	req->issync = 0;

	spin_lock(&fuse_lock);
	if(!fc->file) {
		spin_unlock(&fuse_lock);
		request_free(req);
		return -ENOTCONN;
	}

	list_add_tail(&req->list, &fc->pending);
	wake_up(&fc->waitq);
	spin_unlock(&fuse_lock);
	return 0;
}

int request_send_nonblock(struct fuse_conn *fc, struct fuse_in *in,
			  struct fuse_out *out, fuse_reqend_t end, void *data)
{
	int err;
	struct fuse_req *req;

	BUG_ON(!end);

	if(down_trylock(&fc->outstanding))
		return -EWOULDBLOCK;

	err = -ENOMEM;
	req = request_new();
	if(req) {
		req->in = in;
		req->out = out;
		req->issync = 1;
		req->end = end;
		req->data = data;

		spin_lock(&fuse_lock);
		err = -ENOTCONN;
		if(fc->file) {
			in->h.unique = get_unique(fc);		
			list_add_tail(&req->list, &fc->pending);
			wake_up(&fc->waitq);
			spin_unlock(&fuse_lock);
			return 0;
		}
		spin_unlock(&fuse_lock);
		request_free(req);
	}
	up(&fc->outstanding);
	return err;
}

static void request_wait(struct fuse_conn *fc)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue_exclusive(&fc->waitq, &wait);
	while(fc->sb != NULL && list_empty(&fc->pending)) {
		set_current_state(TASK_INTERRUPTIBLE);
		if(signal_pending(current))
			break;

		spin_unlock(&fuse_lock);
		schedule();
		spin_lock(&fuse_lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&fc->waitq, &wait);
}

static inline int copy_in_one(const void *src, size_t srclen, char **dstp,
			      size_t *dstlenp)
{
	if(*dstlenp < srclen) {
		printk("fuse_dev_read: buffer too small\n");
		return -EINVAL;
	}
			
	if(copy_to_user(*dstp, src, srclen))
		return -EFAULT;

	*dstp += srclen;
	*dstlenp -= srclen;

	return 0;
}

static inline int copy_in_args(struct fuse_in *in, char *buf, size_t nbytes)
{
	int err;
	int i;
	size_t orignbytes = nbytes;
		
	err = copy_in_one(&in->h, sizeof(in->h), &buf, &nbytes);
	if(err)
		return err;

	for(i = 0; i < in->numargs; i++) {
		struct fuse_in_arg *arg = &in->args[i];
		err = copy_in_one(arg->value, arg->size, &buf, &nbytes);
		if(err)
			return err;
	}

	return orignbytes - nbytes;
}

static ssize_t fuse_dev_read(struct file *file, char *buf, size_t nbytes,
			     loff_t *off)
{
	ssize_t ret;
	struct fuse_conn *fc = DEV_FC(file);
	struct fuse_req *req = NULL;

	spin_lock(&fuse_lock);
	request_wait(fc);
	if(fc->sb != NULL && !list_empty(&fc->pending)) {
		req = list_entry(fc->pending.next, struct fuse_req, list);
		list_del_init(&req->list);
		req->locked = 1;
	}
	spin_unlock(&fuse_lock);
	if(fc->sb == NULL)
		return -ENODEV;
	if(req == NULL)
		return -EINTR;

	ret = copy_in_args(req->in, buf, nbytes);
	spin_lock(&fuse_lock);
	if(req->issync) {
		if(ret < 0) {
			req->out->h.error = -EPROTO;
			req->finished = 1;
		} else {
			list_add_tail(&req->list, &fc->processing);
			req->sent = 1;
		}
		req->locked = 0;
		if(ret < 0 || req->interrupted)
			/* Unlocks fuse_lock: */
			request_end(fc, req);
		else
			spin_unlock(&fuse_lock);
	} else {
		spin_unlock(&fuse_lock);
		destroy_request(req);
	}
	return ret;
}

static struct fuse_req *request_find(struct fuse_conn *fc, unsigned int unique)
{
	struct list_head *entry;
	struct fuse_req *req = NULL;

	list_for_each(entry, &fc->processing) {
		struct fuse_req *tmp;
		tmp = list_entry(entry, struct fuse_req, list);
		if(tmp->in->h.unique == unique) {
			req = tmp;
			break;
		}
	}

	return req;
}

static void process_getdir(struct fuse_req *req)
{
	struct fuse_getdir_out *arg;
	arg = (struct fuse_getdir_out *) req->out->args[0].value;
	arg->file = fget(arg->fd);
}

static inline int copy_out_one(struct fuse_out_arg *arg, const char **srcp,
			       size_t *srclenp, int allowvar)
{
	size_t dstlen = arg->size;
	if(*srclenp < dstlen) {
		if(!allowvar) {
			printk("fuse_dev_write: write is short\n");
			return -EINVAL;
		}
		dstlen = *srclenp;
	}

	if(dstlen) {
		if(copy_from_user(arg->value, *srcp, dstlen))
			return -EFAULT;
	}

	*srcp += dstlen;
	*srclenp -= dstlen;
	arg->size = dstlen;

	return 0;
}

static inline int copy_out_args(struct fuse_out *out, const char *buf,
				size_t nbytes)
{
	int err;
	int i;

	buf += sizeof(struct fuse_out_header);
	nbytes -= sizeof(struct fuse_out_header);
		
	if(!out->h.error) {
		for(i = 0; i < out->numargs; i++) {
			struct fuse_out_arg *arg = &out->args[i];
			int allowvar;

			if(out->argvar && i == out->numargs - 1)
				allowvar = 1;
			else
				allowvar = 0;

			err = copy_out_one(arg, &buf, &nbytes, allowvar);
			if(err)
				return err;
		}
	}

	if(nbytes != 0) {
		printk("fuse_dev_write: write is long\n");
		return -EINVAL;
	}

	return 0;
}

static inline int copy_out_header(struct fuse_out_header *oh, const char *buf,
				  size_t nbytes)
{
	if(nbytes < sizeof(struct fuse_out_header)) {
		printk("fuse_dev_write: write is short\n");
		return -EINVAL;
	}
	
	if(copy_from_user(oh, buf, sizeof(struct fuse_out_header)))
		return -EFAULT;

	return 0;
}

#ifdef KERNEL_2_6
static int fuse_invalidate(struct fuse_conn *fc, struct fuse_user_header *uh)
{
	struct inode *inode = ilookup(fc->sb, uh->ino);
	if (!inode)
		return -ENOENT;
	invalidate_inode_pages(inode->i_mapping);
	iput(inode);
	return 0;
}
#else 
static int fuse_invalidate(struct fuse_conn *fc, struct fuse_user_header *uh)
{
	struct inode *inode = iget(fc->sb, uh->ino);
	int err = -ENOENT;
	if(inode) {
		if(inode->u.generic_ip) {
			invalidate_inode_pages(inode);
			err = 0;
		}
		iput(inode);
	}
	return err;
}
#endif

static int fuse_user_request(struct fuse_conn *fc, const char *buf,
			     size_t nbytes)
{
	struct fuse_user_header uh;
	int err;

	if (nbytes < sizeof(struct fuse_user_header)) {
		printk("fuse_dev_write: write is short\n");
		return -EINVAL;
	}

	if(copy_from_user(&uh, buf, sizeof(struct fuse_out_header)))
		return -EFAULT;
	
	switch(uh.opcode) {
	case FUSE_INVALIDATE:
		err = fuse_invalidate(fc, &uh);
		break;

	default:
		err = -ENOSYS;
	}
	return err;
}
    

static ssize_t fuse_dev_write(struct file *file, const char *buf,
			      size_t nbytes, loff_t *off)
{
	int err;
	struct fuse_conn *fc = DEV_FC(file);
	struct fuse_req *req;
	struct fuse_out_header oh;

	if(!fc->sb)
		return -EPERM;

	err = copy_out_header(&oh, buf, nbytes);
	if(err)
		return err;

	if (!oh.unique)	{
		err = fuse_user_request(fc, buf, nbytes);
		goto out;
	}     

        if (oh.error <= -512 || oh.error > 0) {
                printk("fuse_dev_write: bad error value\n");
                return -EINVAL;
        }

	spin_lock(&fuse_lock);
	req = request_find(fc, oh.unique);
	if(req != NULL) {
		list_del_init(&req->list);
		req->locked = 1;
	}
	spin_unlock(&fuse_lock);
	if(!req)
		return -ENOENT;

	req->out->h = oh;
	err = copy_out_args(req->out, buf, nbytes);

	spin_lock(&fuse_lock);
	if(err)
		req->out->h.error = -EPROTO;
	else {
		/* fget() needs to be done in this context */
		if(req->in->h.opcode == FUSE_GETDIR && !oh.error)
			process_getdir(req);
	}	
	req->finished = 1;
	req->locked = 0;
	/* Unlocks fuse_lock: */
	request_end(fc, req);

  out:
	if(!err)
		return nbytes;
	else
		return err;
}


static unsigned int fuse_dev_poll(struct file *file, poll_table *wait)
{
	struct fuse_conn *fc = DEV_FC(file);
	unsigned int mask = POLLOUT | POLLWRNORM;

	if(!fc->sb)
		return -EPERM;

	poll_wait(file, &fc->waitq, wait);

	spin_lock(&fuse_lock);
	if (!list_empty(&fc->pending))
                mask |= POLLIN | POLLRDNORM;
	spin_unlock(&fuse_lock);

	return mask;
}

static struct fuse_conn *new_conn(void)
{
	struct fuse_conn *fc;

	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	if(fc != NULL) {
		fc->sb = NULL;
		fc->file = NULL;
		fc->flags = 0;
		fc->uid = 0;
		init_waitqueue_head(&fc->waitq);
		INIT_LIST_HEAD(&fc->pending);
		INIT_LIST_HEAD(&fc->processing);
		sema_init(&fc->outstanding, MAX_OUTSTANDING);
		fc->reqctr = 1;
	}
	return fc;
}

static int fuse_dev_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc;

	fc = new_conn();
	if(!fc)
		return -ENOMEM;

	fc->file = file;
	file->private_data = fc;

	return 0;
}

static void end_requests(struct fuse_conn *fc, struct list_head *head)
{
	while(!list_empty(head)) {
		struct fuse_req *req;
		req = list_entry(head->next, struct fuse_req, list);
		list_del_init(&req->list);
		if(req->issync) {
			req->out->h.error = -ECONNABORTED;
			req->finished = 1;
			/* Unlocks fuse_lock: */
			request_end(fc, req);
			spin_lock(&fuse_lock);
		} else
			destroy_request(req);
	}
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = DEV_FC(file);

	spin_lock(&fuse_lock);
	fc->file = NULL;
	end_requests(fc, &fc->pending);
	end_requests(fc, &fc->processing);
	fuse_release_conn(fc);
	spin_unlock(&fuse_lock);
	return 0;
}

static struct file_operations fuse_dev_operations = {
	.owner		= THIS_MODULE,
	.read		= fuse_dev_read,
	.write		= fuse_dev_write,
	.poll		= fuse_dev_poll,
	.open		= fuse_dev_open,
	.release	= fuse_dev_release,
};

int fuse_dev_init()
{
	int ret;

	proc_fs_fuse = NULL;
	proc_fuse_dev = NULL;

	fuse_req_cachep = kmem_cache_create("fuser_request",
					     sizeof(struct fuse_req),
					     0, 0, NULL, NULL);
	if(!fuse_req_cachep)
		return -ENOMEM;

	ret = -ENOMEM;
	proc_fs_fuse = proc_mkdir("fuse", proc_root_fs);
	if(!proc_fs_fuse) {
		printk("fuse: failed to create directory in /proc/fs\n");
		goto err;
	}

	proc_fs_fuse->owner = THIS_MODULE;
	proc_fuse_dev = create_proc_entry("dev", S_IFSOCK | 0600, proc_fs_fuse);
	if(!proc_fuse_dev) {
		printk("fuse: failed to create entry in /proc/fs/fuse\n");
		goto err;
	}

	proc_fuse_dev->proc_fops = &fuse_dev_operations;

	return 0;

  err:
	fuse_dev_cleanup();
	return ret;
}

void fuse_dev_cleanup()
{
	if(proc_fs_fuse) {
		remove_proc_entry("dev", proc_fs_fuse);
		remove_proc_entry("fuse", proc_root_fs);
	}
	
	kmem_cache_destroy(fuse_req_cachep);
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
