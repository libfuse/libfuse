/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/file.h>

#define ICSIZE sizeof(struct fuse_in_common)
#define OCSIZE sizeof(struct fuse_out_common)

static struct proc_dir_entry *proc_fs_fuse;
struct proc_dir_entry *proc_fuse_dev;

static int request_wait_answer(struct fuse_req *req)
{
	int ret = 0;
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(&req->waitq, &wait);
	while(!req->done) {
		set_current_state(TASK_INTERRUPTIBLE);
		if(signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		spin_unlock(&fuse_lock);
		schedule();
		spin_lock(&fuse_lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&req->waitq, &wait);

	return ret;
}

void request_send(struct fuse_conn *fc, struct fuse_in *in,
		  struct fuse_out *out)
{
	int ret;
	struct fuse_req *req;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if(req == NULL) {
		out->result = -ENOMEM;
		return;
	}
	
	req->in = in;
	req->out = out;
	req->done = 0;
	init_waitqueue_head(&req->waitq);
	
	spin_lock(&fuse_lock);
	if(fc->file == NULL) {
		ret = -ENOTCONN;
		goto out;
	}

	req->in->h.unique = fc->reqctr ++;
	list_add_tail(&req->list, &fc->pending);
	fc->outstanding ++;
	/* FIXME: Wait until the number of outstanding requests drops
           below a certain level */
	wake_up(&fc->waitq);
	ret = request_wait_answer(req);
	fc->outstanding --;
	list_del(&req->list);

  out:
	kfree(req);
	spin_unlock(&fuse_lock);

	if(ret)
		out->result = ret;
	else if (out->result <= -512 || out->result > 0) {
		printk("Bad result from client: %i\n", out->result);
		out->result = -EPROTO;
	}
}

static int request_wait(struct fuse_conn *fc)
{
	int ret = 0;
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(&fc->waitq, &wait);
	while(list_empty(&fc->pending)) {
		set_current_state(TASK_INTERRUPTIBLE);
		if(signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		spin_unlock(&fuse_lock);
		schedule();
		spin_lock(&fuse_lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&fc->waitq, &wait);

	return ret;
}


static ssize_t fuse_dev_read(struct file *file, char *buf, size_t nbytes,
			     loff_t *off)
{
	ssize_t ret;
	struct fuse_conn *fc = file->private_data;
	struct fuse_req *req;
	size_t size;

	spin_lock(&fuse_lock);
	ret = request_wait(fc);
	if(ret)
		goto err;
	
	req = list_entry(fc->pending.next, struct fuse_req, list);
	size = ICSIZE + req->in->argsize;

	ret = -EPROTO;
	if(nbytes < size) {
		printk("fuse_dev_read: buffer too small (%i)\n", size);
		goto err;
	}
	
	list_del(&req->list);
	list_add_tail(&req->list, &fc->processing);
	spin_unlock(&fuse_lock);

	if(copy_to_user(buf, &req->in->c, ICSIZE) ||
	   copy_to_user(buf + ICSIZE, req->in->arg, req->in->argsize))
		return -EFAULT;
	
	return size;

  err:
	spin_unlock(&fuse_lock);
	return ret;
}

static struct fuse_req *request_find(struct fuse_conn *fc, unsigned int unique)
{
	struct list_head *entry;
	struct fuse_req *req = NULL;

	list_for_each(entry, &fc->processing) {
		struct fuse_req *tmp;
		tmp = list_entry(entry, struct fuse_req, list);
		if(tmp->in->c.unique == unique) {
			req = tmp;
			break;
		}
	}

	return req;
}

static ssize_t fuse_dev_write(struct file *file, const char *buf,
			      size_t nbytes, loff_t *off)
{
	struct fuse_conn *fc = file->private_data;
	struct fuse_req *req;
	struct fuse_out_common oc;
	char *tmpbuf;

	if(nbytes > 2 * PAGE_SIZE) {
		printk("fuse_dev_write: write is too long\n");
		return -EPROTO;
	}
	
	tmpbuf = (char *)  __get_free_pages(GFP_KERNEL, 1);
	if(!tmpbuf)
		return -ENOMEM;

	if(copy_from_user(tmpbuf, buf, nbytes))
		return -EFAULT;
	
	spin_lock(&fuse_lock);
	req = request_find(fc, oc.unique);
	
	if(req == NULL)
		printk("fuse_dev_write[%i]: unknown request: %i", fc->id,
		       oc.unique);

		

	else {
		struct fuse_outparam *out = &param.u.o;
		if(req->param.u.i.opcode == FUSE_OPEN && out->result == 0)
			out->u.open_internal.file = fget(out->u.open.fd);

		req->param = param;
		req->done = 1;
		wake_up(&req->waitq);
	}
	spin_unlock(&fuse_lock);

	return nbytes;
}


static unsigned int fuse_dev_poll(struct file *file, poll_table *wait)
{
	struct fuse_conn *fc = file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;

	poll_wait(file, &fc->waitq, wait);

	spin_lock(&fuse_lock);
	if (!list_empty(&fc->pending))
                mask |= POLLIN | POLLRDNORM;
	spin_unlock(&fuse_lock);

	return mask;
}

static struct fuse_conn *new_conn(void)
{
	static int connctr = 1;
	struct fuse_conn *fc;

	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	if(fc != NULL) {
		fc->sb = NULL;
		fc->file = NULL;
		init_waitqueue_head(&fc->waitq);
		INIT_LIST_HEAD(&fc->pending);
		INIT_LIST_HEAD(&fc->processing);
		fc->outstanding = 0;
		fc->reqctr = 0;
		
		spin_lock(&fuse_lock);
		fc->id = connctr ++;
		spin_unlock(&fuse_lock);
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

static void end_requests(struct list_head *head)
{
	while(!list_empty(head)) {
		struct fuse_req *req;
		req = list_entry(head->next, struct fuse_req, list);
		list_del_init(&req->list);
		req->done = 1;
		req->param.u.o.result = -ECONNABORTED;
		wake_up(&req->waitq);
	}
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = file->private_data;

	spin_lock(&fuse_lock);
	fc->file = NULL;
	end_requests(&fc->pending);
	end_requests(&fc->processing);
	fuse_release_conn(fc);
	spin_unlock(&fuse_lock);
	return 0;
}

static struct file_operations fuse_dev_operations = {
	owner:		THIS_MODULE,
	read:		fuse_dev_read,
	write:		fuse_dev_write,
	poll:		fuse_dev_poll,
	open:		fuse_dev_open,
	release:	fuse_dev_release,
};

int fuse_dev_init()
{
	int ret;

	proc_fs_fuse = NULL;
	proc_fuse_dev = NULL;

	ret = -EIO;
	proc_fs_fuse = proc_mkdir("fuse", proc_root_fs);
	if(!proc_fs_fuse) {
		printk("fuse: failed to create directory in /proc/fs\n");
		goto err;
	}

	proc_fs_fuse->owner = THIS_MODULE;
	proc_fuse_dev = create_proc_entry("dev", S_IFSOCK | S_IRUGO | S_IWUGO,
					  proc_fs_fuse);
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
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
