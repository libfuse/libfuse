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

#define IHSIZE sizeof(struct fuse_in_header)
#define OHSIZE sizeof(struct fuse_out_header)

static struct proc_dir_entry *proc_fs_fuse;
struct proc_dir_entry *proc_fuse_dev;

static int request_wait_answer(struct fuse_req *req)
{
	int ret = 0;
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(&req->waitq, &wait);
	while(!list_empty(&req->list)) {
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

static int request_check(struct fuse_req *req, struct fuse_out *outp)
{
	struct fuse_out_header *oh;
	unsigned int size;

	if(!req->out)
		return -ECONNABORTED;

	oh = (struct fuse_out_header *) req->out;
	size = req->outsize - OHSIZE;
	
	if (oh->error <= -512 || oh->error > 0) {
		printk("fuse: bad error value: %i\n", oh->error);
		return -EPROTO;
	}

	if(size > outp->argsize || 
	   (oh->error == 0 && !outp->argvar && size != outp->argsize) ||
	   (oh->error != 0 && size != 0)) {
		printk("fuse: invalid argument length: %i (%i)\n", size,
		       req->opcode);
		return -EPROTO;
	}
	
	memcpy(&outp->h, oh, OHSIZE);
	outp->argsize = size;
	if(size)
		memcpy(outp->arg, req->out + OHSIZE, size);
	
	return oh->error;
}

static void request_free(struct fuse_req *req)
{
	kfree(req->in);
	kfree(req->out);
	kfree(req);
}


static struct fuse_req *request_new(struct fuse_conn *fc, struct fuse_in *inp,
				    struct fuse_out *outp)
{
	struct fuse_req *req;
	
	req = kmalloc(sizeof(*req), GFP_NOFS);
	if(!req)
		return NULL;

	if(outp)
		req->outsize = OHSIZE + outp->argsize;
	else
		req->outsize = 0;
	req->out = NULL;

	req->insize = IHSIZE + inp->argsize;
	req->in = kmalloc(req->insize, GFP_NOFS);
	if(!req->in) {
		request_free(req);
		return NULL;
	}
	memcpy(req->in, &inp->h, IHSIZE);
	if(inp->argsize)
		memcpy(req->in + IHSIZE, inp->arg, inp->argsize);

	req->opcode = inp->h.opcode;
	init_waitqueue_head(&req->waitq);

	return req;
}

/* If 'outp' is NULL then the request this is asynchronous */
void request_send(struct fuse_conn *fc, struct fuse_in *inp,
		  struct fuse_out *outp)
{
	int ret;
	struct fuse_in_header *ih;
	struct fuse_req *req;

	ret = -ENOMEM;
	req = request_new(fc, inp, outp);
	if(!req)
		goto out;

	spin_lock(&fuse_lock);
	ret = -ENOTCONN;
	if(!fc->file)
		goto out_unlock_free;
	
	ih = (struct fuse_in_header *) req->in;
	if(outp) {
		do fc->reqctr++;
		while(!fc->reqctr);
		ih->unique = req->unique = fc->reqctr;
	}
	else
		ih->unique = req->unique = 0;

	list_add_tail(&req->list, &fc->pending);
	wake_up(&fc->waitq);

	/* Async reqests are freed in fuse_dev_read() */
	if(!outp) 
		goto out_unlock; 
	
	ret = request_wait_answer(req);
	list_del(&req->list);
	if(!ret)
		ret = request_check(req, outp);

  out_unlock_free:
	request_free(req);
  out_unlock:
	spin_unlock(&fuse_lock);
  out:
	if(outp)
		outp->h.error = ret;
}

static int request_wait(struct fuse_conn *fc)
{
	int ret = 0;
	DECLARE_WAITQUEUE(wait, current);
	
	add_wait_queue_exclusive(&fc->waitq, &wait);
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
	int ret;
	struct fuse_conn *fc = DEV_FC(file);
	struct fuse_req *req;
	char *tmpbuf;
	unsigned int size;

	if(fc->sb == NULL)
		return -EPERM;
	
	spin_lock(&fuse_lock);
	ret = request_wait(fc);
	if(ret)
		goto err;
	
	req = list_entry(fc->pending.next, struct fuse_req, list);
	size = req->insize;
	if(nbytes < size) {
		printk("fuse_dev_read: buffer too small\n");
		ret = -EIO;
		goto err;
	}
	tmpbuf = req->in;
	req->in = NULL;

	list_del(&req->list);
	if(req->outsize)
		list_add_tail(&req->list, &fc->processing);
	else
		request_free(req);
	spin_unlock(&fuse_lock);

	if(copy_to_user(buf, tmpbuf, size))
		return -EFAULT;
	
	kfree(tmpbuf);
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
		if(tmp->unique == unique) {
			req = tmp;
			break;
		}
	}

	return req;
}

static ssize_t fuse_dev_write(struct file *file, const char *buf,
			      size_t nbytes, loff_t *off)
{
	ssize_t ret;
	struct fuse_conn *fc = DEV_FC(file);
	struct fuse_req *req;
	char *tmpbuf;
	struct fuse_out_header *oh;

	if(!fc->sb)
		return -EPERM;

	ret = -EIO;
	if(nbytes < OHSIZE || nbytes > OHSIZE + PAGE_SIZE) {
		printk("fuse_dev_write: write is short or long\n");
		goto out;
	}
	
	ret = -ENOMEM;
	tmpbuf = kmalloc(nbytes, GFP_NOFS);
	if(!tmpbuf)
		goto out;
	
	ret = -EFAULT;
	if(copy_from_user(tmpbuf, buf, nbytes))
		goto out_free;
	
	spin_lock(&fuse_lock);
	oh =  (struct fuse_out_header *) tmpbuf;
	req = request_find(fc, oh->unique);
	if(req == NULL) {
		ret = -ENOENT;
		goto out_free_unlock;
	}
	list_del_init(&req->list);
	if(req->opcode == FUSE_GETDIR) {
		/* fget() needs to be done in this context */
		struct fuse_getdir_out *arg;
		arg = (struct fuse_getdir_out *) (tmpbuf + OHSIZE);
		arg->file = fget(arg->fd);
	}
	req->out = tmpbuf;
	req->outsize = nbytes;
	tmpbuf = NULL;
	ret = nbytes;
	wake_up(&req->waitq);
  out_free_unlock:
	spin_unlock(&fuse_lock);
  out_free:
	kfree(tmpbuf);
  out:
	return ret;
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

static void end_requests(struct list_head *head)
{
	while(!list_empty(head)) {
		struct fuse_req *req;
		req = list_entry(head->next, struct fuse_req, list);
		list_del_init(&req->list);
		if(req->outsize)
			wake_up(&req->waitq);
		else
			request_free(req);
	}
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = DEV_FC(file);

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
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
