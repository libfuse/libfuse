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

static struct proc_dir_entry *proc_fs_fuse;
struct proc_dir_entry *proc_fuse_dev;

static struct fuse_req *request_wait(struct fuse_conn *fc)
{
	DECLARE_WAITQUEUE(wait, current);
	struct fuse_req *req;

	spin_lock(&fuse_lock);
	add_wait_queue(&fc->waitq, &wait);
	set_current_state(TASK_INTERRUPTIBLE);
	while(list_empty(&fc->pending)) {
		if(signal_pending(current))
			break;

		spin_unlock(&fuse_lock);
		schedule();
		spin_lock(&fuse_lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&fc->waitq, &wait);

	if(list_empty(&fc->pending))
		return NULL;

	req = list_entry(fc->pending.next, struct fuse_req, list);
	list_del(&req->list);
	spin_unlock(&fuse_lock);

	return req;
}

static void request_processing(struct fuse_conn *fc, struct fuse_req *req)
{
	spin_lock(&fuse_lock);
	list_add_tail(&req->list, &fc->processing);
	fc->outstanding ++;
	spin_unlock(&fuse_lock);
}

static void request_free(struct fuse_req *req)
{
	kfree(req);
}

static ssize_t fuse_dev_read(struct file *file, char *buf, size_t nbytes,
			     loff_t *off)
{
	ssize_t res;
	struct fuse_conn *fc = file->private_data;
	struct fuse_req *req;

	printk(KERN_DEBUG "fuse_dev_read[%i]\n", fc->id);

	res = -ERESTARTSYS;
	req = request_wait(fc);
	if(req == NULL)
		goto err;

	res = -EIO;
	if(nbytes < req->size) {
		printk("fuse_dev_read: buffer too small (%i)\n", req->size);
		goto err_free_req;
	}
	
	res = -EFAULT;
	if(copy_to_user(buf, req->data, req->size))
		goto err_free_req;

	request_processing(fc, req);
	return req->size;

  err_free_req:
	request_free(req);
  err:
	return res;
}

static ssize_t fuse_dev_write(struct file *file, const char *buf,
				size_t nbytes, loff_t *off)
{
	struct fuse_conn *fc = file->private_data;

	printk(KERN_DEBUG "fuse_dev_write[%i] <%.*s>\n", fc->id, (int) nbytes,
	       buf);
	return nbytes;
}


static unsigned int fuse_dev_poll(struct file *file, poll_table *wait)
{
	struct fuse_conn *fc = file->private_data;

	printk(KERN_DEBUG "fuse_dev_poll[%i]\n", fc->id);
	return 0;
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
		
		spin_lock(&fuse_lock);
		fc->id = connctr ++;
		spin_unlock(&fuse_lock);
	}
	return fc;
}

static int fuse_dev_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc;

	printk(KERN_DEBUG "fuse_dev_open\n");

	fc = new_conn();
	if(!fc)
		return -ENOMEM;

	fc->file = file;
	file->private_data = fc;

	printk(KERN_DEBUG "new connection: %i\n", fc->id);

	return 0;
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = file->private_data;

	printk(KERN_DEBUG "fuse_dev_release[%i]\n", fc->id);

	spin_lock(&fuse_lock);
	fc->file = NULL;
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
	int res;

	proc_fs_fuse = NULL;
	proc_fuse_dev = NULL;

	res = -EIO;
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
	return res;

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
