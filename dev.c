/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp_lock.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/proc_fs.h>

static struct proc_dir_entry *proc_fs_fuse;
struct proc_dir_entry *proc_fuse_dev;

static ssize_t fuse_dev_read(struct file *file, char *buf, size_t nbytes,
			     loff_t *off)
{
	printk(KERN_DEBUG "fuse_dev_read\n");
	return 0;
}

static ssize_t fuse_dev_write(struct file *file, const char *buf,
				size_t nbytes, loff_t *off)
{
	printk(KERN_DEBUG "fuse_dev_write <%.*s>\n", (int) nbytes, buf);
	return nbytes;
}


static unsigned int fuse_dev_poll(struct file *file, poll_table *wait)
{
	printk(KERN_DEBUG "fuse_dev_poll\n");
	return 0;
}

static int fuse_dev_open(struct inode *inode, struct file *file)
{
	int res;
	struct fuse_conn *fc;

	printk(KERN_DEBUG "fuse_dev_open\n");

	res = -ENOMEM;
	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	if(!fc)
		goto out;
	
	fc->sb = NULL;
	fc->file = file;
	
	lock_kernel();
	file->private_data = fc;
	unlock_kernel();
	res = 0;
	
  out:
	return res;
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = file->private_data;

	printk(KERN_DEBUG "fuse_dev_release\n");

	lock_kernel();
	fc->file = NULL;
	fuse_release_conn(fc);
	unlock_kernel();
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
