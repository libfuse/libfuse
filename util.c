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
#include <linux/slab.h>

#define FUSE_VERSION "0.1"

spinlock_t fuse_lock = SPIN_LOCK_UNLOCKED;

/* Must be called with the fuse lock held */
void fuse_release_conn(struct fuse_conn *fc)
{
	if(fc->sb == NULL && fc->file == NULL) {
		printk(KERN_DEBUG "fuse: release connection: %i\n", fc->id);
		kfree(fc);
	}
}

int init_module(void)
{
	int res;

	printk(KERN_DEBUG "fuse init (version %s)\n", FUSE_VERSION);

	res = fuse_fs_init();
	if(res)
		goto err;
	
	res = fuse_dev_init();
	if(res)
		goto err_fs_cleanup;
	
	return 0;

  err_fs_cleanup:
	fuse_fs_cleanup();
  err:
	return res;
}

void cleanup_module(void)
{
	printk(KERN_DEBUG "fuse cleanup\n");
	
	fuse_fs_cleanup();
	fuse_dev_cleanup();
}

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 */
