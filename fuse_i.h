/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#define FUSE_VERSION "0.1"

/**
 * A Fuse connection.
 *
 * This structure is created, when the client device is opened, and is
 * destroyed, when the client device is closed _and_ the filesystem is
 * umounted.
 */
struct fuse_conn {
	/** The superblock of the mounted filesystem */
	struct super_block *sb;
	
	/** The opened client device */
	struct file *file;

	/** The client wait queue */
	wait_queue_head_t waitq;

	/** The list of pending requests */
	struct list_head pending;

	/** The list of requests being processed */
	struct list_head processing;

	/** The number of outstanding requests */
	int outstanding;

	/** Connnection number (for debuging) */
	int id;
};

/**
 * A filesystem request
 */
struct fuse_req {
	/** The request list */
	struct list_head list;

	/** The size of the data */
	size_t size;

	/** A pointer to the data */
	void *data;
};

/**
 * The proc entry for the client device ("/proc/fs/fuse/dev")
 */
extern struct proc_dir_entry *proc_fuse_dev;

/**
 * The lock to protect fuses structures
 */
extern spinlock_t fuse_lock;

/**
 * Fill in the directory operations
 */
void fuse_dir_init(struct inode *inode);

/**
 * Check if the connection can be released, and if yes, then free the
 * connection structure
 */
void fuse_release_conn(struct fuse_conn *fc);

/**
 * Initialize the client device
 */
int fuse_dev_init(void);

/**
 * Cleanup the client device
 */
void fuse_dev_cleanup(void);

/**
 * Initialize the fuse filesystem 
 */
int fuse_fs_init(void);

/**
 * Cleanup the fuse filesystem
 */
void fuse_fs_cleanup(void);

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 */
