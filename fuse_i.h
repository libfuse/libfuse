/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse.h"

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

	/** The request id */
	int reqctr;
};

/**
 * A request to the client
 */
struct fuse_req {
	/** The request list */
	struct list_head list;

	/** The request input parameters */
	struct fuse_in *in;

	/** The request result */
	struct fuse_out *out;

	/** The file returned by open */
	struct file *file;

	/** The request wait queue */
	wait_queue_head_t waitq;

	/** True if the request is finished */
	int done;
};

struct fuse_out_open_internal {
	file *file;
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
 * Fill in the file operations
 */
void fuse_file_init(struct inode *inode);

/**
 * Fill in the symlink operations
 */
void fuse_symlink_init(struct inode *inode);

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

/**
 * Send a request
 *
 */
void request_send(struct fuse_conn *fc, struct fuse_in *in,
		  struct fuse_out *out);

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 */
