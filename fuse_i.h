/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <linux/fs.h>

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
};

/**
 * The proc entry for the client device ("/proc/fs/fuse/dev")
 */
extern struct proc_dir_entry *proc_fuse_dev;

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
