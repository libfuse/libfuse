/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/


#include <linux/fuse.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#error Kernel version 2.5.* not supported
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define KERNEL_2_6
#endif

#ifndef KERNEL_2_6
#include <linux/config.h>
#ifdef CONFIG_MODVERSIONS
#define MODVERSIONS
#include <linux/modversions.h>
#endif
#endif 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/spinlock.h>

/** Read combining parameters */
#define FUSE_BLOCK_SHIFT 16
#define FUSE_BLOCK_SIZE 65536
#define FUSE_BLOCK_MASK 0xffff0000

#define FUSE_BLOCK_PAGE_SHIFT (FUSE_BLOCK_SHIFT - PAGE_CACHE_SHIFT)

/**
 * A Fuse connection.
 *
 * This structure is created, when the client device is opened, and is
 * destroyed, when the client device is closed _and_ the filesystem is
 * unmounted.
 */
struct fuse_conn {
	/** The superblock of the mounted filesystem */
	struct super_block *sb;
	
	/** The opened client device */
	struct file *file;

	/** The user id for this mount */
	uid_t uid;

	/** The fuse mount flags for this mount */
	unsigned int flags;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The list of pending requests */
	struct list_head pending;

	/** The list of requests being processed */
	struct list_head processing;

	/** Controls the maximum number of outstanding requests */
	struct semaphore outstanding;
	
	/** The next unique request id */
	int reqctr;
};

/** One input argument of a request */
struct fuse_in_arg {
	unsigned int size;
	const void *value;
};

/** The request input */
struct fuse_in {
	struct fuse_in_header h;
	unsigned int numargs;
	struct fuse_in_arg args[3];
};

/** One output argument of a request */
struct fuse_out_arg {
	unsigned int size;
	void *value;
};

/** The request output */
struct fuse_out {
	struct fuse_out_header h;
	unsigned int argvar;
	unsigned int numargs;
	struct fuse_out_arg args[3];
};

#define FUSE_IN_INIT { {0, 0, 0, current->fsuid, current->fsgid}, 0}
#define FUSE_OUT_INIT { {0, 0}, 0, 0}

struct fuse_req;
typedef void (*fuse_reqend_t)(struct fuse_conn *, struct fuse_in *,
			      struct fuse_out *, void *data);

/**
 * A request to the client
 */
struct fuse_req {
	/** The request list */
	struct list_head list;

	/** True if the request is synchronous */
	unsigned int issync:1;

	/** The request is locked */
	unsigned int locked:1;

	/** The request has been interrupted while it was locked */
	unsigned int interrupted:1;

	/* The request has been sent to the client */
	unsigned int sent:1;

	/* The request is finished */
	unsigned int finished:1;

	/** The request input */
	struct fuse_in *in;

	/** The request output */
	struct fuse_out *out;

	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;

	/** Request completion callback */
	fuse_reqend_t end;

	/** User data */
	void *data;
};

#ifdef KERNEL_2_6
#define SB_FC(sb) ((struct fuse_conn *) (sb)->s_fs_info)
#else
#define SB_FC(sb) ((struct fuse_conn *) (sb)->u.generic_sbp)
#endif
#define INO_FC(inode) SB_FC((inode)->i_sb)
#define DEV_FC(file) ((struct fuse_conn *) (file)->private_data)


/**
 * The proc entry for the client device ("/proc/fs/fuse/dev")
 */
extern struct proc_dir_entry *proc_fuse_dev;

/**
 * The lock to protect fuses structures
 */
extern spinlock_t fuse_lock;


/**
 * Get a filled in inode
 */
struct inode *fuse_iget(struct super_block *sb, ino_t ino,
			struct fuse_attr *attr, int version);


/**
 * Initialise operations on regular file
 */
void fuse_init_file_inode(struct inode *inode);

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

/**
 * Send a request for which a reply is not expected
 */
int request_send_noreply(struct fuse_conn *fc, struct fuse_in *in);


/**
 * Send a synchronous request without blocking
 */
int request_send_nonblock(struct fuse_conn *fc, struct fuse_in *in,
			  struct fuse_out *out, fuse_reqend_t end, void *data);

/**
 * Get the attributes of a file
 */
int fuse_do_getattr(struct inode *inode);

/*
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
