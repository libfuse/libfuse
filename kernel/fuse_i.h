/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#ifdef FUSE_MAINLINE
#include <linux/fuse.h>
#else
#include "fuse_kernel.h"
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#error Kernel version 2.5.* not supported
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#  define KERNEL_2_6
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)
#    define KERNEL_2_6_6_PLUS
#  endif
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#    define KERNEL_2_6_10_PLUS
#  endif
#endif

#include <config.h>
#ifndef KERNEL_2_6
#  include <linux/config.h>
#  ifdef CONFIG_MODVERSIONS
#     define MODVERSIONS
#     include <linux/modversions.h>
#  endif
#  ifndef HAVE_I_SIZE_FUNC
#     define i_size_read(inode) ((inode)->i_size)
#     define i_size_write(inode, size) do { (inode)->i_size = size; } while(0)
#  endif
#endif
#endif /* FUSE_MAINLINE */
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#ifdef KERNEL_2_6
#include <linux/mm.h>
#include <linux/backing-dev.h>
#endif
#include <asm/semaphore.h>

#ifndef BUG_ON
#define BUG_ON(x)
#endif
#ifndef __user
#define __user
#endif
/* Max number of pages that can be used in a single read request */
#define FUSE_MAX_PAGES_PER_REQ 32

/* If more requests are outstanding, then the operation will block */
#define FUSE_MAX_OUTSTANDING 10


/** If the FUSE_DEFAULT_PERMISSIONS flag is given, the filesystem
    module will check permissions based on the file mode.  Otherwise no
    permission checking is done in the kernel */
#define FUSE_DEFAULT_PERMISSIONS (1 << 0)

/** If the FUSE_ALLOW_OTHER flag is given, then not only the user
    doing the mount will be allowed to access the filesystem */
#define FUSE_ALLOW_OTHER         (1 << 1)

/** If the FUSE_KERNEL_CACHE flag is given, then cached data will not
    be flushed on open */
#define FUSE_KERNEL_CACHE        (1 << 2)

#ifndef KERNEL_2_6
/** Allow FUSE to combine reads into 64k chunks.  This is useful if
    the filesystem is better at handling large chunks */
#define FUSE_LARGE_READ          (1 << 31)
#endif
/** Bypass the page cache for read and write operations  */
#define FUSE_DIRECT_IO           (1 << 3)

/** Allow root and setuid-root programs to access fuse-mounted
    filesystems */
#define FUSE_ALLOW_ROOT		 (1 << 4)

/** FUSE specific inode data */
struct fuse_inode {
	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	unsigned long nodeid;

	/** The request used for sending the FORGET message */
	struct fuse_req *forget_req;

	/** Semaphore protects the 'write_files' list, and against
	    truncate racing with async writeouts */
	struct rw_semaphore write_sem;

	/** Time in jiffies until the file attributes are valid */
	unsigned long i_time;

	/* List of fuse_files which can provide file handles in
	 * writepage, protected by write_sem */
	struct list_head write_files;
};

/** FUSE specific file data */
struct fuse_file {
	/** Request reserved for flush and release */
	struct fuse_req *release_req;
	
	/** File handle used by userspace */
	unsigned long fh;

	/** Element in fuse_inode->write_files */
	struct list_head ff_list;
};

/** One input argument of a request */
struct fuse_in_arg {
	unsigned size;
	const void *value;
};

/** The request input */
struct fuse_in {
	/** The request header */
	struct fuse_in_header h;

	/** True if the data for the last argument is in req->pages */
	unsigned argpages:1;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_in_arg args[3];
};

/** One output argument of a request */
struct fuse_out_arg {
	unsigned size;
	void *value;
};

/** The request output */
struct fuse_out {
	/** Header returned from userspace */
	struct fuse_out_header h;

	/** Last argument is variable length (can be shorter than
	    arg->size) */
	unsigned argvar:1;
	
	/** Last argument is a list of pages to copy data to */
	unsigned argpages:1;
	
	/** Zero partially or not copied pages */
	unsigned page_zeroing:1;

	/** Number or arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_out_arg args[3];
};

struct fuse_req;
struct fuse_conn;

/** Function called on finishing an async request */
typedef void (*fuse_reqend_t)(struct fuse_conn *, struct fuse_req *);

/**
 * A request to the client
 */
struct fuse_req {
	/** The request list */
	struct list_head list;

	/** True if the request has reply */
	unsigned isreply:1;

	/* The request is preallocated */
	unsigned preallocated:1;

	/* The request is finished */
	unsigned finished;

	/** The request input */
	struct fuse_in in;

	/** The request output */
	struct fuse_out out;

	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;

	/** Request completion callback */
	fuse_reqend_t end;

	/** Data for asynchronous requests */
	union {
		struct {
			struct fuse_write_in in;
			struct fuse_write_out out;
		} write;
		struct fuse_read_in read_in;
		struct fuse_forget_in forget_in;
	} misc;

	/** page vector */
	struct page *pages[FUSE_MAX_PAGES_PER_REQ];

	/** number of pages in vector */
	unsigned num_pages;

	/** offset of data on first page */
	unsigned page_offset;
};

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
	unsigned flags;

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The list of pending requests */
	struct list_head pending;

	/** The list of requests being processed */
	struct list_head processing;

	/** Controls the maximum number of outstanding requests */
	struct semaphore unused_sem;

	/** Semaphore protecting the super block from going away */
	struct semaphore sb_sem;

	/** The list of unused requests */
	struct list_head unused_list;

	/** The next unique request id */
	int reqctr;

	/** Is fsync not implemented by fs? */
	unsigned no_fsync : 1;

	/** Is flush not implemented by fs? */
	unsigned no_flush : 1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr : 1;

	/** Is getxattr not implemented by fs? */
	unsigned no_getxattr : 1;

	/** Is listxattr not implemented by fs? */
	unsigned no_listxattr : 1;

	/** Is removexattr not implemented by fs? */
	unsigned no_removexattr : 1;

#ifdef KERNEL_2_6
	/** Backing dev info */
	struct backing_dev_info bdi;
#endif
};

struct fuse_getdir_out_i {
	int fd;
	void *file; /* Used by kernel only */
};

static inline struct fuse_conn **get_fuse_conn_super_p(struct super_block *sb)
{
#ifdef KERNEL_2_6
	return (struct fuse_conn **) &sb->s_fs_info;
#else
	return (struct fuse_conn **) &sb->u.generic_sbp;
#endif
}

static inline struct fuse_conn *get_fuse_conn_super(struct super_block *sb)
{
	return *get_fuse_conn_super_p(sb);
}

static inline struct fuse_conn *get_fuse_conn(struct inode *inode)
{
	return get_fuse_conn_super(inode->i_sb);
}

static inline struct fuse_inode *get_fuse_inode(struct inode *inode)
{
	return (struct fuse_inode *) (&inode[1]);
}

static inline unsigned long get_node_id(struct inode *inode)
{
	return get_fuse_inode(inode)->nodeid;
}

/** Device operations */
extern struct file_operations fuse_dev_operations;

/**
 * This is the single global spinlock which protects FUSE's structures
 *
 * The following data is protected by this lock:
 *
 *  - the private_data field of the device file
 *  - the s_fs_info field of the super block
 *  - unused_list, pending, processing lists in fuse_conn
 *  - the unique request ID counter reqctr in fuse_conn
 *  - the sb (super_block) field in fuse_conn
 *  - the file (device file) field in fuse_conn
 */
extern spinlock_t fuse_lock;

/**
 * Get a filled in inode
 */
struct inode *fuse_iget(struct super_block *sb, unsigned long nodeid,
			int generation, struct fuse_attr *attr, int version);

/**
 * Lookup an inode by nodeid
 */
#ifdef KERNEL_2_6
struct inode *fuse_ilookup(struct super_block *sb, unsigned long nodeid);
#else
struct inode *fuse_ilookup(struct super_block *sb, ino_t ino, unsigned long nodeid);
#endif

/**
 * Send FORGET command
 */
void fuse_send_forget(struct fuse_conn *fc, struct fuse_req *req,
		      unsigned long nodeid, int version);

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
 * Allocate a request
 */
struct fuse_req *fuse_request_alloc(void);

/**
 * Free a request
 */
void fuse_request_free(struct fuse_req *req);

/**
 * Reinitialize a request, the preallocated flag is left unmodified
 */
void fuse_reset_request(struct fuse_req *req);

/**
 * Reserve a preallocated request
 */
struct fuse_req *fuse_get_request(struct fuse_conn *fc);

/**
 * Reserve a preallocated request, non-interruptible
 */
struct fuse_req *fuse_get_request_nonint(struct fuse_conn *fc);

/**
 * Reserve a preallocated request, non-blocking
 */
struct fuse_req *fuse_get_request_nonblock(struct fuse_conn *fc);

/**
 * Free a request
 */
void fuse_put_request(struct fuse_conn *fc, struct fuse_req *req);

/**
 * Send a request
 */
void request_send(struct fuse_conn *fc, struct fuse_req *req);

/**
 * Send a request for which a reply is not expected
 */
void request_send_noreply(struct fuse_conn *fc, struct fuse_req *req);

/**
 * Send asynchronous request
 */
void request_send_async(struct fuse_conn *fc, struct fuse_req *req,
			fuse_reqend_t end);

/**
 * Get the attributes of a file
 */
int fuse_do_getattr(struct inode *inode);

/**
 * Write dirty pages
 */
void fuse_sync_inode(struct inode *inode);
