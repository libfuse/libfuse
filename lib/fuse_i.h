/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse.h"
#include "fuse_lowlevel.h"

struct fuse_chan;
struct fuse_ll;

/**
 * Channel operations
 *
 * This is used in channel creation
 */
struct fuse_chan_ops {
	/**
	 * Hook for receiving a raw request
	 *
	 * @param ch pointer to the channel
	 * @param buf the buffer to store the request in
	 * @param size the size of the buffer
	 * @return the actual size of the raw request, or -1 on error
	 */
	int (*receive)(struct fuse_chan **chp, char *buf, size_t size);

	/**
	 * Hook for sending a raw reply
	 *
	 * A return value of -ENOENT means, that the request was
	 * interrupted, and the reply was discarded
	 *
	 * @param ch the channel
	 * @param iov vector of blocks
	 * @param count the number of blocks in vector
	 * @return zero on success, -errno on failure
	 */
	int (*send)(struct fuse_chan *ch, const struct iovec iov[],
		    size_t count);

	/**
	 * Destroy the channel
	 *
	 * @param ch the channel
	 */
	void (*destroy)(struct fuse_chan *ch);
};

struct fuse_session {
	int (*receive_buf)(struct fuse_session *se, struct fuse_buf *buf,
			   struct fuse_chan **chp);

	void (*process_buf)(void *data, const struct fuse_buf *buf,
			    struct fuse_chan *ch);

	void (*destroy) (void *data);

	void *data;

	volatile int exited;

	struct fuse_chan *ch;
};

struct fuse_req {
	struct fuse_ll *f;
	uint64_t unique;
	int ctr;
	pthread_mutex_t lock;
	struct fuse_ctx ctx;
	struct fuse_chan *ch;
	int interrupted;
	unsigned int ioctl_64bit : 1;
	union {
		struct {
			uint64_t unique;
		} i;
		struct {
			fuse_interrupt_func_t func;
			void *data;
		} ni;
	} u;
	struct fuse_req *next;
	struct fuse_req *prev;
};

struct fuse_notify_req {
	uint64_t unique;
	void (*reply)(struct fuse_notify_req *, fuse_req_t, fuse_ino_t,
		      const void *, const struct fuse_buf *);
	struct fuse_notify_req *next;
	struct fuse_notify_req *prev;
};

struct fuse_ll {
	int debug;
	int allow_root;
	int atomic_o_trunc;
	int no_remote_posix_lock;
	int no_remote_flock;
	int big_writes;
	int splice_write;
	int splice_move;
	int splice_read;
	int no_splice_write;
	int no_splice_move;
	int no_splice_read;
	int auto_inval_data;
	int no_auto_inval_data;
	int no_readdirplus;
	int no_readdirplus_auto;
	struct fuse_lowlevel_ops op;
	int got_init;
	struct cuse_data *cuse_data;
	void *userdata;
	uid_t owner;
	struct fuse_conn_info conn;
	struct fuse_req list;
	struct fuse_req interrupts;
	pthread_mutex_t lock;
	int got_destroy;
	pthread_key_t pipe_key;
	int broken_splice_nonblock;
	uint64_t notify_ctr;
	struct fuse_notify_req notify_list;
};

struct fuse_chan *fuse_kern_chan_new(int fd);

int fuse_chan_clearfd(struct fuse_chan *ch);

/**
 * Create a new session
 *
 * @param data user data
 * @return new session object, or NULL on failure
 */
struct fuse_session *fuse_session_new(void *data);

/**
 * Get the user data provided to the session
 *
 * @param se the session
 * @return the user data
 */
void *fuse_session_data(struct fuse_session *se);

/**
 * Create a new channel
 *
 * @param op channel operations
 * @param fd file descriptor of the channel
 * @param bufsize the minimal receive buffer size
 * @return the new channel object, or NULL on failure
 */
struct fuse_chan *fuse_chan_new(struct fuse_chan_ops *op, int fd,
                               size_t bufsize);

/**
 * Query the session to which this channel is assigned
 *
 * @param ch the channel
 * @return the session, or NULL if the channel is not assigned
 */
struct fuse_session *fuse_chan_session(struct fuse_chan *ch);

/**
 * Send a raw reply
 *
 * A return value of -ENOENT means, that the request was
 * interrupted, and the reply was discarded
 *
 * @param ch the channel
 * @param iov vector of blocks
 * @param count the number of blocks in vector
 * @return zero on success, -errno on failure
 */
int fuse_chan_send(struct fuse_chan *ch, const struct iovec iov[],
		   size_t count);

/**
 * Receive a raw request
 *
 * A return value of -ENODEV means, that the filesystem was unmounted
 *
 * @param ch pointer to the channel
 * @param buf the buffer to store the request in
 * @param size the size of the buffer
 * @return the actual size of the raw request, or -errno on error
 */
int fuse_chan_recv(struct fuse_chan **ch, char *buf, size_t size);

void fuse_kern_unmount(const char *mountpoint, int fd);
int fuse_kern_mount(const char *mountpoint, struct fuse_args *args);

int fuse_send_reply_iov_nofree(fuse_req_t req, int error, struct iovec *iov,
			       int count);
void fuse_free_req(fuse_req_t req);

void cuse_lowlevel_init(fuse_req_t req, fuse_ino_t nodeide, const void *inarg);

int fuse_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg);
