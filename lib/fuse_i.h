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

struct fuse_session {
	struct fuse_session_ops op;

	int (*receive_buf)(struct fuse_session *se, struct fuse_buf *buf,
			   struct fuse_chan **chp);

	void (*process_buf)(void *data, const struct fuse_buf *buf,
			    struct fuse_chan *ch);

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

struct fuse_cmd {
	char *buf;
	size_t buflen;
	struct fuse_chan *ch;
};

struct fuse *fuse_new_common(struct fuse_chan *ch, struct fuse_args *args,
			     const struct fuse_operations *op,
			     size_t op_size, void *user_data, int compat);

int fuse_sync_compat_args(struct fuse_args *args);

struct fuse_chan *fuse_kern_chan_new(int fd);

struct fuse_session *fuse_lowlevel_new_common(struct fuse_args *args,
					const struct fuse_lowlevel_ops *op,
					size_t op_size, void *userdata);

void fuse_kern_unmount_compat22(const char *mountpoint);
void fuse_kern_unmount(const char *mountpoint, int fd);
int fuse_kern_mount(const char *mountpoint, struct fuse_args *args);

int fuse_send_reply_iov_nofree(fuse_req_t req, int error, struct iovec *iov,
			       int count);
void fuse_free_req(fuse_req_t req);


struct fuse *fuse_setup_common(int argc, char *argv[],
			       const struct fuse_operations *op,
			       size_t op_size,
			       char **mountpoint,
			       int *multithreaded,
			       int *fd,
			       void *user_data,
			       int compat);

void cuse_lowlevel_init(fuse_req_t req, fuse_ino_t nodeide, const void *inarg);

int fuse_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg);
