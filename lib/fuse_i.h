/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt
*/

#ifndef LIB_FUSE_I_H_
#define LIB_FUSE_I_H_

#include "fuse.h"
#include "fuse_lowlevel.h"
#include "util.h"

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdatomic.h>

#define MIN(a, b) \
({									\
	typeof(a) _a = (a);						\
	typeof(b) _b = (b);						\
	_a < _b ? _a : _b;						\
})

struct mount_opts;
struct fuse_ring_pool;

struct fuse_req {
	struct fuse_session *se;
	uint64_t unique;
	_Atomic int ref_cnt;
	pthread_mutex_t lock;
	struct fuse_ctx ctx;
	struct fuse_chan *ch;
	int interrupted;
	struct {
		unsigned int ioctl_64bit : 1;
		unsigned int is_uring : 1;
		unsigned int is_copy_file_range_64 : 1;
	} flags;
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

struct fuse_session_uring {
	bool enable;
	unsigned int q_depth;
	struct fuse_ring_pool *pool;
};

struct fuse_session {
	_Atomic(char *)mountpoint;
	int fd;
	struct fuse_custom_io *io;
	struct mount_opts *mo;
	int debug;
	int deny_others;
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
	_Atomic size_t bufsize;
	int error;

	/*
	 * This is useful if any kind of ABI incompatibility is found at
	 * a later version, to 'fix' it at run time.
	 */
	struct libfuse_version version;

	/* thread synchronization */
	_Atomic bool mt_exited;
	pthread_mutex_t mt_lock;
	sem_t mt_finish;

	/* true if reading requests from /dev/fuse are handled internally */
	bool buf_reallocable;

	/* io_uring */
	struct fuse_session_uring uring;

	/*
	 * conn->want and conn_want_ext options set by libfuse , needed
	 * to correctly convert want to want_ext
	 */
	uint32_t conn_want;
	uint64_t conn_want_ext;
};

struct fuse_chan {
	pthread_mutex_t lock;
	int ctr;
	int fd;
};

/**
 * Filesystem module
 *
 * Filesystem modules are registered with the FUSE_REGISTER_MODULE()
 * macro.
 *
 */
struct fuse_module {
	char *name;
	fuse_module_factory_t factory;
	struct fuse_module *next;
	struct fusemod_so *so;
	int ctr;
};

/**
 * Configuration parameters passed to fuse_session_loop_mt() and
 * fuse_loop_mt().
 *
 * Internal API to avoid exposing the plain data structure and
 * causing compat issues after adding or removing struct members.
 *
 */
#if FUSE_USE_VERSION >= FUSE_MAKE_VERSION(3, 12)
struct fuse_loop_config
{
	/* verififier that a correct struct was was passed. This is especially
	 * needed, as versions below (3, 12) were using a public struct
	 * (now called  fuse_loop_config_v1), which was hard to extend with
	 * additional parameters, without risking that file system implementations
	 * would not have noticed and might either pass uninitialized members
	 * or even too small structs.
	 * fuse_loop_config_v1 has clone_fd at this offset, which should be either 0
	 * or 1. v2 or even higher version just need to set a value here
	 * which not conflicting and very unlikely as having been set by
	 * file system implementation.
	 */
	int version_id;

	/**
	 * whether to use separate device fds for each thread
	 * (may increase performance)
	 */
	int clone_fd;
	/**
	 * The maximum number of available worker threads before they
	 * start to get deleted when they become idle. If not
	 * specified, the default is 10.
	 *
	 * Adjusting this has performance implications; a very small number
	 * of threads in the pool will cause a lot of thread creation and
	 * deletion overhead and performance may suffer. When set to 0, a new
	 * thread will be created to service every operation.
	 * The special value of -1 means that this parameter is disabled.
	 */
	int max_idle_threads;

	/**
	 *  max number of threads taking and processing kernel requests
	 *
	 *  As of now threads are created dynamically
	 */
	unsigned int max_threads;
};
#endif

/* ----------------------------------------------------------- *
 * Channel interface (when using -o clone_fd)		       *
 * ----------------------------------------------------------- */

/**
 * Obtain counted reference to the channel
 *
 * @param ch the channel
 * @return the channel
 */
struct fuse_chan *fuse_chan_get(struct fuse_chan *ch);

/**
 * Drop counted reference to a channel
 *
 * @param ch the channel
 */
void fuse_chan_put(struct fuse_chan *ch);

struct mount_opts *parse_mount_opts(struct fuse_args *args);
void destroy_mount_opts(struct mount_opts *mo);
void fuse_mount_version(void);
unsigned get_max_read(struct mount_opts *o);
void fuse_kern_unmount(const char *mountpoint, int fd);
int fuse_kern_mount(const char *mountpoint, struct mount_opts *mo);

int fuse_send_reply_iov_nofree(fuse_req_t req, int error, struct iovec *iov,
			       int count);
void fuse_free_req(fuse_req_t req);
void list_init_req(struct fuse_req *req);

void _cuse_lowlevel_init(fuse_req_t req, const fuse_ino_t nodeid,
			 const void *req_header, const void *req_payload);
void cuse_lowlevel_init(fuse_req_t req, fuse_ino_t nodeide, const void *inarg);

int fuse_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg);

void fuse_buf_free(struct fuse_buf *buf);

int fuse_session_receive_buf_internal(struct fuse_session *se,
				      struct fuse_buf *buf,
				      struct fuse_chan *ch);
void fuse_session_process_buf_internal(struct fuse_session *se,
				       const struct fuse_buf *buf,
				       struct fuse_chan *ch);

struct fuse *fuse_new_31(struct fuse_args *args, const struct fuse_operations *op,
		      size_t op_size, void *private_data);
int fuse_loop_mt_312(struct fuse *f, struct fuse_loop_config *config);
int fuse_session_loop_mt_312(struct fuse_session *se, struct fuse_loop_config *config);

/**
 * Internal verifier for the given config.
 *
 * @return negative standard error code or 0 on success
 */
int fuse_loop_cfg_verify(struct fuse_loop_config *config);


/*
 * This can be changed dynamically on recent kernels through the
 * /proc/sys/fs/fuse/max_pages_limit interface.
 *
 * Older kernels will always use the default value.
 */
#define FUSE_DEFAULT_MAX_PAGES_LIMIT 256
#define FUSE_DEFAULT_MAX_PAGES_PER_REQ 32

/* room needed in buffer to accommodate header */
#define FUSE_BUFFER_HEADER_SIZE 0x1000


#endif /* LIB_FUSE_I_H_*/
