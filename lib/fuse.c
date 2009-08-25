/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/


/* For pthread_rwlock_t */
#define _GNU_SOURCE

#include "fuse_i.h"
#include "fuse_lowlevel.h"
#include "fuse_opt.h"
#include "fuse_misc.h"
#include "fuse_common_compat.h"
#include "fuse_compat.h"
#include "fuse_kernel.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/time.h>

#define FUSE_DEFAULT_INTR_SIGNAL SIGUSR1

#define FUSE_UNKNOWN_INO 0xffffffff
#define OFFSET_MAX 0x7fffffffffffffffLL

struct fuse_config {
	unsigned int uid;
	unsigned int gid;
	unsigned int  umask;
	double entry_timeout;
	double negative_timeout;
	double attr_timeout;
	double ac_attr_timeout;
	int ac_attr_timeout_set;
	int noforget;
	int debug;
	int hard_remove;
	int use_ino;
	int readdir_ino;
	int set_mode;
	int set_uid;
	int set_gid;
	int direct_io;
	int kernel_cache;
	int auto_cache;
	int intr;
	int intr_signal;
	int help;
	char *modules;
};

struct fuse_fs {
	struct fuse_operations op;
	struct fuse_module *m;
	void *user_data;
	int compat;
	int debug;
};

struct fusemod_so {
	void *handle;
	int ctr;
};

struct lock_queue_element {
       struct lock_queue_element *next;
       pthread_cond_t cond;
};

struct fuse {
	struct fuse_session *se;
	struct node **name_table;
	size_t name_table_size;
	struct node **id_table;
	size_t id_table_size;
	fuse_ino_t ctr;
	unsigned int generation;
	unsigned int hidectr;
	pthread_mutex_t lock;
	struct fuse_config conf;
	int intr_installed;
	struct fuse_fs *fs;
	int nullpath_ok;
	int curr_ticket;
	struct lock_queue_element *lockq;
};

struct lock {
	int type;
	off_t start;
	off_t end;
	pid_t pid;
	uint64_t owner;
	struct lock *next;
};

struct node {
	struct node *name_next;
	struct node *id_next;
	fuse_ino_t nodeid;
	unsigned int generation;
	int refctr;
	struct node *parent;
	char *name;
	uint64_t nlookup;
	int open_count;
	struct timespec stat_updated;
	struct timespec mtime;
	off_t size;
	struct lock *locks;
	unsigned int is_hidden : 1;
	unsigned int cache_valid : 1;
	int treelock;
	int ticket;
};

struct fuse_dh {
	pthread_mutex_t lock;
	struct fuse *fuse;
	fuse_req_t req;
	char *contents;
	int allocated;
	unsigned len;
	unsigned size;
	unsigned needlen;
	int filled;
	uint64_t fh;
	int error;
	fuse_ino_t nodeid;
};

/* old dir handle */
struct fuse_dirhandle {
	fuse_fill_dir_t filler;
	void *buf;
};

struct fuse_context_i {
	struct fuse_context ctx;
	fuse_req_t req;
};

static pthread_key_t fuse_context_key;
static pthread_mutex_t fuse_context_lock = PTHREAD_MUTEX_INITIALIZER;
static int fuse_context_ref;
static struct fusemod_so *fuse_current_so;
static struct fuse_module *fuse_modules;

static int fuse_load_so_name(const char *soname)
{
	struct fusemod_so *so;

	so = calloc(1, sizeof(struct fusemod_so));
	if (!so) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		return -1;
	}

	fuse_current_so = so;
	so->handle = dlopen(soname, RTLD_NOW);
	fuse_current_so = NULL;
	if (!so->handle) {
		fprintf(stderr, "fuse: %s\n", dlerror());
		goto err;
	}
	if (!so->ctr) {
		fprintf(stderr, "fuse: %s did not register any modules\n",
			soname);
		goto err;
	}
	return 0;

err:
	if (so->handle)
		dlclose(so->handle);
	free(so);
	return -1;
}

static int fuse_load_so_module(const char *module)
{
	int res;
	char *soname = malloc(strlen(module) + 64);
	if (!soname) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		return -1;
	}
	sprintf(soname, "libfusemod_%s.so", module);
	res = fuse_load_so_name(soname);
	free(soname);
	return res;
}

static struct fuse_module *fuse_find_module(const char *module)
{
	struct fuse_module *m;
	for (m = fuse_modules; m; m = m->next) {
		if (strcmp(module, m->name) == 0) {
			m->ctr++;
			break;
		}
	}
	return m;
}

static struct fuse_module *fuse_get_module(const char *module)
{
	struct fuse_module *m;

	pthread_mutex_lock(&fuse_context_lock);
	m = fuse_find_module(module);
	if (!m) {
		int err = fuse_load_so_module(module);
		if (!err)
			m = fuse_find_module(module);
	}
	pthread_mutex_unlock(&fuse_context_lock);
	return m;
}

static void fuse_put_module(struct fuse_module *m)
{
	pthread_mutex_lock(&fuse_context_lock);
	assert(m->ctr > 0);
	m->ctr--;
	if (!m->ctr && m->so) {
		struct fusemod_so *so = m->so;
		assert(so->ctr > 0);
		so->ctr--;
		if (!so->ctr) {
			struct fuse_module **mp;
			for (mp = &fuse_modules; *mp;) {
				if ((*mp)->so == so)
					*mp = (*mp)->next;
				else
					mp = &(*mp)->next;
			}
			dlclose(so->handle);
			free(so);
		}
	}
	pthread_mutex_unlock(&fuse_context_lock);
}

static struct node *get_node_nocheck(struct fuse *f, fuse_ino_t nodeid)
{
	size_t hash = nodeid % f->id_table_size;
	struct node *node;

	for (node = f->id_table[hash]; node != NULL; node = node->id_next)
		if (node->nodeid == nodeid)
			return node;

	return NULL;
}

static struct node *get_node(struct fuse *f, fuse_ino_t nodeid)
{
	struct node *node = get_node_nocheck(f, nodeid);
	if (!node) {
		fprintf(stderr, "fuse internal error: node %llu not found\n",
			(unsigned long long) nodeid);
		abort();
	}
	return node;
}

static void free_node(struct node *node)
{
	free(node->name);
	free(node);
}

static void unhash_id(struct fuse *f, struct node *node)
{
	size_t hash = node->nodeid % f->id_table_size;
	struct node **nodep = &f->id_table[hash];

	for (; *nodep != NULL; nodep = &(*nodep)->id_next)
		if (*nodep == node) {
			*nodep = node->id_next;
			return;
		}
}

static void hash_id(struct fuse *f, struct node *node)
{
	size_t hash = node->nodeid % f->id_table_size;
	node->id_next = f->id_table[hash];
	f->id_table[hash] = node;
}

static unsigned int name_hash(struct fuse *f, fuse_ino_t parent,
			      const char *name)
{
	unsigned int hash = *name;

	if (hash)
		for (name += 1; *name != '\0'; name++)
			hash = (hash << 5) - hash + *name;

	return (hash + parent) % f->name_table_size;
}

static void unref_node(struct fuse *f, struct node *node);

static void unhash_name(struct fuse *f, struct node *node)
{
	if (node->name) {
		size_t hash = name_hash(f, node->parent->nodeid, node->name);
		struct node **nodep = &f->name_table[hash];

		for (; *nodep != NULL; nodep = &(*nodep)->name_next)
			if (*nodep == node) {
				*nodep = node->name_next;
				node->name_next = NULL;
				unref_node(f, node->parent);
				free(node->name);
				node->name = NULL;
				node->parent = NULL;
				return;
			}
		fprintf(stderr,
			"fuse internal error: unable to unhash node: %llu\n",
			(unsigned long long) node->nodeid);
		abort();
	}
}

static int hash_name(struct fuse *f, struct node *node, fuse_ino_t parentid,
		     const char *name)
{
	size_t hash = name_hash(f, parentid, name);
	struct node *parent = get_node(f, parentid);
	node->name = strdup(name);
	if (node->name == NULL)
		return -1;

	parent->refctr ++;
	node->parent = parent;
	node->name_next = f->name_table[hash];
	f->name_table[hash] = node;
	return 0;
}

static void delete_node(struct fuse *f, struct node *node)
{
	if (f->conf.debug)
		fprintf(stderr, "DELETE: %llu\n",
			(unsigned long long) node->nodeid);

	assert(node->treelock == 0);
	assert(!node->name);
	unhash_id(f, node);
	free_node(node);
}

static void unref_node(struct fuse *f, struct node *node)
{
	assert(node->refctr > 0);
	node->refctr --;
	if (!node->refctr)
		delete_node(f, node);
}

static fuse_ino_t next_id(struct fuse *f)
{
	do {
		f->ctr = (f->ctr + 1) & 0xffffffff;
		if (!f->ctr)
			f->generation ++;
	} while (f->ctr == 0 || f->ctr == FUSE_UNKNOWN_INO ||
		 get_node_nocheck(f, f->ctr) != NULL);
	return f->ctr;
}

static struct node *lookup_node(struct fuse *f, fuse_ino_t parent,
				const char *name)
{
	size_t hash = name_hash(f, parent, name);
	struct node *node;

	for (node = f->name_table[hash]; node != NULL; node = node->name_next)
		if (node->parent->nodeid == parent &&
		    strcmp(node->name, name) == 0)
			return node;

	return NULL;
}

static struct node *find_node(struct fuse *f, fuse_ino_t parent,
			      const char *name)
{
	struct node *node;

	pthread_mutex_lock(&f->lock);
	if (!name)
		node = get_node(f, parent);
	else
		node = lookup_node(f, parent, name);
	if (node == NULL) {
		node = (struct node *) calloc(1, sizeof(struct node));
		if (node == NULL)
			goto out_err;

		if (f->conf.noforget)
			node->nlookup = 1;
		node->refctr = 1;
		node->nodeid = next_id(f);
		node->generation = f->generation;
		node->open_count = 0;
		node->is_hidden = 0;
		node->treelock = 0;
		node->ticket = 0;
		if (hash_name(f, node, parent, name) == -1) {
			free(node);
			node = NULL;
			goto out_err;
		}
		hash_id(f, node);
	}
	node->nlookup ++;
out_err:
	pthread_mutex_unlock(&f->lock);
	return node;
}

static char *add_name(char **buf, unsigned *bufsize, char *s, const char *name)
{
	size_t len = strlen(name);

	if (s - len <= *buf) {
		unsigned pathlen = *bufsize - (s - *buf);
		unsigned newbufsize = *bufsize;
		char *newbuf;

		while (newbufsize < pathlen + len + 1) {
			if (newbufsize >= 0x80000000)
				newbufsize = 0xffffffff;
			else
				newbufsize *= 2;
		}

		newbuf = realloc(*buf, newbufsize);
		if (newbuf == NULL)
			return NULL;

		*buf = newbuf;
		s = newbuf + newbufsize - pathlen;
		memmove(s, newbuf + *bufsize - pathlen, pathlen);
		*bufsize = newbufsize;
	}
	s -= len;
	strncpy(s, name, len);
	s--;
	*s = '/';

	return s;
}

static void unlock_path(struct fuse *f, fuse_ino_t nodeid, struct node *wnode,
			struct node *end, int ticket)
{
	struct node *node;

	if (wnode) {
		assert(wnode->treelock == -1);
		wnode->treelock = 0;
		if (!wnode->ticket)
			wnode->ticket = ticket;
	}

	for (node = get_node(f, nodeid);
	     node != end && node->nodeid != FUSE_ROOT_ID; node = node->parent) {
		assert(node->treelock > 0);
		node->treelock--;
		if (!node->ticket)
			node->ticket = ticket;
	}
}

static int try_get_path(struct fuse *f, fuse_ino_t nodeid, const char *name,
			char **path, struct node **wnodep, int ticket)
{
	unsigned bufsize = 256;
	char *buf;
	char *s;
	struct node *node;
	struct node *wnode = NULL;
	int err;

	*path = NULL;

	buf = malloc(bufsize);
	if (buf == NULL)
		return -ENOMEM;

	s = buf + bufsize - 1;
	*s = '\0';

	if (name != NULL) {
		s = add_name(&buf, &bufsize, s, name);
		err = -ENOMEM;
		if (s == NULL)
			goto out_free;
	}

	if (wnodep) {
		assert(ticket);
		wnode = lookup_node(f, nodeid, name);
		if (wnode) {
			if (wnode->treelock != 0 ||
			    (wnode->ticket && wnode->ticket != ticket)) {
				if (!wnode->ticket)
					wnode->ticket = ticket;
				err = -EAGAIN;
				goto out_free;
			}
			wnode->treelock = -1;
			wnode->ticket = 0;
		}
	}

	err = 0;
	for (node = get_node(f, nodeid); node->nodeid != FUSE_ROOT_ID;
	     node = node->parent) {
		err = -ENOENT;
		if (node->name == NULL || node->parent == NULL)
			goto out_unlock;

		err = -ENOMEM;
		s = add_name(&buf, &bufsize, s, node->name);
		if (s == NULL)
			goto out_unlock;

		if (ticket) {
			err = -EAGAIN;
			if (node->treelock == -1 ||
			    (node->ticket && node->ticket != ticket))
				goto out_unlock;

			node->treelock++;
			node->ticket = 0;
		}
	}

	if (s[0])
		memmove(buf, s, bufsize - (s - buf));
	else
		strcpy(buf, "/");

	*path = buf;
	if (wnodep)
		*wnodep = wnode;

	return 0;

 out_unlock:
	if (ticket)
		unlock_path(f, nodeid, wnode, node, ticket);
 out_free:
	free(buf);

	return err;
}

static void wake_up_first(struct fuse *f)
{
	if (f->lockq)
		pthread_cond_signal(&f->lockq->cond);
}

static void wake_up_next(struct lock_queue_element *qe)
{
	if (qe->next)
		pthread_cond_signal(&qe->next->cond);
}

static int get_ticket(struct fuse *f)
{
	do f->curr_ticket++;
	while (f->curr_ticket == 0);

	return f->curr_ticket;
}

static void debug_path(struct fuse *f, const char *msg, fuse_ino_t nodeid,
		       const char *name, int wr)
{
	if (f->conf.debug) {
		struct node *wnode = NULL;

		if (wr)
			wnode = lookup_node(f, nodeid, name);

		if (wnode)
			fprintf(stderr, "%s %li (w)\n",	msg, wnode->nodeid);
		else
			fprintf(stderr, "%s %li\n", msg, nodeid);
	}
}

static void queue_path(struct fuse *f, struct lock_queue_element *qe,
		       fuse_ino_t nodeid, const char *name, int wr)
{
	struct lock_queue_element **qp;

	debug_path(f, "QUEUE PATH", nodeid, name, wr);
	pthread_cond_init(&qe->cond, NULL);
	qe->next = NULL;
	for (qp = &f->lockq; *qp != NULL; qp = &(*qp)->next);
	*qp = qe;
}

static void dequeue_path(struct fuse *f, struct lock_queue_element *qe,
			 fuse_ino_t nodeid, const char *name, int wr)
{
	struct lock_queue_element **qp;

	debug_path(f, "DEQUEUE PATH", nodeid, name, wr);
	pthread_cond_destroy(&qe->cond);
	for (qp = &f->lockq; *qp != qe; qp = &(*qp)->next);
	*qp = qe->next;
}

static void wait_on_path(struct fuse *f, struct lock_queue_element *qe,
			 fuse_ino_t nodeid, const char *name, int wr)
{
	debug_path(f, "WAIT ON PATH", nodeid, name, wr);
	pthread_cond_wait(&qe->cond, &f->lock);
}

static int get_path_common(struct fuse *f, fuse_ino_t nodeid, const char *name,
			   char **path, struct node **wnode)
{
	int err;
	int ticket;

	pthread_mutex_lock(&f->lock);
	ticket = get_ticket(f);
	err = try_get_path(f, nodeid, name, path, wnode, ticket);
	if (err == -EAGAIN) {
		struct lock_queue_element qe;

		queue_path(f, &qe, nodeid, name, !!wnode);
		do {
			wait_on_path(f, &qe, nodeid, name, !!wnode);
			err = try_get_path(f, nodeid, name, path, wnode,
					   ticket);
			wake_up_next(&qe);
		} while (err == -EAGAIN);
		dequeue_path(f, &qe, nodeid, name, !!wnode);
	}
	pthread_mutex_unlock(&f->lock);

	return err;
}

static int get_path(struct fuse *f, fuse_ino_t nodeid, char **path)
{
	return get_path_common(f, nodeid, NULL, path, NULL);
}

static int get_path_nullok(struct fuse *f, fuse_ino_t nodeid, char **path)
{
	int err = get_path_common(f, nodeid, NULL, path, NULL);

	if (err == -ENOENT && f->nullpath_ok)
		err = 0;

	return err;
}

static int get_path_name(struct fuse *f, fuse_ino_t nodeid, const char *name,
			 char **path)
{
	return get_path_common(f, nodeid, name, path, NULL);
}

static int get_path_wrlock(struct fuse *f, fuse_ino_t nodeid, const char *name,
			   char **path, struct node **wnode)
{
	return get_path_common(f, nodeid, name, path, wnode);
}

static int try_get_path2(struct fuse *f, fuse_ino_t nodeid1, const char *name1,
			 fuse_ino_t nodeid2, const char *name2,
			 char **path1, char **path2,
			 struct node **wnode1, struct node **wnode2,
			 int ticket)
{
	int err;

	/* FIXME: locking two paths needs deadlock checking */
	err = try_get_path(f, nodeid1, name1, path1, wnode1, ticket);
	if (!err) {
		err = try_get_path(f, nodeid2, name2, path2, wnode2, ticket);
		if (err)
			unlock_path(f, nodeid1, wnode1 ? *wnode1 : NULL, NULL,
				    ticket);
	}
	return err;
}

static int get_path2(struct fuse *f, fuse_ino_t nodeid1, const char *name1,
		     fuse_ino_t nodeid2, const char *name2,
		     char **path1, char **path2,
		     struct node **wnode1, struct node **wnode2)
{
	int err;
	int ticket;

	pthread_mutex_lock(&f->lock);
	ticket = get_ticket(f);
	err = try_get_path2(f, nodeid1, name1, nodeid2, name2,
			    path1, path2, wnode1, wnode2, ticket);
	if (err == -EAGAIN) {
		struct lock_queue_element qe;

		queue_path(f, &qe, nodeid1, name1, !!wnode1);
		debug_path(f, "      path2", nodeid2, name2, !!wnode2);
		do {
			wait_on_path(f, &qe, nodeid1, name1, !!wnode1);
			debug_path(f, "        path2", nodeid2, name2, !!wnode2);
			err = try_get_path2(f, nodeid1, name1, nodeid2, name2,
					    path1, path2, wnode1, wnode2,
					    ticket);
			wake_up_next(&qe);
		} while (err == -EAGAIN);
		dequeue_path(f, &qe, nodeid1, name1, !!wnode1);
		debug_path(f, "        path2", nodeid2, name2, !!wnode2);
	}
	pthread_mutex_unlock(&f->lock);

	return err;
}

static void free_path_wrlock(struct fuse *f, fuse_ino_t nodeid,
			     struct node *wnode, char *path)
{
	pthread_mutex_lock(&f->lock);
	unlock_path(f, nodeid, wnode, NULL, 0);
	wake_up_first(f);
	pthread_mutex_unlock(&f->lock);
	free(path);
}

static void free_path(struct fuse *f, fuse_ino_t nodeid, char *path)
{
	if (path)
		free_path_wrlock(f, nodeid, NULL, path);
}

static void free_path2(struct fuse *f, fuse_ino_t nodeid1, fuse_ino_t nodeid2,
		       struct node *wnode1, struct node *wnode2,
		       char *path1, char *path2)
{
	pthread_mutex_lock(&f->lock);
	unlock_path(f, nodeid1, wnode1, NULL, 0);
	unlock_path(f, nodeid2, wnode2, NULL, 0);
	wake_up_first(f);
	pthread_mutex_unlock(&f->lock);
	free(path1);
	free(path2);
}

static void forget_node(struct fuse *f, fuse_ino_t nodeid, uint64_t nlookup)
{
	struct node *node;
	if (nodeid == FUSE_ROOT_ID)
		return;
	pthread_mutex_lock(&f->lock);
	node = get_node(f, nodeid);

	/*
	 * Node may still be locked due to interrupt idiocy in open,
	 * create and opendir
	 */
	while (node->nlookup == nlookup && node->treelock) {
		struct lock_queue_element qe;

		queue_path(f, &qe, node->nodeid, NULL, 0);
		do {
			wait_on_path(f, &qe, node->nodeid, NULL, 0);
			wake_up_next(&qe);

		} while (node->nlookup == nlookup && node->treelock);
		dequeue_path(f, &qe, node->nodeid, NULL, 0);
	}

	assert(node->nlookup >= nlookup);
	node->nlookup -= nlookup;
	if (!node->nlookup) {
		unhash_name(f, node);
		unref_node(f, node);
	}
	pthread_mutex_unlock(&f->lock);
}

static void unlink_node(struct fuse *f, struct node *node)
{
	if (f->conf.noforget) {
		assert(node->nlookup > 1);
		node->nlookup--;
	}
	unhash_name(f, node);
}

static void remove_node(struct fuse *f, fuse_ino_t dir, const char *name)
{
	struct node *node;

	pthread_mutex_lock(&f->lock);
	node = lookup_node(f, dir, name);
	if (node != NULL)
		unlink_node(f, node);
	pthread_mutex_unlock(&f->lock);
}

static int rename_node(struct fuse *f, fuse_ino_t olddir, const char *oldname,
		       fuse_ino_t newdir, const char *newname, int hide)
{
	struct node *node;
	struct node *newnode;
	int err = 0;

	pthread_mutex_lock(&f->lock);
	node  = lookup_node(f, olddir, oldname);
	newnode	 = lookup_node(f, newdir, newname);
	if (node == NULL)
		goto out;

	if (newnode != NULL) {
		if (hide) {
			fprintf(stderr, "fuse: hidden file got created during hiding\n");
			err = -EBUSY;
			goto out;
		}
		unlink_node(f, newnode);
	}

	unhash_name(f, node);
	if (hash_name(f, node, newdir, newname) == -1) {
		err = -ENOMEM;
		goto out;
	}

	if (hide)
		node->is_hidden = 1;

out:
	pthread_mutex_unlock(&f->lock);
	return err;
}

static void set_stat(struct fuse *f, fuse_ino_t nodeid, struct stat *stbuf)
{
	if (!f->conf.use_ino)
		stbuf->st_ino = nodeid;
	if (f->conf.set_mode)
		stbuf->st_mode = (stbuf->st_mode & S_IFMT) |
				 (0777 & ~f->conf.umask);
	if (f->conf.set_uid)
		stbuf->st_uid = f->conf.uid;
	if (f->conf.set_gid)
		stbuf->st_gid = f->conf.gid;
}

static struct fuse *req_fuse(fuse_req_t req)
{
	return (struct fuse *) fuse_req_userdata(req);
}

static void fuse_intr_sighandler(int sig)
{
	(void) sig;
	/* Nothing to do */
}

struct fuse_intr_data {
	pthread_t id;
	pthread_cond_t cond;
	int finished;
};

static void fuse_interrupt(fuse_req_t req, void *d_)
{
	struct fuse_intr_data *d = d_;
	struct fuse *f = req_fuse(req);

	if (d->id == pthread_self())
		return;

	pthread_mutex_lock(&f->lock);
	while (!d->finished) {
		struct timeval now;
		struct timespec timeout;

		pthread_kill(d->id, f->conf.intr_signal);
		gettimeofday(&now, NULL);
		timeout.tv_sec = now.tv_sec + 1;
		timeout.tv_nsec = now.tv_usec * 1000;
		pthread_cond_timedwait(&d->cond, &f->lock, &timeout);
	}
	pthread_mutex_unlock(&f->lock);
}

static void fuse_do_finish_interrupt(struct fuse *f, fuse_req_t req,
				     struct fuse_intr_data *d)
{
	pthread_mutex_lock(&f->lock);
	d->finished = 1;
	pthread_cond_broadcast(&d->cond);
	pthread_mutex_unlock(&f->lock);
	fuse_req_interrupt_func(req, NULL, NULL);
	pthread_cond_destroy(&d->cond);
}

static void fuse_do_prepare_interrupt(fuse_req_t req, struct fuse_intr_data *d)
{
	d->id = pthread_self();
	pthread_cond_init(&d->cond, NULL);
	d->finished = 0;
	fuse_req_interrupt_func(req, fuse_interrupt, d);
}

static inline void fuse_finish_interrupt(struct fuse *f, fuse_req_t req,
					 struct fuse_intr_data *d)
{
	if (f->conf.intr)
		fuse_do_finish_interrupt(f, req, d);
}

static inline void fuse_prepare_interrupt(struct fuse *f, fuse_req_t req,
					  struct fuse_intr_data *d)
{
	if (f->conf.intr)
		fuse_do_prepare_interrupt(req, d);
}

#ifndef __FreeBSD__

static int fuse_compat_open(struct fuse_fs *fs, const char *path,
			    struct fuse_file_info *fi)
{
	int err;
	if (!fs->compat || fs->compat >= 25)
		err = fs->op.open(path, fi);
	else if (fs->compat == 22) {
		struct fuse_file_info_compat tmp;
		memcpy(&tmp, fi, sizeof(tmp));
		err = ((struct fuse_operations_compat22 *) &fs->op)->open(path,
									  &tmp);
		memcpy(fi, &tmp, sizeof(tmp));
		fi->fh = tmp.fh;
	} else
		err = ((struct fuse_operations_compat2 *) &fs->op)
			->open(path, fi->flags);
	return err;
}

static int fuse_compat_release(struct fuse_fs *fs, const char *path,
			       struct fuse_file_info *fi)
{
	if (!fs->compat || fs->compat >= 22)
		return fs->op.release(path, fi);
	else
		return ((struct fuse_operations_compat2 *) &fs->op)
			->release(path, fi->flags);
}

static int fuse_compat_opendir(struct fuse_fs *fs, const char *path,
			       struct fuse_file_info *fi)
{
	if (!fs->compat || fs->compat >= 25)
		return fs->op.opendir(path, fi);
	else {
		int err;
		struct fuse_file_info_compat tmp;
		memcpy(&tmp, fi, sizeof(tmp));
		err = ((struct fuse_operations_compat22 *) &fs->op)
			->opendir(path, &tmp);
		memcpy(fi, &tmp, sizeof(tmp));
		fi->fh = tmp.fh;
		return err;
	}
}

static void convert_statfs_compat(struct fuse_statfs_compat1 *compatbuf,
				  struct statvfs *stbuf)
{
	stbuf->f_bsize	 = compatbuf->block_size;
	stbuf->f_blocks	 = compatbuf->blocks;
	stbuf->f_bfree	 = compatbuf->blocks_free;
	stbuf->f_bavail	 = compatbuf->blocks_free;
	stbuf->f_files	 = compatbuf->files;
	stbuf->f_ffree	 = compatbuf->files_free;
	stbuf->f_namemax = compatbuf->namelen;
}

static void convert_statfs_old(struct statfs *oldbuf, struct statvfs *stbuf)
{
	stbuf->f_bsize	 = oldbuf->f_bsize;
	stbuf->f_blocks	 = oldbuf->f_blocks;
	stbuf->f_bfree	 = oldbuf->f_bfree;
	stbuf->f_bavail	 = oldbuf->f_bavail;
	stbuf->f_files	 = oldbuf->f_files;
	stbuf->f_ffree	 = oldbuf->f_ffree;
	stbuf->f_namemax = oldbuf->f_namelen;
}

static int fuse_compat_statfs(struct fuse_fs *fs, const char *path,
			      struct statvfs *buf)
{
	int err;

	if (!fs->compat || fs->compat >= 25) {
		err = fs->op.statfs(fs->compat == 25 ? "/" : path, buf);
	} else if (fs->compat > 11) {
		struct statfs oldbuf;
		err = ((struct fuse_operations_compat22 *) &fs->op)
			->statfs("/", &oldbuf);
		if (!err)
			convert_statfs_old(&oldbuf, buf);
	} else {
		struct fuse_statfs_compat1 compatbuf;
		memset(&compatbuf, 0, sizeof(struct fuse_statfs_compat1));
		err = ((struct fuse_operations_compat1 *) &fs->op)
			->statfs(&compatbuf);
		if (!err)
			convert_statfs_compat(&compatbuf, buf);
	}
	return err;
}

#else /* __FreeBSD__ */

static inline int fuse_compat_open(struct fuse_fs *fs, char *path,
				   struct fuse_file_info *fi)
{
	return fs->op.open(path, fi);
}

static inline int fuse_compat_release(struct fuse_fs *fs, const char *path,
				      struct fuse_file_info *fi)
{
	return fs->op.release(path, fi);
}

static inline int fuse_compat_opendir(struct fuse_fs *fs, const char *path,
				      struct fuse_file_info *fi)
{
	return fs->op.opendir(path, fi);
}

static inline int fuse_compat_statfs(struct fuse_fs *fs, const char *path,
				     struct statvfs *buf)
{
	return fs->op.statfs(fs->compat == 25 ? "/" : path, buf);
}

#endif /* __FreeBSD__ */

int fuse_fs_getattr(struct fuse_fs *fs, const char *path, struct stat *buf)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.getattr) {
		if (fs->debug)
			fprintf(stderr, "getattr %s\n", path);

		return fs->op.getattr(path, buf);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_fgetattr(struct fuse_fs *fs, const char *path, struct stat *buf,
		     struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.fgetattr) {
		if (fs->debug)
			fprintf(stderr, "fgetattr[%llu] %s\n",
				(unsigned long long) fi->fh, path);

		return fs->op.fgetattr(path, buf, fi);
	} else if (path && fs->op.getattr) {
		if (fs->debug)
			fprintf(stderr, "getattr %s\n", path);

		return fs->op.getattr(path, buf);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_rename(struct fuse_fs *fs, const char *oldpath,
		   const char *newpath)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.rename) {
		if (fs->debug)
			fprintf(stderr, "rename %s %s\n", oldpath, newpath);

		return fs->op.rename(oldpath, newpath);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_unlink(struct fuse_fs *fs, const char *path)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.unlink) {
		if (fs->debug)
			fprintf(stderr, "unlink %s\n", path);

		return fs->op.unlink(path);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_rmdir(struct fuse_fs *fs, const char *path)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.rmdir) {
		if (fs->debug)
			fprintf(stderr, "rmdir %s\n", path);

		return fs->op.rmdir(path);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_symlink(struct fuse_fs *fs, const char *linkname, const char *path)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.symlink) {
		if (fs->debug)
			fprintf(stderr, "symlink %s %s\n", linkname, path);

		return fs->op.symlink(linkname, path);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_link(struct fuse_fs *fs, const char *oldpath, const char *newpath)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.link) {
		if (fs->debug)
			fprintf(stderr, "link %s %s\n", oldpath, newpath);

		return fs->op.link(oldpath, newpath);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_release(struct fuse_fs *fs,	 const char *path,
		    struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.release) {
		if (fs->debug)
			fprintf(stderr, "release%s[%llu] flags: 0x%x\n",
				fi->flush ? "+flush" : "",
				(unsigned long long) fi->fh, fi->flags);

		return fuse_compat_release(fs, path, fi);
	} else {
		return 0;
	}
}

int fuse_fs_opendir(struct fuse_fs *fs, const char *path,
		    struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.opendir) {
		int err;

		if (fs->debug)
			fprintf(stderr, "opendir flags: 0x%x %s\n", fi->flags,
				path);

		err = fuse_compat_opendir(fs, path, fi);

		if (fs->debug && !err)
			fprintf(stderr, "   opendir[%lli] flags: 0x%x %s\n",
				(unsigned long long) fi->fh, fi->flags, path);

		return err;
	} else {
		return 0;
	}
}

int fuse_fs_open(struct fuse_fs *fs, const char *path,
		 struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.open) {
		int err;

		if (fs->debug)
			fprintf(stderr, "open flags: 0x%x %s\n", fi->flags,
				path);

		err = fuse_compat_open(fs, path, fi);

		if (fs->debug && !err)
			fprintf(stderr, "   open[%lli] flags: 0x%x %s\n",
				(unsigned long long) fi->fh, fi->flags, path);

		return err;
	} else {
		return 0;
	}
}

int fuse_fs_read(struct fuse_fs *fs, const char *path, char *buf, size_t size,
		 off_t off, struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.read) {
		int res;

		if (fs->debug)
			fprintf(stderr,
				"read[%llu] %lu bytes from %llu flags: 0x%x\n",
				(unsigned long long) fi->fh,
				(unsigned long) size, (unsigned long long) off,
				fi->flags);

		res = fs->op.read(path, buf, size, off, fi);

		if (fs->debug && res >= 0)
			fprintf(stderr, "   read[%llu] %u bytes from %llu\n",
				(unsigned long long) fi->fh, res,
				(unsigned long long) off);
		if (res > (int) size)
			fprintf(stderr, "fuse: read too many bytes\n");

		return res;
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_write(struct fuse_fs *fs, const char *path, const char *buf,
		  size_t size, off_t off, struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.write) {
		int res;

		if (fs->debug)
			fprintf(stderr,
				"write%s[%llu] %lu bytes to %llu flags: 0x%x\n",
				fi->writepage ? "page" : "",
				(unsigned long long) fi->fh,
				(unsigned long) size, (unsigned long long) off,
				fi->flags);

		res = fs->op.write(path, buf, size, off, fi);

		if (fs->debug && res >= 0)
			fprintf(stderr, "   write%s[%llu] %u bytes to %llu\n",
				fi->writepage ? "page" : "",
				(unsigned long long) fi->fh, res,
				(unsigned long long) off);
		if (res > (int) size)
			fprintf(stderr, "fuse: wrote too many bytes\n");

		return res;
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_fsync(struct fuse_fs *fs, const char *path, int datasync,
		  struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.fsync) {
		if (fs->debug)
			fprintf(stderr, "fsync[%llu] datasync: %i\n",
				(unsigned long long) fi->fh, datasync);

		return fs->op.fsync(path, datasync, fi);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_fsyncdir(struct fuse_fs *fs, const char *path, int datasync,
		     struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.fsyncdir) {
		if (fs->debug)
			fprintf(stderr, "fsyncdir[%llu] datasync: %i\n",
				(unsigned long long) fi->fh, datasync);

		return fs->op.fsyncdir(path, datasync, fi);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_flush(struct fuse_fs *fs, const char *path,
		  struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.flush) {
		if (fs->debug)
			fprintf(stderr, "flush[%llu]\n",
				(unsigned long long) fi->fh);

		return fs->op.flush(path, fi);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_statfs(struct fuse_fs *fs, const char *path, struct statvfs *buf)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.statfs) {
		if (fs->debug)
			fprintf(stderr, "statfs %s\n", path);

		return fuse_compat_statfs(fs, path, buf);
	} else {
		buf->f_namemax = 255;
		buf->f_bsize = 512;
		return 0;
	}
}

int fuse_fs_releasedir(struct fuse_fs *fs, const char *path,
		       struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.releasedir) {
		if (fs->debug)
			fprintf(stderr, "releasedir[%llu] flags: 0x%x\n",
				(unsigned long long) fi->fh, fi->flags);

		return fs->op.releasedir(path, fi);
	} else {
		return 0;
	}
}

static int fill_dir_old(struct fuse_dirhandle *dh, const char *name, int type,
			ino_t ino)
{
	int res;
	struct stat stbuf;

	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_mode = type << 12;
	stbuf.st_ino = ino;

	res = dh->filler(dh->buf, name, &stbuf, 0);
	return res ? -ENOMEM : 0;
}

int fuse_fs_readdir(struct fuse_fs *fs, const char *path, void *buf,
		    fuse_fill_dir_t filler, off_t off,
		    struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.readdir) {
		if (fs->debug)
			fprintf(stderr, "readdir[%llu] from %llu\n",
				(unsigned long long) fi->fh,
				(unsigned long long) off);

		return fs->op.readdir(path, buf, filler, off, fi);
	} else if (fs->op.getdir) {
		struct fuse_dirhandle dh;

		if (fs->debug)
			fprintf(stderr, "getdir[%llu]\n",
				(unsigned long long) fi->fh);

		dh.filler = filler;
		dh.buf = buf;
		return fs->op.getdir(path, &dh, fill_dir_old);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_create(struct fuse_fs *fs, const char *path, mode_t mode,
		   struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.create) {
		int err;

		if (fs->debug)
			fprintf(stderr,
				"create flags: 0x%x %s 0%o umask=0%03o\n",
				fi->flags, path, mode,
				fuse_get_context()->umask);

		err = fs->op.create(path, mode, fi);

		if (fs->debug && !err)
			fprintf(stderr, "   create[%llu] flags: 0x%x %s\n",
				(unsigned long long) fi->fh, fi->flags, path);

		return err;
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_lock(struct fuse_fs *fs, const char *path,
		 struct fuse_file_info *fi, int cmd, struct flock *lock)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.lock) {
		if (fs->debug)
			fprintf(stderr, "lock[%llu] %s %s start: %llu len: %llu pid: %llu\n",
				(unsigned long long) fi->fh,
				(cmd == F_GETLK ? "F_GETLK" :
				 (cmd == F_SETLK ? "F_SETLK" :
				  (cmd == F_SETLKW ? "F_SETLKW" : "???"))),
				(lock->l_type == F_RDLCK ? "F_RDLCK" :
				 (lock->l_type == F_WRLCK ? "F_WRLCK" :
				  (lock->l_type == F_UNLCK ? "F_UNLCK" :
				   "???"))),
				(unsigned long long) lock->l_start,
				(unsigned long long) lock->l_len,
				(unsigned long long) lock->l_pid);

		return fs->op.lock(path, fi, cmd, lock);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_chown(struct fuse_fs *fs, const char *path, uid_t uid, gid_t gid)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.chown) {
		if (fs->debug)
			fprintf(stderr, "chown %s %lu %lu\n", path,
				(unsigned long) uid, (unsigned long) gid);

		return fs->op.chown(path, uid, gid);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_truncate(struct fuse_fs *fs, const char *path, off_t size)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.truncate) {
		if (fs->debug)
			fprintf(stderr, "truncate %s %llu\n", path,
				(unsigned long long) size);

		return fs->op.truncate(path, size);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_ftruncate(struct fuse_fs *fs, const char *path, off_t size,
		      struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.ftruncate) {
		if (fs->debug)
			fprintf(stderr, "ftruncate[%llu] %s %llu\n",
				(unsigned long long) fi->fh, path,
				(unsigned long long) size);

		return fs->op.ftruncate(path, size, fi);
	} else if (path && fs->op.truncate) {
		if (fs->debug)
			fprintf(stderr, "truncate %s %llu\n", path,
				(unsigned long long) size);

		return fs->op.truncate(path, size);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_utimens(struct fuse_fs *fs, const char *path,
		    const struct timespec tv[2])
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.utimens) {
		if (fs->debug)
			fprintf(stderr, "utimens %s %li.%09lu %li.%09lu\n",
				path, tv[0].tv_sec, tv[0].tv_nsec,
				tv[1].tv_sec, tv[1].tv_nsec);

		return fs->op.utimens(path, tv);
	} else if(fs->op.utime) {
		struct utimbuf buf;

		if (fs->debug)
			fprintf(stderr, "utime %s %li %li\n", path,
				tv[0].tv_sec, tv[1].tv_sec);

		buf.actime = tv[0].tv_sec;
		buf.modtime = tv[1].tv_sec;
		return fs->op.utime(path, &buf);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_access(struct fuse_fs *fs, const char *path, int mask)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.access) {
		if (fs->debug)
			fprintf(stderr, "access %s 0%o\n", path, mask);

		return fs->op.access(path, mask);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_readlink(struct fuse_fs *fs, const char *path, char *buf,
		     size_t len)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.readlink) {
		if (fs->debug)
			fprintf(stderr, "readlink %s %lu\n", path,
				(unsigned long) len);

		return fs->op.readlink(path, buf, len);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_mknod(struct fuse_fs *fs, const char *path, mode_t mode,
		  dev_t rdev)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.mknod) {
		if (fs->debug)
			fprintf(stderr, "mknod %s 0%o 0x%llx umask=0%03o\n",
				path, mode, (unsigned long long) rdev,
				fuse_get_context()->umask);

		return fs->op.mknod(path, mode, rdev);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_mkdir(struct fuse_fs *fs, const char *path, mode_t mode)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.mkdir) {
		if (fs->debug)
			fprintf(stderr, "mkdir %s 0%o umask=0%03o\n",
				path, mode, fuse_get_context()->umask);

		return fs->op.mkdir(path, mode);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_setxattr(struct fuse_fs *fs, const char *path, const char *name,
		     const char *value, size_t size, int flags)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.setxattr) {
		if (fs->debug)
			fprintf(stderr, "setxattr %s %s %lu 0x%x\n",
				path, name, (unsigned long) size, flags);

		return fs->op.setxattr(path, name, value, size, flags);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_getxattr(struct fuse_fs *fs, const char *path, const char *name,
		     char *value, size_t size)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.getxattr) {
		if (fs->debug)
			fprintf(stderr, "getxattr %s %s %lu\n",
				path, name, (unsigned long) size);

		return fs->op.getxattr(path, name, value, size);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_listxattr(struct fuse_fs *fs, const char *path, char *list,
		      size_t size)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.listxattr) {
		if (fs->debug)
			fprintf(stderr, "listxattr %s %lu\n",
				path, (unsigned long) size);

		return fs->op.listxattr(path, list, size);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_bmap(struct fuse_fs *fs, const char *path, size_t blocksize,
		 uint64_t *idx)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.bmap) {
		if (fs->debug)
			fprintf(stderr, "bmap %s blocksize: %lu index: %llu\n",
				path, (unsigned long) blocksize,
				(unsigned long long) *idx);

		return fs->op.bmap(path, blocksize, idx);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_removexattr(struct fuse_fs *fs, const char *path, const char *name)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.removexattr) {
		if (fs->debug)
			fprintf(stderr, "removexattr %s %s\n", path, name);

		return fs->op.removexattr(path, name);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_ioctl(struct fuse_fs *fs, const char *path, int cmd, void *arg,
		  struct fuse_file_info *fi, unsigned int flags, void *data)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.ioctl) {
		if (fs->debug)
			fprintf(stderr, "ioctl[%llu] 0x%x flags: 0x%x\n",
				(unsigned long long) fi->fh, cmd, flags);

		return fs->op.ioctl(path, cmd, arg, fi, flags, data);
	} else
		return -ENOSYS;
}

int fuse_fs_poll(struct fuse_fs *fs, const char *path,
		 struct fuse_file_info *fi, struct fuse_pollhandle *ph,
		 unsigned *reventsp)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.poll) {
		int res;

		if (fs->debug)
			fprintf(stderr, "poll[%llu] ph: %p\n",
				(unsigned long long) fi->fh, ph);

		res = fs->op.poll(path, fi, ph, reventsp);

		if (fs->debug && !res)
			fprintf(stderr, "   poll[%llu] revents: 0x%x\n",
				(unsigned long long) fi->fh, *reventsp);

		return res;
	} else
		return -ENOSYS;
}

static int is_open(struct fuse *f, fuse_ino_t dir, const char *name)
{
	struct node *node;
	int isopen = 0;
	pthread_mutex_lock(&f->lock);
	node = lookup_node(f, dir, name);
	if (node && node->open_count > 0)
		isopen = 1;
	pthread_mutex_unlock(&f->lock);
	return isopen;
}

static char *hidden_name(struct fuse *f, fuse_ino_t dir, const char *oldname,
			 char *newname, size_t bufsize)
{
	struct stat buf;
	struct node *node;
	struct node *newnode;
	char *newpath;
	int res;
	int failctr = 10;

	do {
		pthread_mutex_lock(&f->lock);
		node = lookup_node(f, dir, oldname);
		if (node == NULL) {
			pthread_mutex_unlock(&f->lock);
			return NULL;
		}
		do {
			f->hidectr ++;
			snprintf(newname, bufsize, ".fuse_hidden%08x%08x",
				 (unsigned int) node->nodeid, f->hidectr);
			newnode = lookup_node(f, dir, newname);
		} while(newnode);

		try_get_path(f, dir, newname, &newpath, NULL, 0);
		pthread_mutex_unlock(&f->lock);

		if (!newpath)
			break;

		res = fuse_fs_getattr(f->fs, newpath, &buf);
		if (res == -ENOENT)
			break;
		free(newpath);
		newpath = NULL;
	} while(res == 0 && --failctr);

	return newpath;
}

static int hide_node(struct fuse *f, const char *oldpath,
		     fuse_ino_t dir, const char *oldname)
{
	char newname[64];
	char *newpath;
	int err = -EBUSY;

	newpath = hidden_name(f, dir, oldname, newname, sizeof(newname));
	if (newpath) {
		err = fuse_fs_rename(f->fs, oldpath, newpath);
		if (!err)
			err = rename_node(f, dir, oldname, dir, newname, 1);
		free(newpath);
	}
	return err;
}

static int mtime_eq(const struct stat *stbuf, const struct timespec *ts)
{
	return stbuf->st_mtime == ts->tv_sec &&
		ST_MTIM_NSEC(stbuf) == ts->tv_nsec;
}

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC CLOCK_REALTIME
#endif

static void curr_time(struct timespec *now)
{
	static clockid_t clockid = CLOCK_MONOTONIC;
	int res = clock_gettime(clockid, now);
	if (res == -1 && errno == EINVAL) {
		clockid = CLOCK_REALTIME;
		res = clock_gettime(clockid, now);
	}
	if (res == -1) {
		perror("fuse: clock_gettime");
		abort();
	}
}

static void update_stat(struct node *node, const struct stat *stbuf)
{
	if (node->cache_valid && (!mtime_eq(stbuf, &node->mtime) ||
				  stbuf->st_size != node->size))
		node->cache_valid = 0;
	node->mtime.tv_sec = stbuf->st_mtime;
	node->mtime.tv_nsec = ST_MTIM_NSEC(stbuf);
	node->size = stbuf->st_size;
	curr_time(&node->stat_updated);
}

static int lookup_path(struct fuse *f, fuse_ino_t nodeid,
		       const char *name, const char *path,
		       struct fuse_entry_param *e, struct fuse_file_info *fi)
{
	int res;

	memset(e, 0, sizeof(struct fuse_entry_param));
	if (fi)
		res = fuse_fs_fgetattr(f->fs, path, &e->attr, fi);
	else
		res = fuse_fs_getattr(f->fs, path, &e->attr);
	if (res == 0) {
		struct node *node;

		node = find_node(f, nodeid, name);
		if (node == NULL)
			res = -ENOMEM;
		else {
			e->ino = node->nodeid;
			e->generation = node->generation;
			e->entry_timeout = f->conf.entry_timeout;
			e->attr_timeout = f->conf.attr_timeout;
			if (f->conf.auto_cache) {
				pthread_mutex_lock(&f->lock);
				update_stat(node, &e->attr);
				pthread_mutex_unlock(&f->lock);
			}
			set_stat(f, e->ino, &e->attr);
			if (f->conf.debug)
				fprintf(stderr, "   NODEID: %lu\n",
					(unsigned long) e->ino);
		}
	}
	return res;
}

static struct fuse_context_i *fuse_get_context_internal(void)
{
	struct fuse_context_i *c;

	c = (struct fuse_context_i *) pthread_getspecific(fuse_context_key);
	if (c == NULL) {
		c = (struct fuse_context_i *)
			malloc(sizeof(struct fuse_context_i));
		if (c == NULL) {
			/* This is hard to deal with properly, so just
			   abort.  If memory is so low that the
			   context cannot be allocated, there's not
			   much hope for the filesystem anyway */
			fprintf(stderr, "fuse: failed to allocate thread specific data\n");
			abort();
		}
		pthread_setspecific(fuse_context_key, c);
	}
	return c;
}

static void fuse_freecontext(void *data)
{
	free(data);
}

static int fuse_create_context_key(void)
{
	int err = 0;
	pthread_mutex_lock(&fuse_context_lock);
	if (!fuse_context_ref) {
		err = pthread_key_create(&fuse_context_key, fuse_freecontext);
		if (err) {
			fprintf(stderr, "fuse: failed to create thread specific key: %s\n",
				strerror(err));
			pthread_mutex_unlock(&fuse_context_lock);
			return -1;
		}
	}
	fuse_context_ref++;
	pthread_mutex_unlock(&fuse_context_lock);
	return 0;
}

static void fuse_delete_context_key(void)
{
	pthread_mutex_lock(&fuse_context_lock);
	fuse_context_ref--;
	if (!fuse_context_ref) {
		free(pthread_getspecific(fuse_context_key));
		pthread_key_delete(fuse_context_key);
	}
	pthread_mutex_unlock(&fuse_context_lock);
}

static struct fuse *req_fuse_prepare(fuse_req_t req)
{
	struct fuse_context_i *c = fuse_get_context_internal();
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	c->req = req;
	c->ctx.fuse = req_fuse(req);
	c->ctx.uid = ctx->uid;
	c->ctx.gid = ctx->gid;
	c->ctx.pid = ctx->pid;
	c->ctx.umask = ctx->umask;
	return c->ctx.fuse;
}

static inline void reply_err(fuse_req_t req, int err)
{
	/* fuse_reply_err() uses non-negated errno values */
	fuse_reply_err(req, -err);
}

static void reply_entry(fuse_req_t req, const struct fuse_entry_param *e,
			int err)
{
	if (!err) {
		struct fuse *f = req_fuse(req);
		if (fuse_reply_entry(req, e) == -ENOENT) {
			/* Skip forget for negative result */
			if  (e->ino != 0)
				forget_node(f, e->ino, 1);
		}
	} else
		reply_err(req, err);
}

void fuse_fs_init(struct fuse_fs *fs, struct fuse_conn_info *conn)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.init)
		fs->user_data = fs->op.init(conn);
}

static void fuse_lib_init(void *data, struct fuse_conn_info *conn)
{
	struct fuse *f = (struct fuse *) data;
	struct fuse_context_i *c = fuse_get_context_internal();

	memset(c, 0, sizeof(*c));
	c->ctx.fuse = f;
	conn->want |= FUSE_CAP_EXPORT_SUPPORT;
	fuse_fs_init(f->fs, conn);
}

void fuse_fs_destroy(struct fuse_fs *fs)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.destroy)
		fs->op.destroy(fs->user_data);
	if (fs->m)
		fuse_put_module(fs->m);
	free(fs);
}

static void fuse_lib_destroy(void *data)
{
	struct fuse *f = (struct fuse *) data;
	struct fuse_context_i *c = fuse_get_context_internal();

	memset(c, 0, sizeof(*c));
	c->ctx.fuse = f;
	fuse_fs_destroy(f->fs);
	f->fs = NULL;
}

static void fuse_lib_lookup(fuse_req_t req, fuse_ino_t parent,
			    const char *name)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_entry_param e;
	char *path;
	int err;
	struct node *dot = NULL;

	if (name[0] == '.') {
		int len = strlen(name);

		if (len == 1 || (name[1] == '.' && len == 2)) {
			pthread_mutex_lock(&f->lock);
			if (len == 1) {
				if (f->conf.debug)
					fprintf(stderr, "LOOKUP-DOT\n");
				dot = get_node_nocheck(f, parent);
				if (dot == NULL) {
					pthread_mutex_unlock(&f->lock);
					reply_entry(req, &e, -ESTALE);
					return;
				}
				dot->refctr++;
			} else {
				if (f->conf.debug)
					fprintf(stderr, "LOOKUP-DOTDOT\n");
				parent = get_node(f, parent)->parent->nodeid;
			}
			pthread_mutex_unlock(&f->lock);
			name = NULL;
		}
	}

	err = get_path_name(f, parent, name, &path);
	if (!err) {
		struct fuse_intr_data d;
		if (f->conf.debug)
			fprintf(stderr, "LOOKUP %s\n", path);
		fuse_prepare_interrupt(f, req, &d);
		err = lookup_path(f, parent, name, path, &e, NULL);
		if (err == -ENOENT && f->conf.negative_timeout != 0.0) {
			e.ino = 0;
			e.entry_timeout = f->conf.negative_timeout;
			err = 0;
		}
		fuse_finish_interrupt(f, req, &d);
		free_path(f, parent, path);
	}
	if (dot) {
		pthread_mutex_lock(&f->lock);
		unref_node(f, dot);
		pthread_mutex_unlock(&f->lock);
	}
	reply_entry(req, &e, err);
}

static void fuse_lib_forget(fuse_req_t req, fuse_ino_t ino,
			    unsigned long nlookup)
{
	struct fuse *f = req_fuse(req);
	if (f->conf.debug)
		fprintf(stderr, "FORGET %llu/%lu\n", (unsigned long long)ino,
			nlookup);
	forget_node(f, ino, nlookup);
	fuse_reply_none(req);
}

static void fuse_lib_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct stat buf;
	char *path;
	int err;

	memset(&buf, 0, sizeof(buf));

	if (fi != NULL)
		err = get_path_nullok(f, ino, &path);
	else
		err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		if (fi)
			err = fuse_fs_fgetattr(f->fs, path, &buf, fi);
		else
			err = fuse_fs_getattr(f->fs, path, &buf);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	if (!err) {
		if (f->conf.auto_cache) {
			pthread_mutex_lock(&f->lock);
			update_stat(get_node(f, ino), &buf);
			pthread_mutex_unlock(&f->lock);
		}
		set_stat(f, ino, &buf);
		fuse_reply_attr(req, &buf, f->conf.attr_timeout);
	} else
		reply_err(req, err);
}

int fuse_fs_chmod(struct fuse_fs *fs, const char *path, mode_t mode)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.chmod)
		return fs->op.chmod(path, mode);
	else
		return -ENOSYS;
}

static void fuse_lib_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			     int valid, struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct stat buf;
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = 0;
		if (!err && (valid & FUSE_SET_ATTR_MODE))
			err = fuse_fs_chmod(f->fs, path, attr->st_mode);
		if (!err && (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID))) {
			uid_t uid = (valid & FUSE_SET_ATTR_UID) ?
				attr->st_uid : (uid_t) -1;
			gid_t gid = (valid & FUSE_SET_ATTR_GID) ?
				attr->st_gid : (gid_t) -1;
			err = fuse_fs_chown(f->fs, path, uid, gid);
		}
		if (!err && (valid & FUSE_SET_ATTR_SIZE)) {
			if (fi)
				err = fuse_fs_ftruncate(f->fs, path,
							attr->st_size, fi);
			else
				err = fuse_fs_truncate(f->fs, path,
						       attr->st_size);
		}
		if (!err &&
		    (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) ==
		    (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
			struct timespec tv[2];
			tv[0].tv_sec = attr->st_atime;
			tv[0].tv_nsec = ST_ATIM_NSEC(attr);
			tv[1].tv_sec = attr->st_mtime;
			tv[1].tv_nsec = ST_MTIM_NSEC(attr);
			err = fuse_fs_utimens(f->fs, path, tv);
		}
		if (!err)
			err = fuse_fs_getattr(f->fs,  path, &buf);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	if (!err) {
		if (f->conf.auto_cache) {
			pthread_mutex_lock(&f->lock);
			update_stat(get_node(f, ino), &buf);
			pthread_mutex_unlock(&f->lock);
		}
		set_stat(f, ino, &buf);
		fuse_reply_attr(req, &buf, f->conf.attr_timeout);
	} else
		reply_err(req, err);
}

static void fuse_lib_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_access(f->fs, path, mask);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	reply_err(req, err);
}

static void fuse_lib_readlink(fuse_req_t req, fuse_ino_t ino)
{
	struct fuse *f = req_fuse_prepare(req);
	char linkname[PATH_MAX + 1];
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_readlink(f->fs, path, linkname, sizeof(linkname));
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	if (!err) {
		linkname[PATH_MAX] = '\0';
		fuse_reply_readlink(req, linkname);
	} else
		reply_err(req, err);
}

static void fuse_lib_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
			   mode_t mode, dev_t rdev)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_entry_param e;
	char *path;
	int err;

	err = get_path_name(f, parent, name, &path);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = -ENOSYS;
		if (S_ISREG(mode)) {
			struct fuse_file_info fi;

			memset(&fi, 0, sizeof(fi));
			fi.flags = O_CREAT | O_EXCL | O_WRONLY;
			err = fuse_fs_create(f->fs, path, mode, &fi);
			if (!err) {
				err = lookup_path(f, parent, name, path, &e,
						  &fi);
				fuse_fs_release(f->fs, path, &fi);
			}
		}
		if (err == -ENOSYS) {
			err = fuse_fs_mknod(f->fs, path, mode, rdev);
			if (!err)
				err = lookup_path(f, parent, name, path, &e,
						  NULL);
		}
		fuse_finish_interrupt(f, req, &d);
		free_path(f, parent, path);
	}
	reply_entry(req, &e, err);
}

static void fuse_lib_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
			   mode_t mode)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_entry_param e;
	char *path;
	int err;

	err = get_path_name(f, parent, name, &path);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_mkdir(f->fs, path, mode);
		if (!err)
			err = lookup_path(f, parent, name, path, &e, NULL);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, parent, path);
	}
	reply_entry(req, &e, err);
}

static void fuse_lib_unlink(fuse_req_t req, fuse_ino_t parent,
			    const char *name)
{
	struct fuse *f = req_fuse_prepare(req);
	struct node *wnode;
	char *path;
	int err;

	err = get_path_wrlock(f, parent, name, &path, &wnode);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		if (!f->conf.hard_remove && is_open(f, parent, name)) {
			err = hide_node(f, path, parent, name);
		} else {
			err = fuse_fs_unlink(f->fs, path);
			if (!err)
				remove_node(f, parent, name);
		}
		fuse_finish_interrupt(f, req, &d);
		free_path_wrlock(f, parent, wnode, path);
	}
	reply_err(req, err);
}

static void fuse_lib_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse *f = req_fuse_prepare(req);
	struct node *wnode;
	char *path;
	int err;

	err = get_path_wrlock(f, parent, name, &path, &wnode);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_rmdir(f->fs, path);
		fuse_finish_interrupt(f, req, &d);
		if (!err)
			remove_node(f, parent, name);
		free_path_wrlock(f, parent, wnode, path);
	}
	reply_err(req, err);
}

static void fuse_lib_symlink(fuse_req_t req, const char *linkname,
			     fuse_ino_t parent, const char *name)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_entry_param e;
	char *path;
	int err;

	err = get_path_name(f, parent, name, &path);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_symlink(f->fs, linkname, path);
		if (!err)
			err = lookup_path(f, parent, name, path, &e, NULL);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, parent, path);
	}
	reply_entry(req, &e, err);
}

static void fuse_lib_rename(fuse_req_t req, fuse_ino_t olddir,
			    const char *oldname, fuse_ino_t newdir,
			    const char *newname)
{
	struct fuse *f = req_fuse_prepare(req);
	char *oldpath;
	char *newpath;
	struct node *wnode1;
	struct node *wnode2;
	int err;

	err = get_path2(f, olddir, oldname, newdir, newname,
			&oldpath, &newpath, &wnode1, &wnode2);
	if (!err) {
		struct fuse_intr_data d;
		err = 0;
		fuse_prepare_interrupt(f, req, &d);
		if (!f->conf.hard_remove && is_open(f, newdir, newname))
			err = hide_node(f, newpath, newdir, newname);
		if (!err) {
			err = fuse_fs_rename(f->fs, oldpath, newpath);
			if (!err)
				err = rename_node(f, olddir, oldname, newdir,
						  newname, 0);
		}
		fuse_finish_interrupt(f, req, &d);
		free_path2(f, olddir, newdir, wnode1, wnode2, oldpath, newpath);
	}
	reply_err(req, err);
}

static void fuse_lib_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
			  const char *newname)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_entry_param e;
	char *oldpath;
	char *newpath;
	int err;

	err = get_path2(f, ino, NULL, newparent, newname,
			&oldpath, &newpath, NULL, NULL);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_link(f->fs, oldpath, newpath);
		if (!err)
			err = lookup_path(f, newparent, newname, newpath,
					  &e, NULL);
		fuse_finish_interrupt(f, req, &d);
		free_path2(f, ino, newparent, NULL, NULL, oldpath, newpath);
	}
	reply_entry(req, &e, err);
}

static void fuse_do_release(struct fuse *f, fuse_ino_t ino, const char *path,
			    struct fuse_file_info *fi)
{
	struct node *node;
	int unlink_hidden = 0;

	fuse_fs_release(f->fs, (path || f->nullpath_ok) ? path : "-", fi);

	pthread_mutex_lock(&f->lock);
	node = get_node(f, ino);
	assert(node->open_count > 0);
	--node->open_count;
	if (node->is_hidden && !node->open_count) {
		unlink_hidden = 1;
		node->is_hidden = 0;
	}
	pthread_mutex_unlock(&f->lock);

	if(unlink_hidden && path)
		fuse_fs_unlink(f->fs, path);
}

static void fuse_lib_create(fuse_req_t req, fuse_ino_t parent,
			    const char *name, mode_t mode,
			    struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_entry_param e;
	char *path;
	int err;

	err = get_path_name(f, parent, name, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_create(f->fs, path, mode, fi);
		if (!err) {
			err = lookup_path(f, parent, name, path, &e, fi);
			if (err)
				fuse_fs_release(f->fs, path, fi);
			else if (!S_ISREG(e.attr.st_mode)) {
				err = -EIO;
				fuse_fs_release(f->fs, path, fi);
				forget_node(f, e.ino, 1);
			} else {
				if (f->conf.direct_io)
					fi->direct_io = 1;
				if (f->conf.kernel_cache)
					fi->keep_cache = 1;

			}
		}
		fuse_finish_interrupt(f, req, &d);
	}
	if (!err) {
		pthread_mutex_lock(&f->lock);
		get_node(f, e.ino)->open_count++;
		pthread_mutex_unlock(&f->lock);
		if (fuse_reply_create(req, &e, fi) == -ENOENT) {
			/* The open syscall was interrupted, so it
			   must be cancelled */
			fuse_prepare_interrupt(f, req, &d);
			fuse_do_release(f, e.ino, path, fi);
			fuse_finish_interrupt(f, req, &d);
			forget_node(f, e.ino, 1);
		}
	} else {
		reply_err(req, err);
	}

	free_path(f, parent, path);
}

static double diff_timespec(const struct timespec *t1,
			    const struct timespec *t2)
{
	return (t1->tv_sec - t2->tv_sec) +
		((double) t1->tv_nsec - (double) t2->tv_nsec) / 1000000000.0;
}

static void open_auto_cache(struct fuse *f, fuse_ino_t ino, const char *path,
			    struct fuse_file_info *fi)
{
	struct node *node;

	pthread_mutex_lock(&f->lock);
	node = get_node(f, ino);
	if (node->cache_valid) {
		struct timespec now;

		curr_time(&now);
		if (diff_timespec(&now, &node->stat_updated) >
		    f->conf.ac_attr_timeout) {
			struct stat stbuf;
			int err;
			pthread_mutex_unlock(&f->lock);
			err = fuse_fs_fgetattr(f->fs, path, &stbuf, fi);
			pthread_mutex_lock(&f->lock);
			if (!err)
				update_stat(node, &stbuf);
			else
				node->cache_valid = 0;
		}
	}
	if (node->cache_valid)
		fi->keep_cache = 1;

	node->cache_valid = 1;
	pthread_mutex_unlock(&f->lock);
}

static void fuse_lib_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_open(f->fs, path, fi);
		if (!err) {
			if (f->conf.direct_io)
				fi->direct_io = 1;
			if (f->conf.kernel_cache)
				fi->keep_cache = 1;

			if (f->conf.auto_cache)
				open_auto_cache(f, ino, path, fi);
		}
		fuse_finish_interrupt(f, req, &d);
	}
	if (!err) {
		pthread_mutex_lock(&f->lock);
		get_node(f, ino)->open_count++;
		pthread_mutex_unlock(&f->lock);
		if (fuse_reply_open(req, fi) == -ENOENT) {
			/* The open syscall was interrupted, so it
			   must be cancelled */
			fuse_prepare_interrupt(f, req, &d);
			fuse_do_release(f, ino, path, fi);
			fuse_finish_interrupt(f, req, &d);
		}
	} else
		reply_err(req, err);

	free_path(f, ino, path);
}

static void fuse_lib_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	char *buf;
	int res;

	buf = (char *) malloc(size);
	if (buf == NULL) {
		reply_err(req, -ENOMEM);
		return;
	}

	res = get_path_nullok(f, ino, &path);
	if (res == 0) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		res = fuse_fs_read(f->fs, path, buf, size, off, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}

	if (res >= 0)
		fuse_reply_buf(req, buf, res);
	else
		reply_err(req, res);

	free(buf);
}

static void fuse_lib_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			   size_t size, off_t off, struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int res;

	res = get_path_nullok(f, ino, &path);
	if (res == 0) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		res = fuse_fs_write(f->fs, path, buf, size, off, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}

	if (res >= 0)
		fuse_reply_write(req, res);
	else
		reply_err(req, res);
}

static void fuse_lib_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			   struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_fsync(f->fs, path, datasync, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	reply_err(req, err);
}

static struct fuse_dh *get_dirhandle(const struct fuse_file_info *llfi,
				     struct fuse_file_info *fi)
{
	struct fuse_dh *dh = (struct fuse_dh *) (uintptr_t) llfi->fh;
	memset(fi, 0, sizeof(struct fuse_file_info));
	fi->fh = dh->fh;
	fi->fh_old = dh->fh;
	return dh;
}

static void fuse_lib_opendir(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_dh *dh;
	struct fuse_file_info fi;
	char *path;
	int err;

	dh = (struct fuse_dh *) malloc(sizeof(struct fuse_dh));
	if (dh == NULL) {
		reply_err(req, -ENOMEM);
		return;
	}
	memset(dh, 0, sizeof(struct fuse_dh));
	dh->fuse = f;
	dh->contents = NULL;
	dh->len = 0;
	dh->filled = 0;
	dh->nodeid = ino;
	fuse_mutex_init(&dh->lock);

	llfi->fh = (uintptr_t) dh;

	memset(&fi, 0, sizeof(fi));
	fi.flags = llfi->flags;

	err = get_path(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_opendir(f->fs, path, &fi);
		fuse_finish_interrupt(f, req, &d);
		dh->fh = fi.fh;
	}
	if (!err) {
		if (fuse_reply_open(req, llfi) == -ENOENT) {
			/* The opendir syscall was interrupted, so it
			   must be cancelled */
			fuse_prepare_interrupt(f, req, &d);
			fuse_fs_releasedir(f->fs, path, &fi);
			fuse_finish_interrupt(f, req, &d);
			pthread_mutex_destroy(&dh->lock);
			free(dh);
		}
	} else {
		reply_err(req, err);
		pthread_mutex_destroy(&dh->lock);
		free(dh);
	}
	free_path(f, ino, path);
}

static int extend_contents(struct fuse_dh *dh, unsigned minsize)
{
	if (minsize > dh->size) {
		char *newptr;
		unsigned newsize = dh->size;
		if (!newsize)
			newsize = 1024;
		while (newsize < minsize) {
			if (newsize >= 0x80000000)
				newsize = 0xffffffff;
			else
				newsize *= 2;
		}

		newptr = (char *) realloc(dh->contents, newsize);
		if (!newptr) {
			dh->error = -ENOMEM;
			return -1;
		}
		dh->contents = newptr;
		dh->size = newsize;
	}
	return 0;
}

static int fill_dir(void *dh_, const char *name, const struct stat *statp,
		    off_t off)
{
	struct fuse_dh *dh = (struct fuse_dh *) dh_;
	struct stat stbuf;
	size_t newlen;

	if (statp)
		stbuf = *statp;
	else {
		memset(&stbuf, 0, sizeof(stbuf));
		stbuf.st_ino = FUSE_UNKNOWN_INO;
	}

	if (!dh->fuse->conf.use_ino) {
		stbuf.st_ino = FUSE_UNKNOWN_INO;
		if (dh->fuse->conf.readdir_ino) {
			struct node *node;
			pthread_mutex_lock(&dh->fuse->lock);
			node = lookup_node(dh->fuse, dh->nodeid, name);
			if (node)
				stbuf.st_ino  = (ino_t) node->nodeid;
			pthread_mutex_unlock(&dh->fuse->lock);
		}
	}

	if (off) {
		if (extend_contents(dh, dh->needlen) == -1)
			return 1;

		dh->filled = 0;
		newlen = dh->len +
			fuse_add_direntry(dh->req, dh->contents + dh->len,
					  dh->needlen - dh->len, name,
					  &stbuf, off);
		if (newlen > dh->needlen)
			return 1;
	} else {
		newlen = dh->len +
			fuse_add_direntry(dh->req, NULL, 0, name, NULL, 0);
		if (extend_contents(dh, newlen) == -1)
			return 1;

		fuse_add_direntry(dh->req, dh->contents + dh->len,
				  dh->size - dh->len, name, &stbuf, newlen);
	}
	dh->len = newlen;
	return 0;
}

static int readdir_fill(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
			size_t size, off_t off, struct fuse_dh *dh,
			struct fuse_file_info *fi)
{
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;

		dh->len = 0;
		dh->error = 0;
		dh->needlen = size;
		dh->filled = 1;
		dh->req = req;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_readdir(f->fs, path, dh, fill_dir, off, fi);
		fuse_finish_interrupt(f, req, &d);
		dh->req = NULL;
		if (!err)
			err = dh->error;
		if (err)
			dh->filled = 0;
		free_path(f, ino, path);
	}
	return err;
}

static void fuse_lib_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_file_info fi;
	struct fuse_dh *dh = get_dirhandle(llfi, &fi);

	pthread_mutex_lock(&dh->lock);
	/* According to SUS, directory contents need to be refreshed on
	   rewinddir() */
	if (!off)
		dh->filled = 0;

	if (!dh->filled) {
		int err = readdir_fill(f, req, ino, size, off, dh, &fi);
		if (err) {
			reply_err(req, err);
			goto out;
		}
	}
	if (dh->filled) {
		if (off < dh->len) {
			if (off + size > dh->len)
				size = dh->len - off;
		} else
			size = 0;
	} else {
		size = dh->len;
		off = 0;
	}
	fuse_reply_buf(req, dh->contents + off, size);
out:
	pthread_mutex_unlock(&dh->lock);
}

static void fuse_lib_releasedir(fuse_req_t req, fuse_ino_t ino,
				struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_file_info fi;
	struct fuse_dh *dh = get_dirhandle(llfi, &fi);
	char *path;

	get_path(f, ino, &path);
	fuse_prepare_interrupt(f, req, &d);
	fuse_fs_releasedir(f->fs, (path || f->nullpath_ok) ? path : "-", &fi);
	fuse_finish_interrupt(f, req, &d);
	free_path(f, ino, path);

	pthread_mutex_lock(&dh->lock);
	pthread_mutex_unlock(&dh->lock);
	pthread_mutex_destroy(&dh->lock);
	free(dh->contents);
	free(dh);
	reply_err(req, 0);
}

static void fuse_lib_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
			      struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_file_info fi;
	char *path;
	int err;

	get_dirhandle(llfi, &fi);

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_fsyncdir(f->fs, path, datasync, &fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	reply_err(req, err);
}

static void fuse_lib_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct fuse *f = req_fuse_prepare(req);
	struct statvfs buf;
	char *path = NULL;
	int err = 0;

	memset(&buf, 0, sizeof(buf));
	if (ino)
		err = get_path(f, ino, &path);

	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_statfs(f->fs, path ? path : "/", &buf);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}

	if (!err)
		fuse_reply_statfs(req, &buf);
	else
		reply_err(req, err);
}

static void fuse_lib_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			      const char *value, size_t size, int flags)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_setxattr(f->fs, path, name, value, size, flags);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	reply_err(req, err);
}

static int common_getxattr(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
			   const char *name, char *value, size_t size)
{
	int err;
	char *path;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_getxattr(f->fs, path, name, value, size);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	return err;
}

static void fuse_lib_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			      size_t size)
{
	struct fuse *f = req_fuse_prepare(req);
	int res;

	if (size) {
		char *value = (char *) malloc(size);
		if (value == NULL) {
			reply_err(req, -ENOMEM);
			return;
		}
		res = common_getxattr(f, req, ino, name, value, size);
		if (res > 0)
			fuse_reply_buf(req, value, res);
		else
			reply_err(req, res);
		free(value);
	} else {
		res = common_getxattr(f, req, ino, name, NULL, 0);
		if (res >= 0)
			fuse_reply_xattr(req, res);
		else
			reply_err(req, res);
	}
}

static int common_listxattr(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
			    char *list, size_t size)
{
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_listxattr(f->fs, path, list, size);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	return err;
}

static void fuse_lib_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	struct fuse *f = req_fuse_prepare(req);
	int res;

	if (size) {
		char *list = (char *) malloc(size);
		if (list == NULL) {
			reply_err(req, -ENOMEM);
			return;
		}
		res = common_listxattr(f, req, ino, list, size);
		if (res > 0)
			fuse_reply_buf(req, list, res);
		else
			reply_err(req, res);
		free(list);
	} else {
		res = common_listxattr(f, req, ino, NULL, 0);
		if (res >= 0)
			fuse_reply_xattr(req, res);
		else
			reply_err(req, res);
	}
}

static void fuse_lib_removexattr(fuse_req_t req, fuse_ino_t ino,
				 const char *name)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_removexattr(f->fs, path, name);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	reply_err(req, err);
}

static struct lock *locks_conflict(struct node *node, const struct lock *lock)
{
	struct lock *l;

	for (l = node->locks; l; l = l->next)
		if (l->owner != lock->owner &&
		    lock->start <= l->end && l->start <= lock->end &&
		    (l->type == F_WRLCK || lock->type == F_WRLCK))
			break;

	return l;
}

static void delete_lock(struct lock **lockp)
{
	struct lock *l = *lockp;
	*lockp = l->next;
	free(l);
}

static void insert_lock(struct lock **pos, struct lock *lock)
{
	lock->next = *pos;
	*pos = lock;
}

static int locks_insert(struct node *node, struct lock *lock)
{
	struct lock **lp;
	struct lock *newl1 = NULL;
	struct lock *newl2 = NULL;

	if (lock->type != F_UNLCK || lock->start != 0 ||
	    lock->end != OFFSET_MAX) {
		newl1 = malloc(sizeof(struct lock));
		newl2 = malloc(sizeof(struct lock));

		if (!newl1 || !newl2) {
			free(newl1);
			free(newl2);
			return -ENOLCK;
		}
	}

	for (lp = &node->locks; *lp;) {
		struct lock *l = *lp;
		if (l->owner != lock->owner)
			goto skip;

		if (lock->type == l->type) {
			if (l->end < lock->start - 1)
				goto skip;
			if (lock->end < l->start - 1)
				break;
			if (l->start <= lock->start && lock->end <= l->end)
				goto out;
			if (l->start < lock->start)
				lock->start = l->start;
			if (lock->end < l->end)
				lock->end = l->end;
			goto delete;
		} else {
			if (l->end < lock->start)
				goto skip;
			if (lock->end < l->start)
				break;
			if (lock->start <= l->start && l->end <= lock->end)
				goto delete;
			if (l->end <= lock->end) {
				l->end = lock->start - 1;
				goto skip;
			}
			if (lock->start <= l->start) {
				l->start = lock->end + 1;
				break;
			}
			*newl2 = *l;
			newl2->start = lock->end + 1;
			l->end = lock->start - 1;
			insert_lock(&l->next, newl2);
			newl2 = NULL;
		}
	skip:
		lp = &l->next;
		continue;

	delete:
		delete_lock(lp);
	}
	if (lock->type != F_UNLCK) {
		*newl1 = *lock;
		insert_lock(lp, newl1);
		newl1 = NULL;
	}
out:
	free(newl1);
	free(newl2);
	return 0;
}

static void flock_to_lock(struct flock *flock, struct lock *lock)
{
	memset(lock, 0, sizeof(struct lock));
	lock->type = flock->l_type;
	lock->start = flock->l_start;
	lock->end =
		flock->l_len ? flock->l_start + flock->l_len - 1 : OFFSET_MAX;
	lock->pid = flock->l_pid;
}

static void lock_to_flock(struct lock *lock, struct flock *flock)
{
	flock->l_type = lock->type;
	flock->l_start = lock->start;
	flock->l_len =
		(lock->end == OFFSET_MAX) ? 0 : lock->end - lock->start + 1;
	flock->l_pid = lock->pid;
}

static int fuse_flush_common(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
			     const char *path, struct fuse_file_info *fi)
{
	struct fuse_intr_data d;
	struct flock lock;
	struct lock l;
	int err;
	int errlock;

	fuse_prepare_interrupt(f, req, &d);
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	err = fuse_fs_flush(f->fs, path, fi);
	errlock = fuse_fs_lock(f->fs, path, fi, F_SETLK, &lock);
	fuse_finish_interrupt(f, req, &d);

	if (errlock != -ENOSYS) {
		flock_to_lock(&lock, &l);
		l.owner = fi->lock_owner;
		pthread_mutex_lock(&f->lock);
		locks_insert(get_node(f, ino), &l);
		pthread_mutex_unlock(&f->lock);

		/* if op.lock() is defined FLUSH is needed regardless
		   of op.flush() */
		if (err == -ENOSYS)
			err = 0;
	}
	return err;
}

static void fuse_lib_release(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int err = 0;

	get_path(f, ino, &path);
	if (fi->flush) {
		err = fuse_flush_common(f, req, ino, path, fi);
		if (err == -ENOSYS)
			err = 0;
	}

	fuse_prepare_interrupt(f, req, &d);
	fuse_do_release(f, ino, path, fi);
	fuse_finish_interrupt(f, req, &d);
	free_path(f, ino, path);

	reply_err(req, err);
}

static void fuse_lib_flush(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	get_path(f, ino, &path);
	err = fuse_flush_common(f, req, ino, path, fi);
	free_path(f, ino, path);

	reply_err(req, err);
}

static int fuse_lock_common(fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi, struct flock *lock,
			    int cmd)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_lock(f->fs, path, fi, cmd, lock);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	return err;
}

static void fuse_lib_getlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock)
{
	int err;
	struct lock l;
	struct lock *conflict;
	struct fuse *f = req_fuse(req);

	flock_to_lock(lock, &l);
	l.owner = fi->lock_owner;
	pthread_mutex_lock(&f->lock);
	conflict = locks_conflict(get_node(f, ino), &l);
	if (conflict)
		lock_to_flock(conflict, lock);
	pthread_mutex_unlock(&f->lock);
	if (!conflict)
		err = fuse_lock_common(req, ino, fi, lock, F_GETLK);
	else
		err = 0;

	if (!err)
		fuse_reply_lock(req, lock);
	else
		reply_err(req, err);
}

static void fuse_lib_setlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock,
			   int sleep)
{
	int err = fuse_lock_common(req, ino, fi, lock,
				   sleep ? F_SETLKW : F_SETLK);
	if (!err) {
		struct fuse *f = req_fuse(req);
		struct lock l;
		flock_to_lock(lock, &l);
		l.owner = fi->lock_owner;
		pthread_mutex_lock(&f->lock);
		locks_insert(get_node(f, ino), &l);
		pthread_mutex_unlock(&f->lock);
	}
	reply_err(req, err);
}

static void fuse_lib_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize,
			  uint64_t idx)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_bmap(f->fs, path, blocksize, &idx);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	if (!err)
		fuse_reply_bmap(req, idx);
	else
		reply_err(req, err);
}

static void fuse_lib_ioctl(fuse_req_t req, fuse_ino_t ino, int cmd, void *arg,
			   struct fuse_file_info *fi, unsigned int flags,
			   const void *in_buf, size_t in_bufsz,
			   size_t out_bufsz)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path, *out_buf = NULL;
	int err;

	err = -EPERM;
	if (flags & FUSE_IOCTL_UNRESTRICTED)
		goto err;

	if (out_bufsz) {
		err = -ENOMEM;
		out_buf = malloc(out_bufsz);
		if (!out_buf)
			goto err;
	}

	assert(!in_bufsz || !out_bufsz || in_bufsz == out_bufsz);
	if (out_buf)
		memcpy(out_buf, in_buf, in_bufsz);

	err = get_path(f, ino, &path);
	if (err)
		goto err;

	fuse_prepare_interrupt(f, req, &d);

	err = fuse_fs_ioctl(f->fs, path, cmd, arg, fi, flags,
			    out_buf ?: (void *)in_buf);

	fuse_finish_interrupt(f, req, &d);
	free_path(f, ino, path);

	fuse_reply_ioctl(req, err, out_buf, out_bufsz);
	goto out;
err:
	reply_err(req, err);
out:
	free(out_buf);
}

static void fuse_lib_poll(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi, struct fuse_pollhandle *ph)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int ret;
	unsigned revents = 0;

	ret = get_path(f, ino, &path);
	if (!ret) {
		fuse_prepare_interrupt(f, req, &d);
		ret = fuse_fs_poll(f->fs, path, fi, ph, &revents);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	if (!ret)
		fuse_reply_poll(req, revents);
	else
		reply_err(req, ret);
}

static struct fuse_lowlevel_ops fuse_path_ops = {
	.init = fuse_lib_init,
	.destroy = fuse_lib_destroy,
	.lookup = fuse_lib_lookup,
	.forget = fuse_lib_forget,
	.getattr = fuse_lib_getattr,
	.setattr = fuse_lib_setattr,
	.access = fuse_lib_access,
	.readlink = fuse_lib_readlink,
	.mknod = fuse_lib_mknod,
	.mkdir = fuse_lib_mkdir,
	.unlink = fuse_lib_unlink,
	.rmdir = fuse_lib_rmdir,
	.symlink = fuse_lib_symlink,
	.rename = fuse_lib_rename,
	.link = fuse_lib_link,
	.create = fuse_lib_create,
	.open = fuse_lib_open,
	.read = fuse_lib_read,
	.write = fuse_lib_write,
	.flush = fuse_lib_flush,
	.release = fuse_lib_release,
	.fsync = fuse_lib_fsync,
	.opendir = fuse_lib_opendir,
	.readdir = fuse_lib_readdir,
	.releasedir = fuse_lib_releasedir,
	.fsyncdir = fuse_lib_fsyncdir,
	.statfs = fuse_lib_statfs,
	.setxattr = fuse_lib_setxattr,
	.getxattr = fuse_lib_getxattr,
	.listxattr = fuse_lib_listxattr,
	.removexattr = fuse_lib_removexattr,
	.getlk = fuse_lib_getlk,
	.setlk = fuse_lib_setlk,
	.bmap = fuse_lib_bmap,
	.ioctl = fuse_lib_ioctl,
	.poll = fuse_lib_poll,
};

int fuse_notify_poll(struct fuse_pollhandle *ph)
{
	return fuse_lowlevel_notify_poll(ph);
}

static void free_cmd(struct fuse_cmd *cmd)
{
	free(cmd->buf);
	free(cmd);
}

void fuse_process_cmd(struct fuse *f, struct fuse_cmd *cmd)
{
	fuse_session_process(f->se, cmd->buf, cmd->buflen, cmd->ch);
	free_cmd(cmd);
}

int fuse_exited(struct fuse *f)
{
	return fuse_session_exited(f->se);
}

struct fuse_session *fuse_get_session(struct fuse *f)
{
	return f->se;
}

static struct fuse_cmd *fuse_alloc_cmd(size_t bufsize)
{
	struct fuse_cmd *cmd = (struct fuse_cmd *) malloc(sizeof(*cmd));
	if (cmd == NULL) {
		fprintf(stderr, "fuse: failed to allocate cmd\n");
		return NULL;
	}
	cmd->buf = (char *) malloc(bufsize);
	if (cmd->buf == NULL) {
		fprintf(stderr, "fuse: failed to allocate read buffer\n");
		free(cmd);
		return NULL;
	}
	return cmd;
}

struct fuse_cmd *fuse_read_cmd(struct fuse *f)
{
	struct fuse_chan *ch = fuse_session_next_chan(f->se, NULL);
	size_t bufsize = fuse_chan_bufsize(ch);
	struct fuse_cmd *cmd = fuse_alloc_cmd(bufsize);
	if (cmd != NULL) {
		int res = fuse_chan_recv(&ch, cmd->buf, bufsize);
		if (res <= 0) {
			free_cmd(cmd);
			if (res < 0 && res != -EINTR && res != -EAGAIN)
				fuse_exit(f);
			return NULL;
		}
		cmd->buflen = res;
		cmd->ch = ch;
	}
	return cmd;
}

int fuse_loop(struct fuse *f)
{
	if (f)
		return fuse_session_loop(f->se);
	else
		return -1;
}

int fuse_invalidate(struct fuse *f, const char *path)
{
	(void) f;
	(void) path;
	return -EINVAL;
}

void fuse_exit(struct fuse *f)
{
	fuse_session_exit(f->se);
}

struct fuse_context *fuse_get_context(void)
{
	return &fuse_get_context_internal()->ctx;
}

/*
 * The size of fuse_context got extended, so need to be careful about
 * incompatibility (i.e. a new binary cannot work with an old
 * library).
 */
struct fuse_context *fuse_get_context_compat22(void);
struct fuse_context *fuse_get_context_compat22(void)
{
	return &fuse_get_context_internal()->ctx;
}
FUSE_SYMVER(".symver fuse_get_context_compat22,fuse_get_context@FUSE_2.2");

int fuse_getgroups(int size, gid_t list[])
{
	fuse_req_t req = fuse_get_context_internal()->req;
	return fuse_req_getgroups(req, size, list);
}

int fuse_interrupted(void)
{
	return fuse_req_interrupted(fuse_get_context_internal()->req);
}

void fuse_set_getcontext_func(struct fuse_context *(*func)(void))
{
	(void) func;
	/* no-op */
}

enum {
	KEY_HELP,
};

#define FUSE_LIB_OPT(t, p, v) { t, offsetof(struct fuse_config, p), v }

static const struct fuse_opt fuse_lib_opts[] = {
	FUSE_OPT_KEY("-h",		      KEY_HELP),
	FUSE_OPT_KEY("--help",		      KEY_HELP),
	FUSE_OPT_KEY("debug",		      FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("-d",		      FUSE_OPT_KEY_KEEP),
	FUSE_LIB_OPT("debug",		      debug, 1),
	FUSE_LIB_OPT("-d",		      debug, 1),
	FUSE_LIB_OPT("hard_remove",	      hard_remove, 1),
	FUSE_LIB_OPT("use_ino",		      use_ino, 1),
	FUSE_LIB_OPT("readdir_ino",	      readdir_ino, 1),
	FUSE_LIB_OPT("direct_io",	      direct_io, 1),
	FUSE_LIB_OPT("kernel_cache",	      kernel_cache, 1),
	FUSE_LIB_OPT("auto_cache",	      auto_cache, 1),
	FUSE_LIB_OPT("noauto_cache",	      auto_cache, 0),
	FUSE_LIB_OPT("umask=",		      set_mode, 1),
	FUSE_LIB_OPT("umask=%o",	      umask, 0),
	FUSE_LIB_OPT("uid=",		      set_uid, 1),
	FUSE_LIB_OPT("uid=%d",		      uid, 0),
	FUSE_LIB_OPT("gid=",		      set_gid, 1),
	FUSE_LIB_OPT("gid=%d",		      gid, 0),
	FUSE_LIB_OPT("entry_timeout=%lf",     entry_timeout, 0),
	FUSE_LIB_OPT("attr_timeout=%lf",      attr_timeout, 0),
	FUSE_LIB_OPT("ac_attr_timeout=%lf",   ac_attr_timeout, 0),
	FUSE_LIB_OPT("ac_attr_timeout=",      ac_attr_timeout_set, 1),
	FUSE_LIB_OPT("negative_timeout=%lf",  negative_timeout, 0),
	FUSE_LIB_OPT("noforget",              noforget, 1),
	FUSE_LIB_OPT("intr",		      intr, 1),
	FUSE_LIB_OPT("intr_signal=%d",	      intr_signal, 0),
	FUSE_LIB_OPT("modules=%s",	      modules, 0),
	FUSE_OPT_END
};

static void fuse_lib_help(void)
{
	fprintf(stderr,
"    -o hard_remove         immediate removal (don't hide files)\n"
"    -o use_ino             let filesystem set inode numbers\n"
"    -o readdir_ino         try to fill in d_ino in readdir\n"
"    -o direct_io           use direct I/O\n"
"    -o kernel_cache        cache files in kernel\n"
"    -o [no]auto_cache      enable caching based on modification times (off)\n"
"    -o umask=M             set file permissions (octal)\n"
"    -o uid=N               set file owner\n"
"    -o gid=N               set file group\n"
"    -o entry_timeout=T     cache timeout for names (1.0s)\n"
"    -o negative_timeout=T  cache timeout for deleted names (0.0s)\n"
"    -o attr_timeout=T      cache timeout for attributes (1.0s)\n"
"    -o ac_attr_timeout=T   auto cache timeout for attributes (attr_timeout)\n"
"    -o intr                allow requests to be interrupted\n"
"    -o intr_signal=NUM     signal to send on interrupt (%i)\n"
"    -o modules=M1[:M2...]  names of modules to push onto filesystem stack\n"
"\n", FUSE_DEFAULT_INTR_SIGNAL);
}

static void fuse_lib_help_modules(void)
{
	struct fuse_module *m;
	fprintf(stderr, "\nModule options:\n");
	pthread_mutex_lock(&fuse_context_lock);
	for (m = fuse_modules; m; m = m->next) {
		struct fuse_fs *fs = NULL;
		struct fuse_fs *newfs;
		struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
		if (fuse_opt_add_arg(&args, "") != -1 &&
		    fuse_opt_add_arg(&args, "-h") != -1) {
			fprintf(stderr, "\n[%s]\n", m->name);
			newfs = m->factory(&args, &fs);
			assert(newfs == NULL);
		}
		fuse_opt_free_args(&args);
	}
	pthread_mutex_unlock(&fuse_context_lock);
}

static int fuse_lib_opt_proc(void *data, const char *arg, int key,
			     struct fuse_args *outargs)
{
	(void) arg; (void) outargs;

	if (key == KEY_HELP) {
		struct fuse_config *conf = (struct fuse_config *) data;
		fuse_lib_help();
		conf->help = 1;
	}

	return 1;
}

int fuse_is_lib_option(const char *opt)
{
	return fuse_lowlevel_is_lib_option(opt) ||
		fuse_opt_match(fuse_lib_opts, opt);
}

static int fuse_init_intr_signal(int signum, int *installed)
{
	struct sigaction old_sa;

	if (sigaction(signum, NULL, &old_sa) == -1) {
		perror("fuse: cannot get old signal handler");
		return -1;
	}

	if (old_sa.sa_handler == SIG_DFL) {
		struct sigaction sa;

		memset(&sa, 0, sizeof(struct sigaction));
		sa.sa_handler = fuse_intr_sighandler;
		sigemptyset(&sa.sa_mask);

		if (sigaction(signum, &sa, NULL) == -1) {
			perror("fuse: cannot set interrupt signal handler");
			return -1;
		}
		*installed = 1;
	}
	return 0;
}

static void fuse_restore_intr_signal(int signum)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = SIG_DFL;
	sigaction(signum, &sa, NULL);
}


static int fuse_push_module(struct fuse *f, const char *module,
			    struct fuse_args *args)
{
	struct fuse_fs *fs[2] = { f->fs, NULL };
	struct fuse_fs *newfs;
	struct fuse_module *m = fuse_get_module(module);

	if (!m)
		return -1;

	newfs = m->factory(args, fs);
	if (!newfs) {
		fuse_put_module(m);
		return -1;
	}
	newfs->m = m;
	f->fs = newfs;
	f->nullpath_ok = newfs->op.flag_nullpath_ok && f->nullpath_ok;
	return 0;
}

struct fuse_fs *fuse_fs_new(const struct fuse_operations *op, size_t op_size,
			    void *user_data)
{
	struct fuse_fs *fs;

	if (sizeof(struct fuse_operations) < op_size) {
		fprintf(stderr, "fuse: warning: library too old, some operations may not not work\n");
		op_size = sizeof(struct fuse_operations);
	}

	fs = (struct fuse_fs *) calloc(1, sizeof(struct fuse_fs));
	if (!fs) {
		fprintf(stderr, "fuse: failed to allocate fuse_fs object\n");
		return NULL;
	}

	fs->user_data = user_data;
	if (op)
		memcpy(&fs->op, op, op_size);
	return fs;
}

struct fuse *fuse_new_common(struct fuse_chan *ch, struct fuse_args *args,
			     const struct fuse_operations *op,
			     size_t op_size, void *user_data, int compat)
{
	struct fuse *f;
	struct node *root;
	struct fuse_fs *fs;
	struct fuse_lowlevel_ops llop = fuse_path_ops;

	if (fuse_create_context_key() == -1)
		goto out;

	f = (struct fuse *) calloc(1, sizeof(struct fuse));
	if (f == NULL) {
		fprintf(stderr, "fuse: failed to allocate fuse object\n");
		goto out_delete_context_key;
	}

	fs = fuse_fs_new(op, op_size, user_data);
	if (!fs)
		goto out_free;

	fs->compat = compat;
	f->fs = fs;
	f->nullpath_ok = fs->op.flag_nullpath_ok;

	/* Oh f**k, this is ugly! */
	if (!fs->op.lock) {
		llop.getlk = NULL;
		llop.setlk = NULL;
	}

	f->conf.entry_timeout = 1.0;
	f->conf.attr_timeout = 1.0;
	f->conf.negative_timeout = 0.0;
	f->conf.intr_signal = FUSE_DEFAULT_INTR_SIGNAL;

	if (fuse_opt_parse(args, &f->conf, fuse_lib_opts,
			   fuse_lib_opt_proc) == -1)
		goto out_free_fs;

	if (f->conf.modules) {
		char *module;
		char *next;

		for (module = f->conf.modules; module; module = next) {
			char *p;
			for (p = module; *p && *p != ':'; p++);
			next = *p ? p + 1 : NULL;
			*p = '\0';
			if (module[0] &&
			    fuse_push_module(f, module, args) == -1)
				goto out_free_fs;
		}
	}

	if (!f->conf.ac_attr_timeout_set)
		f->conf.ac_attr_timeout = f->conf.attr_timeout;

#ifdef __FreeBSD__
	/*
	 * In FreeBSD, we always use these settings as inode numbers
	 * are needed to make getcwd(3) work.
	 */
	f->conf.readdir_ino = 1;
#endif

	if (compat && compat <= 25) {
		if (fuse_sync_compat_args(args) == -1)
			goto out_free_fs;
	}

	f->se = fuse_lowlevel_new_common(args, &llop, sizeof(llop), f);
	if (f->se == NULL) {
		if (f->conf.help)
			fuse_lib_help_modules();
		goto out_free_fs;
	}

	fuse_session_add_chan(f->se, ch);

	if (f->conf.debug)
		fprintf(stderr, "nullpath_ok: %i\n", f->nullpath_ok);

	/* Trace topmost layer by default */
	f->fs->debug = f->conf.debug;
	f->ctr = 0;
	f->generation = 0;
	/* FIXME: Dynamic hash table */
	f->name_table_size = 14057;
	f->name_table = (struct node **)
		calloc(1, sizeof(struct node *) * f->name_table_size);
	if (f->name_table == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		goto out_free_session;
	}

	f->id_table_size = 14057;
	f->id_table = (struct node **)
		calloc(1, sizeof(struct node *) * f->id_table_size);
	if (f->id_table == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		goto out_free_name_table;
	}

	fuse_mutex_init(&f->lock);

	root = (struct node *) calloc(1, sizeof(struct node));
	if (root == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		goto out_free_id_table;
	}

	root->name = strdup("/");
	if (root->name == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		goto out_free_root;
	}

	if (f->conf.intr &&
	    fuse_init_intr_signal(f->conf.intr_signal,
				  &f->intr_installed) == -1)
		goto out_free_root_name;

	root->parent = NULL;
	root->nodeid = FUSE_ROOT_ID;
	root->generation = 0;
	root->refctr = 1;
	root->nlookup = 1;
	hash_id(f, root);

	return f;

out_free_root_name:
	free(root->name);
out_free_root:
	free(root);
out_free_id_table:
	free(f->id_table);
out_free_name_table:
	free(f->name_table);
out_free_session:
	fuse_session_destroy(f->se);
out_free_fs:
	/* Horrible compatibility hack to stop the destructor from being
	   called on the filesystem without init being called first */
	fs->op.destroy = NULL;
	fuse_fs_destroy(f->fs);
	free(f->conf.modules);
out_free:
	free(f);
out_delete_context_key:
	fuse_delete_context_key();
out:
	return NULL;
}

struct fuse *fuse_new(struct fuse_chan *ch, struct fuse_args *args,
		      const struct fuse_operations *op, size_t op_size,
		      void *user_data)
{
	return fuse_new_common(ch, args, op, op_size, user_data, 0);
}

void fuse_destroy(struct fuse *f)
{
	size_t i;

	if (f->conf.intr && f->intr_installed)
		fuse_restore_intr_signal(f->conf.intr_signal);

	if (f->fs) {
		struct fuse_context_i *c = fuse_get_context_internal();

		memset(c, 0, sizeof(*c));
		c->ctx.fuse = f;

		for (i = 0; i < f->id_table_size; i++) {
			struct node *node;

			for (node = f->id_table[i]; node != NULL;
			     node = node->id_next) {
				if (node->is_hidden) {
					char *path;
					if (try_get_path(f, node->nodeid, NULL, &path, NULL, 0) == 0) {
						fuse_fs_unlink(f->fs, path);
						free(path);
					}
				}
			}
		}
	}
	for (i = 0; i < f->id_table_size; i++) {
		struct node *node;
		struct node *next;

		for (node = f->id_table[i]; node != NULL; node = next) {
			next = node->id_next;
			free_node(node);
		}
	}
	free(f->id_table);
	free(f->name_table);
	pthread_mutex_destroy(&f->lock);
	fuse_session_destroy(f->se);
	free(f->conf.modules);
	free(f);
	fuse_delete_context_key();
}

static struct fuse *fuse_new_common_compat25(int fd, struct fuse_args *args,
					     const struct fuse_operations *op,
					     size_t op_size, int compat)
{
	struct fuse *f = NULL;
	struct fuse_chan *ch = fuse_kern_chan_new(fd);

	if (ch)
		f = fuse_new_common(ch, args, op, op_size, NULL, compat);

	return f;
}

/* called with fuse_context_lock held or during initialization (before
   main() has been called) */
void fuse_register_module(struct fuse_module *mod)
{
	mod->ctr = 0;
	mod->so = fuse_current_so;
	if (mod->so)
		mod->so->ctr++;
	mod->next = fuse_modules;
	fuse_modules = mod;
}

#ifndef __FreeBSD__

static struct fuse *fuse_new_common_compat(int fd, const char *opts,
					   const struct fuse_operations *op,
					   size_t op_size, int compat)
{
	struct fuse *f;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

	if (fuse_opt_add_arg(&args, "") == -1)
		return NULL;
	if (opts &&
	    (fuse_opt_add_arg(&args, "-o") == -1 ||
	     fuse_opt_add_arg(&args, opts) == -1)) {
		fuse_opt_free_args(&args);
		return NULL;
	}
	f = fuse_new_common_compat25(fd, &args, op, op_size, compat);
	fuse_opt_free_args(&args);

	return f;
}

struct fuse *fuse_new_compat22(int fd, const char *opts,
			       const struct fuse_operations_compat22 *op,
			       size_t op_size)
{
	return fuse_new_common_compat(fd, opts, (struct fuse_operations *) op,
				      op_size, 22);
}

struct fuse *fuse_new_compat2(int fd, const char *opts,
			      const struct fuse_operations_compat2 *op)
{
	return fuse_new_common_compat(fd, opts, (struct fuse_operations *) op,
				      sizeof(struct fuse_operations_compat2),
				      21);
}

struct fuse *fuse_new_compat1(int fd, int flags,
			      const struct fuse_operations_compat1 *op)
{
	const char *opts = NULL;
	if (flags & FUSE_DEBUG_COMPAT1)
		opts = "debug";
	return fuse_new_common_compat(fd, opts, (struct fuse_operations *) op,
				      sizeof(struct fuse_operations_compat1),
				      11);
}

FUSE_SYMVER(".symver fuse_exited,__fuse_exited@");
FUSE_SYMVER(".symver fuse_process_cmd,__fuse_process_cmd@");
FUSE_SYMVER(".symver fuse_read_cmd,__fuse_read_cmd@");
FUSE_SYMVER(".symver fuse_set_getcontext_func,__fuse_set_getcontext_func@");
FUSE_SYMVER(".symver fuse_new_compat2,fuse_new@");
FUSE_SYMVER(".symver fuse_new_compat22,fuse_new@FUSE_2.2");

#endif /* __FreeBSD__ */

struct fuse *fuse_new_compat25(int fd, struct fuse_args *args,
			       const struct fuse_operations_compat25 *op,
			       size_t op_size)
{
	return fuse_new_common_compat25(fd, args, (struct fuse_operations *) op,
					op_size, 25);
}

FUSE_SYMVER(".symver fuse_new_compat25,fuse_new@FUSE_2.5");
