/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Implementation of the high-level FUSE API on top of the low-level
  API.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/


/* For pthread_rwlock_t */
#define _GNU_SOURCE

#include "config.h"
#include "fuse_i.h"
#include "fuse_lowlevel.h"
#include "fuse_opt.h"
#include "fuse_misc.h"
#include "fuse_kernel.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <assert.h>
#include <poll.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/file.h>

#define FUSE_NODE_SLAB 1

#ifndef MAP_ANONYMOUS
#undef FUSE_NODE_SLAB
#endif

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE		(1 << 1)	/* Exchange source and dest */
#endif

#define FUSE_DEFAULT_INTR_SIGNAL SIGUSR1

#define FUSE_UNKNOWN_INO 0xffffffff
#define OFFSET_MAX 0x7fffffffffffffffLL

#define NODE_TABLE_MIN_SIZE 8192

struct fuse_fs {
	struct fuse_operations op;
	struct fuse_module *m;
	void *user_data;
	int debug;
};

struct fusemod_so {
	void *handle;
	int ctr;
};

struct lock_queue_element {
	struct lock_queue_element *next;
	pthread_cond_t cond;
	fuse_ino_t nodeid1;
	const char *name1;
	char **path1;
	struct node **wnode1;
	fuse_ino_t nodeid2;
	const char *name2;
	char **path2;
	struct node **wnode2;
	int err;
	bool first_locked : 1;
	bool second_locked : 1;
	bool done : 1;
};

struct node_table {
	struct node **array;
	size_t use;
	size_t size;
	size_t split;
};

#define container_of(ptr, type, member) ({                              \
			const typeof( ((type *)0)->member ) *__mptr = (ptr); \
			(type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member)           \
	container_of(ptr, type, member)

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct node_slab {
	struct list_head list;  /* must be the first member */
	struct list_head freelist;
	int used;
};

struct fuse {
	struct fuse_session *se;
	struct node_table name_table;
	struct node_table id_table;
	struct list_head lru_table;
	fuse_ino_t ctr;
	unsigned int generation;
	unsigned int hidectr;
	pthread_mutex_t lock;
	struct fuse_config conf;
	int intr_installed;
	struct fuse_fs *fs;
	struct lock_queue_element *lockq;
	int pagesize;
	struct list_head partial_slabs;
	struct list_head full_slabs;
	pthread_t prune_thread;
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
	char inline_name[32];
};

#define TREELOCK_WRITE -1
#define TREELOCK_WAIT_OFFSET INT_MIN

struct node_lru {
	struct node node;
	struct list_head lru;
	struct timespec forget_time;
};

struct fuse_direntry {
	struct stat stat;
	char *name;
	struct fuse_direntry *next;
};

struct fuse_dh {
	pthread_mutex_t lock;
	struct fuse *fuse;
	fuse_req_t req;
	char *contents;
	struct fuse_direntry *first;
	struct fuse_direntry **last;
	unsigned len;
	unsigned size;
	unsigned needlen;
	int filled;
	uint64_t fh;
	int error;
	fuse_ino_t nodeid;
};

struct fuse_context_i {
	struct fuse_context ctx;
	fuse_req_t req;
};

/* Defined by FUSE_REGISTER_MODULE() in lib/modules/subdir.c and iconv.c.  */
extern fuse_module_factory_t fuse_module_subdir_factory;
#ifdef HAVE_ICONV
extern fuse_module_factory_t fuse_module_iconv_factory;
#endif

static pthread_key_t fuse_context_key;
static pthread_mutex_t fuse_context_lock = PTHREAD_MUTEX_INITIALIZER;
static int fuse_context_ref;
static struct fuse_module *fuse_modules = NULL;

static int fuse_register_module(const char *name,
				fuse_module_factory_t factory,
				struct fusemod_so *so)
{
	struct fuse_module *mod;

	mod = calloc(1, sizeof(struct fuse_module));
	if (!mod) {
		fprintf(stderr, "fuse: failed to allocate module\n");
		return -1;
	}
	mod->name = strdup(name);
	if (!mod->name) {
		fprintf(stderr, "fuse: failed to allocate module name\n");
		free(mod);
		return -1;
	}
	mod->factory = factory;
	mod->ctr = 0;
	mod->so = so;
	if (mod->so)
		mod->so->ctr++;
	mod->next = fuse_modules;
	fuse_modules = mod;

	return 0;
}

static void fuse_unregister_module(struct fuse_module *m)
{
	struct fuse_module **mp;
	for (mp = &fuse_modules; *mp; mp = &(*mp)->next) {
		if (*mp == m) {
			*mp = (*mp)->next;
			break;
		}
	}
	free(m->name);
	free(m);
}

static int fuse_load_so_module(const char *module)
{
	int ret = -1;
	char *tmp;
	struct fusemod_so *so;
	fuse_module_factory_t factory;

	tmp = malloc(strlen(module) + 64);
	if (!tmp) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		return -1;
	}
	sprintf(tmp, "libfusemod_%s.so", module);
	so = calloc(1, sizeof(struct fusemod_so));
	if (!so) {
		fprintf(stderr, "fuse: failed to allocate module so\n");
		goto out;
	}

	so->handle = dlopen(tmp, RTLD_NOW);
	if (so->handle == NULL) {
		fprintf(stderr, "fuse: dlopen(%s) failed: %s\n",
			tmp, dlerror());
		goto out_free_so;
	}

	sprintf(tmp, "fuse_module_%s_factory", module);
	*(void**)(&factory) = dlsym(so->handle, tmp);
	if (factory == NULL) {
		fprintf(stderr, "fuse: symbol <%s> not found in module: %s\n",
			tmp, dlerror());
		goto out_dlclose;
	}
	ret = fuse_register_module(module, factory, so);
	if (ret)
		goto out_dlclose;

out:
	free(tmp);
	return ret;

out_dlclose:
	dlclose(so->handle);
out_free_so:
	free(so);
	goto out;
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
	if (m->so)
		assert(m->ctr > 0);
	/* Builtin modules may already have m->ctr == 0 */
	if (m->ctr > 0)
		m->ctr--;
	if (!m->ctr && m->so) {
		struct fusemod_so *so = m->so;
		assert(so->ctr > 0);
		so->ctr--;
		if (!so->ctr) {
			struct fuse_module **mp;
			for (mp = &fuse_modules; *mp;) {
				if ((*mp)->so == so)
					fuse_unregister_module(*mp);
				else
					mp = &(*mp)->next;
			}
			dlclose(so->handle);
			free(so);
		}
	} else if (!m->ctr) {
		fuse_unregister_module(m);
	}
	pthread_mutex_unlock(&fuse_context_lock);
}

static void init_list_head(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static void list_add(struct list_head *new, struct list_head *prev,
		     struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add_head(struct list_head *new, struct list_head *head)
{
	list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	list_add(new, head->prev, head);
}

static inline void list_del(struct list_head *entry)
{
	struct list_head *prev = entry->prev;
	struct list_head *next = entry->next;

	next->prev = prev;
	prev->next = next;
}

static inline int lru_enabled(struct fuse *f)
{
	return f->conf.remember > 0;
}

static struct node_lru *node_lru(struct node *node)
{
	return (struct node_lru *) node;
}

static size_t get_node_size(struct fuse *f)
{
	if (lru_enabled(f))
		return sizeof(struct node_lru);
	else
		return sizeof(struct node);
}

#ifdef FUSE_NODE_SLAB
static struct node_slab *list_to_slab(struct list_head *head)
{
	return (struct node_slab *) head;
}

static struct node_slab *node_to_slab(struct fuse *f, struct node *node)
{
	return (struct node_slab *) (((uintptr_t) node) & ~((uintptr_t) f->pagesize - 1));
}

static int alloc_slab(struct fuse *f)
{
	void *mem;
	struct node_slab *slab;
	char *start;
	size_t num;
	size_t i;
	size_t node_size = get_node_size(f);

	mem = mmap(NULL, f->pagesize, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (mem == MAP_FAILED)
		return -1;

	slab = mem;
	init_list_head(&slab->freelist);
	slab->used = 0;
	num = (f->pagesize - sizeof(struct node_slab)) / node_size;

	start = (char *) mem + f->pagesize - num * node_size;
	for (i = 0; i < num; i++) {
		struct list_head *n;

		n = (struct list_head *) (start + i * node_size);
		list_add_tail(n, &slab->freelist);
	}
	list_add_tail(&slab->list, &f->partial_slabs);

	return 0;
}

static struct node *alloc_node(struct fuse *f)
{
	struct node_slab *slab;
	struct list_head *node;

	if (list_empty(&f->partial_slabs)) {
		int res = alloc_slab(f);
		if (res != 0)
			return NULL;
	}
	slab = list_to_slab(f->partial_slabs.next);
	slab->used++;
	node = slab->freelist.next;
	list_del(node);
	if (list_empty(&slab->freelist)) {
		list_del(&slab->list);
		list_add_tail(&slab->list, &f->full_slabs);
	}
	memset(node, 0, sizeof(struct node));

	return (struct node *) node;
}

static void free_slab(struct fuse *f, struct node_slab *slab)
{
	int res;

	list_del(&slab->list);
	res = munmap(slab, f->pagesize);
	if (res == -1)
		fprintf(stderr, "fuse warning: munmap(%p) failed\n", slab);
}

static void free_node_mem(struct fuse *f, struct node *node)
{
	struct node_slab *slab = node_to_slab(f, node);
	struct list_head *n = (struct list_head *) node;

	slab->used--;
	if (slab->used) {
		if (list_empty(&slab->freelist)) {
			list_del(&slab->list);
			list_add_tail(&slab->list, &f->partial_slabs);
		}
		list_add_head(n, &slab->freelist);
	} else {
		free_slab(f, slab);
	}
}
#else
static struct node *alloc_node(struct fuse *f)
{
	return (struct node *) calloc(1, get_node_size(f));
}

static void free_node_mem(struct fuse *f, struct node *node)
{
	(void) f;
	free(node);
}
#endif

static size_t id_hash(struct fuse *f, fuse_ino_t ino)
{
	uint64_t hash = ((uint32_t) ino * 2654435761U) % f->id_table.size;
	uint64_t oldhash = hash % (f->id_table.size / 2);

	if (oldhash >= f->id_table.split)
		return oldhash;
	else
		return hash;
}

static struct node *get_node_nocheck(struct fuse *f, fuse_ino_t nodeid)
{
	size_t hash = id_hash(f, nodeid);
	struct node *node;

	for (node = f->id_table.array[hash]; node != NULL; node = node->id_next)
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

static void curr_time(struct timespec *now);
static double diff_timespec(const struct timespec *t1,
			   const struct timespec *t2);

static void remove_node_lru(struct node *node)
{
	struct node_lru *lnode = node_lru(node);
	list_del(&lnode->lru);
	init_list_head(&lnode->lru);
}

static void set_forget_time(struct fuse *f, struct node *node)
{
	struct node_lru *lnode = node_lru(node);

	list_del(&lnode->lru);
	list_add_tail(&lnode->lru, &f->lru_table);
	curr_time(&lnode->forget_time);
}

static void free_node(struct fuse *f, struct node *node)
{
	if (node->name != node->inline_name)
		free(node->name);
	free_node_mem(f, node);
}

static void node_table_reduce(struct node_table *t)
{
	size_t newsize = t->size / 2;
	void *newarray;

	if (newsize < NODE_TABLE_MIN_SIZE)
		return;

	newarray = realloc(t->array, sizeof(struct node *) * newsize);
	if (newarray != NULL)
		t->array = newarray;

	t->size = newsize;
	t->split = t->size / 2;
}

static void remerge_id(struct fuse *f)
{
	struct node_table *t = &f->id_table;
	int iter;

	if (t->split == 0)
		node_table_reduce(t);

	for (iter = 8; t->split > 0 && iter; iter--) {
		struct node **upper;

		t->split--;
		upper = &t->array[t->split + t->size / 2];
		if (*upper) {
			struct node **nodep;

			for (nodep = &t->array[t->split]; *nodep;
			     nodep = &(*nodep)->id_next);

			*nodep = *upper;
			*upper = NULL;
			break;
		}
	}
}

static void unhash_id(struct fuse *f, struct node *node)
{
	struct node **nodep = &f->id_table.array[id_hash(f, node->nodeid)];

	for (; *nodep != NULL; nodep = &(*nodep)->id_next)
		if (*nodep == node) {
			*nodep = node->id_next;
			f->id_table.use--;

			if(f->id_table.use < f->id_table.size / 4)
				remerge_id(f);
			return;
		}
}

static int node_table_resize(struct node_table *t)
{
	size_t newsize = t->size * 2;
	void *newarray;

	newarray = realloc(t->array, sizeof(struct node *) * newsize);
	if (newarray == NULL)
		return -1;

	t->array = newarray;
	memset(t->array + t->size, 0, t->size * sizeof(struct node *));
	t->size = newsize;
	t->split = 0;

	return 0;
}

static void rehash_id(struct fuse *f)
{
	struct node_table *t = &f->id_table;
	struct node **nodep;
	struct node **next;
	size_t hash;

	if (t->split == t->size / 2)
		return;

	hash = t->split;
	t->split++;
	for (nodep = &t->array[hash]; *nodep != NULL; nodep = next) {
		struct node *node = *nodep;
		size_t newhash = id_hash(f, node->nodeid);

		if (newhash != hash) {
			next = nodep;
			*nodep = node->id_next;
			node->id_next = t->array[newhash];
			t->array[newhash] = node;
		} else {
			next = &node->id_next;
		}
	}
	if (t->split == t->size / 2)
		node_table_resize(t);
}

static void hash_id(struct fuse *f, struct node *node)
{
	size_t hash = id_hash(f, node->nodeid);
	node->id_next = f->id_table.array[hash];
	f->id_table.array[hash] = node;
	f->id_table.use++;

	if (f->id_table.use >= f->id_table.size / 2)
		rehash_id(f);
}

static size_t name_hash(struct fuse *f, fuse_ino_t parent,
			const char *name)
{
	uint64_t hash = parent;
	uint64_t oldhash;

	for (; *name; name++)
		hash = hash * 31 + (unsigned char) *name;

	hash %= f->name_table.size;
	oldhash = hash % (f->name_table.size / 2);
	if (oldhash >= f->name_table.split)
		return oldhash;
	else
		return hash;
}

static void unref_node(struct fuse *f, struct node *node);

static void remerge_name(struct fuse *f)
{
	struct node_table *t = &f->name_table;
	int iter;

	if (t->split == 0)
		node_table_reduce(t);

	for (iter = 8; t->split > 0 && iter; iter--) {
		struct node **upper;

		t->split--;
		upper = &t->array[t->split + t->size / 2];
		if (*upper) {
			struct node **nodep;

			for (nodep = &t->array[t->split]; *nodep;
			     nodep = &(*nodep)->name_next);

			*nodep = *upper;
			*upper = NULL;
			break;
		}
	}
}

static void unhash_name(struct fuse *f, struct node *node)
{
	if (node->name) {
		size_t hash = name_hash(f, node->parent->nodeid, node->name);
		struct node **nodep = &f->name_table.array[hash];

		for (; *nodep != NULL; nodep = &(*nodep)->name_next)
			if (*nodep == node) {
				*nodep = node->name_next;
				node->name_next = NULL;
				unref_node(f, node->parent);
				if (node->name != node->inline_name)
					free(node->name);
				node->name = NULL;
				node->parent = NULL;
				f->name_table.use--;

				if (f->name_table.use < f->name_table.size / 4)
					remerge_name(f);
				return;
			}
		fprintf(stderr,
			"fuse internal error: unable to unhash node: %llu\n",
			(unsigned long long) node->nodeid);
		abort();
	}
}

static void rehash_name(struct fuse *f)
{
	struct node_table *t = &f->name_table;
	struct node **nodep;
	struct node **next;
	size_t hash;

	if (t->split == t->size / 2)
		return;

	hash = t->split;
	t->split++;
	for (nodep = &t->array[hash]; *nodep != NULL; nodep = next) {
		struct node *node = *nodep;
		size_t newhash = name_hash(f, node->parent->nodeid, node->name);

		if (newhash != hash) {
			next = nodep;
			*nodep = node->name_next;
			node->name_next = t->array[newhash];
			t->array[newhash] = node;
		} else {
			next = &node->name_next;
		}
	}
	if (t->split == t->size / 2)
		node_table_resize(t);
}

static int hash_name(struct fuse *f, struct node *node, fuse_ino_t parentid,
		     const char *name)
{
	size_t hash = name_hash(f, parentid, name);
	struct node *parent = get_node(f, parentid);
	if (strlen(name) < sizeof(node->inline_name)) {
		strcpy(node->inline_name, name);
		node->name = node->inline_name;
	} else {
		node->name = strdup(name);
		if (node->name == NULL)
			return -1;
	}

	parent->refctr ++;
	node->parent = parent;
	node->name_next = f->name_table.array[hash];
	f->name_table.array[hash] = node;
	f->name_table.use++;

	if (f->name_table.use >= f->name_table.size / 2)
		rehash_name(f);

	return 0;
}

static void delete_node(struct fuse *f, struct node *node)
{
	if (f->conf.debug)
		fprintf(stderr, "DELETE: %llu\n",
			(unsigned long long) node->nodeid);

	assert(node->treelock == 0);
	unhash_name(f, node);
	if (lru_enabled(f))
		remove_node_lru(node);
	unhash_id(f, node);
	free_node(f, node);
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

	for (node = f->name_table.array[hash]; node != NULL; node = node->name_next)
		if (node->parent->nodeid == parent &&
		    strcmp(node->name, name) == 0)
			return node;

	return NULL;
}

static void inc_nlookup(struct node *node)
{
	if (!node->nlookup)
		node->refctr++;
	node->nlookup++;
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
		node = alloc_node(f);
		if (node == NULL)
			goto out_err;

		node->nodeid = next_id(f);
		node->generation = f->generation;
		if (f->conf.remember)
			inc_nlookup(node);

		if (hash_name(f, node, parent, name) == -1) {
			free_node(f, node);
			node = NULL;
			goto out_err;
		}
		hash_id(f, node);
		if (lru_enabled(f)) {
			struct node_lru *lnode = node_lru(node);
			init_list_head(&lnode->lru);
		}
	} else if (lru_enabled(f) && node->nlookup == 1) {
		remove_node_lru(node);
	}
	inc_nlookup(node);
out_err:
	pthread_mutex_unlock(&f->lock);
	return node;
}

static int lookup_path_in_cache(struct fuse *f,
		const char *path, fuse_ino_t *inop)
{
	char *tmp = strdup(path);
	if (!tmp)
		return -ENOMEM;

	pthread_mutex_lock(&f->lock);
	fuse_ino_t ino = FUSE_ROOT_ID;

	int err = 0;
	char *save_ptr;
	char *path_element = strtok_r(tmp, "/", &save_ptr);
	while (path_element != NULL) {
		struct node *node = lookup_node(f, ino, path_element);
		if (node == NULL) {
			err = -ENOENT;
			break;
		}
		ino = node->nodeid;
		path_element = strtok_r(NULL, "/", &save_ptr);
	}
	pthread_mutex_unlock(&f->lock);
	free(tmp);

	if (!err)
		*inop = ino;
	return err;
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
			struct node *end)
{
	struct node *node;

	if (wnode) {
		assert(wnode->treelock == TREELOCK_WRITE);
		wnode->treelock = 0;
	}

	for (node = get_node(f, nodeid);
	     node != end && node->nodeid != FUSE_ROOT_ID; node = node->parent) {
		assert(node->treelock != 0);
		assert(node->treelock != TREELOCK_WAIT_OFFSET);
		assert(node->treelock != TREELOCK_WRITE);
		node->treelock--;
		if (node->treelock == TREELOCK_WAIT_OFFSET)
			node->treelock = 0;
	}
}

static int try_get_path(struct fuse *f, fuse_ino_t nodeid, const char *name,
			char **path, struct node **wnodep, bool need_lock)
{
	unsigned bufsize = 256;
	char *buf;
	char *s;
	struct node *node;
	struct node *wnode = NULL;
	int err;

	*path = NULL;

	err = -ENOMEM;
	buf = malloc(bufsize);
	if (buf == NULL)
		goto out_err;

	s = buf + bufsize - 1;
	*s = '\0';

	if (name != NULL) {
		s = add_name(&buf, &bufsize, s, name);
		err = -ENOMEM;
		if (s == NULL)
			goto out_free;
	}

	if (wnodep) {
		assert(need_lock);
		wnode = lookup_node(f, nodeid, name);
		if (wnode) {
			if (wnode->treelock != 0) {
				if (wnode->treelock > 0)
					wnode->treelock += TREELOCK_WAIT_OFFSET;
				err = -EAGAIN;
				goto out_free;
			}
			wnode->treelock = TREELOCK_WRITE;
		}
	}

	for (node = get_node(f, nodeid); node->nodeid != FUSE_ROOT_ID;
	     node = node->parent) {
		err = -ENOENT;
		if (node->name == NULL || node->parent == NULL)
			goto out_unlock;

		err = -ENOMEM;
		s = add_name(&buf, &bufsize, s, node->name);
		if (s == NULL)
			goto out_unlock;

		if (need_lock) {
			err = -EAGAIN;
			if (node->treelock < 0)
				goto out_unlock;

			node->treelock++;
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
	if (need_lock)
		unlock_path(f, nodeid, wnode, node);
 out_free:
	free(buf);

 out_err:
	return err;
}

static void queue_element_unlock(struct fuse *f, struct lock_queue_element *qe)
{
	struct node *wnode;

	if (qe->first_locked) {
		wnode = qe->wnode1 ? *qe->wnode1 : NULL;
		unlock_path(f, qe->nodeid1, wnode, NULL);
		qe->first_locked = false;
	}
	if (qe->second_locked) {
		wnode = qe->wnode2 ? *qe->wnode2 : NULL;
		unlock_path(f, qe->nodeid2, wnode, NULL);
		qe->second_locked = false;
	}
}

static void queue_element_wakeup(struct fuse *f, struct lock_queue_element *qe)
{
	int err;
	bool first = (qe == f->lockq);

	if (!qe->path1) {
		/* Just waiting for it to be unlocked */
		if (get_node(f, qe->nodeid1)->treelock == 0)
			pthread_cond_signal(&qe->cond);

		return;
	}

	if (!qe->first_locked) {
		err = try_get_path(f, qe->nodeid1, qe->name1, qe->path1,
				   qe->wnode1, true);
		if (!err)
			qe->first_locked = true;
		else if (err != -EAGAIN)
			goto err_unlock;
	}
	if (!qe->second_locked && qe->path2) {
		err = try_get_path(f, qe->nodeid2, qe->name2, qe->path2,
				   qe->wnode2, true);
		if (!err)
			qe->second_locked = true;
		else if (err != -EAGAIN)
			goto err_unlock;
	}

	if (qe->first_locked && (qe->second_locked || !qe->path2)) {
		err = 0;
		goto done;
	}

	/*
	 * Only let the first element be partially locked otherwise there could
	 * be a deadlock.
	 *
	 * But do allow the first element to be partially locked to prevent
	 * starvation.
	 */
	if (!first)
		queue_element_unlock(f, qe);

	/* keep trying */
	return;

err_unlock:
	queue_element_unlock(f, qe);
done:
	qe->err = err;
	qe->done = true;
	pthread_cond_signal(&qe->cond);
}

static void wake_up_queued(struct fuse *f)
{
	struct lock_queue_element *qe;

	for (qe = f->lockq; qe != NULL; qe = qe->next)
		queue_element_wakeup(f, qe);
}

static void debug_path(struct fuse *f, const char *msg, fuse_ino_t nodeid,
		       const char *name, bool wr)
{
	if (f->conf.debug) {
		struct node *wnode = NULL;

		if (wr)
			wnode = lookup_node(f, nodeid, name);

		if (wnode) {
			fprintf(stderr, "%s %llu (w)\n",
				msg, (unsigned long long) wnode->nodeid);
		} else {
			fprintf(stderr, "%s %llu\n",
				msg, (unsigned long long) nodeid);
		}
	}
}

static void queue_path(struct fuse *f, struct lock_queue_element *qe)
{
	struct lock_queue_element **qp;

	qe->done = false;
	qe->first_locked = false;
	qe->second_locked = false;
	pthread_cond_init(&qe->cond, NULL);
	qe->next = NULL;
	for (qp = &f->lockq; *qp != NULL; qp = &(*qp)->next);
	*qp = qe;
}

static void dequeue_path(struct fuse *f, struct lock_queue_element *qe)
{
	struct lock_queue_element **qp;

	pthread_cond_destroy(&qe->cond);
	for (qp = &f->lockq; *qp != qe; qp = &(*qp)->next);
	*qp = qe->next;
}

static int wait_path(struct fuse *f, struct lock_queue_element *qe)
{
	queue_path(f, qe);

	do {
		pthread_cond_wait(&qe->cond, &f->lock);
	} while (!qe->done);

	dequeue_path(f, qe);

	return qe->err;
}

static int get_path_common(struct fuse *f, fuse_ino_t nodeid, const char *name,
			   char **path, struct node **wnode)
{
	int err;

	pthread_mutex_lock(&f->lock);
	err = try_get_path(f, nodeid, name, path, wnode, true);
	if (err == -EAGAIN) {
		struct lock_queue_element qe = {
			.nodeid1 = nodeid,
			.name1 = name,
			.path1 = path,
			.wnode1 = wnode,
		};
		debug_path(f, "QUEUE PATH", nodeid, name, !!wnode);
		err = wait_path(f, &qe);
		debug_path(f, "DEQUEUE PATH", nodeid, name, !!wnode);
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
	int err = 0;

	if (f->conf.nullpath_ok) {
		*path = NULL;
	} else {
		err = get_path_common(f, nodeid, NULL, path, NULL);
		if (err == -ENOENT)
			err = 0;
	}

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

#if defined(__FreeBSD__)
#define CHECK_DIR_LOOP
#endif

#if defined(CHECK_DIR_LOOP)
static int check_dir_loop(struct fuse *f,
			  fuse_ino_t nodeid1, const char *name1,
			  fuse_ino_t nodeid2, const char *name2)
{
	struct node *node, *node1, *node2;
	fuse_ino_t id1, id2;

	node1 = lookup_node(f, nodeid1, name1);
	id1 = node1 ? node1->nodeid : nodeid1;

	node2 = lookup_node(f, nodeid2, name2);
	id2 = node2 ? node2->nodeid : nodeid2;

	for (node = get_node(f, id2); node->nodeid != FUSE_ROOT_ID;
	     node = node->parent) {
		if (node->name == NULL || node->parent == NULL)
			break;

		if (node->nodeid != id2 && node->nodeid == id1)
			return -EINVAL;
	}

	if (node2)
	{
		for (node = get_node(f, id1); node->nodeid != FUSE_ROOT_ID;
		     node = node->parent) {
			if (node->name == NULL || node->parent == NULL)
				break;

			if (node->nodeid != id1 && node->nodeid == id2)
				return -ENOTEMPTY;
		}
	}

	return 0;
}
#endif

static int try_get_path2(struct fuse *f, fuse_ino_t nodeid1, const char *name1,
			 fuse_ino_t nodeid2, const char *name2,
			 char **path1, char **path2,
			 struct node **wnode1, struct node **wnode2)
{
	int err;

	/* FIXME: locking two paths needs deadlock checking */
	err = try_get_path(f, nodeid1, name1, path1, wnode1, true);
	if (!err) {
		err = try_get_path(f, nodeid2, name2, path2, wnode2, true);
		if (err) {
			struct node *wn1 = wnode1 ? *wnode1 : NULL;

			unlock_path(f, nodeid1, wn1, NULL);
			free(*path1);
		}
	}
	return err;
}

static int get_path2(struct fuse *f, fuse_ino_t nodeid1, const char *name1,
		     fuse_ino_t nodeid2, const char *name2,
		     char **path1, char **path2,
		     struct node **wnode1, struct node **wnode2)
{
	int err;

	pthread_mutex_lock(&f->lock);

#if defined(CHECK_DIR_LOOP)
	if (name1)
	{
		// called during rename; perform dir loop check
		err = check_dir_loop(f, nodeid1, name1, nodeid2, name2);
		if (err)
			goto out_unlock;
	}
#endif

	err = try_get_path2(f, nodeid1, name1, nodeid2, name2,
			    path1, path2, wnode1, wnode2);
	if (err == -EAGAIN) {
		struct lock_queue_element qe = {
			.nodeid1 = nodeid1,
			.name1 = name1,
			.path1 = path1,
			.wnode1 = wnode1,
			.nodeid2 = nodeid2,
			.name2 = name2,
			.path2 = path2,
			.wnode2 = wnode2,
		};

		debug_path(f, "QUEUE PATH1", nodeid1, name1, !!wnode1);
		debug_path(f, "      PATH2", nodeid2, name2, !!wnode2);
		err = wait_path(f, &qe);
		debug_path(f, "DEQUEUE PATH1", nodeid1, name1, !!wnode1);
		debug_path(f, "        PATH2", nodeid2, name2, !!wnode2);
	}

#if defined(CHECK_DIR_LOOP)
out_unlock:
#endif
	pthread_mutex_unlock(&f->lock);

	return err;
}

static void free_path_wrlock(struct fuse *f, fuse_ino_t nodeid,
			     struct node *wnode, char *path)
{
	pthread_mutex_lock(&f->lock);
	unlock_path(f, nodeid, wnode, NULL);
	if (f->lockq)
		wake_up_queued(f);
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
	unlock_path(f, nodeid1, wnode1, NULL);
	unlock_path(f, nodeid2, wnode2, NULL);
	wake_up_queued(f);
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
		struct lock_queue_element qe = {
			.nodeid1 = nodeid,
		};

		debug_path(f, "QUEUE PATH (forget)", nodeid, NULL, false);
		queue_path(f, &qe);

		do {
			pthread_cond_wait(&qe.cond, &f->lock);
		} while (node->nlookup == nlookup && node->treelock);

		dequeue_path(f, &qe);
		debug_path(f, "DEQUEUE_PATH (forget)", nodeid, NULL, false);
	}

	assert(node->nlookup >= nlookup);
	node->nlookup -= nlookup;
	if (!node->nlookup) {
		unref_node(f, node);
	} else if (lru_enabled(f) && node->nlookup == 1) {
		set_forget_time(f, node);
	}
	pthread_mutex_unlock(&f->lock);
}

static void unlink_node(struct fuse *f, struct node *node)
{
	if (f->conf.remember) {
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

static int exchange_node(struct fuse *f, fuse_ino_t olddir, const char *oldname,
			 fuse_ino_t newdir, const char *newname)
{
	struct node *oldnode;
	struct node *newnode;
	int err;

	pthread_mutex_lock(&f->lock);
	oldnode  = lookup_node(f, olddir, oldname);
	newnode	 = lookup_node(f, newdir, newname);

	if (oldnode)
		unhash_name(f, oldnode);
	if (newnode)
		unhash_name(f, newnode);

	err = -ENOMEM;
	if (oldnode) {
		if (hash_name(f, oldnode, newdir, newname) == -1)
			goto out;
	}
	if (newnode) {
		if (hash_name(f, newnode, olddir, oldname) == -1)
			goto out;
	}
	err = 0;
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

static const char* file_info_string(struct fuse_file_info *fi,
			      char* buf, size_t len)
{
	if(fi == NULL)
		return "NULL";
	snprintf(buf, len, "%llu", (unsigned long long) fi->fh);
	return buf;
}

int fuse_fs_getattr(struct fuse_fs *fs, const char *path, struct stat *buf,
		    struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.getattr) {
		if (fs->debug) {
			char buf[10];
			fprintf(stderr, "getattr[%s] %s\n",
				file_info_string(fi, buf, sizeof(buf)),
				path);
		}
		return fs->op.getattr(path, buf, fi);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_rename(struct fuse_fs *fs, const char *oldpath,
		   const char *newpath, unsigned int flags)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.rename) {
		if (fs->debug)
			fprintf(stderr, "rename %s %s 0x%x\n", oldpath, newpath,
				flags);

		return fs->op.rename(oldpath, newpath, flags);
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

		return fs->op.release(path, fi);
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

		err = fs->op.opendir(path, fi);

		if (fs->debug && !err)
			fprintf(stderr, "   opendir[%llu] flags: 0x%x %s\n",
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

		err = fs->op.open(path, fi);

		if (fs->debug && !err)
			fprintf(stderr, "   open[%llu] flags: 0x%x %s\n",
				(unsigned long long) fi->fh, fi->flags, path);

		return err;
	} else {
		return 0;
	}
}

static void fuse_free_buf(struct fuse_bufvec *buf)
{
	if (buf != NULL) {
		size_t i;

		for (i = 0; i < buf->count; i++)
			if (!(buf->buf[i].flags & FUSE_BUF_IS_FD))
				free(buf->buf[i].mem);
		free(buf);
	}
}

int fuse_fs_read_buf(struct fuse_fs *fs, const char *path,
		     struct fuse_bufvec **bufp, size_t size, off_t off,
		     struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.read || fs->op.read_buf) {
		int res;

		if (fs->debug)
			fprintf(stderr,
				"read[%llu] %zu bytes from %llu flags: 0x%x\n",
				(unsigned long long) fi->fh,
				size, (unsigned long long) off, fi->flags);

		if (fs->op.read_buf) {
			res = fs->op.read_buf(path, bufp, size, off, fi);
		} else {
			struct fuse_bufvec *buf;
			void *mem;

			buf = malloc(sizeof(struct fuse_bufvec));
			if (buf == NULL)
				return -ENOMEM;

			mem = malloc(size);
			if (mem == NULL) {
				free(buf);
				return -ENOMEM;
			}
			*buf = FUSE_BUFVEC_INIT(size);
			buf->buf[0].mem = mem;
			*bufp = buf;

			res = fs->op.read(path, mem, size, off, fi);
			if (res >= 0)
				buf->buf[0].size = res;
		}

		if (fs->debug && res >= 0)
			fprintf(stderr, "   read[%llu] %zu bytes from %llu\n",
				(unsigned long long) fi->fh,
				fuse_buf_size(*bufp),
				(unsigned long long) off);
		if (res >= 0 && fuse_buf_size(*bufp) > size)
			fprintf(stderr, "fuse: read too many bytes\n");

		if (res < 0)
			return res;

		return 0;
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_read(struct fuse_fs *fs, const char *path, char *mem, size_t size,
		 off_t off, struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.read || fs->op.read_buf) {
		int res;

		if (fs->debug)
			fprintf(stderr,
				"read[%llu] %zu bytes from %llu flags: 0x%x\n",
				(unsigned long long) fi->fh,
				size, (unsigned long long) off, fi->flags);

		if (fs->op.read_buf) {
			struct fuse_bufvec *buf = NULL;

			res = fs->op.read_buf(path, &buf, size, off, fi);
			if (res == 0) {
				struct fuse_bufvec dst = FUSE_BUFVEC_INIT(size);

				dst.buf[0].mem = mem;
				res = fuse_buf_copy(&dst, buf, 0);
			}
			fuse_free_buf(buf);
		} else {
			res = fs->op.read(path, mem, size, off, fi);
		}

		if (fs->debug && res >= 0)
			fprintf(stderr, "   read[%llu] %u bytes from %llu\n",
				(unsigned long long) fi->fh,
				res,
				(unsigned long long) off);
		if (res >= 0 && res > (int) size)
			fprintf(stderr, "fuse: read too many bytes\n");

		return res;
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_write_buf(struct fuse_fs *fs, const char *path,
		      struct fuse_bufvec *buf, off_t off,
		      struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.write_buf || fs->op.write) {
		int res;
		size_t size = fuse_buf_size(buf);

		assert(buf->idx == 0 && buf->off == 0);
		if (fs->debug)
			fprintf(stderr,
				"write%s[%llu] %zu bytes to %llu flags: 0x%x\n",
				fi->writepage ? "page" : "",
				(unsigned long long) fi->fh,
				size,
				(unsigned long long) off,
				fi->flags);

		if (fs->op.write_buf) {
			res = fs->op.write_buf(path, buf, off, fi);
		} else {
			void *mem = NULL;
			struct fuse_buf *flatbuf;
			struct fuse_bufvec tmp = FUSE_BUFVEC_INIT(size);

			if (buf->count == 1 &&
			    !(buf->buf[0].flags & FUSE_BUF_IS_FD)) {
				flatbuf = &buf->buf[0];
			} else {
				res = -ENOMEM;
				mem = malloc(size);
				if (mem == NULL)
					goto out;

				tmp.buf[0].mem = mem;
				res = fuse_buf_copy(&tmp, buf, 0);
				if (res <= 0)
					goto out_free;

				tmp.buf[0].size = res;
				flatbuf = &tmp.buf[0];
			}

			res = fs->op.write(path, flatbuf->mem, flatbuf->size,
					   off, fi);
out_free:
			free(mem);
		}
out:
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

int fuse_fs_write(struct fuse_fs *fs, const char *path, const char *mem,
		  size_t size, off_t off, struct fuse_file_info *fi)
{
	struct fuse_bufvec bufv = FUSE_BUFVEC_INIT(size);

	bufv.buf[0].mem = (void *) mem;

	return fuse_fs_write_buf(fs, path, &bufv, off, fi);
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

		return fs->op.statfs(path, buf);
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

int fuse_fs_readdir(struct fuse_fs *fs, const char *path, void *buf,
		    fuse_fill_dir_t filler, off_t off,
		    struct fuse_file_info *fi,
		    enum fuse_readdir_flags flags)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.readdir) {
		if (fs->debug) {
			fprintf(stderr, "readdir%s[%llu] from %llu\n",
				(flags & FUSE_READDIR_PLUS) ? "plus" : "",
				(unsigned long long) fi->fh,
				(unsigned long long) off);
		}

		return fs->op.readdir(path, buf, filler, off, fi, flags);
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

int fuse_fs_flock(struct fuse_fs *fs, const char *path,
		  struct fuse_file_info *fi, int op)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.flock) {
		if (fs->debug) {
			int xop = op & ~LOCK_NB;

			fprintf(stderr, "lock[%llu] %s%s\n",
				(unsigned long long) fi->fh,
				xop == LOCK_SH ? "LOCK_SH" :
				(xop == LOCK_EX ? "LOCK_EX" :
				 (xop == LOCK_UN ? "LOCK_UN" : "???")),
				(op & LOCK_NB) ? "|LOCK_NB" : "");
		}
		return fs->op.flock(path, fi, op);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_chown(struct fuse_fs *fs, const char *path, uid_t uid,
		  gid_t gid, struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.chown) {
		if (fs->debug) {
			char buf[10];
			fprintf(stderr, "chown[%s] %s %lu %lu\n",
				file_info_string(fi, buf, sizeof(buf)),
				path, (unsigned long) uid, (unsigned long) gid);
		}
		return fs->op.chown(path, uid, gid, fi);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_truncate(struct fuse_fs *fs, const char *path, off_t size,
		      struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.truncate) {
		if (fs->debug) {
			char buf[10];
			fprintf(stderr, "truncate[%s] %llu\n",
				file_info_string(fi, buf, sizeof(buf)),
				(unsigned long long) size);
		}
		return fs->op.truncate(path, size, fi);
	} else {
		return -ENOSYS;
	}
}

int fuse_fs_utimens(struct fuse_fs *fs, const char *path,
		    const struct timespec tv[2], struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.utimens) {
		if (fs->debug) {
			char buf[10];
			fprintf(stderr, "utimens[%s] %s %li.%09lu %li.%09lu\n",
				file_info_string(fi, buf, sizeof(buf)),
				path, tv[0].tv_sec, tv[0].tv_nsec,
				tv[1].tv_sec, tv[1].tv_nsec);
		}
		return fs->op.utimens(path, tv, fi);
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

int fuse_fs_ioctl(struct fuse_fs *fs, const char *path, unsigned int cmd,
		  void *arg, struct fuse_file_info *fi, unsigned int flags,
		  void *data)
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
			fprintf(stderr, "poll[%llu] ph: %p, events 0x%x\n",
				(unsigned long long) fi->fh, ph,
				fi->poll_events);

		res = fs->op.poll(path, fi, ph, reventsp);

		if (fs->debug && !res)
			fprintf(stderr, "   poll[%llu] revents: 0x%x\n",
				(unsigned long long) fi->fh, *reventsp);

		return res;
	} else
		return -ENOSYS;
}

int fuse_fs_fallocate(struct fuse_fs *fs, const char *path, int mode,
		off_t offset, off_t length, struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.fallocate) {
		if (fs->debug)
			fprintf(stderr, "fallocate %s mode %x, offset: %llu, length: %llu\n",
				path,
				mode,
				(unsigned long long) offset,
				(unsigned long long) length);

		return fs->op.fallocate(path, mode, offset, length, fi);
	} else
		return -ENOSYS;
}

ssize_t fuse_fs_copy_file_range(struct fuse_fs *fs, const char *path_in,
				struct fuse_file_info *fi_in, off_t off_in,
				const char *path_out,
				struct fuse_file_info *fi_out, off_t off_out,
				size_t len, int flags)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.copy_file_range) {
		if (fs->debug)
			fprintf(stderr, "copy_file_range from %s:%llu to "
			                "%s:%llu, length: %llu\n",
				path_in,
				(unsigned long long) off_in,
				path_out,
				(unsigned long long) off_out,
				(unsigned long long) len);

		return fs->op.copy_file_range(path_in, fi_in, off_in, path_out,
					      fi_out, off_out, len, flags);
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

		res = try_get_path(f, dir, newname, &newpath, NULL, false);
		pthread_mutex_unlock(&f->lock);
		if (res)
			break;

		memset(&buf, 0, sizeof(buf));
		res = fuse_fs_getattr(f->fs, newpath, &buf, NULL);
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
		err = fuse_fs_rename(f->fs, oldpath, newpath, 0);
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

static int do_lookup(struct fuse *f, fuse_ino_t nodeid, const char *name,
		     struct fuse_entry_param *e)
{
	struct node *node;

	node = find_node(f, nodeid, name);
	if (node == NULL)
		return -ENOMEM;

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
	return 0;
}

static int lookup_path(struct fuse *f, fuse_ino_t nodeid,
		       const char *name, const char *path,
		       struct fuse_entry_param *e, struct fuse_file_info *fi)
{
	int res;

	memset(e, 0, sizeof(struct fuse_entry_param));
	res = fuse_fs_getattr(f->fs, path, &e->attr, fi);
	if (res == 0) {
		res = do_lookup(f, nodeid, name, e);
		if (res == 0 && f->conf.debug) {
			fprintf(stderr, "   NODEID: %llu\n",
				(unsigned long long) e->ino);
		}
	}
	return res;
}

static struct fuse_context_i *fuse_get_context_internal(void)
{
	return (struct fuse_context_i *) pthread_getspecific(fuse_context_key);
}

static struct fuse_context_i *fuse_create_context(struct fuse *f)
{
	struct fuse_context_i *c = fuse_get_context_internal();
	if (c == NULL) {
		c = (struct fuse_context_i *)
			calloc(1, sizeof(struct fuse_context_i));
		if (c == NULL) {
			/* This is hard to deal with properly, so just
			   abort.  If memory is so low that the
			   context cannot be allocated, there's not
			   much hope for the filesystem anyway */
			fprintf(stderr, "fuse: failed to allocate thread specific data\n");
			abort();
		}
		pthread_setspecific(fuse_context_key, c);
	} else {
		memset(c, 0, sizeof(*c));
	}
	c->ctx.fuse = f;

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
	struct fuse_context_i *c = fuse_create_context(req_fuse(req));
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	c->req = req;
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

void fuse_fs_init(struct fuse_fs *fs, struct fuse_conn_info *conn,
		  struct fuse_config *cfg)
{
	fuse_get_context()->private_data = fs->user_data;
	if (!fs->op.write_buf)
		conn->want &= ~FUSE_CAP_SPLICE_READ;
	if (!fs->op.lock)
		conn->want &= ~FUSE_CAP_POSIX_LOCKS;
	if (!fs->op.flock)
		conn->want &= ~FUSE_CAP_FLOCK_LOCKS;
	if (fs->op.init)
		fs->user_data = fs->op.init(conn, cfg);
}

static void fuse_lib_init(void *data, struct fuse_conn_info *conn)
{
	struct fuse *f = (struct fuse *) data;

	fuse_create_context(f);
	if(conn->capable & FUSE_CAP_EXPORT_SUPPORT)
		conn->want |= FUSE_CAP_EXPORT_SUPPORT;
	fuse_fs_init(f->fs, conn, &f->conf);
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

	fuse_create_context(f);
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

static void do_forget(struct fuse *f, fuse_ino_t ino, uint64_t nlookup)
{
	if (f->conf.debug)
		fprintf(stderr, "FORGET %llu/%llu\n", (unsigned long long)ino,
			(unsigned long long) nlookup);
	forget_node(f, ino, nlookup);
}

static void fuse_lib_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	do_forget(req_fuse(req), ino, nlookup);
	fuse_reply_none(req);
}

static void fuse_lib_forget_multi(fuse_req_t req, size_t count,
				  struct fuse_forget_data *forgets)
{
	struct fuse *f = req_fuse(req);
	size_t i;

	for (i = 0; i < count; i++)
		do_forget(f, forgets[i].ino, forgets[i].nlookup);

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
		err = fuse_fs_getattr(f->fs, path, &buf, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	if (!err) {
		struct node *node;

		pthread_mutex_lock(&f->lock);
		node = get_node(f, ino);
		if (node->is_hidden && buf.st_nlink > 0)
			buf.st_nlink--;
		if (f->conf.auto_cache)
			update_stat(node, &buf);
		pthread_mutex_unlock(&f->lock);
		set_stat(f, ino, &buf);
		fuse_reply_attr(req, &buf, f->conf.attr_timeout);
	} else
		reply_err(req, err);
}

int fuse_fs_chmod(struct fuse_fs *fs, const char *path, mode_t mode,
		  struct fuse_file_info *fi)
{
	fuse_get_context()->private_data = fs->user_data;
	if (fs->op.chmod) {
		if (fs->debug) {
			char buf[10];
			fprintf(stderr, "chmod[%s] %s %llo\n",
				file_info_string(fi, buf, sizeof(buf)),
				path, (unsigned long long) mode);
		}
		return fs->op.chmod(path, mode, fi);
	}
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

	memset(&buf, 0, sizeof(buf));
	if (fi != NULL)
		err = get_path_nullok(f, ino, &path);
	else
		err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = 0;
		if (!err && (valid & FUSE_SET_ATTR_MODE))
			err = fuse_fs_chmod(f->fs, path, attr->st_mode, fi);
		if (!err && (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID))) {
			uid_t uid = (valid & FUSE_SET_ATTR_UID) ?
				attr->st_uid : (uid_t) -1;
			gid_t gid = (valid & FUSE_SET_ATTR_GID) ?
				attr->st_gid : (gid_t) -1;
			err = fuse_fs_chown(f->fs, path, uid, gid, fi);
		}
		if (!err && (valid & FUSE_SET_ATTR_SIZE)) {
			err = fuse_fs_truncate(f->fs, path,
					       attr->st_size, fi);
		}
#ifdef HAVE_UTIMENSAT
		if (!err &&
		    (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME))) {
			struct timespec tv[2];

			tv[0].tv_sec = 0;
			tv[1].tv_sec = 0;
			tv[0].tv_nsec = UTIME_OMIT;
			tv[1].tv_nsec = UTIME_OMIT;

			if (valid & FUSE_SET_ATTR_ATIME_NOW)
				tv[0].tv_nsec = UTIME_NOW;
			else if (valid & FUSE_SET_ATTR_ATIME)
				tv[0] = attr->st_atim;

			if (valid & FUSE_SET_ATTR_MTIME_NOW)
				tv[1].tv_nsec = UTIME_NOW;
			else if (valid & FUSE_SET_ATTR_MTIME)
				tv[1] = attr->st_mtim;

			err = fuse_fs_utimens(f->fs, path, tv, fi);
		} else
#endif
		if (!err &&
		    (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) ==
		    (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
			struct timespec tv[2];
			tv[0].tv_sec = attr->st_atime;
			tv[0].tv_nsec = ST_ATIM_NSEC(attr);
			tv[1].tv_sec = attr->st_mtime;
			tv[1].tv_nsec = ST_MTIM_NSEC(attr);
			err = fuse_fs_utimens(f->fs, path, tv, fi);
		}
		if (!err) {
			err = fuse_fs_getattr(f->fs, path, &buf, fi);
		}
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
			    const char *newname, unsigned int flags)
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
		if (!f->conf.hard_remove && !(flags & RENAME_EXCHANGE) &&
		    is_open(f, newdir, newname))
			err = hide_node(f, newpath, newdir, newname);
		if (!err) {
			err = fuse_fs_rename(f->fs, oldpath, newpath, flags);
			if (!err) {
				if (flags & RENAME_EXCHANGE) {
					err = exchange_node(f, olddir, oldname,
							    newdir, newname);
				} else {
					err = rename_node(f, olddir, oldname,
							  newdir, newname, 0);
				}
			}
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

	fuse_fs_release(f->fs, path, fi);

	pthread_mutex_lock(&f->lock);
	node = get_node(f, ino);
	assert(node->open_count > 0);
	--node->open_count;
	if (node->is_hidden && !node->open_count) {
		unlink_hidden = 1;
		node->is_hidden = 0;
	}
	pthread_mutex_unlock(&f->lock);

	if(unlink_hidden) {
		if (path) {
			fuse_fs_unlink(f->fs, path);
		} else if (f->conf.nullpath_ok) {
			char *unlinkpath;

			if (get_path(f, ino, &unlinkpath) == 0)
				fuse_fs_unlink(f->fs, unlinkpath);

			free_path(f, ino, unlinkpath);
		}
	}
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
			fuse_do_release(f, e.ino, path, fi);
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
			err = fuse_fs_getattr(f->fs, path, &stbuf, fi);
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
			fuse_do_release(f, ino, path, fi);
		}
	} else
		reply_err(req, err);

	free_path(f, ino, path);
}

static void fuse_lib_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_bufvec *buf = NULL;
	char *path;
	int res;

	res = get_path_nullok(f, ino, &path);
	if (res == 0) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		res = fuse_fs_read_buf(f->fs, path, &buf, size, off, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}

	if (res == 0)
		fuse_reply_data(req, buf, FUSE_BUF_SPLICE_MOVE);
	else
		reply_err(req, res);

	fuse_free_buf(buf);
}

static void fuse_lib_write_buf(fuse_req_t req, fuse_ino_t ino,
			       struct fuse_bufvec *buf, off_t off,
			       struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int res;

	res = get_path_nullok(f, ino, &path);
	if (res == 0) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		res = fuse_fs_write_buf(f->fs, path, buf, off, fi);
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
	dh->first = NULL;
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
			fuse_fs_releasedir(f->fs, path, &fi);
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

static int fuse_add_direntry_to_dh(struct fuse_dh *dh, const char *name,
				   struct stat *st)
{
	struct fuse_direntry *de;

	de = malloc(sizeof(struct fuse_direntry));
	if (!de) {
		dh->error = -ENOMEM;
		return -1;
	}
	de->name = strdup(name);
	if (!de->name) {
		dh->error = -ENOMEM;
		free(de);
		return -1;
	}
	de->stat = *st;
	de->next = NULL;

	*dh->last = de;
	dh->last = &de->next;

	return 0;
}

static fuse_ino_t lookup_nodeid(struct fuse *f, fuse_ino_t parent,
				const char *name)
{
	struct node *node;
	fuse_ino_t res = FUSE_UNKNOWN_INO;

	pthread_mutex_lock(&f->lock);
	node = lookup_node(f, parent, name);
	if (node)
		res = node->nodeid;
	pthread_mutex_unlock(&f->lock);

	return res;
}

static int fill_dir(void *dh_, const char *name, const struct stat *statp,
		    off_t off, enum fuse_fill_dir_flags flags)
{
	struct fuse_dh *dh = (struct fuse_dh *) dh_;
	struct stat stbuf;

	if ((flags & ~FUSE_FILL_DIR_PLUS) != 0) {
		dh->error = -EIO;
		return 1;
	}

	if (statp)
		stbuf = *statp;
	else {
		memset(&stbuf, 0, sizeof(stbuf));
		stbuf.st_ino = FUSE_UNKNOWN_INO;
	}

	if (!dh->fuse->conf.use_ino) {
		stbuf.st_ino = FUSE_UNKNOWN_INO;
		if (dh->fuse->conf.readdir_ino) {
			stbuf.st_ino = (ino_t)
				lookup_nodeid(dh->fuse, dh->nodeid, name);
		}
	}

	if (off) {
		size_t newlen;

		if (dh->filled) {
			dh->error = -EIO;
			return 1;
		}

		if (dh->first) {
			dh->error = -EIO;
			return 1;
		}

		if (extend_contents(dh, dh->needlen) == -1)
			return 1;

		newlen = dh->len +
			fuse_add_direntry(dh->req, dh->contents + dh->len,
					  dh->needlen - dh->len, name,
					  &stbuf, off);
		if (newlen > dh->needlen)
			return 1;

		dh->len = newlen;
	} else {
		dh->filled = 1;

		if (fuse_add_direntry_to_dh(dh, name, &stbuf) == -1)
			return 1;
	}
	return 0;
}

static int is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' ||
				  (name[1] == '.' && name[2] == '\0'));
}

static int fill_dir_plus(void *dh_, const char *name, const struct stat *statp,
			 off_t off, enum fuse_fill_dir_flags flags)
{
	struct fuse_dh *dh = (struct fuse_dh *) dh_;
	struct fuse_entry_param e = {
		/* ino=0 tells the kernel to ignore readdirplus stat info */
		.ino = 0,
	};
	struct fuse *f = dh->fuse;
	int res;

	if ((flags & ~FUSE_FILL_DIR_PLUS) != 0) {
		dh->error = -EIO;
		return 1;
	}

	if (off && statp && (flags & FUSE_FILL_DIR_PLUS)) {
		e.attr = *statp;

		if (!is_dot_or_dotdot(name)) {
			res = do_lookup(f, dh->nodeid, name, &e);
			if (res) {
				dh->error = res;
				return 1;
			}
		}
	} else {
		e.attr.st_ino = FUSE_UNKNOWN_INO;
		if (!f->conf.use_ino && f->conf.readdir_ino) {
			e.attr.st_ino = (ino_t)
				lookup_nodeid(f, dh->nodeid, name);
		}
	}

	if (off) {
		size_t newlen;

		if (dh->filled) {
			dh->error = -EIO;
			return 1;
		}

		if (dh->first) {
			dh->error = -EIO;
			return 1;
		}
		if (extend_contents(dh, dh->needlen) == -1)
			return 1;

		newlen = dh->len +
			fuse_add_direntry_plus(dh->req, dh->contents + dh->len,
					       dh->needlen - dh->len, name,
					       &e, off);
		if (newlen > dh->needlen)
			return 1;
		dh->len = newlen;
	} else {
		dh->filled = 1;

		if (fuse_add_direntry_to_dh(dh, name, &e.attr) == -1)
			return 1;
	}

	return 0;
}

static void free_direntries(struct fuse_direntry *de)
{
	while (de) {
		struct fuse_direntry *next = de->next;
		free(de->name);
		free(de);
		de = next;
	}
}

static int readdir_fill(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
			size_t size, off_t off, struct fuse_dh *dh,
			struct fuse_file_info *fi,
			enum fuse_readdir_flags flags)
{
	char *path;
	int err;

	if (f->fs->op.readdir)
		err = get_path_nullok(f, ino, &path);
	else
		err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_fill_dir_t filler = fill_dir;

		if (flags & FUSE_READDIR_PLUS)
			filler = fill_dir_plus;

		free_direntries(dh->first);
		dh->first = NULL;
		dh->last = &dh->first;
		dh->len = 0;
		dh->error = 0;
		dh->needlen = size;
		dh->filled = 0;
		dh->req = req;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_readdir(f->fs, path, dh, filler, off, fi, flags);
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

static int readdir_fill_from_list(fuse_req_t req, struct fuse_dh *dh,
				  off_t off, enum fuse_readdir_flags flags)
{
	off_t pos;
	struct fuse_direntry *de = dh->first;

	dh->len = 0;

	if (extend_contents(dh, dh->needlen) == -1)
		return dh->error;

	for (pos = 0; pos < off; pos++) {
		if (!de)
			break;

		de = de->next;
	}
	while (de) {
		char *p = dh->contents + dh->len;
		unsigned rem = dh->needlen - dh->len;
		unsigned thislen;
		unsigned newlen;
		pos++;

		if (flags & FUSE_READDIR_PLUS) {
			struct fuse_entry_param e = {
				.ino = 0,
				.attr = de->stat,
			};
			thislen = fuse_add_direntry_plus(req, p, rem,
							 de->name, &e, pos);
		} else {
			thislen = fuse_add_direntry(req, p, rem,
						    de->name, &de->stat, pos);
		}
		newlen = dh->len + thislen;
		if (newlen > dh->needlen)
			break;
		dh->len = newlen;
		de = de->next;
	}
	return 0;
}

static void fuse_readdir_common(fuse_req_t req, fuse_ino_t ino, size_t size,
				off_t off, struct fuse_file_info *llfi,
				enum fuse_readdir_flags flags)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_file_info fi;
	struct fuse_dh *dh = get_dirhandle(llfi, &fi);
	int err;

	pthread_mutex_lock(&dh->lock);
	/* According to SUS, directory contents need to be refreshed on
	   rewinddir() */
	if (!off)
		dh->filled = 0;

	if (!dh->filled) {
		err = readdir_fill(f, req, ino, size, off, dh, &fi, flags);
		if (err) {
			reply_err(req, err);
			goto out;
		}
	}
	if (dh->filled) {
		dh->needlen = size;
		err = readdir_fill_from_list(req, dh, off, flags);
		if (err) {
			reply_err(req, err);
			goto out;
		}
	}
	fuse_reply_buf(req, dh->contents, dh->len);
out:
	pthread_mutex_unlock(&dh->lock);
}

static void fuse_lib_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *llfi)
{
	fuse_readdir_common(req, ino, size, off, llfi, 0);
}

static void fuse_lib_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
				  off_t off, struct fuse_file_info *llfi)
{
	fuse_readdir_common(req, ino, size, off, llfi, FUSE_READDIR_PLUS);
}

static void fuse_lib_releasedir(fuse_req_t req, fuse_ino_t ino,
				struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_file_info fi;
	struct fuse_dh *dh = get_dirhandle(llfi, &fi);
	char *path;

	get_path_nullok(f, ino, &path);

	fuse_prepare_interrupt(f, req, &d);
	fuse_fs_releasedir(f->fs, path, &fi);
	fuse_finish_interrupt(f, req, &d);
	free_path(f, ino, path);

	pthread_mutex_lock(&dh->lock);
	pthread_mutex_unlock(&dh->lock);
	pthread_mutex_destroy(&dh->lock);
	free_direntries(dh->first);
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

	err = get_path_nullok(f, ino, &path);
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

	get_path_nullok(f, ino, &path);
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

	get_path_nullok(f, ino, &path);
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

static void fuse_lib_flock(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, int op)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path_nullok(f, ino, &path);
	if (err == 0) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_flock(f->fs, path, fi, op);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
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

static void fuse_lib_ioctl(fuse_req_t req, fuse_ino_t ino, unsigned int cmd,
			   void *arg, struct fuse_file_info *llfi,
			   unsigned int flags, const void *in_buf,
			   size_t in_bufsz, size_t out_bufsz)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_file_info fi;
	char *path, *out_buf = NULL;
	int err;

	err = -EPERM;
	if (flags & FUSE_IOCTL_UNRESTRICTED)
		goto err;

	if (flags & FUSE_IOCTL_DIR)
		get_dirhandle(llfi, &fi);
	else
		fi = *llfi;

	if (out_bufsz) {
		err = -ENOMEM;
		out_buf = malloc(out_bufsz);
		if (!out_buf)
			goto err;
	}

	assert(!in_bufsz || !out_bufsz || in_bufsz == out_bufsz);
	if (out_buf && in_bufsz)
		memcpy(out_buf, in_buf, in_bufsz);

	err = get_path_nullok(f, ino, &path);
	if (err)
		goto err;

	fuse_prepare_interrupt(f, req, &d);

	err = fuse_fs_ioctl(f->fs, path, cmd, arg, &fi, flags,
			    out_buf ? out_buf : (void *)in_buf);

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
	int err;
	unsigned revents = 0;

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_poll(f->fs, path, fi, ph, &revents);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	if (!err)
		fuse_reply_poll(req, revents);
	else
		reply_err(req, err);
}

static void fuse_lib_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
		off_t offset, off_t length, struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int err;

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_fallocate(f->fs, path, mode, offset, length, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
	reply_err(req, err);
}

static void fuse_lib_copy_file_range(fuse_req_t req, fuse_ino_t nodeid_in,
				     off_t off_in, struct fuse_file_info *fi_in,
				     fuse_ino_t nodeid_out, off_t off_out,
				     struct fuse_file_info *fi_out, size_t len,
				     int flags)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path_in, *path_out;
	int err;
	ssize_t res;

	err = get_path_nullok(f, nodeid_in, &path_in);
	if (err) {
		reply_err(req, err);
		return;
	}

	err = get_path_nullok(f, nodeid_out, &path_out);
	if (err) {
		free_path(f, nodeid_in, path_in);
		reply_err(req, err);
		return;
	}

	fuse_prepare_interrupt(f, req, &d);
	res = fuse_fs_copy_file_range(f->fs, path_in, fi_in, off_in, path_out,
				      fi_out, off_out, len, flags);
	fuse_finish_interrupt(f, req, &d);

	if (res >= 0)
		fuse_reply_write(req, res);
	else
		reply_err(req, res);

	free_path(f, nodeid_in, path_in);
	free_path(f, nodeid_out, path_out);
}

static int clean_delay(struct fuse *f)
{
	/*
	 * This is calculating the delay between clean runs.  To
	 * reduce the number of cleans we are doing them 10 times
	 * within the remember window.
	 */
	int min_sleep = 60;
	int max_sleep = 3600;
	int sleep_time = f->conf.remember / 10;

	if (sleep_time > max_sleep)
		return max_sleep;
	if (sleep_time < min_sleep)
		return min_sleep;
	return sleep_time;
}

int fuse_clean_cache(struct fuse *f)
{
	struct node_lru *lnode;
	struct list_head *curr, *next;
	struct node *node;
	struct timespec now;

	pthread_mutex_lock(&f->lock);

	curr_time(&now);

	for (curr = f->lru_table.next; curr != &f->lru_table; curr = next) {
		double age;

		next = curr->next;
		lnode = list_entry(curr, struct node_lru, lru);
		node = &lnode->node;

		age = diff_timespec(&now, &lnode->forget_time);
		if (age <= f->conf.remember)
			break;

		assert(node->nlookup == 1);

		/* Don't forget active directories */
		if (node->refctr > 1)
			continue;

		node->nlookup = 0;
		unhash_name(f, node);
		unref_node(f, node);
	}
	pthread_mutex_unlock(&f->lock);

	return clean_delay(f);
}

static struct fuse_lowlevel_ops fuse_path_ops = {
	.init = fuse_lib_init,
	.destroy = fuse_lib_destroy,
	.lookup = fuse_lib_lookup,
	.forget = fuse_lib_forget,
	.forget_multi = fuse_lib_forget_multi,
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
	.write_buf = fuse_lib_write_buf,
	.flush = fuse_lib_flush,
	.release = fuse_lib_release,
	.fsync = fuse_lib_fsync,
	.opendir = fuse_lib_opendir,
	.readdir = fuse_lib_readdir,
	.readdirplus = fuse_lib_readdirplus,
	.releasedir = fuse_lib_releasedir,
	.fsyncdir = fuse_lib_fsyncdir,
	.statfs = fuse_lib_statfs,
	.setxattr = fuse_lib_setxattr,
	.getxattr = fuse_lib_getxattr,
	.listxattr = fuse_lib_listxattr,
	.removexattr = fuse_lib_removexattr,
	.getlk = fuse_lib_getlk,
	.setlk = fuse_lib_setlk,
	.flock = fuse_lib_flock,
	.bmap = fuse_lib_bmap,
	.ioctl = fuse_lib_ioctl,
	.poll = fuse_lib_poll,
	.fallocate = fuse_lib_fallocate,
	.copy_file_range = fuse_lib_copy_file_range,
};

int fuse_notify_poll(struct fuse_pollhandle *ph)
{
	return fuse_lowlevel_notify_poll(ph);
}

struct fuse_session *fuse_get_session(struct fuse *f)
{
	return f->se;
}

static int fuse_session_loop_remember(struct fuse *f)
{
	struct fuse_session *se = f->se;
	int res = 0;
	struct timespec now;
	time_t next_clean;
	struct pollfd fds = {
		.fd = se->fd,
		.events = POLLIN
	};
	struct fuse_buf fbuf = {
		.mem = NULL,
	};

	curr_time(&now);
	next_clean = now.tv_sec;
	while (!fuse_session_exited(se)) {
		unsigned timeout;

		curr_time(&now);
		if (now.tv_sec < next_clean)
			timeout = next_clean - now.tv_sec;
		else
			timeout = 0;

		res = poll(&fds, 1, timeout * 1000);
		if (res == -1) {
			if (errno == -EINTR)
				continue;
			else
				break;
		} else if (res > 0) {
			res = fuse_session_receive_buf_int(se, &fbuf, NULL);

			if (res == -EINTR)
				continue;
			if (res <= 0)
				break;

			fuse_session_process_buf_int(se, &fbuf, NULL);
		} else {
			timeout = fuse_clean_cache(f);
			curr_time(&now);
			next_clean = now.tv_sec + timeout;
		}
	}

	free(fbuf.mem);
	fuse_session_reset(se);
	return res < 0 ? -1 : 0;
}

int fuse_loop(struct fuse *f)
{
	if (!f)
		return -1;

	if (lru_enabled(f))
		return fuse_session_loop_remember(f);

	return fuse_session_loop(f->se);
}

FUSE_SYMVER(".symver fuse_loop_mt_32,fuse_loop_mt@@FUSE_3.2");
int fuse_loop_mt_32(struct fuse *f, struct fuse_loop_config *config)
{
	if (f == NULL)
		return -1;

	int res = fuse_start_cleanup_thread(f);
	if (res)
		return -1;

	res = fuse_session_loop_mt_32(fuse_get_session(f), config);
	fuse_stop_cleanup_thread(f);
	return res;
}

int fuse_loop_mt_31(struct fuse *f, int clone_fd);
FUSE_SYMVER(".symver fuse_loop_mt_31,fuse_loop_mt@FUSE_3.0");
int fuse_loop_mt_31(struct fuse *f, int clone_fd)
{
	struct fuse_loop_config config;
	config.clone_fd = clone_fd;
	config.max_idle_threads = 10;
	return fuse_loop_mt_32(f, &config);
}

void fuse_exit(struct fuse *f)
{
	fuse_session_exit(f->se);
}

struct fuse_context *fuse_get_context(void)
{
	struct fuse_context_i *c = fuse_get_context_internal();

	if (c)
		return &c->ctx;
	else
		return NULL;
}

int fuse_getgroups(int size, gid_t list[])
{
	struct fuse_context_i *c = fuse_get_context_internal();
	if (!c)
		return -EINVAL;

	return fuse_req_getgroups(c->req, size, list);
}

int fuse_interrupted(void)
{
	struct fuse_context_i *c = fuse_get_context_internal();

	if (c)
		return fuse_req_interrupted(c->req);
	else
		return 0;
}

int fuse_invalidate_path(struct fuse *f, const char *path) {
	fuse_ino_t ino;
	int err = lookup_path_in_cache(f, path, &ino);
	if (err) {
		return err;
	}

	return fuse_lowlevel_notify_inval_inode(f->se, ino, 0, 0);
}

#define FUSE_LIB_OPT(t, p, v) { t, offsetof(struct fuse_config, p), v }

static const struct fuse_opt fuse_lib_opts[] = {
	FUSE_OPT_KEY("debug",		      FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("-d",		      FUSE_OPT_KEY_KEEP),
	FUSE_LIB_OPT("debug",		      debug, 1),
	FUSE_LIB_OPT("-d",		      debug, 1),
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
	FUSE_LIB_OPT("noforget",              remember, -1),
	FUSE_LIB_OPT("remember=%u",           remember, 0),
	FUSE_LIB_OPT("modules=%s",	      modules, 0),
	FUSE_OPT_END
};

static int fuse_lib_opt_proc(void *data, const char *arg, int key,
			     struct fuse_args *outargs)
{
	(void) arg; (void) outargs; (void) data; (void) key;

	/* Pass through unknown options */
	return 1;
}


static const struct fuse_opt fuse_help_opts[] = {
	FUSE_LIB_OPT("modules=%s", modules, 1),
	FUSE_OPT_KEY("modules=%s", FUSE_OPT_KEY_KEEP),
	FUSE_OPT_END
};

static void print_module_help(const char *name,
			      fuse_module_factory_t *fac)
{
	struct fuse_args a = FUSE_ARGS_INIT(0, NULL);
	if (fuse_opt_add_arg(&a, "") == -1 ||
	    fuse_opt_add_arg(&a, "-h") == -1)
		return;
	printf("\nOptions for %s module:\n", name);
	(*fac)(&a, NULL);
	fuse_opt_free_args(&a);
}

void fuse_lib_help(struct fuse_args *args)
{
	/* These are not all options, but only the ones that
	   may be of interest to an end-user */
	printf(
"    -o kernel_cache        cache files in kernel\n"
"    -o [no]auto_cache      enable caching based on modification times (off)\n"
"    -o umask=M             set file permissions (octal)\n"
"    -o uid=N               set file owner\n"
"    -o gid=N               set file group\n"
"    -o entry_timeout=T     cache timeout for names (1.0s)\n"
"    -o negative_timeout=T  cache timeout for deleted names (0.0s)\n"
"    -o attr_timeout=T      cache timeout for attributes (1.0s)\n"
"    -o ac_attr_timeout=T   auto cache timeout for attributes (attr_timeout)\n"
"    -o noforget            never forget cached inodes\n"
"    -o remember=T          remember cached inodes for T seconds (0s)\n"
"    -o modules=M1[:M2...]  names of modules to push onto filesystem stack\n");


	/* Print low-level help */
	fuse_lowlevel_help();

	/* Print help for builtin modules */
	print_module_help("subdir", &fuse_module_subdir_factory);
#ifdef HAVE_ICONV
	print_module_help("iconv", &fuse_module_iconv_factory);
#endif

	/* Parse command line options in case we need to
	   activate more modules */
	struct fuse_config conf = { .modules = NULL };
	if (fuse_opt_parse(args, &conf, fuse_help_opts,
			   fuse_lib_opt_proc) == -1
	    || !conf.modules)
		return;
	
	char *module;
	char *next;
	struct fuse_module *m;

	// Iterate over all modules
	for (module = conf.modules; module; module = next) {
		char *p;
		for (p = module; *p && *p != ':'; p++);
		next = *p ? p + 1 : NULL;
		*p = '\0';

		m = fuse_get_module(module);
		if (m)
			print_module_help(module, &m->factory);
	}
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

static int node_table_init(struct node_table *t)
{
	t->size = NODE_TABLE_MIN_SIZE;
	t->array = (struct node **) calloc(1, sizeof(struct node *) * t->size);
	if (t->array == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		return -1;
	}
	t->use = 0;
	t->split = 0;

	return 0;
}

static void *fuse_prune_nodes(void *fuse)
{
	struct fuse *f = fuse;
	int sleep_time;

	while(1) {
		sleep_time = fuse_clean_cache(f);
		sleep(sleep_time);
	}
	return NULL;
}

int fuse_start_cleanup_thread(struct fuse *f)
{
	if (lru_enabled(f))
		return fuse_start_thread(&f->prune_thread, fuse_prune_nodes, f);

	return 0;
}

void fuse_stop_cleanup_thread(struct fuse *f)
{
	if (lru_enabled(f)) {
		pthread_mutex_lock(&f->lock);
		pthread_cancel(f->prune_thread);
		pthread_mutex_unlock(&f->lock);
		pthread_join(f->prune_thread, NULL);
	}
}


FUSE_SYMVER(".symver fuse_new_31,fuse_new@@FUSE_3.1");
struct fuse *fuse_new_31(struct fuse_args *args,
		      const struct fuse_operations *op,
		      size_t op_size, void *user_data)
{
	struct fuse *f;
	struct node *root;
	struct fuse_fs *fs;
	struct fuse_lowlevel_ops llop = fuse_path_ops;

	f = (struct fuse *) calloc(1, sizeof(struct fuse));
	if (f == NULL) {
		fprintf(stderr, "fuse: failed to allocate fuse object\n");
		goto out;
	}

	f->conf.entry_timeout = 1.0;
	f->conf.attr_timeout = 1.0;
	f->conf.negative_timeout = 0.0;
	f->conf.intr_signal = FUSE_DEFAULT_INTR_SIGNAL;

	/* Parse options */
	if (fuse_opt_parse(args, &f->conf, fuse_lib_opts,
			   fuse_lib_opt_proc) == -1)
		goto out_free;

	pthread_mutex_lock(&fuse_context_lock);
	static int builtin_modules_registered = 0;
	/* Have the builtin modules already been registered? */
	if (builtin_modules_registered == 0) {
		/* If not, register them. */
		fuse_register_module("subdir", fuse_module_subdir_factory, NULL);
#ifdef HAVE_ICONV
		fuse_register_module("iconv", fuse_module_iconv_factory, NULL);
#endif
		builtin_modules_registered= 1;
	}
	pthread_mutex_unlock(&fuse_context_lock);

	if (fuse_create_context_key() == -1)
		goto out_free;

	fs = fuse_fs_new(op, op_size, user_data);
	if (!fs)
		goto out_delete_context_key;

	f->fs = fs;

	/* Oh f**k, this is ugly! */
	if (!fs->op.lock) {
		llop.getlk = NULL;
		llop.setlk = NULL;
	}

	f->pagesize = getpagesize();
	init_list_head(&f->partial_slabs);
	init_list_head(&f->full_slabs);
	init_list_head(&f->lru_table);

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

#if defined(__FreeBSD__) || defined(__NetBSD__)
	/*
	 * In FreeBSD, we always use these settings as inode numbers
	 * are needed to make getcwd(3) work.
	 */
	f->conf.readdir_ino = 1;
#endif

	f->se = fuse_session_new(args, &llop, sizeof(llop), f);
	if (f->se == NULL)
		goto out_free_fs;

	if (f->conf.debug) {
		fprintf(stderr, "nullpath_ok: %i\n", f->conf.nullpath_ok);
	}

	/* Trace topmost layer by default */
	f->fs->debug = f->conf.debug;
	f->ctr = 0;
	f->generation = 0;
	if (node_table_init(&f->name_table) == -1)
		goto out_free_session;

	if (node_table_init(&f->id_table) == -1)
		goto out_free_name_table;

	fuse_mutex_init(&f->lock);

	root = alloc_node(f);
	if (root == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		goto out_free_id_table;
	}
	if (lru_enabled(f)) {
		struct node_lru *lnode = node_lru(root);
		init_list_head(&lnode->lru);
	}

	strcpy(root->inline_name, "/");
	root->name = root->inline_name;

	if (f->conf.intr &&
	    fuse_init_intr_signal(f->conf.intr_signal,
				  &f->intr_installed) == -1)
		goto out_free_root;

	root->parent = NULL;
	root->nodeid = FUSE_ROOT_ID;
	inc_nlookup(root);
	hash_id(f, root);

	return f;

out_free_root:
	free(root);
out_free_id_table:
	free(f->id_table.array);
out_free_name_table:
	free(f->name_table.array);
out_free_session:
	fuse_session_destroy(f->se);
out_free_fs:
	if (f->fs->m)
		fuse_put_module(f->fs->m);
	free(f->fs);
	free(f->conf.modules);
out_delete_context_key:
	fuse_delete_context_key();
out_free:
	free(f);
out:
	return NULL;
}

/* Emulates 3.0-style fuse_new(), which processes --help */
struct fuse *fuse_new_30(struct fuse_args *args, const struct fuse_operations *op,
			 size_t op_size, void *private_data);
FUSE_SYMVER(".symver fuse_new_30,fuse_new@FUSE_3.0");
struct fuse *fuse_new_30(struct fuse_args *args,
			 const struct fuse_operations *op,
			 size_t op_size, void *user_data)
{
	struct fuse_config conf;

	memset(&conf, 0, sizeof(conf));

	const struct fuse_opt opts[] = {
		FUSE_LIB_OPT("-h", show_help, 1),
		FUSE_LIB_OPT("--help", show_help, 1),
		FUSE_OPT_END
	};

	if (fuse_opt_parse(args, &conf, opts,
			   fuse_lib_opt_proc) == -1)
		return NULL;

	if (conf.show_help) {
		fuse_lib_help(args);
		return NULL;
	} else
		return fuse_new_31(args, op, op_size, user_data);
}

void fuse_destroy(struct fuse *f)
{
	size_t i;

	if (f->conf.intr && f->intr_installed)
		fuse_restore_intr_signal(f->conf.intr_signal);

	if (f->fs) {
		fuse_create_context(f);

		for (i = 0; i < f->id_table.size; i++) {
			struct node *node;

			for (node = f->id_table.array[i]; node != NULL;
			     node = node->id_next) {
				if (node->is_hidden) {
					char *path;
					if (try_get_path(f, node->nodeid, NULL, &path, NULL, false) == 0) {
						fuse_fs_unlink(f->fs, path);
						free(path);
					}
				}
			}
		}
	}
	for (i = 0; i < f->id_table.size; i++) {
		struct node *node;
		struct node *next;

		for (node = f->id_table.array[i]; node != NULL; node = next) {
			next = node->id_next;
			free_node(f, node);
			f->id_table.use--;
		}
	}
	assert(list_empty(&f->partial_slabs));
	assert(list_empty(&f->full_slabs));

	while (fuse_modules) {
		fuse_put_module(fuse_modules);
	}
	free(f->id_table.array);
	free(f->name_table.array);
	pthread_mutex_destroy(&f->lock);
	fuse_session_destroy(f->se);
	free(f->conf.modules);
	free(f);
	fuse_delete_context_key();
}

int fuse_mount(struct fuse *f, const char *mountpoint) {
	return fuse_session_mount(fuse_get_session(f), mountpoint);
}


void fuse_unmount(struct fuse *f) {
	fuse_session_unmount(fuse_get_session(f));
}

int fuse_version(void)
{
	return FUSE_VERSION;
}

const char *fuse_pkgversion(void)
{
	return PACKAGE_VERSION;
}
