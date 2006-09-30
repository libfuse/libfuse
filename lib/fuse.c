/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/


/* For pthread_rwlock_t */
#define _GNU_SOURCE

#include "fuse_i.h"
#include "fuse_lowlevel.h"
#include "fuse_opt.h"
#include "fuse_misc.h"

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
#include <assert.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/time.h>

#define FUSE_MAX_PATH 4096
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
};

struct fuse {
    struct fuse_session *se;
    struct fuse_operations op;
    int compat;
    struct node **name_table;
    size_t name_table_size;
    struct node **id_table;
    size_t id_table_size;
    fuse_ino_t ctr;
    unsigned int generation;
    unsigned int hidectr;
    pthread_mutex_t lock;
    pthread_rwlock_t tree_lock;
    void *user_data;
    struct fuse_config conf;
    int intr_installed;
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
    fuse_ino_t parent;
    char *name;
    uint64_t nlookup;
    int open_count;
    int is_hidden;
    struct timespec stat_updated;
    struct timespec mtime;
    off_t size;
    int cache_valid;
    struct lock *locks;
};

struct fuse_dirhandle {
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

struct fuse_context_i {
    struct fuse_context ctx;
    fuse_req_t req;
};

static pthread_key_t fuse_context_key;
static pthread_mutex_t fuse_context_lock = PTHREAD_MUTEX_INITIALIZER;
static int fuse_context_ref;

static int fuse_compat_open(struct fuse *, fuse_req_t, char *,
                            struct fuse_file_info *);
static void fuse_compat_release(struct fuse *, fuse_req_t, char *,
                                struct fuse_file_info *);
static int fuse_compat_opendir(struct fuse *, fuse_req_t, char *,
                               struct fuse_file_info *);
static int fuse_compat_statfs(struct fuse *, fuse_req_t, struct statvfs *);

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

static unsigned int name_hash(struct fuse *f, fuse_ino_t parent, const char *name)
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
        size_t hash = name_hash(f, node->parent, node->name);
        struct node **nodep = &f->name_table[hash];

        for (; *nodep != NULL; nodep = &(*nodep)->name_next)
            if (*nodep == node) {
                *nodep = node->name_next;
                node->name_next = NULL;
                unref_node(f, get_node(f, node->parent));
                free(node->name);
                node->name = NULL;
                node->parent = 0;
                return;
            }
        fprintf(stderr, "fuse internal error: unable to unhash node: %llu\n",
                (unsigned long long) node->nodeid);
        abort();
    }
}

static int hash_name(struct fuse *f, struct node *node, fuse_ino_t parent,
                     const char *name)
{
    size_t hash = name_hash(f, parent, name);
    node->name = strdup(name);
    if (node->name == NULL)
        return -1;

    get_node(f, parent)->refctr ++;
    node->parent = parent;
    node->name_next = f->name_table[hash];
    f->name_table[hash] = node;
    return 0;
}

static void delete_node(struct fuse *f, struct node *node)
{
    if (f->conf.debug) {
        printf("delete: %llu\n", (unsigned long long) node->nodeid);
        fflush(stdout);
    }
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
        f->ctr++;
        if (!f->ctr)
            f->generation ++;
    } while (f->ctr == 0 || get_node_nocheck(f, f->ctr) != NULL);
    return f->ctr;
}

static struct node *lookup_node(struct fuse *f, fuse_ino_t parent,
                                const char *name)
{
    size_t hash = name_hash(f, parent, name);
    struct node *node;

    for (node = f->name_table[hash]; node != NULL; node = node->name_next)
        if (node->parent == parent && strcmp(node->name, name) == 0)
            return node;

    return NULL;
}

static struct node *find_node(struct fuse *f, fuse_ino_t parent,
                              const char *name)
{
    struct node *node;

    pthread_mutex_lock(&f->lock);
    node = lookup_node(f, parent, name);
    if (node == NULL) {
        node = (struct node *) calloc(1, sizeof(struct node));
        if (node == NULL)
            goto out_err;

        node->refctr = 1;
        node->nodeid = next_id(f);
        node->open_count = 0;
        node->is_hidden = 0;
        node->generation = f->generation;
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

static char *add_name(char *buf, char *s, const char *name)
{
    size_t len = strlen(name);
    s -= len;
    if (s <= buf) {
        fprintf(stderr, "fuse: path too long: ...%s\n", s + len);
        return NULL;
    }
    strncpy(s, name, len);
    s--;
    *s = '/';

    return s;
}

static char *get_path_name(struct fuse *f, fuse_ino_t nodeid, const char *name)
{
    char buf[FUSE_MAX_PATH];
    char *s = buf + FUSE_MAX_PATH - 1;
    struct node *node;

    *s = '\0';

    if (name != NULL) {
        s = add_name(buf, s, name);
        if (s == NULL)
            return NULL;
    }

    pthread_mutex_lock(&f->lock);
    for (node = get_node(f, nodeid); node && node->nodeid != FUSE_ROOT_ID;
         node = get_node(f, node->parent)) {
        if (node->name == NULL) {
            s = NULL;
            break;
        }

        s = add_name(buf, s, node->name);
        if (s == NULL)
            break;
    }
    pthread_mutex_unlock(&f->lock);

    if (node == NULL || s == NULL)
        return NULL;
    else if (*s == '\0')
        return strdup("/");
    else
        return strdup(s);
}

static char *get_path(struct fuse *f, fuse_ino_t nodeid)
{
    return get_path_name(f, nodeid, NULL);
}

static void forget_node(struct fuse *f, fuse_ino_t nodeid, uint64_t nlookup)
{
    struct node *node;
    if (nodeid == FUSE_ROOT_ID)
        return;
    pthread_mutex_lock(&f->lock);
    node = get_node(f, nodeid);
    assert(node->nlookup >= nlookup);
    node->nlookup -= nlookup;
    if (!node->nlookup) {
        unhash_name(f, node);
        unref_node(f, node);
    }
    pthread_mutex_unlock(&f->lock);
}

static void remove_node(struct fuse *f, fuse_ino_t dir, const char *name)
{
    struct node *node;

    pthread_mutex_lock(&f->lock);
    node = lookup_node(f, dir, name);
    if (node != NULL)
        unhash_name(f, node);
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
    newnode  = lookup_node(f, newdir, newname);
    if (node == NULL)
        goto out;

    if (newnode != NULL) {
        if (hide) {
            fprintf(stderr, "fuse: hidden file got created during hiding\n");
            err = -EBUSY;
            goto out;
        }
        unhash_name(f, newnode);
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
        stbuf->st_mode = (stbuf->st_mode & S_IFMT) | (0777 & ~f->conf.umask);
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

static int fuse_do_getattr(struct fuse *f, fuse_req_t req, const char *path,
                           struct stat *buf)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.getattr(path, buf);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static int fuse_do_fgetattr(struct fuse *f, fuse_req_t req, const char *path,
                            struct stat *buf, struct fuse_file_info *fi)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.fgetattr(path, buf, fi);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static int fuse_do_rename(struct fuse *f, fuse_req_t req, const char *oldpath,
                          const char *newpath)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.rename(oldpath, newpath);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static int fuse_do_unlink(struct fuse *f, fuse_req_t req, const char *path)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.unlink(path);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static void fuse_do_release(struct fuse *f, fuse_req_t req, const char *path,
                            struct fuse_file_info *fi)
{
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    f->op.release(path, fi);
    fuse_finish_interrupt(f, req, &d);
}

static int fuse_do_opendir(struct fuse *f, fuse_req_t req, char *path,
                           struct fuse_file_info *fi)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.opendir(path, fi);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static int fuse_do_open(struct fuse *f, fuse_req_t req, char *path,
                           struct fuse_file_info *fi)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.open(path, fi);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static int fuse_do_statfs(struct fuse *f, fuse_req_t req, const char *path,
                          struct statvfs *buf)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.statfs(path, buf);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static void fuse_do_releasedir(struct fuse *f, fuse_req_t req,
                               const char *path, struct fuse_file_info *fi)
{
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    f->op.releasedir(path, fi);
    fuse_finish_interrupt(f, req, &d);
}

static int fuse_do_create(struct fuse *f, fuse_req_t req, const char *path,
                          mode_t mode, struct fuse_file_info *fi)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.create(path, mode, fi);
    fuse_finish_interrupt(f, req, &d);
    return res;
}

static int fuse_do_lock(struct fuse *f, fuse_req_t req, const char *path,
                        struct fuse_file_info *fi, int cmd, struct flock *lock)
{
    int res;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(f, req, &d);
    res = f->op.lock(path, fi, cmd, lock);
    fuse_finish_interrupt(f, req, &d);
    return res;
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

static char *hidden_name(struct fuse *f, fuse_req_t req, fuse_ino_t dir,
                         const char *oldname, char *newname, size_t bufsize)
{
    struct stat buf;
    struct node *node;
    struct node *newnode;
    char *newpath;
    int res;
    int failctr = 10;

    if (!f->op.getattr)
        return NULL;

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
        pthread_mutex_unlock(&f->lock);

        newpath = get_path_name(f, dir, newname);
        if (!newpath)
            break;

        res = fuse_do_getattr(f, req, newpath, &buf);
        if (res != 0)
            break;
        free(newpath);
        newpath = NULL;
    } while(--failctr);

    return newpath;
}

static int hide_node(struct fuse *f, fuse_req_t req, const char *oldpath,
                     fuse_ino_t dir, const char *oldname)
{
    char newname[64];
    char *newpath;
    int err = -EBUSY;

    if (f->op.rename && f->op.unlink) {
        newpath = hidden_name(f, req, dir, oldname, newname, sizeof(newname));
        if (newpath) {
            int res = fuse_do_rename(f, req, oldpath, newpath);
            if (res == 0)
                err = rename_node(f, dir, oldname, dir, newname, 1);
            free(newpath);
        }
    }
    return err;
}

static int mtime_eq(const struct stat *stbuf, const struct timespec *ts)
{
    return stbuf->st_mtime == ts->tv_sec
#ifdef FUSE_STAT_HAS_NANOSEC
        && ST_MTIM(stbuf).tv_nsec == ts->tv_nsec
#endif
        ;
}

static void mtime_set(const struct stat *stbuf, struct timespec *ts)
{
#ifdef FUSE_STAT_HAS_NANOSEC
    *ts = ST_MTIM(stbuf);
#else
    ts->tv_sec = stbuf->st_mtime;
#endif
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
    mtime_set(stbuf, &node->mtime);
    node->size = stbuf->st_size;
    curr_time(&node->stat_updated);
}

static int lookup_path(struct fuse *f, fuse_req_t req, fuse_ino_t nodeid,
                       const char *name, const char *path,
                       struct fuse_entry_param *e, struct fuse_file_info *fi)
{
    int res;

    memset(e, 0, sizeof(struct fuse_entry_param));
    if (fi && f->op.fgetattr)
        res = fuse_do_fgetattr(f, req, path, &e->attr, fi);
    else
        res = fuse_do_getattr(f, req, path, &e->attr);
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
            if (f->conf.debug) {
                printf("   NODEID: %lu\n", (unsigned long) e->ino);
                fflush(stdout);
            }
        }
    }
    return res;
}

static struct fuse_context_i *fuse_get_context_internal(void)
{
    struct fuse_context_i *c;

    c = (struct fuse_context_i *) pthread_getspecific(fuse_context_key);
    if (c == NULL) {
        c = (struct fuse_context_i *) malloc(sizeof(struct fuse_context_i));
        if (c == NULL) {
            /* This is hard to deal with properly, so just abort.  If
               memory is so low that the context cannot be allocated,
               there's not much hope for the filesystem anyway */ 
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
    c->ctx.private_data = c->ctx.fuse->user_data;
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
        if (fuse_reply_entry(req, e) == -ENOENT)
            forget_node(f, e->ino, 1);
    } else
        reply_err(req, err);
}

static void fuse_data_init(void *data, struct fuse_conn_info *conn)
{
    struct fuse *f = (struct fuse *) data;
    struct fuse_context_i *c = fuse_get_context_internal();

    memset(c, 0, sizeof(*c));
    c->ctx.fuse = f;
    c->ctx.private_data = f->user_data;

    if (f->op.init)
        f->user_data = f->op.init(conn);
}

static void fuse_data_destroy(void *data)
{
    struct fuse *f = (struct fuse *) data;
    struct fuse_context_i *c = fuse_get_context_internal();

    memset(c, 0, sizeof(*c));
    c->ctx.fuse = f;
    c->ctx.private_data = f->user_data;

    if (f->op.destroy)
        f->op.destroy(f->user_data);
}

static void fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path_name(f, parent, name);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("LOOKUP %s\n", path);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.getattr) {
            err = lookup_path(f, req, parent, name, path, &e, NULL);
            if (err == -ENOENT && f->conf.negative_timeout != 0.0) {
                e.ino = 0;
                e.entry_timeout = f->conf.negative_timeout;
                err = 0;
            }
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_entry(req, &e, err);
}

static void fuse_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
    struct fuse *f = req_fuse(req);
    if (f->conf.debug) {
        printf("FORGET %llu/%lu\n", (unsigned long long) ino, nlookup);
        fflush(stdout);
    }
    forget_node(f, ino, nlookup);
    fuse_reply_none(req);
}

static void fuse_getattr(fuse_req_t req, fuse_ino_t ino,
                         struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    struct stat buf;
    char *path;
    int err;

    (void) fi;
    memset(&buf, 0, sizeof(buf));

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.getattr)
            err = fuse_do_getattr(f, req, path, &buf);
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
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

static int do_chmod(struct fuse *f, fuse_req_t req, const char *path,
                    struct stat *attr)
{
    int err;

    err = -ENOSYS;
    if (f->op.chmod) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        err = f->op.chmod(path, attr->st_mode);
        fuse_finish_interrupt(f, req, &d);
    }

    return err;
}

static int do_chown(struct fuse *f, fuse_req_t req, const char *path,
                    struct stat *attr, int valid)
{
    int err;
    uid_t uid = (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : (uid_t) -1;
    gid_t gid = (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : (gid_t) -1;

    err = -ENOSYS;
    if (f->op.chown) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        err = f->op.chown(path, uid, gid);
        fuse_finish_interrupt(f, req, &d);
    }

    return err;
}

static int do_truncate(struct fuse *f, fuse_req_t req,  const char *path,
                       struct stat *attr, struct fuse_file_info *fi)
{
    int err;
    struct fuse_intr_data d;

    err = -ENOSYS;
    if (fi && f->op.ftruncate) {
        fuse_prepare_interrupt(f, req, &d);
        err = f->op.ftruncate(path, attr->st_size, fi);
        fuse_finish_interrupt(f, req, &d);
    } else if (f->op.truncate) {
        fuse_prepare_interrupt(f, req, &d);
        err = f->op.truncate(path, attr->st_size);
        fuse_finish_interrupt(f, req, &d);
    }
    return err;
}

static int do_utimens(struct fuse *f, fuse_req_t req, const char *path,
                      struct stat *attr)
{
    int err;
    struct fuse_intr_data d;

    err = -ENOSYS;
    if (f->op.utimens) {
        struct timespec tv[2];
#ifdef FUSE_STAT_HAS_NANOSEC
        tv[0] = ST_ATIM(attr);
        tv[1] = ST_MTIM(attr);
#else
        tv[0].tv_sec = attr->st_atime;
        tv[0].tv_nsec = 0;
        tv[1].tv_sec = attr->st_mtime;
        tv[1].tv_nsec = 0;
#endif
        fuse_prepare_interrupt(f, req, &d);
        err = f->op.utimens(path, tv);
        fuse_finish_interrupt(f, req, &d);
    } else if (f->op.utime) {
        struct utimbuf buf;
        buf.actime = attr->st_atime;
        buf.modtime = attr->st_mtime;
        fuse_prepare_interrupt(f, req, &d);
        err = f->op.utime(path, &buf);
        fuse_finish_interrupt(f, req, &d);
    }

    return err;
}

static void fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                         int valid, struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    struct stat buf;
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.getattr) {
            err = 0;
            if (!err && (valid & FUSE_SET_ATTR_MODE))
                err = do_chmod(f, req, path, attr);
            if (!err && (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)))
                err = do_chown(f, req, path, attr, valid);
            if (!err && (valid & FUSE_SET_ATTR_SIZE))
                err = do_truncate(f, req, path, attr, fi);
            if (!err && (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) == (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME))
                err = do_utimens(f, req, path, attr);
            if (!err)
                err = fuse_do_getattr(f, req, path, &buf);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
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

static void fuse_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("ACCESS %s 0%o\n", path, mask);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.access) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.access(path, mask);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static void fuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct fuse *f = req_fuse_prepare(req);
    char linkname[PATH_MAX + 1];
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.readlink) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.readlink(path, linkname, sizeof(linkname));
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    if (!err) {
        linkname[PATH_MAX] = '\0';
        fuse_reply_readlink(req, linkname);
    } else
        reply_err(req, err);
}

static void fuse_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
                       mode_t mode, dev_t rdev)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path_name(f, parent, name);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("MKNOD %s\n", path);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (S_ISREG(mode) && f->op.create && f->op.getattr) {
            struct fuse_file_info fi;

            memset(&fi, 0, sizeof(fi));
            fi.flags = O_CREAT | O_EXCL | O_WRONLY;
            err = fuse_do_create(f, req, path, mode, &fi);
            if (!err) {
                err = lookup_path(f, req, parent, name, path, &e, &fi);
                if (f->op.release)
                    fuse_do_release(f, req, path, &fi);
            }
        } else if (f->op.mknod && f->op.getattr) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.mknod(path, mode, rdev);
            fuse_finish_interrupt(f, req, &d);
            if (!err)
                err = lookup_path(f, req, parent, name, path, &e, NULL);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_entry(req, &e, err);
}

static void fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                       mode_t mode)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path_name(f, parent, name);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("MKDIR %s\n", path);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.mkdir && f->op.getattr) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.mkdir(path, mode);
            fuse_finish_interrupt(f, req, &d);
            if (!err)
                err = lookup_path(f, req, parent, name, path, &e, NULL);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_entry(req, &e, err);
}

static void fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_wrlock(&f->tree_lock);
    path = get_path_name(f, parent, name);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("UNLINK %s\n", path);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.unlink) {
            if (!f->conf.hard_remove && is_open(f, parent, name))
                err = hide_node(f, req, path, parent, name);
            else {
                err = fuse_do_unlink(f, req, path);
                if (!err)
                    remove_node(f, parent, name);
            }
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static void fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_wrlock(&f->tree_lock);
    path = get_path_name(f, parent, name);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("RMDIR %s\n", path);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.rmdir) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.rmdir(path);
            fuse_finish_interrupt(f, req, &d);
            if (!err)
                remove_node(f, parent, name);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static void fuse_symlink(fuse_req_t req, const char *linkname,
                         fuse_ino_t parent, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path_name(f, parent, name);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("SYMLINK %s\n", path);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.symlink && f->op.getattr) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.symlink(linkname, path);
            fuse_finish_interrupt(f, req, &d);
            if (!err)
                err = lookup_path(f, req, parent, name, path, &e, NULL);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_entry(req, &e, err);
}

static void fuse_rename(fuse_req_t req, fuse_ino_t olddir, const char *oldname,
                        fuse_ino_t newdir, const char *newname)
{
    struct fuse *f = req_fuse_prepare(req);
    char *oldpath;
    char *newpath;
    int err;

    err = -ENOENT;
    pthread_rwlock_wrlock(&f->tree_lock);
    oldpath = get_path_name(f, olddir, oldname);
    if (oldpath != NULL) {
        newpath = get_path_name(f, newdir, newname);
        if (newpath != NULL) {
            if (f->conf.debug) {
                printf("RENAME %s -> %s\n", oldpath, newpath);
                fflush(stdout);
            }
            err = -ENOSYS;
            if (f->op.rename) {
                err = 0;
                if (!f->conf.hard_remove &&
                    is_open(f, newdir, newname))
                    err = hide_node(f, req, newpath, newdir, newname);
                if (!err) {
                    fuse_do_rename(f, req, oldpath, newpath);
                    if (!err)
                        err = rename_node(f, olddir, oldname, newdir, newname, 0);
                }
            }
            free(newpath);
        }
        free(oldpath);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static void fuse_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
                      const char *newname)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *oldpath;
    char *newpath;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    oldpath = get_path(f, ino);
    if (oldpath != NULL) {
        newpath =  get_path_name(f, newparent, newname);
        if (newpath != NULL) {
            if (f->conf.debug) {
                printf("LINK %s\n", newpath);
                fflush(stdout);
            }
            err = -ENOSYS;
            if (f->op.link && f->op.getattr) {
                struct fuse_intr_data d;
                fuse_prepare_interrupt(f, req, &d);
                err = f->op.link(oldpath, newpath);
                fuse_finish_interrupt(f, req, &d);
                if (!err)
                    err = lookup_path(f, req, newparent, newname, newpath, &e,
                                      NULL);
            }
            free(newpath);
        }
        free(oldpath);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_entry(req, &e, err);
}

static void fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                        mode_t mode, struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path_name(f, parent, name);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.create && f->op.getattr) {
            err = fuse_do_create(f, req, path, mode, fi);
            if (!err) {
                if (f->conf.debug) {
                    printf("CREATE[%llu] flags: 0x%x %s\n",
                           (unsigned long long) fi->fh, fi->flags, path);
                    fflush(stdout);
                }
                err = lookup_path(f, req, parent, name, path, &e, fi);
                if (err) {
                    if (f->op.release)
                        fuse_do_release(f, req, path, fi);
                } else if (!S_ISREG(e.attr.st_mode)) {
                    err = -EIO;
                    if (f->op.release)
                        fuse_do_release(f, req, path, fi);
                    forget_node(f, e.ino, 1);
                }
            }
        }
    }

    if (!err) {
        if (f->conf.direct_io)
            fi->direct_io = 1;
        if (f->conf.kernel_cache)
            fi->keep_cache = 1;

        pthread_mutex_lock(&f->lock);
        if (fuse_reply_create(req, &e, fi) == -ENOENT) {
            /* The open syscall was interrupted, so it must be cancelled */
            if(f->op.release)
                fuse_do_release(f, req, path, fi);
            forget_node(f, e.ino, 1);
        } else {
            struct node *node = get_node(f, e.ino);
            node->open_count ++;
        }
        pthread_mutex_unlock(&f->lock);
    } else
        reply_err(req, err);

    if (path)
        free(path);
    pthread_rwlock_unlock(&f->tree_lock);
}

static double diff_timespec(const struct timespec *t1,
                            const struct timespec *t2)
{
    return (t1->tv_sec - t2->tv_sec) + 
        ((double) t1->tv_nsec - (double) t2->tv_nsec) / 1000000000.0;
}

static void open_auto_cache(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
                            const char *path, struct fuse_file_info *fi)
{
    struct node *node = get_node(f, ino);
    if (node->cache_valid) {
        struct timespec now;

        curr_time(&now);
        if (diff_timespec(&now, &node->stat_updated) > f->conf.ac_attr_timeout) {
            struct stat stbuf;
            int err;

            if (f->op.fgetattr)
                err = fuse_do_fgetattr(f, req, path, &stbuf, fi);
            else
                err = fuse_do_getattr(f, req, path, &stbuf);

            if (!err)
                update_stat(node, &stbuf);
            else
                node->cache_valid = 0;
        }
    }
    if (node->cache_valid)
        fi->keep_cache = 1;

    node->cache_valid = 1;
}

static void fuse_open(fuse_req_t req, fuse_ino_t ino,
                      struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path = NULL;
    int err = 0;

    pthread_rwlock_rdlock(&f->tree_lock);
    if (f->op.open) {
        err = -ENOENT;
        path = get_path(f, ino);
        if (path != NULL)
            err = fuse_compat_open(f, req, path, fi);
    }
    if (!err) {
        if (f->conf.debug) {
            printf("OPEN[%llu] flags: 0x%x\n", (unsigned long long) fi->fh,
                   fi->flags);
            fflush(stdout);
        }

        if (f->conf.direct_io)
            fi->direct_io = 1;
        if (f->conf.kernel_cache)
            fi->keep_cache = 1;

        pthread_mutex_lock(&f->lock);
        if (f->conf.auto_cache)
            open_auto_cache(f, req, ino, path, fi);

        if (fuse_reply_open(req, fi) == -ENOENT) {
            /* The open syscall was interrupted, so it must be cancelled */
            if(f->op.release && path != NULL)
                fuse_compat_release(f, req, path, fi);
        } else {
            struct node *node = get_node(f, ino);
            node->open_count ++;
        }
        pthread_mutex_unlock(&f->lock);
    } else
        reply_err(req, err);

    if (path)
        free(path);
    pthread_rwlock_unlock(&f->tree_lock);
}

static void fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                      struct fuse_file_info *fi)
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

    res = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("READ[%llu] %lu bytes from %llu\n",
                   (unsigned long long) fi->fh, (unsigned long) size,
                   (unsigned long long) off);
            fflush(stdout);
        }

        res = -ENOSYS;
        if (f->op.read) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            res = f->op.read(path, buf, size, off, fi);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);

    if (res >= 0) {
        if (f->conf.debug) {
            printf("   READ[%llu] %u bytes\n", (unsigned long long) fi->fh,
                   res);
            fflush(stdout);
        }
        if ((size_t) res > size)
            fprintf(stderr, "fuse: read too many bytes");
        fuse_reply_buf(req, buf, res);
    } else
        reply_err(req, res);

    free(buf);
}

static void fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                       size_t size, off_t off, struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int res;

    res = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("WRITE%s[%llu] %lu bytes to %llu\n",
                   fi->writepage ? "PAGE" : "", (unsigned long long) fi->fh,
                   (unsigned long) size, (unsigned long long) off);
            fflush(stdout);
        }

        res = -ENOSYS;
        if (f->op.write) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            res = f->op.write(path, buf, size, off, fi);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);

    if (res >= 0) {
        if (f->conf.debug) {
            printf("   WRITE%s[%llu] %u bytes\n",
                   fi->writepage ? "PAGE" : "", (unsigned long long) fi->fh,
                   res);
            fflush(stdout);
        }
        if ((size_t) res > size)
            fprintf(stderr, "fuse: wrote too many bytes");
        fuse_reply_write(req, res);
    } else
        reply_err(req, res);
}

static void fuse_release(fuse_req_t req, fuse_ino_t ino,
                         struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    struct node *node;
    int unlink_hidden = 0;

    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (f->conf.debug) {
        printf("RELEASE[%llu] flags: 0x%x\n", (unsigned long long) fi->fh,
               fi->flags);
        fflush(stdout);
    }
    if (f->op.release)
        fuse_compat_release(f, req, path, fi);

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
        fuse_do_unlink(f, req, path);

    if (path)
        free(path);
    pthread_rwlock_unlock(&f->tree_lock);

    reply_err(req, 0);
}

static void fuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
                       struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("FSYNC[%llu]\n", (unsigned long long) fi->fh);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.fsync) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.fsync(path, datasync, fi);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static struct fuse_dirhandle *get_dirhandle(const struct fuse_file_info *llfi,
                                            struct fuse_file_info *fi)
{
    struct fuse_dirhandle *dh = (struct fuse_dirhandle *) (uintptr_t) llfi->fh;
    memset(fi, 0, sizeof(struct fuse_file_info));
    fi->fh = dh->fh;
    fi->fh_old = dh->fh;
    return dh;
}

static void fuse_opendir(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *llfi)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_dirhandle *dh;

    dh = (struct fuse_dirhandle *) malloc(sizeof(struct fuse_dirhandle));
    if (dh == NULL) {
        reply_err(req, -ENOMEM);
        return;
    }
    memset(dh, 0, sizeof(struct fuse_dirhandle));
    dh->fuse = f;
    dh->contents = NULL;
    dh->len = 0;
    dh->filled = 0;
    dh->nodeid = ino;
    fuse_mutex_init(&dh->lock);

    llfi->fh = (uintptr_t) dh;

    if (f->op.opendir) {
        struct fuse_file_info fi;
        char *path;
        int err;

        memset(&fi, 0, sizeof(fi));
        fi.flags = llfi->flags;

        err = -ENOENT;
        pthread_rwlock_rdlock(&f->tree_lock);
        path = get_path(f, ino);
        if (path != NULL) {
            err = fuse_compat_opendir(f, req, path, &fi);
            dh->fh = fi.fh;
        }
        if (!err) {
            pthread_mutex_lock(&f->lock);
            if (fuse_reply_open(req, llfi) == -ENOENT) {
                /* The opendir syscall was interrupted, so it must be
                   cancelled */
                if(f->op.releasedir)
                    fuse_do_releasedir(f, req, path, &fi);
                pthread_mutex_destroy(&dh->lock);
                free(dh);
            }
            pthread_mutex_unlock(&f->lock);
        } else {
            reply_err(req, err);
            free(dh);
        }
        free(path);
        pthread_rwlock_unlock(&f->tree_lock);
    } else
        fuse_reply_open(req, llfi);
}

static int extend_contents(struct fuse_dirhandle *dh, unsigned minsize)
{
    if (minsize > dh->size) {
        char *newptr;
        unsigned newsize = dh->size;
        if (!newsize)
            newsize = 1024;
        while (newsize < minsize)
            newsize *= 2;

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

static int fill_dir_common(struct fuse_dirhandle *dh, const char *name,
                           const struct stat *statp, off_t off)
{
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
        newlen = dh->len + fuse_add_direntry(dh->req, dh->contents + dh->len,
                                             dh->needlen - dh->len, name,
                                             &stbuf, off);
        if (newlen > dh->needlen)
            return 1;
    } else {
        newlen = dh->len + fuse_add_direntry(dh->req, NULL, 0, name, NULL, 0);
        if (extend_contents(dh, newlen) == -1)
            return 1;

        fuse_add_direntry(dh->req, dh->contents + dh->len, dh->size - dh->len,
                          name, &stbuf, newlen);
    }
    dh->len = newlen;
    return 0;
}

static int fill_dir(void *buf, const char *name, const struct stat *stbuf,
                    off_t off)
{
    return fill_dir_common((struct fuse_dirhandle *) buf, name, stbuf, off);
}

static int fill_dir_old(struct fuse_dirhandle *dh, const char *name, int type,
                        ino_t ino)
{
    struct stat stbuf;

    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_mode = type << 12;
    stbuf.st_ino = ino;

    fill_dir_common(dh, name, &stbuf, 0);
    return dh->error;
}

static int readdir_fill(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
                        size_t size, off_t off, struct fuse_dirhandle *dh,
                        struct fuse_file_info *fi)
{
    int err = -ENOENT;
    char *path;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        dh->len = 0;
        dh->error = 0;
        dh->needlen = size;
        dh->filled = 1;
        dh->req = req;
        err = -ENOSYS;
        if (f->op.readdir) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.readdir(path, dh, fill_dir, off, fi);
            fuse_finish_interrupt(f, req, &d);
        } else if (f->op.getdir) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.getdir(path, dh, fill_dir_old);
            fuse_finish_interrupt(f, req, &d);
        }
        dh->req = NULL;
        if (!err)
            err = dh->error;
        if (err)
            dh->filled = 0;
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    return err;
}

static void fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                         off_t off, struct fuse_file_info *llfi)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_file_info fi;
    struct fuse_dirhandle *dh = get_dirhandle(llfi, &fi);

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

static void fuse_releasedir(fuse_req_t req, fuse_ino_t ino,
                            struct fuse_file_info *llfi)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_file_info fi;
    struct fuse_dirhandle *dh = get_dirhandle(llfi, &fi);
    if (f->op.releasedir) {
        char *path;

        pthread_rwlock_rdlock(&f->tree_lock);
        path = get_path(f, ino);
        fuse_do_releasedir(f, req, path ? path : "-", &fi);
        free(path);
        pthread_rwlock_unlock(&f->tree_lock);
    }
    pthread_mutex_lock(&dh->lock);
    pthread_mutex_unlock(&dh->lock);
    pthread_mutex_destroy(&dh->lock);
    free(dh->contents);
    free(dh);
    reply_err(req, 0);
}

static void fuse_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
                          struct fuse_file_info *llfi)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_file_info fi;
    char *path;
    int err;

    get_dirhandle(llfi, &fi);

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.fsyncdir) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.fsyncdir(path, datasync, &fi);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static int default_statfs(struct statvfs *buf)
{
    buf->f_namemax = 255;
    buf->f_bsize = 512;
    return 0;
}

static void fuse_statfs(fuse_req_t req, fuse_ino_t ino)
{
    struct fuse *f = req_fuse_prepare(req);
    struct statvfs buf;
    int err;

    memset(&buf, 0, sizeof(buf));
    if (f->op.statfs) {
        if (ino && (!f->compat || f->compat >= 26)) {
            char *path;
            pthread_rwlock_rdlock(&f->tree_lock);
            err = -ENOENT;
            path = get_path(f, ino);
            if (path) {
                err = fuse_do_statfs(f, req, path, &buf);
                free(path);
            }
            pthread_rwlock_unlock(&f->tree_lock);
        } else
            err = fuse_compat_statfs(f, req, &buf);
    } else
        err = default_statfs(&buf);

    if (!err)
        fuse_reply_statfs(req, &buf);
    else
        reply_err(req, err);
}

static void fuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                          const char *value, size_t size, int flags)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.setxattr) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.setxattr(path, name, value, size, flags);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static int common_getxattr(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
                           const char *name, char *value, size_t size)
{
    int err;
    char *path;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.getxattr) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.getxattr(path, name, value, size);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    return err;
}

static void fuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
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

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.listxattr) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.listxattr(path, list, size);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    return err;
}

static void fuse_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
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

static void fuse_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.removexattr) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.removexattr(path, name);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
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

    if (lock->type != F_UNLCK || lock->start != 0 || lock->end != OFFSET_MAX) {
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
    lock->end = flock->l_len ? flock->l_start + flock->l_len - 1 : OFFSET_MAX;
    lock->pid = flock->l_pid;
}

static void lock_to_flock(struct lock *lock, struct flock *flock)
{
    flock->l_type = lock->type;
    flock->l_start = lock->start;
    flock->l_len = (lock->end == OFFSET_MAX) ? 0 : lock->end - lock->start + 1;
    flock->l_pid = lock->pid;
}

static void fuse_flush(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        if (f->conf.debug) {
            printf("FLUSH[%llu]\n", (unsigned long long) fi->fh);
            fflush(stdout);
        }
        err = -ENOSYS;
        if (f->op.flush) {
            struct fuse_intr_data d;
            fuse_prepare_interrupt(f, req, &d);
            err = f->op.flush(path, fi);
            fuse_finish_interrupt(f, req, &d);
        }
        free(path);
    }
    if (f->op.lock) {
        struct flock lock;
        struct lock l;
        memset(&lock, 0, sizeof(lock));
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_SET;
        fuse_do_lock(f, req, path, fi, F_SETLK, &lock);
        flock_to_lock(&lock, &l);
        l.owner = fi->lock_owner;
        pthread_mutex_lock(&f->lock);
        locks_insert(get_node(f, ino), &l);
        pthread_mutex_unlock(&f->lock);

        /* if op.lock() is defined FLUSH is needed regardless of op.flush() */
        if (err == -ENOSYS)
            err = 0;
    }
    pthread_rwlock_unlock(&f->tree_lock);
    reply_err(req, err);
}

static int fuse_lock_common(fuse_req_t req, fuse_ino_t ino,
                            struct fuse_file_info *fi, struct flock *lock,
                            int cmd)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = fuse_do_lock(f, req, path, fi, cmd, lock);
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    return err;
}

static void fuse_getlk(fuse_req_t req, fuse_ino_t ino,
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

static void fuse_setlk(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi, struct flock *lock,
                       int sleep)
{
    int err = fuse_lock_common(req, ino, fi, lock, sleep ? F_SETLKW : F_SETLK);
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

static void fuse_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize,
                      uint64_t idx)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = -ENOENT;
    pthread_rwlock_rdlock(&f->tree_lock);
    path = get_path(f, ino);
    if (path != NULL) {
        err = -ENOSYS;
        if (f->op.bmap)
            err = f->op.bmap(path, blocksize, &idx);
        free(path);
    }
    pthread_rwlock_unlock(&f->tree_lock);
    if (!err)
        fuse_reply_bmap(req, idx);
    else
        reply_err(req, err);
}

static struct fuse_lowlevel_ops fuse_path_ops = {
    .init = fuse_data_init,
    .destroy = fuse_data_destroy,
    .lookup = fuse_lookup,
    .forget = fuse_forget,
    .getattr = fuse_getattr,
    .setattr = fuse_setattr,
    .access = fuse_access,
    .readlink = fuse_readlink,
    .mknod = fuse_mknod,
    .mkdir = fuse_mkdir,
    .unlink = fuse_unlink,
    .rmdir = fuse_rmdir,
    .symlink = fuse_symlink,
    .rename = fuse_rename,
    .link = fuse_link,
    .create = fuse_create,
    .open = fuse_open,
    .read = fuse_read,
    .write = fuse_write,
    .flush = fuse_flush,
    .release = fuse_release,
    .fsync = fuse_fsync,
    .opendir = fuse_opendir,
    .readdir = fuse_readdir,
    .releasedir = fuse_releasedir,
    .fsyncdir = fuse_fsyncdir,
    .statfs = fuse_statfs,
    .setxattr = fuse_setxattr,
    .getxattr = fuse_getxattr,
    .listxattr = fuse_listxattr,
    .removexattr = fuse_removexattr,
    .getlk = fuse_getlk,
    .setlk = fuse_setlk,
    .bmap = fuse_bmap,
};

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
    FUSE_OPT_KEY("-h",                    KEY_HELP),
    FUSE_OPT_KEY("--help",                KEY_HELP),
    FUSE_OPT_KEY("debug",                 FUSE_OPT_KEY_KEEP),
    FUSE_OPT_KEY("-d",                    FUSE_OPT_KEY_KEEP),
    FUSE_LIB_OPT("debug",                 debug, 1),
    FUSE_LIB_OPT("-d",                    debug, 1),
    FUSE_LIB_OPT("hard_remove",           hard_remove, 1),
    FUSE_LIB_OPT("use_ino",               use_ino, 1),
    FUSE_LIB_OPT("readdir_ino",           readdir_ino, 1),
    FUSE_LIB_OPT("direct_io",             direct_io, 1),
    FUSE_LIB_OPT("kernel_cache",          kernel_cache, 1),
    FUSE_LIB_OPT("auto_cache",            auto_cache, 1),
    FUSE_LIB_OPT("noauto_cache",          auto_cache, 0),
    FUSE_LIB_OPT("umask=",                set_mode, 1),
    FUSE_LIB_OPT("umask=%o",              umask, 0),
    FUSE_LIB_OPT("uid=",                  set_uid, 1),
    FUSE_LIB_OPT("uid=%d",                uid, 0),
    FUSE_LIB_OPT("gid=",                  set_gid, 1),
    FUSE_LIB_OPT("gid=%d",                gid, 0),
    FUSE_LIB_OPT("entry_timeout=%lf",     entry_timeout, 0),
    FUSE_LIB_OPT("attr_timeout=%lf",      attr_timeout, 0),
    FUSE_LIB_OPT("ac_attr_timeout=%lf",   ac_attr_timeout, 0),
    FUSE_LIB_OPT("ac_attr_timeout=",      ac_attr_timeout_set, 1),
    FUSE_LIB_OPT("negative_timeout=%lf",  negative_timeout, 0),
    FUSE_LIB_OPT("intr",                  intr, 1),
    FUSE_LIB_OPT("intr_signal=%d",        intr_signal, 0),
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
"    -o [no]auto_cache      enable caching based on modification times\n"
"    -o umask=M             set file permissions (octal)\n"
"    -o uid=N               set file owner\n"
"    -o gid=N               set file group\n"
"    -o entry_timeout=T     cache timeout for names (1.0s)\n"
"    -o negative_timeout=T  cache timeout for deleted names (0.0s)\n"
"    -o attr_timeout=T      cache timeout for attributes (1.0s)\n"
"    -o ac_attr_timeout=T   auto cache timeout for attributes (attr_timeout)\n"
"    -o intr                allow requests to be interrupted\n"
"    -o intr_signal=NUM     signal to send on interrupt (%i)\n"
"\n", FUSE_DEFAULT_INTR_SIGNAL);
}

static int fuse_lib_opt_proc(void *data, const char *arg, int key,
                             struct fuse_args *outargs)
{
    (void) data; (void) arg; (void) outargs;

    if (key == KEY_HELP)
        fuse_lib_help();

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

struct fuse *fuse_new_common(struct fuse_chan *ch, struct fuse_args *args,
                             const struct fuse_operations *op,
                             size_t op_size, void *user_data, int compat)
{
    struct fuse *f;
    struct node *root;
    struct fuse_lowlevel_ops llop = fuse_path_ops;

    if (sizeof(struct fuse_operations) < op_size) {
        fprintf(stderr, "fuse: warning: library too old, some operations may not not work\n");
        op_size = sizeof(struct fuse_operations);
    }

    if (fuse_create_context_key() == -1)
        goto out;

    f = (struct fuse *) calloc(1, sizeof(struct fuse));
    if (f == NULL) {
        fprintf(stderr, "fuse: failed to allocate fuse object\n");
        goto out_delete_context_key;
    }

    f->user_data = user_data;
    f->conf.entry_timeout = 1.0;
    f->conf.attr_timeout = 1.0;
    f->conf.negative_timeout = 0.0;
    f->conf.intr_signal = FUSE_DEFAULT_INTR_SIGNAL;

    if (fuse_opt_parse(args, &f->conf, fuse_lib_opts, fuse_lib_opt_proc) == -1)
            goto out_free;

    if (!f->conf.ac_attr_timeout_set)
        f->conf.ac_attr_timeout = f->conf.attr_timeout;

#ifdef __FreeBSD__
    /*
     * In FreeBSD, we always use these settings as inode numbers are needed to
     * make getcwd(3) work.
     */
    f->conf.readdir_ino = 1;
#endif

    if (compat && compat <= 25) {
        if (fuse_sync_compat_args(args) == -1)
            goto out_free;
    }

    memcpy(&f->op, op, op_size);
    if (!f->op.lock) {
        llop.getlk = NULL;
        llop.setlk = NULL;
    }

    f->se = fuse_lowlevel_new_common(args, &llop, sizeof(llop), f);
    if (f->se == NULL)
        goto out_free;

    fuse_session_add_chan(f->se, ch);

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
    pthread_rwlock_init(&f->tree_lock, NULL);
    f->compat = compat;

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
        fuse_init_intr_signal(f->conf.intr_signal, &f->intr_installed) == -1)
        goto out_free_root_name;

    root->parent = 0;
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
    struct fuse_context_i *c = fuse_get_context_internal();

    if (f->conf.intr && f->intr_installed)
        fuse_restore_intr_signal(f->conf.intr_signal);

    memset(c, 0, sizeof(*c));
    c->ctx.fuse = f;
    c->ctx.private_data = f->user_data;

    for (i = 0; i < f->id_table_size; i++) {
        struct node *node;

        for (node = f->id_table[i]; node != NULL; node = node->id_next) {
            if (node->is_hidden) {
                char *path = get_path(f, node->nodeid);
                if (path) {
                    f->op.unlink(path);
                    free(path);
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
    pthread_rwlock_destroy(&f->tree_lock);
    fuse_session_destroy(f->se);
    free(f);
    fuse_delete_context_key();
}

#include "fuse_common_compat.h"
#include "fuse_compat.h"

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

#ifndef __FreeBSD__

static int fuse_compat_open(struct fuse *f, fuse_req_t req, char *path,
                            struct fuse_file_info *fi)
{
    int err;
    struct fuse_intr_data d;
    if (!f->compat || f->compat >= 25)
        err = fuse_do_open(f, req, path, fi);
    else if (f->compat == 22) {
        struct fuse_file_info_compat tmp;
        memcpy(&tmp, fi, sizeof(tmp));
        fuse_prepare_interrupt(f, req, &d);
        err = ((struct fuse_operations_compat22 *) &f->op)->open(path, &tmp);
        fuse_finish_interrupt(f, req, &d);
        memcpy(fi, &tmp, sizeof(tmp));
        fi->fh = tmp.fh;
    } else {
        fuse_prepare_interrupt(f, req, &d);
        err =
            ((struct fuse_operations_compat2 *) &f->op)->open(path, fi->flags);
        fuse_finish_interrupt(f, req, &d);
    }
    return err;
}

static void fuse_compat_release(struct fuse *f, fuse_req_t req, char *path,
                                struct fuse_file_info *fi)
{
    if (!f->compat || f->compat >= 22)
        fuse_do_release(f, req, path ? path : "-", fi);
    else if (path) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        ((struct fuse_operations_compat2 *) &f->op)->release(path, fi->flags);
        fuse_finish_interrupt(f, req, &d);
    }
}

static int fuse_compat_opendir(struct fuse *f, fuse_req_t req, char *path,
                               struct fuse_file_info *fi)
{
    if (!f->compat || f->compat >= 25) {
        return fuse_do_opendir(f, req, path, fi);
    } else {
        int err;
        struct fuse_file_info_compat tmp;
        struct fuse_intr_data d;
        memcpy(&tmp, fi, sizeof(tmp));
        fuse_prepare_interrupt(f, req, &d);
        err = ((struct fuse_operations_compat22 *) &f->op)->opendir(path, &tmp);
        fuse_finish_interrupt(f, req, &d);
        memcpy(fi, &tmp, sizeof(tmp));
        fi->fh = tmp.fh;
        return err;
    }
}

static void convert_statfs_compat(struct fuse_statfs_compat1 *compatbuf,
                                  struct statvfs *stbuf)
{
    stbuf->f_bsize   = compatbuf->block_size;
    stbuf->f_blocks  = compatbuf->blocks;
    stbuf->f_bfree   = compatbuf->blocks_free;
    stbuf->f_bavail  = compatbuf->blocks_free;
    stbuf->f_files   = compatbuf->files;
    stbuf->f_ffree   = compatbuf->files_free;
    stbuf->f_namemax = compatbuf->namelen;
}

static void convert_statfs_old(struct statfs *oldbuf, struct statvfs *stbuf)
{
    stbuf->f_bsize   = oldbuf->f_bsize;
    stbuf->f_blocks  = oldbuf->f_blocks;
    stbuf->f_bfree   = oldbuf->f_bfree;
    stbuf->f_bavail  = oldbuf->f_bavail;
    stbuf->f_files   = oldbuf->f_files;
    stbuf->f_ffree   = oldbuf->f_ffree;
    stbuf->f_namemax = oldbuf->f_namelen;
}

static int fuse_compat_statfs(struct fuse *f, fuse_req_t req,
                              struct statvfs *buf)
{
    int err;
    struct fuse_intr_data d;

    if (!f->compat || f->compat >= 25) {
        err = fuse_do_statfs(f, req, "/", buf);
    } else if (f->compat > 11) {
        struct statfs oldbuf;
        fuse_prepare_interrupt(f, req, &d);
        err = ((struct fuse_operations_compat22 *) &f->op)->statfs("/", &oldbuf);
        fuse_finish_interrupt(f, req, &d);
        if (!err)
            convert_statfs_old(&oldbuf, buf);
    } else {
        struct fuse_statfs_compat1 compatbuf;
        memset(&compatbuf, 0, sizeof(struct fuse_statfs_compat1));
        fuse_prepare_interrupt(f, req, &d);
        err = ((struct fuse_operations_compat1 *) &f->op)->statfs(&compatbuf);
        fuse_finish_interrupt(f, req, &d);
        if (!err)
            convert_statfs_compat(&compatbuf, buf);
    }
    return err;
}

static struct fuse *fuse_new_common_compat(int fd, const char *opts,
                                           const struct fuse_operations *op,
                                           size_t op_size, int compat)
{
    struct fuse *f;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

    if (opts &&
        (fuse_opt_add_arg(&args, "") == -1 ||
         fuse_opt_add_arg(&args, "-o") == -1 ||
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
                                  sizeof(struct fuse_operations_compat2), 21);
}

struct fuse *fuse_new_compat1(int fd, int flags,
                              const struct fuse_operations_compat1 *op)
{
    const char *opts = NULL;
    if (flags & FUSE_DEBUG_COMPAT1)
        opts = "debug";
    return fuse_new_common_compat(fd, opts, (struct fuse_operations *) op,
                                  sizeof(struct fuse_operations_compat1), 11);
}

__asm__(".symver fuse_exited,__fuse_exited@");
__asm__(".symver fuse_process_cmd,__fuse_process_cmd@");
__asm__(".symver fuse_read_cmd,__fuse_read_cmd@");
__asm__(".symver fuse_set_getcontext_func,__fuse_set_getcontext_func@");
__asm__(".symver fuse_new_compat2,fuse_new@");
__asm__(".symver fuse_new_compat22,fuse_new@FUSE_2.2");

#else /* __FreeBSD__ */

static int fuse_compat_open(struct fuse *f, fuse_req_t req, char *path,
                            struct fuse_file_info *fi)
{
    return fuse_do_open(f, req, path, fi);
}

static void fuse_compat_release(struct fuse *f, fuse_req_t req, char *path,
                                struct fuse_file_info *fi)
{
    fuse_do_release(f, req, path ? path : "-", fi);
}

static int fuse_compat_opendir(struct fuse *f, fuse_req_t req, char *path,
                               struct fuse_file_info *fi)
{
    return fuse_do_opendir(f, req, path, fi);
}

static int fuse_compat_statfs(struct fuse *f, fuse_req_t req, struct statvfs *buf)
{
    return fuse_do_statfs(f, req, "/", buf);
}

#endif /* __FreeBSD__ */

struct fuse *fuse_new_compat25(int fd, struct fuse_args *args,
                               const struct fuse_operations_compat25 *op,
                               size_t op_size)
{
    return fuse_new_common_compat25(fd, args, (struct fuse_operations *) op,
                                    op_size, 25);
}

__asm__(".symver fuse_new_compat25,fuse_new@FUSE_2.5");
