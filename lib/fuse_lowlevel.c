/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include <config.h>
#include "fuse_lowlevel_i.h"
#include "fuse_kernel.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/uio.h>

#define PARAM(inarg) (((char *)(inarg)) + sizeof(*(inarg)))

struct fuse_cmd {
    char *buf;
    size_t buflen;
};

struct fuse_req {
    struct fuse_ll *f;
    uint64_t unique;
    struct fuse_ctx ctx;
};

#ifndef USE_UCLIBC
#define mutex_init(mut) pthread_mutex_init(mut, NULL)
#else
static void mutex_init(pthread_mutex_t *mut)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
    pthread_mutex_init(mut, &attr);
    pthread_mutexattr_destroy(&attr);
}
#endif

static const char *opname(enum fuse_opcode opcode)
{
    switch (opcode) {
    case FUSE_LOOKUP:		return "LOOKUP";
    case FUSE_FORGET:		return "FORGET";
    case FUSE_GETATTR:		return "GETATTR";
    case FUSE_SETATTR:		return "SETATTR";
    case FUSE_READLINK:		return "READLINK";
    case FUSE_SYMLINK:		return "SYMLINK";
    case FUSE_MKNOD:		return "MKNOD";
    case FUSE_MKDIR:		return "MKDIR";
    case FUSE_UNLINK:		return "UNLINK";
    case FUSE_RMDIR:		return "RMDIR";
    case FUSE_RENAME:		return "RENAME";
    case FUSE_LINK:		return "LINK";
    case FUSE_OPEN:		return "OPEN";
    case FUSE_READ:		return "READ";
    case FUSE_WRITE:		return "WRITE";
    case FUSE_STATFS:		return "STATFS";
    case FUSE_FLUSH:		return "FLUSH";
    case FUSE_RELEASE:		return "RELEASE";
    case FUSE_FSYNC:		return "FSYNC";
    case FUSE_SETXATTR:		return "SETXATTR";
    case FUSE_GETXATTR:		return "GETXATTR";
    case FUSE_LISTXATTR:	return "LISTXATTR";
    case FUSE_REMOVEXATTR:	return "REMOVEXATTR";
    case FUSE_INIT:		return "INIT";
    case FUSE_OPENDIR:		return "OPENDIR";
    case FUSE_READDIR:		return "READDIR";
    case FUSE_RELEASEDIR:	return "RELEASEDIR";
    case FUSE_FSYNCDIR:		return "FSYNCDIR";
    case FUSE_GETLK:		return "GETLK";
    case FUSE_SETLK:		return "SETLK";
    case FUSE_SETLKW:		return "SETLKW";
    default: 			return "???";
    }
}

static inline void fuse_dec_avail(struct fuse_ll *f)
{
    pthread_mutex_lock(&f->worker_lock);
    f->numavail --;
    pthread_mutex_unlock(&f->worker_lock);
}

static inline void fuse_inc_avail(struct fuse_ll *f)
{
    pthread_mutex_lock(&f->worker_lock);
    f->numavail ++;
    pthread_mutex_unlock(&f->worker_lock);
}

static void convert_stat(const struct stat *stbuf, struct fuse_attr *attr)
{
    attr->ino       = stbuf->st_ino;
    attr->mode      = stbuf->st_mode;
    attr->nlink     = stbuf->st_nlink;
    attr->uid       = stbuf->st_uid;
    attr->gid       = stbuf->st_gid;
    attr->rdev      = stbuf->st_rdev;
    attr->size      = stbuf->st_size;
    attr->blocks    = stbuf->st_blocks;
    attr->atime     = stbuf->st_atime;
    attr->mtime     = stbuf->st_mtime;
    attr->ctime     = stbuf->st_ctime;
#ifdef HAVE_STRUCT_STAT_ST_ATIM
    attr->atimensec = stbuf->st_atim.tv_nsec;
    attr->mtimensec = stbuf->st_mtim.tv_nsec;
    attr->ctimensec = stbuf->st_ctim.tv_nsec;
#endif
}

static void convert_attr(const struct fuse_attr *attr, struct stat *stbuf)
{
    stbuf->st_mode         = attr->mode;
    stbuf->st_uid          = attr->uid;
    stbuf->st_gid          = attr->gid;
    stbuf->st_size         = attr->size;
    stbuf->st_atime        = attr->atime;
    stbuf->st_mtime        = attr->mtime;
    stbuf->st_ctime        = attr->ctime;
#ifdef HAVE_STRUCT_STAT_ST_ATIM
    stbuf->st_atim.tv_nsec = attr->atimensec;
    stbuf->st_mtim.tv_nsec = attr->mtimensec;
    stbuf->st_ctim.tv_nsec = attr->ctimensec;
#endif
}

static void convert_file_lock(const struct fuse_file_lock *ffl,
                              struct fuse_lock_param *lk)
{
    lk->type  = ffl->type;
    lk->start = ffl->start;
    lk->end   = ffl->end;
    lk->owner = ffl->owner;
    lk->pid   = ffl->pid;
}

static void convert_lock_param(const struct fuse_lock_param *lk,
                               struct fuse_file_lock *ffl)
{
    ffl->type  = lk->type;
    ffl->start = lk->start;
    ffl->end   = lk->end;
    ffl->owner = lk->owner;
    ffl->pid   = lk->pid;
}

static  size_t iov_length(const struct iovec *iov, size_t count)
{
    size_t seg;
    size_t ret = 0;

    for (seg = 0; seg < count; seg++)
        ret += iov[seg].iov_len;
    return ret;
}

static int send_reply_raw(struct fuse_ll *f, const struct iovec iov[],
                          size_t count)
{
    int res;
    unsigned outsize = iov_length(iov, count);
    struct fuse_out_header *out = (struct fuse_out_header *) iov[0].iov_base;
    out->len = outsize;

    if (f->debug) {
        printf("   unique: %llu, error: %i (%s), outsize: %i\n",
               out->unique, out->error, strerror(-out->error), outsize);
        fflush(stdout);
    }

    /* This needs to be done before the reply, otherwise the scheduler
       could play tricks with us, and only let the counter be
       increased long after the operation is done */
    fuse_inc_avail(f);

    res = writev(f->fd, iov, count);
    if (res == -1) {
        /* ENOENT means the operation was interrupted */
        if (!fuse_ll_exited(f) && errno != ENOENT)
            perror("fuse: writing device");
        return -errno;
    }
    return 0;
}

static int send_reply(struct fuse_ll *f, uint64_t unique, int error,
                      const void *arg, size_t argsize)
{
    struct fuse_out_header out;
    struct iovec iov[2];
    size_t count;

    if (error <= -1000 || error > 0) {
        fprintf(stderr, "fuse: bad error value: %i\n",  error);
        error = -ERANGE;
    }

    out.unique = unique;
    out.error = error;
    count = 1;
    iov[0].iov_base = &out;
    iov[0].iov_len = sizeof(struct fuse_out_header);
    if (argsize && !error) {
        count++;
        iov[1].iov_base = (void *) arg;
        iov[1].iov_len = argsize;
    }
    return send_reply_raw(f, iov, count);
}

size_t fuse_dirent_size(size_t namelen)
{
    return FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
}

char *fuse_add_dirent(char *buf, const char *name, const struct stat *stat,
                      off_t off)
{
    unsigned namelen = strlen(name);
    unsigned entlen = FUSE_NAME_OFFSET + namelen;
    unsigned entsize = fuse_dirent_size(namelen);
    unsigned padlen = entsize - entlen;
    struct fuse_dirent *dirent = (struct fuse_dirent *) buf;

    dirent->ino = stat->st_ino;
    dirent->off = off;
    dirent->namelen = namelen;
    dirent->type = (stat->st_mode & 0170000) >> 12;
    strncpy(dirent->name, name, namelen);
    if (padlen)
        memset(buf + entlen, 0, padlen);

    return buf + entsize;
}

static void convert_statfs(const struct statfs *statfs,
                           struct fuse_kstatfs *kstatfs)
{
    kstatfs->bsize	= statfs->f_bsize;
    kstatfs->blocks	= statfs->f_blocks;
    kstatfs->bfree	= statfs->f_bfree;
    kstatfs->bavail	= statfs->f_bavail;
    kstatfs->files	= statfs->f_files;
    kstatfs->ffree	= statfs->f_ffree;
    kstatfs->namelen	= statfs->f_namelen;
}

static void free_req(fuse_req_t req)
{
    free(req);
}

static int send_reply_req(fuse_req_t req, const void *arg, size_t argsize)
{
    int res = send_reply(req->f, req->unique, 0, arg, argsize);
    free_req(req);
    return res;
}

int fuse_reply_err(fuse_req_t req, int err)
{
    int res = send_reply(req->f, req->unique, -err, NULL, 0);
    free_req(req);
    return res;
}

int fuse_reply_none(fuse_req_t req)
{
    free_req(req);
    return 0;
}

static unsigned long calc_timeout_sec(double t)
{
    if (t > (double) ULONG_MAX)
        return ULONG_MAX;
    else if (t < 0.0)
        return 0;
    else
        return (unsigned long) t;
}

static unsigned int calc_timeout_nsec(double t)
{
    double f = t - (double) calc_timeout_sec(t);
    if (f < 0.0)
        return 0;
    else if (f >= 0.999999999)
        return 999999999;
    else
        return (unsigned int) (f * 1.0e9);
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e)
{
    struct fuse_entry_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.nodeid = e->ino;
    arg.generation = e->generation;
    arg.entry_valid = calc_timeout_sec(e->entry_timeout);
    arg.entry_valid_nsec = calc_timeout_nsec(e->entry_timeout);
    arg.attr_valid = calc_timeout_sec(e->attr_timeout);
    arg.attr_valid_nsec = calc_timeout_nsec(e->attr_timeout);
    convert_stat(&e->attr, &arg.attr);

    return send_reply_req(req, &arg, sizeof(arg));
}

int fuse_reply_attr(fuse_req_t req, const struct stat *attr,
                    double attr_timeout)
{
    struct fuse_attr_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.attr_valid = calc_timeout_sec(attr_timeout);
    arg.attr_valid_nsec = calc_timeout_nsec(attr_timeout);
    convert_stat(attr, &arg.attr);

    return send_reply_req(req, &arg, sizeof(arg));
}

int fuse_reply_readlink(fuse_req_t req, const char *link)
{
    return send_reply_req(req, link, strlen(link));
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *f)
{
    struct fuse_open_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.fh = f->fh;

    return send_reply_req(req, &arg, sizeof(arg));
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
    struct fuse_write_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.size = count;

    return send_reply_req(req, &arg, sizeof(arg));
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
    return send_reply_req(req, buf, size);
}

int fuse_reply_statfs(fuse_req_t req, const struct statfs *statfs)
{
    struct fuse_statfs_out arg;

    memset(&arg, 0, sizeof(arg));
    convert_statfs(statfs, &arg.st);

    return send_reply_req(req, &arg, sizeof(arg));
}

int fuse_reply_xattr(fuse_req_t req, size_t count)
{
    struct fuse_getxattr_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.size = count;

    return send_reply_req(req, &arg, sizeof(arg));
}

int fuse_reply_getlk(fuse_req_t req, const struct fuse_lock_param *lk)
{
    struct fuse_lk_in_out arg;
    
    memset(&arg, 0, sizeof(arg));
    convert_lock_param(lk, &arg.lk);
    
    return send_reply_req(req, &arg, sizeof(arg));
}

static void do_lookup(fuse_req_t req, fuse_ino_t nodeid, char *name)
{
    if (req->f->op.lookup)
        req->f->op.lookup(req, nodeid, name);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_forget(fuse_req_t req, fuse_ino_t nodeid,
                      struct fuse_forget_in *arg)
{
    if (req->f->op.forget)
        req->f->op.forget(req, nodeid, arg->nlookup);
}

static void do_getattr(fuse_req_t req, fuse_ino_t nodeid)
{
    if (req->f->op.getattr)
        req->f->op.getattr(req, nodeid);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_setattr(fuse_req_t req, fuse_ino_t nodeid,
                       struct fuse_setattr_in *arg)
{
    if (req->f->op.setattr) {
        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        convert_attr(&arg->attr, &stbuf);
        req->f->op.setattr(req, nodeid, &stbuf, arg->valid);
    } else
        fuse_reply_err(req, ENOSYS);
}

static void do_readlink(fuse_req_t req, fuse_ino_t nodeid)
{
    if (req->f->op.readlink)
        req->f->op.readlink(req, nodeid);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_mknod(fuse_req_t req, fuse_ino_t nodeid,
                     struct fuse_mknod_in *arg)
{
    if (req->f->op.mknod)
        req->f->op.mknod(req, nodeid, PARAM(arg), arg->mode, arg->rdev);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_mkdir(fuse_req_t req, fuse_ino_t nodeid,
                     struct fuse_mkdir_in *arg)
{
    if (req->f->op.mkdir)
        req->f->op.mkdir(req, nodeid, PARAM(arg), arg->mode);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_unlink(fuse_req_t req, fuse_ino_t nodeid, char *name)
{
    if (req->f->op.unlink)
        req->f->op.unlink(req, nodeid, name);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_rmdir(fuse_req_t req, fuse_ino_t nodeid, char *name)
{
    if (req->f->op.rmdir)
        req->f->op.rmdir(req, nodeid, name);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_symlink(fuse_req_t req, fuse_ino_t nodeid, char *name,
                       char *link)
{
    if (req->f->op.symlink)
        req->f->op.symlink(req, link, nodeid, name);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_rename(fuse_req_t req, fuse_ino_t nodeid,
                      struct fuse_rename_in *arg)
{
    char *oldname = PARAM(arg);
    char *newname = oldname + strlen(oldname) + 1;

    if (req->f->op.rename)
        req->f->op.rename(req, nodeid, oldname, arg->newdir, newname);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_link(fuse_req_t req, fuse_ino_t nodeid,
                    struct fuse_link_in *arg)
{
    if (req->f->op.link)
        req->f->op.link(req, arg->oldnodeid, nodeid, PARAM(arg));
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_open(fuse_req_t req, fuse_ino_t nodeid,
                    struct fuse_open_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.flags = arg->flags;

    if (req->f->op.open)
        req->f->op.open(req, nodeid, &fi);
    else
        fuse_reply_open(req, &fi);
}

static void do_read(fuse_req_t req, fuse_ino_t nodeid,
                    struct fuse_read_in *arg)
{
    if (req->f->op.read) {
        struct fuse_file_info fi;

        memset(&fi, 0, sizeof(fi));
        fi.fh = arg->fh;
        req->f->op.read(req, nodeid, arg->size, arg->offset, &fi);
    } else
        fuse_reply_err(req, ENOSYS);
}

static void do_write(fuse_req_t req, fuse_ino_t nodeid,
                     struct fuse_write_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.fh = arg->fh;
    fi.writepage = arg->write_flags & 1;

    if (req->f->op.write)
        req->f->op.write(req, nodeid, PARAM(arg), arg->size,
                                arg->offset, &fi);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_flush(fuse_req_t req, fuse_ino_t nodeid,
                     struct fuse_flush_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.fh = arg->fh;

    if (req->f->op.flush)
        req->f->op.flush(req, nodeid, &fi);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_release(fuse_req_t req, fuse_ino_t nodeid,
                       struct fuse_release_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.flags = arg->flags;
    fi.fh = arg->fh;

    if (req->f->op.release)
        req->f->op.release(req, nodeid, &fi);
    else
        fuse_reply_err(req, 0);
}

static void do_fsync(fuse_req_t req, fuse_ino_t nodeid,
                     struct fuse_fsync_in *inarg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.fh = inarg->fh;

    if (req->f->op.fsync)
        req->f->op.fsync(req, nodeid, inarg->fsync_flags & 1, &fi);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_opendir(fuse_req_t req, fuse_ino_t nodeid,
                       struct fuse_open_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.flags = arg->flags;

    if (req->f->op.opendir)
        req->f->op.opendir(req, nodeid, &fi);
    else
        fuse_reply_open(req, &fi);
}

static void do_readdir(fuse_req_t req, fuse_ino_t nodeid,
                       struct fuse_read_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.fh = arg->fh;

    if (req->f->op.readdir)
        req->f->op.readdir(req, nodeid, arg->size, arg->offset, &fi);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_releasedir(fuse_req_t req, fuse_ino_t nodeid,
                          struct fuse_release_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.flags = arg->flags;
    fi.fh = arg->fh;

    if (req->f->op.releasedir)
        req->f->op.releasedir(req, nodeid, &fi);
    else
        fuse_reply_err(req, 0);
}

static void do_fsyncdir(fuse_req_t req, fuse_ino_t nodeid,
                        struct fuse_fsync_in *inarg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.fh = inarg->fh;

    if (req->f->op.fsyncdir)
        req->f->op.fsyncdir(req, nodeid, inarg->fsync_flags & 1, &fi);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_statfs(fuse_req_t req)
{
    if (req->f->op.statfs)
        req->f->op.statfs(req);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_setxattr(fuse_req_t req, fuse_ino_t nodeid,
                        struct fuse_setxattr_in *arg)
{
    char *name = PARAM(arg);
    char *value = name + strlen(name) + 1;

    if (req->f->op.setxattr)
            req->f->op.setxattr(req, nodeid, name, value, arg->size,
                                       arg->flags);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_getxattr(fuse_req_t req, fuse_ino_t nodeid,
                        struct fuse_getxattr_in *arg)
{
    if (req->f->op.getxattr)
        req->f->op.getxattr(req, nodeid, PARAM(arg), arg->size);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_listxattr(fuse_req_t req, fuse_ino_t nodeid,
                         struct fuse_getxattr_in *arg)
{
    if (req->f->op.listxattr)
        req->f->op.listxattr(req, nodeid, arg->size);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_removexattr(fuse_req_t req, fuse_ino_t nodeid, char *name)
{
    if (req->f->op.removexattr)
        req->f->op.removexattr(req, nodeid, name);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_getlk(fuse_req_t req, fuse_ino_t nodeid,
                     struct fuse_lk_in_out *arg)
{
    if (req->f->op.getlk) {
        struct fuse_lock_param lk;
        
        memset(&lk, 0, sizeof(lk));
        convert_file_lock(&arg->lk, &lk);
        req->f->op.getlk(req, nodeid, &lk);
    } else
        fuse_reply_err(req, ENOSYS);
}

static void do_setlk(fuse_req_t req, fuse_ino_t nodeid, int sleep, 
                     struct fuse_lk_in_out *arg)
{
    if (req->f->op.setlk) {
        struct fuse_lock_param lk;
        
        memset(&lk, 0, sizeof(lk));
        convert_file_lock(&arg->lk, &lk);
        req->f->op.setlk(req, nodeid, sleep, &lk);
    } else
        fuse_reply_err(req, ENOSYS);
}

static void do_init(struct fuse_ll *f, uint64_t unique,
                    struct fuse_init_in_out *arg)
{
    struct fuse_init_in_out outarg;

    if (f->debug) {
        printf("INIT: %u.%u\n", arg->major, arg->minor);
        fflush(stdout);
    }
    f->got_init = 1;
    if (f->op.init)
        f->userdata = f->op.init(f->userdata);

    f->major = FUSE_KERNEL_VERSION;
    f->minor = FUSE_KERNEL_MINOR_VERSION;

    memset(&outarg, 0, sizeof(outarg));
    outarg.major = f->major;
    outarg.minor = f->minor;

    if (f->debug) {
        printf("   INIT: %u.%u\n", outarg.major, outarg.minor);
        fflush(stdout);
    }

    send_reply(f, unique, 0, &outarg, sizeof(outarg));
}

void *fuse_req_userdata(fuse_req_t req)
{
    return req->f->userdata;
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
    return &req->ctx;
}

static void free_cmd(struct fuse_cmd *cmd)
{
    free(cmd->buf);
    free(cmd);
}

void fuse_ll_process_cmd(struct fuse_ll *f, struct fuse_cmd *cmd)
{
    struct fuse_in_header *in = (struct fuse_in_header *) cmd->buf;
    void *inarg = cmd->buf + sizeof(struct fuse_in_header);
    struct fuse_req *req;

    fuse_dec_avail(f);

    if (f->debug) {
        printf("unique: %llu, opcode: %s (%i), nodeid: %lu, insize: %i\n",
               in->unique, opname(in->opcode), in->opcode,
               (unsigned long) in->nodeid, cmd->buflen);
        fflush(stdout);
    }

    if (!f->got_init) {
        if (in->opcode != FUSE_INIT)
            send_reply(f, in->unique, -EPROTO, NULL, 0);
        else
            do_init(f, in->unique, (struct fuse_init_in_out *) inarg);
        goto out;
    }

    if (f->allow_root && in->uid != f->owner && in->uid != 0 &&
        in->opcode != FUSE_INIT && in->opcode != FUSE_READ &&
        in->opcode != FUSE_WRITE && in->opcode != FUSE_FSYNC &&
        in->opcode != FUSE_RELEASE && in->opcode != FUSE_READDIR &&
        in->opcode != FUSE_FSYNCDIR && in->opcode != FUSE_RELEASEDIR) {
        send_reply(f, in->unique, -EACCES, NULL, 0);
        goto out;
    }

    req = (struct fuse_req *) malloc(sizeof(struct fuse_req));
    if (req == NULL) {
        fprintf(stderr, "fuse: failed to allocate request\n");
        goto out;
    }

    req->f = f;
    req->unique = in->unique;
    req->ctx.uid = in->uid;
    req->ctx.gid = in->gid;
    req->ctx.pid = in->pid;

    switch (in->opcode) {
    case FUSE_LOOKUP:
        do_lookup(req, in->nodeid, (char *) inarg);
        break;

    case FUSE_FORGET:
        do_forget(req, in->nodeid, (struct fuse_forget_in *) inarg);
        break;

    case FUSE_GETATTR:
        do_getattr(req, in->nodeid);
        break;

    case FUSE_SETATTR:
        do_setattr(req, in->nodeid, (struct fuse_setattr_in *) inarg);
        break;

    case FUSE_READLINK:
        do_readlink(req, in->nodeid);
        break;

    case FUSE_MKNOD:
        do_mknod(req, in->nodeid, (struct fuse_mknod_in *) inarg);
        break;

    case FUSE_MKDIR:
        do_mkdir(req, in->nodeid, (struct fuse_mkdir_in *) inarg);
        break;

    case FUSE_UNLINK:
        do_unlink(req, in->nodeid, (char *) inarg);
        break;

    case FUSE_RMDIR:
        do_rmdir(req, in->nodeid, (char *) inarg);
        break;

    case FUSE_SYMLINK:
        do_symlink(req, in->nodeid, (char *) inarg,
                   ((char *) inarg) + strlen((char *) inarg) + 1);
        break;

    case FUSE_RENAME:
        do_rename(req, in->nodeid, (struct fuse_rename_in *) inarg);
        break;

    case FUSE_LINK:
        do_link(req, in->nodeid, (struct fuse_link_in *) inarg);
        break;

    case FUSE_OPEN:
        do_open(req, in->nodeid, (struct fuse_open_in *) inarg);
        break;

    case FUSE_FLUSH:
        do_flush(req, in->nodeid, (struct fuse_flush_in *) inarg);
        break;

    case FUSE_RELEASE:
        do_release(req, in->nodeid, (struct fuse_release_in *) inarg);
        break;

    case FUSE_READ:
        do_read(req, in->nodeid, (struct fuse_read_in *) inarg);
        break;

    case FUSE_WRITE:
        do_write(req, in->nodeid, (struct fuse_write_in *) inarg);
        break;

    case FUSE_STATFS:
        do_statfs(req);
        break;

    case FUSE_FSYNC:
        do_fsync(req, in->nodeid, (struct fuse_fsync_in *) inarg);
        break;

    case FUSE_SETXATTR:
        do_setxattr(req, in->nodeid, (struct fuse_setxattr_in *) inarg);
        break;

    case FUSE_GETXATTR:
        do_getxattr(req, in->nodeid, (struct fuse_getxattr_in *) inarg);
        break;

    case FUSE_LISTXATTR:
        do_listxattr(req, in->nodeid, (struct fuse_getxattr_in *) inarg);
        break;

    case FUSE_REMOVEXATTR:
        do_removexattr(req, in->nodeid, (char *) inarg);
        break;

    case FUSE_OPENDIR:
        do_opendir(req, in->nodeid, (struct fuse_open_in *) inarg);
        break;

    case FUSE_READDIR:
        do_readdir(req, in->nodeid, (struct fuse_read_in *) inarg);
        break;

    case FUSE_RELEASEDIR:
        do_releasedir(req, in->nodeid, (struct fuse_release_in *) inarg);
        break;

    case FUSE_FSYNCDIR:
        do_fsyncdir(req, in->nodeid, (struct fuse_fsync_in *) inarg);
        break;

    case FUSE_GETLK:
        do_getlk(req, in->nodeid, (struct fuse_lk_in_out *) inarg);
        break;

    case FUSE_SETLK:
        do_setlk(req, in->nodeid, 0, (struct fuse_lk_in_out *) inarg);
        break;

    case FUSE_SETLKW:
        do_setlk(req, in->nodeid, 1, (struct fuse_lk_in_out *) inarg);
        break;

    default:
        fuse_reply_err(req, ENOSYS);
    }

 out:
    free_cmd(cmd);
}

void fuse_ll_exit(struct fuse_ll *f)
{
    f->exited = 1;
}

int fuse_ll_exited(struct fuse_ll* f)
{
    return f->exited;
}

struct fuse_cmd *fuse_ll_read_cmd(struct fuse_ll *f)
{
    ssize_t res;
    struct fuse_cmd *cmd;
    struct fuse_in_header *in;
    void *inarg;

    cmd = (struct fuse_cmd *) malloc(sizeof(struct fuse_cmd));
    if (cmd == NULL) {
        fprintf(stderr, "fuse: failed to allocate cmd in read\n");
        return NULL;
    }
    cmd->buf = (char *) malloc(FUSE_MAX_IN);
    if (cmd->buf == NULL) {
        fprintf(stderr, "fuse: failed to allocate read buffer\n");
        free(cmd);
        return NULL;
    }
    in = (struct fuse_in_header *) cmd->buf;
    inarg = cmd->buf + sizeof(struct fuse_in_header);

    res = read(f->fd, cmd->buf, FUSE_MAX_IN);
    if (res == -1) {
        free_cmd(cmd);
        if (fuse_ll_exited(f) || errno == EINTR || errno == ENOENT)
            return NULL;

        /* ENODEV means we got unmounted, so we silenty return failure */
        if (errno != ENODEV) {
            /* BAD... This will happen again */
            perror("fuse: reading device");
        }

        fuse_ll_exit(f);
        return NULL;
    }
    if ((size_t) res < sizeof(struct fuse_in_header)) {
        free_cmd(cmd);
        /* Cannot happen */
        fprintf(stderr, "short read on fuse device\n");
        fuse_ll_exit(f);
        return NULL;
    }
    cmd->buflen = res;


    return cmd;
}

int fuse_ll_loop(struct fuse_ll *f)
{
    if (f == NULL)
        return -1;

    while (1) {
        struct fuse_cmd *cmd;

        if (fuse_ll_exited(f))
            break;

        cmd = fuse_ll_read_cmd(f);
        if (cmd == NULL)
            continue;

        fuse_ll_process_cmd(f, cmd);
    }
    f->exited = 0;
    return 0;
}

int fuse_ll_is_lib_option(const char *opt)
{
    if (strcmp(opt, "debug") == 0 ||
        strcmp(opt, "allow_root") == 0)
        return 1;
    else
        return 0;
}

static int parse_ll_opts(struct fuse_ll *f, const char *opts)
{
    if (opts) {
        char *xopts = strdup(opts);
        char *s = xopts;
        char *opt;

        if (xopts == NULL) {
            fprintf(stderr, "fuse: memory allocation failed\n");
            return -1;
        }

        while((opt = strsep(&s, ","))) {
            if (strcmp(opt, "debug") == 0)
                f->debug = 1;
            else if (strcmp(opt, "allow_root") == 0)
                f->allow_root = 1;
            else
                fprintf(stderr, "fuse: warning: unknown option `%s'\n", opt);
        }
        free(xopts);
    }
    return 0;
}

struct fuse_ll *fuse_ll_new(int fd, const char *opts,
                            const struct fuse_ll_operations *op,
                            size_t op_size, void *userdata)
{
    struct fuse_ll *f;

    if (sizeof(struct fuse_ll_operations) < op_size) {
        fprintf(stderr, "fuse: warning: library too old, some operations may not not work\n");
        op_size = sizeof(struct fuse_ll_operations);
    }

    f = (struct fuse_ll *) calloc(1, sizeof(struct fuse_ll));
    if (f == NULL) {
        fprintf(stderr, "fuse: failed to allocate fuse object\n");
        goto out;
    }

    if (parse_ll_opts(f, opts) == -1)
        goto out_free;

    f->fd = fd;
    memcpy(&f->op, op, op_size);
    f->exited = 0;
    f->owner = getuid();
    f->userdata = userdata;
    mutex_init(&f->worker_lock);

    return f;

 out_free:
    free(f);
 out:
    return NULL;
}

void fuse_ll_destroy(struct fuse_ll *f)
{
    if (f->op.destroy)
        f->op.destroy(f->userdata);

    pthread_mutex_destroy(&f->worker_lock);
    free(f);
}

