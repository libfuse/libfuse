/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include <config.h>
#include "fuse_lowlevel.h"
#include "fuse_kernel.h"
#include "fuse_opt.h"
#include "fuse_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#define PARAM(inarg) (((char *)(inarg)) + sizeof(*(inarg)))

struct fuse_ll {
    int debug;
    int allow_root;
    struct fuse_lowlevel_ops op;
    int got_init;
    void *userdata;
    uid_t owner;
    struct fuse_conn_info conn;
};

struct fuse_req {
    struct fuse_ll *f;
    uint64_t unique;
    struct fuse_ctx ctx;
    struct fuse_chan *ch;
};

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
    case FUSE_ACCESS:		return "ACCESS";
    case FUSE_CREATE:		return "CREATE";
    default: 			return "???";
    }
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

static void convert_attr(const struct fuse_setattr_in *attr, struct stat *stbuf)
{
    stbuf->st_mode         = attr->mode;
    stbuf->st_uid          = attr->uid;
    stbuf->st_gid          = attr->gid;
    stbuf->st_size         = attr->size;
    stbuf->st_atime        = attr->atime;
    stbuf->st_mtime        = attr->mtime;
#ifdef HAVE_STRUCT_STAT_ST_ATIM
    stbuf->st_atim.tv_nsec = attr->atimensec;
    stbuf->st_mtim.tv_nsec = attr->mtimensec;
#endif
}

static  size_t iov_length(const struct iovec *iov, size_t count)
{
    size_t seg;
    size_t ret = 0;

    for (seg = 0; seg < count; seg++)
        ret += iov[seg].iov_len;
    return ret;
}

static void free_req(fuse_req_t req)
{
    free(req);
}

static int send_reply(fuse_req_t req, int error, const void *arg,
                      size_t argsize)
{
    struct fuse_out_header out;
    struct iovec iov[2];
    size_t count;
    int res;

    if (error <= -1000 || error > 0) {
        fprintf(stderr, "fuse: bad error value: %i\n",  error);
        error = -ERANGE;
    }

    out.unique = req->unique;
    out.error = error;
    count = 1;
    iov[0].iov_base = &out;
    iov[0].iov_len = sizeof(struct fuse_out_header);
    if (argsize && !error) {
        count++;
        iov[1].iov_base = (void *) arg;
        iov[1].iov_len = argsize;
    }
    out.len = iov_length(iov, count);

    if (req->f->debug) {
        printf("   unique: %llu, error: %i (%s), outsize: %i\n",
               out.unique, out.error, strerror(-out.error), out.len);
        fflush(stdout);
    }
    res = fuse_chan_send(req->ch, iov, count);
    free_req(req);

    return res;
}

size_t fuse_dirent_size(size_t namelen)
{
    return FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
}

char *fuse_add_dirent(char *buf, const char *name, const struct stat *stbuf,
                      off_t off)
{
    unsigned namelen = strlen(name);
    unsigned entlen = FUSE_NAME_OFFSET + namelen;
    unsigned entsize = fuse_dirent_size(namelen);
    unsigned padlen = entsize - entlen;
    struct fuse_dirent *dirent = (struct fuse_dirent *) buf;

    dirent->ino = stbuf->st_ino;
    dirent->off = off;
    dirent->namelen = namelen;
    dirent->type = (stbuf->st_mode & 0170000) >> 12;
    strncpy(dirent->name, name, namelen);
    if (padlen)
        memset(buf + entlen, 0, padlen);

    return buf + entsize;
}

static void convert_statfs(const struct statvfs *stbuf,
                           struct fuse_kstatfs *kstatfs)
{
    kstatfs->bsize	= stbuf->f_bsize;
    kstatfs->frsize	= stbuf->f_frsize;
    kstatfs->blocks	= stbuf->f_blocks;
    kstatfs->bfree	= stbuf->f_bfree;
    kstatfs->bavail	= stbuf->f_bavail;
    kstatfs->files	= stbuf->f_files;
    kstatfs->ffree	= stbuf->f_ffree;
    kstatfs->namelen	= stbuf->f_namemax;
}

static int send_reply_ok(fuse_req_t req, const void *arg, size_t argsize)
{
    return send_reply(req, 0, arg, argsize);
}

int fuse_reply_err(fuse_req_t req, int err)
{
    return send_reply(req, -err, NULL, 0);
}

void fuse_reply_none(fuse_req_t req)
{
    free_req(req);
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

static void fill_entry(struct fuse_entry_out *arg,
                       const struct fuse_entry_param *e)
{
    arg->nodeid = e->ino;
    arg->generation = e->generation;
    arg->entry_valid = calc_timeout_sec(e->entry_timeout);
    arg->entry_valid_nsec = calc_timeout_nsec(e->entry_timeout);
    arg->attr_valid = calc_timeout_sec(e->attr_timeout);
    arg->attr_valid_nsec = calc_timeout_nsec(e->attr_timeout);
    convert_stat(&e->attr, &arg->attr);
}

static void fill_open(struct fuse_open_out *arg,
                      const struct fuse_file_info *f)
{
    arg->fh = f->fh;
    if (f->direct_io)
        arg->open_flags |= FOPEN_DIRECT_IO;
    if (f->keep_cache)
        arg->open_flags |= FOPEN_KEEP_CACHE;
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e)
{
    struct fuse_entry_out arg;

    /* before ABI 7.4 e->ino == 0 was invalid, only ENOENT meant
       negative entry */
    if (!e->ino && req->f->conn.proto_minor < 4)
        return fuse_reply_err(req, ENOENT);

    memset(&arg, 0, sizeof(arg));
    fill_entry(&arg, e);
    return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_create(fuse_req_t req, const struct fuse_entry_param *e,
                      const struct fuse_file_info *f)
{
    struct {
        struct fuse_entry_out e;
        struct fuse_open_out o;
    } arg;

    memset(&arg, 0, sizeof(arg));
    fill_entry(&arg.e, e);
    fill_open(&arg.o, f);
    return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_attr(fuse_req_t req, const struct stat *attr,
                    double attr_timeout)
{
    struct fuse_attr_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.attr_valid = calc_timeout_sec(attr_timeout);
    arg.attr_valid_nsec = calc_timeout_nsec(attr_timeout);
    convert_stat(attr, &arg.attr);

    return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_readlink(fuse_req_t req, const char *linkname)
{
    return send_reply_ok(req, linkname, strlen(linkname));
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *f)
{
    struct fuse_open_out arg;

    memset(&arg, 0, sizeof(arg));
    fill_open(&arg, f);
    return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
    struct fuse_write_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.size = count;

    return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
    return send_reply_ok(req, buf, size);
}

int fuse_reply_statfs(fuse_req_t req, const struct statvfs *stbuf)
{
    struct fuse_statfs_out arg;
    size_t size = req->f->conn.proto_minor < 4 ? FUSE_COMPAT_STATFS_SIZE : sizeof(arg);

    memset(&arg, 0, sizeof(arg));
    convert_statfs(stbuf, &arg.st);

    return send_reply_ok(req, &arg, size);
}

int fuse_reply_xattr(fuse_req_t req, size_t count)
{
    struct fuse_getxattr_out arg;

    memset(&arg, 0, sizeof(arg));
    arg.size = count;

    return send_reply_ok(req, &arg, sizeof(arg));
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
        req->f->op.getattr(req, nodeid, NULL);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_setattr(fuse_req_t req, fuse_ino_t nodeid,
                       struct fuse_setattr_in *arg)
{
    if (req->f->op.setattr) {
        struct fuse_file_info *fi = NULL;
        struct fuse_file_info fi_store;
        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        convert_attr(arg, &stbuf);
        if (arg->valid & FATTR_FH) {
            arg->valid &= ~FATTR_FH;
            memset(&fi_store, 0, sizeof(fi_store));
            fi = &fi_store;
            fi->fh = arg->fh;
            fi->fh_old = fi->fh;
        }
        req->f->op.setattr(req, nodeid, &stbuf, arg->valid, fi);
    } else
        fuse_reply_err(req, ENOSYS);
}

static void do_access(fuse_req_t req, fuse_ino_t nodeid,
                      struct fuse_access_in *arg)
{
    if (req->f->op.access)
        req->f->op.access(req, nodeid, arg->mask);
    else
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
                       char *linkname)
{
    if (req->f->op.symlink)
        req->f->op.symlink(req, linkname, nodeid, name);
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

static void do_create(fuse_req_t req, fuse_ino_t nodeid,
                      struct fuse_open_in *arg)
{
    if (req->f->op.create) {
        struct fuse_file_info fi;

        memset(&fi, 0, sizeof(fi));
        fi.flags = arg->flags;

        req->f->op.create(req, nodeid, PARAM(arg), arg->mode, &fi);
    } else
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
        fi.fh_old = fi.fh;
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
    fi.fh_old = fi.fh;
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
    fi.fh_old = fi.fh;

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
    fi.fh_old = fi.fh;

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
    fi.fh_old = fi.fh;

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
    fi.fh_old = fi.fh;

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
    fi.fh_old = fi.fh;

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
    fi.fh_old = fi.fh;

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

static void do_init(fuse_req_t req, struct fuse_init_in *arg)
{
    struct fuse_init_out outarg;
    struct fuse_ll *f = req->f;
    size_t bufsize = fuse_chan_bufsize(req->ch);

    if (f->debug) {
        printf("INIT: %u.%u\n", arg->major, arg->minor);
        if (arg->major > 7 || (arg->major == 7 && arg->minor >= 6)) {
            printf("flags=0x%08x\n", arg->flags);
            printf("max_readahead=0x%08x\n", arg->max_readahead);
        }
        fflush(stdout);
    }
    f->conn.proto_major = arg->major;
    f->conn.proto_minor = arg->minor;

    if (arg->major > 7 || (arg->major == 7 && arg->minor >= 6)) {
        if (f->conn.async_read)
            f->conn.async_read = arg->flags & FUSE_ASYNC_READ;
        if (arg->max_readahead < f->conn.max_readahead)
            f->conn.max_readahead = arg->max_readahead;
    } else {
        f->conn.async_read = 0;
        f->conn.max_readahead = 0;
    }

    if (bufsize < FUSE_MIN_READ_BUFFER) {
        fprintf(stderr, "fuse: warning: buffer size too small: %i\n", bufsize);
        bufsize = FUSE_MIN_READ_BUFFER;
    }

    bufsize -= 4096;
    if (bufsize < f->conn.max_write)
        f->conn.max_write = bufsize;

    f->got_init = 1;
    if (f->op.init)
        f->op.init(f->userdata, &f->conn);

    memset(&outarg, 0, sizeof(outarg));
    outarg.major = FUSE_KERNEL_VERSION;
    outarg.minor = FUSE_KERNEL_MINOR_VERSION;
    if (f->conn.async_read)
        outarg.flags |= FUSE_ASYNC_READ;
    outarg.max_readahead = f->conn.max_readahead;
    outarg.max_write = f->conn.max_write;

    if (f->debug) {
        printf("   INIT: %u.%u\n", outarg.major, outarg.minor);
        printf("   flags=0x%08x\n", outarg.flags);
        printf("   max_readahead=0x%08x\n", outarg.max_readahead);
        printf("   max_write=0x%08x\n", outarg.max_write);
        fflush(stdout);
    }

    send_reply_ok(req, &outarg, arg->minor < 5 ? 8 : sizeof(outarg));
}

void *fuse_req_userdata(fuse_req_t req)
{
    return req->f->userdata;
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
    return &req->ctx;
}

static void fuse_ll_process(void *data, const char *buf, size_t len,
                     struct fuse_chan *ch)
{
    struct fuse_ll *f = (struct fuse_ll *) data;
    struct fuse_in_header *in = (struct fuse_in_header *) buf;
    const void *inarg = buf + sizeof(struct fuse_in_header);
    struct fuse_req *req;

    if (f->debug) {
        printf("unique: %llu, opcode: %s (%i), nodeid: %lu, insize: %i\n",
               in->unique, opname((enum fuse_opcode) in->opcode), in->opcode,
               (unsigned long) in->nodeid, len);
        fflush(stdout);
    }

    req = (struct fuse_req *) malloc(sizeof(struct fuse_req));
    if (req == NULL) {
        fprintf(stderr, "fuse: failed to allocate request\n");
        return;
    }

    req->f = f;
    req->unique = in->unique;
    req->ctx.uid = in->uid;
    req->ctx.gid = in->gid;
    req->ctx.pid = in->pid;
    req->ch = ch;

    if (!f->got_init && in->opcode != FUSE_INIT)
        fuse_reply_err(req, EIO);
    else if (f->allow_root && in->uid != f->owner && in->uid != 0 &&
             in->opcode != FUSE_INIT && in->opcode != FUSE_READ &&
             in->opcode != FUSE_WRITE && in->opcode != FUSE_FSYNC &&
             in->opcode != FUSE_RELEASE && in->opcode != FUSE_READDIR &&
             in->opcode != FUSE_FSYNCDIR && in->opcode != FUSE_RELEASEDIR) {
        fuse_reply_err(req, EACCES);
    } else switch (in->opcode) {
    case FUSE_INIT:
        do_init(req, (struct fuse_init_in *) inarg);
        break;

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

    case FUSE_ACCESS:
        do_access(req, in->nodeid, (struct fuse_access_in *) inarg);
        break;

    case FUSE_CREATE:
        do_create(req, in->nodeid, (struct fuse_open_in *) inarg);
        break;

    default:
        fuse_reply_err(req, ENOSYS);
    }
}

enum {
    KEY_HELP,
    KEY_VERSION,
};

static struct fuse_opt fuse_ll_opts[] = {
    { "debug", offsetof(struct fuse_ll, debug), 1 },
    { "-d", offsetof(struct fuse_ll, debug), 1 },
    { "allow_root", offsetof(struct fuse_ll, allow_root), 1 },
    { "max_write=%u", offsetof(struct fuse_ll, conn.max_write), 0 },
    { "max_readahead=%u", offsetof(struct fuse_ll, conn.max_readahead), 0 },
    { "async_read", offsetof(struct fuse_ll, conn.async_read), 1 },
    { "sync_read", offsetof(struct fuse_ll, conn.async_read), 0 },
    FUSE_OPT_KEY("max_read=", FUSE_OPT_KEY_DISCARD),
    FUSE_OPT_KEY("-h", KEY_HELP),
    FUSE_OPT_KEY("--help", KEY_HELP),
    FUSE_OPT_KEY("-V", KEY_VERSION),
    FUSE_OPT_KEY("--version", KEY_VERSION),
    FUSE_OPT_END
};

static void fuse_ll_version(void)
{
    fprintf(stderr, "using FUSE kernel interface version %i.%i\n",
            FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);
}

static void fuse_ll_help(void)
{
    fprintf(stderr,
"    -o max_write=N         set maximum size of write requests\n"
"    -o max_readahead=N     set maximum readahead\n"
"    -o async_read          perform reads asynchronously (default)\n"
"    -o sync_read           perform reads synchronously\n");
}

static int fuse_ll_opt_proc(void *data, const char *arg, int key,
                            struct fuse_args *outargs)
{
    (void) data; (void) outargs;

    switch (key) {
    case KEY_HELP:
        fuse_ll_help();
        break;

    case KEY_VERSION:
        fuse_ll_version();
        break;

    default:
        fprintf(stderr, "fuse: unknown option `%s'\n", arg);
    }

    return -1;
}

int fuse_lowlevel_is_lib_option(const char *opt)
{
    return fuse_opt_match(fuse_ll_opts, opt);
}

static void fuse_ll_destroy(void *data)
{
    struct fuse_ll *f = (struct fuse_ll *) data;

    if (f->op.destroy)
        f->op.destroy(f->userdata);

    free(f);
}

struct fuse_session *fuse_lowlevel_new_common(struct fuse_args *args,
                                       const struct fuse_lowlevel_ops *op,
                                       size_t op_size, void *userdata)
{
    struct fuse_ll *f;
    struct fuse_session *se;
    struct fuse_session_ops sop = {
        .process = fuse_ll_process,
        .destroy = fuse_ll_destroy,
    };

    if (sizeof(struct fuse_lowlevel_ops) < op_size) {
        fprintf(stderr, "fuse: warning: library too old, some operations may not work\n");
        op_size = sizeof(struct fuse_lowlevel_ops);
    }

    f = (struct fuse_ll *) calloc(1, sizeof(struct fuse_ll));
    if (f == NULL) {
        fprintf(stderr, "fuse: failed to allocate fuse object\n");
        goto out;
    }

    f->conn.async_read = 1;
    f->conn.max_write = UINT_MAX;
    f->conn.max_readahead = UINT_MAX;

    if (fuse_opt_parse(args, f, fuse_ll_opts, fuse_ll_opt_proc) == -1)
        goto out_free;

    memcpy(&f->op, op, op_size);
    f->owner = getuid();
    f->userdata = userdata;

    se = fuse_session_new(&sop, f);
    if (!se)
        goto out_free;

    return se;

 out_free:
    free(f);
 out:
    return NULL;
}


/*
 * always call fuse_lowlevel_new_common() internally, to work around a
 * bug in the FreeBSD runtime linker, which links the old version of a
 * symbol to internal references.
 */
struct fuse_session *fuse_lowlevel_new(struct fuse_args *args,
                                       const struct fuse_lowlevel_ops *op,
                                       size_t op_size, void *userdata)
{
    return fuse_lowlevel_new_common(args, op, op_size, userdata);
}


#include "fuse_lowlevel_compat.h"

#ifndef __FreeBSD__

static void fill_open_compat(struct fuse_open_out *arg,
                      const struct fuse_file_info_compat *f)
{
    arg->fh = f->fh;
    if (f->direct_io)
        arg->open_flags |= FOPEN_DIRECT_IO;
    if (f->keep_cache)
        arg->open_flags |= FOPEN_KEEP_CACHE;
}

static void convert_statfs_compat(const struct statfs *compatbuf,
                                  struct statvfs *buf)
{
    buf->f_bsize	= compatbuf->f_bsize;
    buf->f_blocks	= compatbuf->f_blocks;
    buf->f_bfree	= compatbuf->f_bfree;
    buf->f_bavail	= compatbuf->f_bavail;
    buf->f_files	= compatbuf->f_files;
    buf->f_ffree	= compatbuf->f_ffree;
    buf->f_namemax	= compatbuf->f_namelen;
}

int fuse_reply_open_compat(fuse_req_t req,
                           const struct fuse_file_info_compat *f)
{
    struct fuse_open_out arg;

    memset(&arg, 0, sizeof(arg));
    fill_open_compat(&arg, f);
    return send_reply_ok(req, &arg, sizeof(arg));
}

int fuse_reply_statfs_compat(fuse_req_t req, const struct statfs *stbuf)
{
    struct statvfs newbuf;

    memset(&newbuf, 0, sizeof(newbuf));
    convert_statfs_compat(stbuf, &newbuf);

    return fuse_reply_statfs(req, &newbuf);
}

struct fuse_session *fuse_lowlevel_new_compat(const char *opts,
                                              const struct fuse_lowlevel_ops *op,
                                              size_t op_size, void *userdata)
{
    struct fuse_session *se;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

    if (opts &&
        (fuse_opt_add_arg(&args, "") == -1 ||
         fuse_opt_add_arg(&args, "-o") == -1 ||
         fuse_opt_add_arg(&args, opts) == -1)) {
        fuse_opt_free_args(&args);
        return NULL;
    }
    se = fuse_lowlevel_new(&args, op, op_size, userdata);
    fuse_opt_free_args(&args);

    return se;
}

struct fuse_ll_compat_conf {
    unsigned max_read;
    int set_max_read;
};

static const struct fuse_opt fuse_ll_opts_compat[] = {
    { "max_read=", offsetof(struct fuse_ll_compat_conf, set_max_read), 1 },
    { "max_read=%u", offsetof(struct fuse_ll_compat_conf, max_read), 0 },
    FUSE_OPT_KEY("max_read=", FUSE_OPT_KEY_KEEP),
    FUSE_OPT_END
};

int fuse_sync_compat_args(struct fuse_args *args)
{
    struct fuse_ll_compat_conf conf;

    if (fuse_opt_parse(args, &conf, fuse_ll_opts_compat, NULL) == -1)
        return -1;

    if (fuse_opt_insert_arg(args, 1, "-osync_read"))
        return -1;

    if (conf.set_max_read) {
        char tmpbuf[64];

        sprintf(tmpbuf, "-omax_readahead=%u", conf.max_read);
        if (fuse_opt_insert_arg(args, 1, tmpbuf) == -1)
            return -1;
    }
    return 0;
}

__asm__(".symver fuse_reply_statfs_compat,fuse_reply_statfs@FUSE_2.4");
__asm__(".symver fuse_reply_open_compat,fuse_reply_open@FUSE_2.4");
__asm__(".symver fuse_lowlevel_new_compat,fuse_lowlevel_new@FUSE_2.4");

#else /* __FreeBSD__ */

int fuse_sync_compat_args(struct fuse_args *args)
{
    (void) args;
    return 0;
}

#endif /* __FreeBSD__ */

struct fuse_session *fuse_lowlevel_new_compat25(struct fuse_args *args,
                        const struct fuse_lowlevel_ops_compat25 *op,
                        size_t op_size, void *userdata)
{
    if (fuse_sync_compat_args(args) == -1)
        return NULL;

    return fuse_lowlevel_new_common(args,
                                    (const struct fuse_lowlevel_ops *) op,
                                    op_size, userdata);
}

__asm__(".symver fuse_lowlevel_new_compat25,fuse_lowlevel_new@FUSE_2.5");
