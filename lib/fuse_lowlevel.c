/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "fuse_i.h"
#include "fuse_compat.h"
#include "fuse_kernel.h"
#include "fuse_kernel_compat5.h"

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

struct fuse_ll {
    unsigned int debug : 1;
    unsigned int allow_root : 1;
    int fd;
    struct fuse_lowlevel_operations op;
    volatile int exited;
    int got_init;
    void *user_data;
    int major;
    int minor;
    uid_t owner;
};

struct fuse_cmd {
    char *buf;
    size_t buflen;
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
    default: 			return "???";
    }
}

static void convert_stat(struct stat *stbuf, struct fuse_attr *attr)
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

    if ((f->flags & FUSE_DEBUG)) {
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
        if (!f->exited && errno != ENOENT)
            perror("fuse: writing device");
        return -errno;
    }
    return 0;
}

static int send_reply(struct fuse_ll *f, struct fuse_in_header *in, int error,
                      void *arg, size_t argsize)
{
    struct fuse_out_header out;
    struct iovec iov[2];
    size_t count;

    if (error <= -1000 || error > 0) {
        fprintf(stderr, "fuse: bad error value: %i\n",  error);
        error = -ERANGE;
    }

    out.unique = in->unique;
    out.error = error;
    count = 1;
    iov[0].iov_base = &out;
    iov[0].iov_len = sizeof(struct fuse_out_header);
    if (argsize && !error) {
        count++;
        iov[1].iov_base = arg;
        iov[1].iov_len = argsize;
    }
    return send_reply_raw(f, iov, count);
}

size_t fuse_dirent_size(size_t namelen)
{
    return FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
}

void fuse_add_dirent(char *buf, const char *name, const struct stat *stat,
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

    return 0;
}

static void convert_statfs(struct statfs *statfs, struct fuse_kstatfs *kstatfs)
{
    kstatfs->bsize	= statfs->f_bsize;
    kstatfs->blocks	= statfs->f_blocks;
    kstatfs->bfree	= statfs->f_bfree;
    kstatfs->bavail	= statfs->f_bavail;
    kstatfs->files	= statfs->f_files;
    kstatfs->ffree	= statfs->f_ffree;
    kstatfs->namelen	= statfs->f_namelen;
}

static void do_lookup(fuse_req_t req, fuse_ino_t nodeid, char *name)
{
    if (req->f->op.lookup)
        req->f->op.lookup(req, nodeid, name);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_forget(fuse_req_t req, fuse_ino_t nodeid)
{
    if (req->f->op.forget)
        req->f->op.forget(req, nodeid);
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
    if (req->f->op.setattr)
        req->f->op.setattr(req, nodeid, &arg->attr, arg->valid);
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
        fuse_reply_err(req, ENOSYS);
}

static void do_read(fuse_req_t req, fuse_ino_t nodeid,
                    struct fuse_read_in *arg)
{
    struct fuse_file_info fi;

    memset(&fi, 0, sizeof(fi));
    fi.fh = arg->fh;

    if (req->f->op.read)
        req->f->op.read(req, nodeid, arg->size, arg->offset, &fi);
    else
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
        req->f->op.write(req, nodeid, PARAM(arg), arg->size, arg->offset, &fi);
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
        fuse_reply_err(req, ENOSYS);
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
        fuse_reply_err(req, ENOSYS);
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
        fuse_reply_err(req, ENOSYS);
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

static void do_statfs(fuse_req_t req, fuse_ino_t nodeid)
{
    if (req->f->op.statfs)
        res = req->f->op.statfs(req, nodeid);
    else
        fuse_reply_err(req, ENOSYS);
}

static void do_setxattr(fuse_req_t req, fuse_ino_t nodeid,
                        struct fuse_setxattr_in *arg)
{
    char *name = PARAM(arg);
    unsigned char *value = name + strlen(name) + 1;

    if (req->f->op.setxattr)
            req->f->op.setxattr(req, nodeid, name, value, arg->size, arg->flags);
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

static void do_init(struct fuse_ll *f, struct fuse_in_header *in,
                    struct fuse_init_in_out *arg)
{
    struct fuse_init_in_out outarg;

    if (in->padding == 5) {
        arg->minor = arg->major;
        arg->major = in->padding;
    }

    if (f->flags & FUSE_DEBUG) {
        printf("INIT: %u.%u\n", arg->major, arg->minor);
        fflush(stdout);
    }
    f->got_init = 1;
    if (f->op.init)
        f->user_data = f->op.init();

    if (arg->major == 5) {
        f->major = 5;
        f->minor = 1;
    } else if (arg->major == 6) {
        f->major = 6;
        f->minor = 1;
    } else {
        f->major = FUSE_KERNEL_VERSION;
        f->minor = FUSE_KERNEL_MINOR_VERSION;
    }
    memset(&outarg, 0, sizeof(outarg));
    outarg.major = f->major;
    outarg.minor = f->minor;

    if (f->flags & FUSE_DEBUG) {
        printf("   INIT: %u.%u\n", outarg.major, outarg.minor);
        fflush(stdout);
    }

    send_reply(f, in, 0, &outarg, sizeof(outarg));
}

static void free_cmd(struct fuse_cmd *cmd)
{
    free(cmd->buf);
    free(cmd);
}

void fuse_process_cmd(struct fuse_ll *f, struct fuse_cmd *cmd)
{
    struct fuse_in_header *in = (struct fuse_in_header *) cmd->buf;
    void *inarg = cmd->buf + SIZEOF_COMPAT(f, fuse_in_header);
    struct fuse_context *ctx = fuse_get_context();

    fuse_dec_avail(f);

    if ((f->flags & FUSE_DEBUG)) {
        printf("unique: %llu, opcode: %s (%i), nodeid: %lu, insize: %i\n",
               in->unique, opname(in->opcode), in->opcode,
               (unsigned long) in->nodeid, cmd->buflen);
        fflush(stdout);
    }

    if (!f->got_init && in->opcode != FUSE_INIT) {
        /* Old kernel version probably */
        send_reply(f, in, -EPROTO, NULL, 0);
        goto out;
    }

    if ((f->flags & FUSE_ALLOW_ROOT) && in->uid != f->owner && in->uid != 0 &&
        in->opcode != FUSE_INIT && in->opcode != FUSE_READ &&
        in->opcode != FUSE_WRITE && in->opcode != FUSE_FSYNC &&
        in->opcode != FUSE_RELEASE && in->opcode != FUSE_READDIR &&
        in->opcode != FUSE_FSYNCDIR && in->opcode != FUSE_RELEASEDIR) {
        send_reply(f, in, -EACCES, NULL, 0);
        goto out;
    }

    ctx->fuse = f;
    ctx->uid = in->uid;
    ctx->gid = in->gid;
    ctx->pid = in->pid;
    ctx->private_data = f->user_data;

    switch (in->opcode) {
    case FUSE_LOOKUP:
        do_lookup(f, req, nodeid, (char *) inarg);
        break;

        do_forget(f, in, (struct fuse_forget_in *) inarg);
        break;
    }
    case FUSE_GETATTR:
        do_getattr(f, in);
        break;

    case FUSE_SETATTR:
        do_setattr(f, in, (struct fuse_setattr_in *) inarg);
        break;

    case FUSE_READLINK:
        do_readlink(f, in);
        break;

    case FUSE_MKNOD:
        do_mknod(f, in, (struct fuse_mknod_in *) inarg);
        break;

    case FUSE_MKDIR:
        do_mkdir(f, in, (struct fuse_mkdir_in *) inarg);
        break;

    case FUSE_UNLINK:
        do_unlink(f, in, (char *) inarg);
        break;

    case FUSE_RMDIR:
        do_rmdir(f, in, (char *) inarg);
        break;

    case FUSE_SYMLINK:
        do_symlink(f, in, (char *) inarg,
                   ((char *) inarg) + strlen((char *) inarg) + 1);
        break;

    case FUSE_RENAME:
        do_rename(f, in, (struct fuse_rename_in *) inarg);
        break;

    case FUSE_LINK:
        do_link(f, in, (struct fuse_link_in *) inarg);
        break;

    case FUSE_OPEN:
        do_open(f, in, (struct fuse_open_in *) inarg);
        break;

    case FUSE_FLUSH:
        do_flush(f, in, (struct fuse_flush_in *) inarg);
        break;

    case FUSE_RELEASE:
        do_release(f, in, (struct fuse_release_in *) inarg);
        break;

    case FUSE_READ:
        do_read(f, in, (struct fuse_read_in *) inarg);
        break;

    case FUSE_WRITE:
        do_write(f, in, (struct fuse_write_in *) inarg);
        break;

    case FUSE_STATFS:
        do_statfs(f, in);
        break;

    case FUSE_FSYNC:
        do_fsync(f, in, (struct fuse_fsync_in *) inarg);
        break;

    case FUSE_SETXATTR:
        do_setxattr(f, in, (struct fuse_setxattr_in *) inarg);
        break;

    case FUSE_GETXATTR:
        do_getxattr(f, in, (struct fuse_getxattr_in *) inarg);
        break;

    case FUSE_LISTXATTR:
        do_listxattr(f, in, (struct fuse_getxattr_in *) inarg);
        break;

    case FUSE_REMOVEXATTR:
        do_removexattr(f, in, (char *) inarg);
        break;

    case FUSE_INIT:
        do_init(f, in, (struct fuse_init_in_out *) inarg);
        break;

    case FUSE_OPENDIR:
        do_opendir(f, in, (struct fuse_open_in *) inarg);
        break;

    case FUSE_READDIR:
        do_readdir(f, in, (struct fuse_read_in *) inarg);
        break;

    case FUSE_RELEASEDIR:
        do_releasedir(f, in, (struct fuse_release_in *) inarg);
        break;

    case FUSE_FSYNCDIR:
        do_fsyncdir(f, in, (struct fuse_fsync_in *) inarg);
        break;

    default:
        send_reply(f, in, -ENOSYS, NULL, 0);
    }

 out:
    free_cmd(cmd);
}

int fuse_exited(struct fuse_ll* f)
{
    return f->exited;
}

struct fuse_cmd *fuse_read_cmd(struct fuse_ll *f)
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
    inarg = cmd->buf + SIZEOF_COMPAT(f, fuse_in_header);

    res = read(f->fd, cmd->buf, FUSE_MAX_IN);
    if (res == -1) {
        free_cmd(cmd);
        if (fuse_exited(f) || errno == EINTR || errno == ENOENT)
            return NULL;

        /* ENODEV means we got unmounted, so we silenty return failure */
        if (errno != ENODEV) {
            /* BAD... This will happen again */
            perror("fuse: reading device");
        }

        fuse_exit(f);
        return NULL;
    }
    if ((size_t) res < SIZEOF_COMPAT(f, fuse_in_header)) {
        free_cmd(cmd);
        /* Cannot happen */
        fprintf(stderr, "short read on fuse device\n");
        fuse_exit(f);
        return NULL;
    }
    cmd->buflen = res;


    return cmd;
}

int fuse_loop(struct fuse_ll *f)
{
    if (f == NULL)
        return -1;

    while (1) {
        struct fuse_cmd *cmd;

        if (fuse_exited(f))
            break;

        cmd = fuse_read_cmd(f);
        if (cmd == NULL)
            continue;

        fuse_process_cmd(f, cmd);
    }
    f->exited = 0;
    return 0;
}

int fuse_invalidate(struct fuse_ll *f, const char *path)
{
    (void) f;
    (void) path;
    return -EINVAL;
}

void fuse_exit(struct fuse_ll *f)
{
    f->exited = 1;
}

struct fuse_context *fuse_get_context()
{
    static struct fuse_context context;
    if (fuse_getcontext)
        return fuse_getcontext();
    else
        return &context;
}

void fuse_set_getcontext_func(struct fuse_context *(*func)(void))
{
    fuse_getcontext = func;
}

static int begins_with(const char *s, const char *beg)
{
    if (strncmp(s, beg, strlen(beg)) == 0)
        return 1;
    else
        return 0;
}

int fuse_is_lib_option(const char *opt)
{
    if (strcmp(opt, "debug") == 0 ||
        strcmp(opt, "hard_remove") == 0 ||
        strcmp(opt, "use_ino") == 0 ||
        strcmp(opt, "allow_root") == 0 ||
        strcmp(opt, "readdir_ino") == 0 ||
        begins_with(opt, "umask=") ||
        begins_with(opt, "uid=") ||
        begins_with(opt, "gid="))
        return 1;
    else
        return 0;
}

static int parse_lib_opts(struct fuse_ll *f, const char *opts)
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
                f->flags |= FUSE_DEBUG;
            else if (strcmp(opt, "hard_remove") == 0)
                f->flags |= FUSE_HARD_REMOVE;
            else if (strcmp(opt, "use_ino") == 0)
                f->flags |= FUSE_USE_INO;
            else if (strcmp(opt, "allow_root") == 0)
                f->flags |= FUSE_ALLOW_ROOT;
            else if (strcmp(opt, "readdir_ino") == 0)
                f->flags |= FUSE_READDIR_INO;
            else if (sscanf(opt, "umask=%o", &f->umask) == 1)
                f->flags |= FUSE_SET_MODE;
            else if (sscanf(opt, "uid=%u", &f->uid) == 1)
                f->flags |= FUSE_SET_UID;
            else if(sscanf(opt, "gid=%u", &f->gid) == 1)
                f->flags |= FUSE_SET_GID;
            else
                fprintf(stderr, "fuse: warning: unknown option `%s'\n", opt);
        }
        free(xopts);
    }
    return 0;
}

struct fuse_ll *fuse_lowlevel_new(int fd, const char *opts,
                                  const struct fuse_lowlevel_operations *op,
                                  size_t op_size)
{
    struct fuse_ll *f;

    if (sizeof(struct fuse_lowlevel_operations) < op_size) {
        fprintf(stderr, "fuse: warning: library too old, some operations may not not work\n");
        op_size = sizeof(struct fuse_lowlevel_operations);
    }

    f = (struct fuse_ll *) calloc(1, sizeof(struct fuse_ll));
    if (f == NULL) {
        fprintf(stderr, "fuse: failed to allocate fuse object\n");
        goto out;
    }

    if (parse_lib_opts(f, opts) == -1)
        goto out_free;

    f->fd = fd;
    memcpy(&f->op, op, op_size);
    f->exited = 0;
    f->owner = getuid();

    return f;

 out_free:
    free(f);
 out:
    return NULL;
}


