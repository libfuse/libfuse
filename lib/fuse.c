/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "fuse_i.h"
#include <linux/fuse.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/param.h>

#define FUSE_MAX_PATH 4096
#define PARAM(inarg) (((char *)(inarg)) + sizeof(*inarg))

static const char *opname(enum fuse_opcode opcode)
{
    switch(opcode) { 
    case FUSE_LOOKUP:   return "LOOKUP";
    case FUSE_FORGET:   return "FORGET";
    case FUSE_GETATTR:  return "GETATTR";
    case FUSE_SETATTR:  return "SETATTR";
    case FUSE_READLINK: return "READLINK";
    case FUSE_SYMLINK:  return "SYMLINK";
    case FUSE_GETDIR:   return "GETDIR";
    case FUSE_MKNOD:    return "MKNOD";
    case FUSE_MKDIR:    return "MKDIR";
    case FUSE_UNLINK:   return "UNLINK";
    case FUSE_RMDIR:    return "RMDIR";
    case FUSE_RENAME:   return "RENAME";
    case FUSE_LINK:     return "LINK";
    case FUSE_OPEN:     return "OPEN";
    case FUSE_READ:     return "READ";
    case FUSE_WRITE:    return "WRITE";
    case FUSE_STATFS:   return "STATFS";
    case FUSE_RELEASE:  return "RELEASE";
    case FUSE_FSYNC:    return "FSYNC";
    default:            return "???";
    }
}

static inline void inc_avail(struct fuse *f)
{
    pthread_mutex_lock(&f->lock);
    f->numavail ++;
    pthread_mutex_unlock(&f->lock);
}

static inline void dec_avail(struct fuse *f)
{
    pthread_mutex_lock(&f->lock);
    f->numavail --;
    pthread_mutex_unlock(&f->lock);
}

static struct node *__get_node(struct fuse *f, fino_t ino)
{
    size_t hash = ino % f->ino_table_size;
    struct node *node;

    for(node = f->ino_table[hash]; node != NULL; node = node->ino_next)
        if(node->ino == ino)
            return node;
    
    return NULL;
}

static struct node *get_node(struct fuse *f, fino_t ino)
{
    struct node *node = __get_node(f, ino);
    if(node != NULL)
        return node;
    
    fprintf(stderr, "fuse internal error: inode %lu not found\n", ino);
    abort();
}

static void hash_ino(struct fuse *f, struct node *node, fino_t ino)
{
    size_t hash = ino % f->ino_table_size;
    node->ino = ino;
    
    node->ino_next = f->ino_table[hash];
    f->ino_table[hash] = node;    
}

static void unhash_ino(struct fuse *f, struct node *node)
{
    size_t hash = node->ino % f->ino_table_size;
    struct node **nodep = &f->ino_table[hash];

    for(; *nodep != NULL; nodep = &(*nodep)->ino_next) 
        if(*nodep == node) {
            *nodep = node->ino_next;
            return;
        }
}

static fino_t get_ino(struct node *node)
{
    return node->ino;
}

static fino_t next_ino(struct fuse *f)
{
    do f->ctr++;
    while(f->ctr == 0 || __get_node(f, f->ctr) != NULL);
    
    return f->ctr;
}

static void free_node(struct node *node)
{
    free(node->name);
    free(node);
}

static unsigned int name_hash(struct fuse *f, fino_t parent, const char *name)
{
    unsigned int hash = *name;

    if(hash)
        for(name += 1; *name != '\0'; name++)
            hash = (hash << 5) - hash + *name;

    return (hash + parent) % f->name_table_size;
}

static struct node *lookup_node(struct fuse *f, fino_t parent,
                                const char *name)
{
    size_t hash = name_hash(f, parent, name);
    struct node *node;

    for(node = f->name_table[hash]; node != NULL; node = node->name_next)
        if(node->parent == parent && strcmp(node->name, name) == 0)
            return node;

    return NULL;
}

static void hash_name(struct fuse *f, struct node *node, fino_t parent,
                      const char *name)
{
    size_t hash = name_hash(f, parent, name);
    node->parent = parent;
    node->name = strdup(name);
    node->name_next = f->name_table[hash];
    f->name_table[hash] = node;    
}

static void unhash_name(struct fuse *f, struct node *node)
{
    if(node->name != NULL) {
        size_t hash = name_hash(f, node->parent, node->name);
        struct node **nodep = &f->name_table[hash];
        
        for(; *nodep != NULL; nodep = &(*nodep)->name_next)
            if(*nodep == node) {
                *nodep = node->name_next;
                node->name_next = NULL;
                free(node->name);
                node->name = NULL;
                node->parent = 0;
                return;
            }
        fprintf(stderr, "fuse internal error: unable to unhash node: %lu\n",
                node->ino);
        abort();
    }
}

static fino_t find_node(struct fuse *f, fino_t parent, char *name,
                        struct fuse_attr *attr, int version)
{
    struct node *node;
    int mode = attr->mode & S_IFMT;
    int rdev = 0;
    
    if(S_ISCHR(mode) || S_ISBLK(mode))
        rdev = attr->rdev;

    pthread_mutex_lock(&f->lock);
    node = lookup_node(f, parent, name);
    if(node != NULL) {
        if(node->mode == mode && node->rdev == rdev)
            goto out;
        
        unhash_name(f, node);
    }

    node = (struct node *) calloc(1, sizeof(struct node));
    node->mode = mode;
    node->rdev = rdev;
    hash_ino(f, node, next_ino(f));
    hash_name(f, node, parent, name);

  out:
    node->version = version;
    pthread_mutex_unlock(&f->lock);
    return get_ino(node);
}

static char *add_name(char *buf, char *s, const char *name)
{
    size_t len = strlen(name);
    s -= len;
    if(s <= buf) {
        fprintf(stderr, "fuse: path too long: ...%s\n", s + len);
        return NULL;
    }
    strncpy(s, name, len);
    s--;
    *s = '/';

    return s;
}

static char *get_path_name(struct fuse *f, fino_t ino, const char *name)
{
    char buf[FUSE_MAX_PATH];
    char *s = buf + FUSE_MAX_PATH - 1;
    struct node *node;
    
    *s = '\0';

    if(name != NULL) {
        s = add_name(buf, s, name);
        if(s == NULL)
            return NULL;
    }

    pthread_mutex_lock(&f->lock);
    for(node = get_node(f, ino); node->ino != FUSE_ROOT_INO;
        node = get_node(f, node->parent)) {
        if(node->name == NULL) {
            s = NULL;
            break;
        }
        
        s = add_name(buf, s, node->name);
        if(s == NULL)
            break;
    }
    pthread_mutex_unlock(&f->lock);

    if(s == NULL) 
        return NULL;
    else if(*s == '\0')
        return strdup("/");
    else
        return strdup(s);
}

static char *get_path(struct fuse *f, fino_t ino)
{
    return get_path_name(f, ino, NULL);
}

static void destroy_node(struct fuse *f, fino_t ino, int version)
{
    struct node *node;

    pthread_mutex_lock(&f->lock);
    node = get_node(f, ino);
    if(node->version == version && ino != FUSE_ROOT_INO) {
        unhash_name(f, node);
        unhash_ino(f, node);
        free_node(node);
    }
    pthread_mutex_unlock(&f->lock);

}

static void remove_node(struct fuse *f, fino_t dir, const char *name)
{
    struct node *node;

    pthread_mutex_lock(&f->lock);
    node = lookup_node(f, dir, name);
    if(node == NULL) {
        fprintf(stderr, "fuse internal error: unable to remove node %lu/%s\n",
                dir, name);
        abort();
    }
    unhash_name(f, node);
    pthread_mutex_unlock(&f->lock);
}

static void rename_node(struct fuse *f, fino_t olddir, const char *oldname,
                        fino_t newdir, const char *newname)
{
    struct node *node;
    struct node *newnode;
    
    pthread_mutex_lock(&f->lock);
    node  = lookup_node(f, olddir, oldname);
    newnode  = lookup_node(f, newdir, newname);
    if(node == NULL) {
        fprintf(stderr, "fuse internal error: unable to rename node %lu/%s\n",
                olddir, oldname);
        abort();
    }

    if(newnode != NULL)
        unhash_name(f, newnode);
        
    unhash_name(f, node);
    hash_name(f, node, newdir, newname);
    pthread_mutex_unlock(&f->lock);
}

static void convert_stat(struct stat *stbuf, struct fuse_attr *attr)
{
    attr->mode    = stbuf->st_mode;
    attr->nlink   = stbuf->st_nlink;
    attr->uid     = stbuf->st_uid;
    attr->gid     = stbuf->st_gid;
    attr->rdev    = stbuf->st_rdev;
    attr->size    = stbuf->st_size;
    attr->blocks  = stbuf->st_blocks;
    attr->atime   = stbuf->st_atime;
    attr->mtime   = stbuf->st_mtime;
    attr->ctime   = stbuf->st_ctime;
    attr->_dummy  = 4096;
}

static int fill_dir(struct fuse_dirhandle *dh, char *name, int type)
{
    struct fuse_dirent dirent;
    size_t reclen;
    size_t res;

    dirent.ino = (unsigned long) -1;
    dirent.namelen = strlen(name);
    strncpy(dirent.name, name, sizeof(dirent.name));
    dirent.type = type;
    reclen = FUSE_DIRENT_SIZE(&dirent);
    res = fwrite(&dirent, reclen, 1, dh->fp);
    if(res == 0) {
        perror("fuse: writing directory file");
        return -EIO;
    }
    return 0;
}

static int send_reply_raw(struct fuse *f, char *outbuf, size_t outsize)
{
    int res;

    if((f->flags & FUSE_DEBUG)) {
        struct fuse_out_header *out = (struct fuse_out_header *) outbuf;
        printf("   unique: %i, error: %i (%s), outsize: %i\n", out->unique,
               out->error, strerror(-out->error), outsize);
        fflush(stdout);
    }

    /* This needs to be done before the reply because otherwise the
    scheduler can tricks with us, and only let the counter be increased
    long after the operation is done */
    inc_avail(f);

    res = write(f->fd, outbuf, outsize);
    if(res == -1) {
        /* ENOENT means the operation was interrupted */
        if(errno != ENOENT)
            perror("fuse: writing device");
        return -errno;
    }
    return 0;
}

static int send_reply(struct fuse *f, struct fuse_in_header *in, int error,
                      void *arg, size_t argsize)
{
    int res;
    char *outbuf;
    size_t outsize;
    struct fuse_out_header *out;

    if(error <= -512 || error > 0) {
        fprintf(stderr, "fuse: bad error value: %i\n",  error);
        error = -ERANGE;
    }

    if(error)
        argsize = 0;

    outsize = sizeof(struct fuse_out_header) + argsize;
    outbuf = (char *) malloc(outsize);
    out = (struct fuse_out_header *) outbuf;
    memset(out, 0, sizeof(struct fuse_out_header));
    out->unique = in->unique;
    out->error = error;
    if(argsize != 0)
        memcpy(outbuf + sizeof(struct fuse_out_header), arg, argsize);

    res = send_reply_raw(f, outbuf, outsize);
    free(outbuf);

    return res;
}

static void do_lookup(struct fuse *f, struct fuse_in_header *in, char *name)
{
    int res;
    char *path;
    struct stat buf;
    struct fuse_lookup_out arg;

    res = -ENOENT;
    path = get_path_name(f, in->ino, name);
    if(path != NULL) {
        if(f->flags & FUSE_DEBUG) {
            printf("LOOKUP %s\n", path);
            fflush(stdout);
        }
        res = -ENOSYS;
        if(f->op.getattr)
            res = f->op.getattr(path, &buf);
        free(path);
    }

    if(res == 0) {
        memset(&arg, 0, sizeof(struct fuse_lookup_out));
        convert_stat(&buf, &arg.attr);
        arg.ino = find_node(f, in->ino, name, &arg.attr, in->unique);
        if(f->flags & FUSE_DEBUG) {
            printf("   LOOKUP: %li\n", arg.ino);
            fflush(stdout);
        }
    }
    send_reply(f, in, res, &arg, sizeof(arg));
}

static void do_forget(struct fuse *f, struct fuse_in_header *in,
                      struct fuse_forget_in *arg)
{
    if(f->flags & FUSE_DEBUG) {
        printf("FORGET %li/%i\n", in->ino, arg->version);
        fflush(stdout);
    }
    destroy_node(f, in->ino, arg->version);
}

static void do_getattr(struct fuse *f, struct fuse_in_header *in)
{
    int res;
    char *path;
    struct stat buf;
    struct fuse_getattr_out arg;

    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.getattr)
            res = f->op.getattr(path, &buf);
        free(path);
    }

    if(res == 0) {
        memset(&arg, 0, sizeof(struct fuse_getattr_out));
        convert_stat(&buf, &arg.attr);
    }

    send_reply(f, in, res, &arg, sizeof(arg));
}

static int do_chmod(struct fuse *f, const char *path, struct fuse_attr *attr)
{
    int res;

    res = -ENOSYS;
    if(f->op.chmod)
        res = f->op.chmod(path, attr->mode);

    return res;
}        

static int do_chown(struct fuse *f, const char *path, struct fuse_attr *attr,
                    int valid)
{
    int res;
    uid_t uid = (valid & FATTR_UID) ? attr->uid : (uid_t) -1;
    gid_t gid = (valid & FATTR_GID) ? attr->gid : (gid_t) -1;
    
    res = -ENOSYS;
    if(f->op.chown)
        res = f->op.chown(path, uid, gid);

    return res;
}

static int do_truncate(struct fuse *f, const char *path,
                       struct fuse_attr *attr)
{
    int res;

    res = -ENOSYS;
    if(f->op.truncate)
        res = f->op.truncate(path, attr->size);

    return res;
}

static int do_utime(struct fuse *f, const char *path, struct fuse_attr *attr)
{
    int res;
    struct utimbuf buf;
    buf.actime = attr->atime;
    buf.modtime = attr->mtime;
    res = -ENOSYS;
    if(f->op.utime)
        res = f->op.utime(path, &buf);

    return res;
}

static void do_setattr(struct fuse *f, struct fuse_in_header *in,
                       struct fuse_setattr_in *arg)
{
    int res;
    char *path;
    int valid = arg->valid;
    struct fuse_attr *attr = &arg->attr;
    struct fuse_setattr_out outarg;

    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.getattr) {
            res = 0;
            if(!res && (valid & FATTR_MODE))
                res = do_chmod(f, path, attr);
            if(!res && (valid & (FATTR_UID | FATTR_GID)))
                res = do_chown(f, path, attr, valid);
            if(!res && (valid & FATTR_SIZE))
                res = do_truncate(f, path, attr);
            if(!res && (valid & FATTR_UTIME))
                res = do_utime(f, path, attr);
            if(!res) {
                struct stat buf;
                res = f->op.getattr(path, &buf);
                if(!res) {
                    memset(&outarg, 0, sizeof(struct fuse_setattr_out));
                    convert_stat(&buf, &outarg.attr);
                }
            }
        }
        free(path);
    }
    send_reply(f, in, res, &outarg, sizeof(outarg));
}

static void do_readlink(struct fuse *f, struct fuse_in_header *in)
{
    int res;
    char link[PATH_MAX + 1];
    char *path;

    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.readlink)
            res = f->op.readlink(path, link, sizeof(link));
        free(path);
    }
    link[PATH_MAX] = '\0';
    send_reply(f, in, res, link, res == 0 ? strlen(link) : 0);
}

static void do_getdir(struct fuse *f, struct fuse_in_header *in)
{
    int res;
    struct fuse_getdir_out arg;
    struct fuse_dirhandle dh;
    char *path;

    dh.fuse = f;
    dh.fp = tmpfile();
    dh.dir = in->ino;
    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.getdir)
            res = f->op.getdir(path, &dh, (fuse_dirfil_t) fill_dir);
        free(path);
    }
    fflush(dh.fp);

    memset(&arg, 0, sizeof(struct fuse_getdir_out));
    arg.fd = fileno(dh.fp);
    send_reply(f, in, res, &arg, sizeof(arg));
    fclose(dh.fp);
}

static void do_mknod(struct fuse *f, struct fuse_in_header *in,
                     struct fuse_mknod_in *inarg)
{
    int res;
    char *path;
    struct fuse_mknod_out outarg;
    struct stat buf;

    res = -ENOENT;
    path = get_path_name(f, in->ino, PARAM(inarg));
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.mknod && f->op.getattr) {
            res = f->op.mknod(path, inarg->mode, inarg->rdev);
            if(res == 0)
                res = f->op.getattr(path, &buf);
        }
        free(path);
    }
    if(res == 0) {
        memset(&outarg, 0, sizeof(struct fuse_mknod_out));
        convert_stat(&buf, &outarg.attr);
        outarg.ino = find_node(f, in->ino, PARAM(inarg), &outarg.attr,
                               in->unique);
    }

    send_reply(f, in, res, &outarg, sizeof(outarg));
}

static void do_mkdir(struct fuse *f, struct fuse_in_header *in,
                     struct fuse_mkdir_in *inarg)
{
    int res;
    char *path;

    res = -ENOENT;
    path = get_path_name(f, in->ino, PARAM(inarg));
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.mkdir)
            res = f->op.mkdir(path, inarg->mode);
        free(path);
    }
    send_reply(f, in, res, NULL, 0);
}

static void do_remove(struct fuse *f, struct fuse_in_header *in, char *name)
{
    int res;
    char *path;

    res = -ENOENT;
    path = get_path_name(f, in->ino, name);
    if(path != NULL) {
        res = -ENOSYS;
        if(in->opcode == FUSE_UNLINK) {
            if(f->op.unlink)
                res = f->op.unlink(path);
        }
        else {
            if(f->op.rmdir)
                res = f->op.rmdir(path);
        }
        free(path);
    }
    if(res == 0)
        remove_node(f, in->ino, name);
    send_reply(f, in, res, NULL, 0);
}

static void do_symlink(struct fuse *f, struct fuse_in_header *in, char *name,
                       char *link)
{
    int res;
    char *path;

    res = -ENOENT;
    path = get_path_name(f, in->ino, name);
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.symlink)
            res = f->op.symlink(link, path);
        free(path);
    }
    send_reply(f, in, res, NULL, 0);
}

static void do_rename(struct fuse *f, struct fuse_in_header *in,
                      struct fuse_rename_in *inarg)
{
    int res;
    fino_t olddir = in->ino;
    fino_t newdir = inarg->newdir;
    char *oldname = PARAM(inarg);
    char *newname = oldname + strlen(oldname) + 1;
    char *oldpath;
    char *newpath;

    res = -ENOENT;
    oldpath = get_path_name(f, olddir, oldname);
    if(oldpath != NULL) {
        newpath = get_path_name(f, newdir, newname);
        if(newpath != NULL) {
            res = -ENOSYS;
            if(f->op.rename)
                res = f->op.rename(oldpath, newpath);
            if(res == 0)
                rename_node(f, olddir, oldname, newdir, newname);
            free(newpath);
        }
        free(oldpath);
    }
    send_reply(f, in, res, NULL, 0);   
}

static void do_link(struct fuse *f, struct fuse_in_header *in,
                    struct fuse_link_in *arg)
{
    int res;
    char *oldpath;
    char *newpath;

    res = -ENOENT;
    oldpath = get_path(f, in->ino);
    if(oldpath != NULL) {
        newpath =  get_path_name(f, arg->newdir, PARAM(arg));
        if(newpath != NULL) {
            res = -ENOSYS;
            if(f->op.link)
                res = f->op.link(oldpath, newpath);
            free(newpath);
        }
        free(oldpath);
    }
    send_reply(f, in, res, NULL, 0);   
}

static void do_open(struct fuse *f, struct fuse_in_header *in,
                    struct fuse_open_in *arg)
{
    int res;
    int res2;
    char *path;

    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        res = -ENOSYS;
        if(f->op.open)
            res = f->op.open(path, arg->flags);
    }
    res2 = send_reply(f, in, res, NULL, 0);
    if(path != NULL) {
        /* The open syscall was interrupted, so it must be cancelled */
        if(res == 0 && res2 == -ENOENT && f->op.release)
            f->op.release(path, arg->flags);
        free(path);
    }
}

static void do_release(struct fuse *f, struct fuse_in_header *in,
                       struct fuse_open_in *arg)
{
    char *path;

    path = get_path(f, in->ino);
    if(path != NULL) {
        if(f->op.release)
            f->op.release(path, arg->flags);
        free(path);
    }
}

static void do_read(struct fuse *f, struct fuse_in_header *in,
                    struct fuse_read_in *arg)
{
    int res;
    char *path;
    char *outbuf = (char *) malloc(sizeof(struct fuse_out_header) + arg->size);
    struct fuse_out_header *out = (struct fuse_out_header *) outbuf;
    char *buf = outbuf + sizeof(struct fuse_out_header);
    size_t size;
    size_t outsize;

    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        if(f->flags & FUSE_DEBUG) {
            printf("READ %u bytes from %llu\n", arg->size, arg->offset);
            fflush(stdout);
        }

        res = -ENOSYS;
        if(f->op.read)
            res = f->op.read(path, buf, arg->size, arg->offset);
        free(path);
    }
    
    size = 0;
    if(res > 0) {
        size = res;
        res = 0;
        if(f->flags & FUSE_DEBUG) {
            printf("   READ %u bytes\n", size);
            fflush(stdout);
        }
    }
    memset(out, 0, sizeof(struct fuse_out_header));
    out->unique = in->unique;
    out->error = res;
    outsize = sizeof(struct fuse_out_header) + size;
    
    send_reply_raw(f, outbuf, outsize);
    free(outbuf);
}

static void do_write(struct fuse *f, struct fuse_in_header *in,
                     struct fuse_write_in *arg)
{
    int res;
    char *path;

    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        if(f->flags & FUSE_DEBUG) {
            printf("WRITE %u bytes to %llu\n", arg->size, arg->offset);
            fflush(stdout);
        }

        res = -ENOSYS;
        if(f->op.write)
            res = f->op.write(path, PARAM(arg), arg->size, arg->offset);
        free(path);
    }
    
    if(res > 0) {
        if((size_t) res != arg->size) {
            fprintf(stderr, "short write: %u (should be %u)\n", res,
                    arg->size);
            res = -EINVAL;
        }
        else 
            res = 0;
    }

    send_reply(f, in, res, NULL, 0);
}

static void do_statfs(struct fuse *f, struct fuse_in_header *in)
{
    int res;
    struct fuse_statfs_out arg;

    res = -ENOSYS;
    if(f->op.statfs) {
        memset(&arg, 0, sizeof(struct fuse_statfs_out));
        res = f->op.statfs((struct fuse_statfs *) &arg.st);
    }

    send_reply(f, in, res, &arg, sizeof(arg));
}

static void do_fsync(struct fuse *f, struct fuse_in_header *in,
                     struct fuse_fsync_in *inarg)
{
    int res;
    char *path;

    res = -ENOENT;
    path = get_path(f, in->ino);
    if(path != NULL) {
        /* fsync is not mandatory, so don't return ENOSYS */
        res = 0;
        if(f->op.fsync)
            res = f->op.fsync(path, inarg->datasync);
        free(path);
    }
    send_reply(f, in, res, NULL, 0);
}

static void free_cmd(struct fuse_cmd *cmd)
{
    free(cmd->buf);
    free(cmd);
}

void __fuse_process_cmd(struct fuse *f, struct fuse_cmd *cmd)
{
    struct fuse_in_header *in = (struct fuse_in_header *) cmd->buf;
    void *inarg = cmd->buf + sizeof(struct fuse_in_header);
    size_t argsize;
    struct fuse_context *ctx = fuse_get_context(f);

    dec_avail(f);

    if((f->flags & FUSE_DEBUG)) {
        printf("unique: %i, opcode: %s (%i), ino: %li, insize: %i\n",
               in->unique, opname(in->opcode), in->opcode, in->ino,
               cmd->buflen);
        fflush(stdout);
    }

    ctx->uid = in->uid;
    ctx->gid = in->gid;
    
    argsize = cmd->buflen - sizeof(struct fuse_in_header);
        
    switch(in->opcode) {
    case FUSE_LOOKUP:
        do_lookup(f, in, (char *) inarg);
        break;

    case FUSE_GETATTR:
        do_getattr(f, in);
        break;

    case FUSE_SETATTR:
        do_setattr(f, in, (struct fuse_setattr_in *) inarg);
        break;

    case FUSE_READLINK:
        do_readlink(f, in);
        break;

    case FUSE_GETDIR:
        do_getdir(f, in);
        break;

    case FUSE_MKNOD:
        do_mknod(f, in, (struct fuse_mknod_in *) inarg);
        break;
            
    case FUSE_MKDIR:
        do_mkdir(f, in, (struct fuse_mkdir_in *) inarg);
        break;
            
    case FUSE_UNLINK:
    case FUSE_RMDIR:
        do_remove(f, in, (char *) inarg);
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

    case FUSE_RELEASE:
        do_release(f, in, (struct fuse_open_in *) inarg);
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

    default:
        send_reply(f, in, -ENOSYS, NULL, 0);
    }

    free_cmd(cmd);
}

struct fuse_cmd *__fuse_read_cmd(struct fuse *f)
{
    ssize_t res;
    struct fuse_cmd *cmd;
    struct fuse_in_header *in;
    void *inarg;

    cmd = (struct fuse_cmd *) malloc(sizeof(struct fuse_cmd));
    cmd->buf = (char *) malloc(FUSE_MAX_IN);
    in = (struct fuse_in_header *) cmd->buf;
    inarg = cmd->buf + sizeof(struct fuse_in_header);

    do {
        res = read(f->fd, cmd->buf, FUSE_MAX_IN);
        if(res == -1) {
            free_cmd(cmd);
            if(f->exited || errno == EINTR)
                return NULL;

            /* ENODEV means we got unmounted, so we silenty return failure */
            if(errno != ENODEV) {
                /* BAD... This will happen again */
                perror("fuse: reading device");
            }

            fuse_exit(f);
            return NULL;
        }
        if((size_t) res < sizeof(struct fuse_in_header)) {
            free_cmd(cmd);
            /* Cannot happen */
            fprintf(stderr, "short read on fuse device\n");
            fuse_exit(f);
            return NULL;
        }
        cmd->buflen = res;
        
        /* Forget is special, it can be done without messing with threads. */
        if(in->opcode == FUSE_FORGET)
            do_forget(f, in, (struct fuse_forget_in *) inarg);

    } while(in->opcode == FUSE_FORGET);

    return cmd;
}

void fuse_loop(struct fuse *f)
{
    while(1) {
        struct fuse_cmd *cmd;

        if(f->exited)
            return;

        cmd = __fuse_read_cmd(f);
        if(cmd == NULL)
            continue;

        __fuse_process_cmd(f, cmd);
    }
}

void fuse_exit(struct fuse *f)
{
    f->exited = 1;
}

struct fuse_context *fuse_get_context(struct fuse *f)
{
    if(f->getcontext)
        return f->getcontext(f);
    else
        return &f->context;
}

struct fuse *fuse_new(int fd, int flags, const struct fuse_operations *op)
{
    struct fuse *f;
    struct node *root;

    f = (struct fuse *) calloc(1, sizeof(struct fuse));

    f->flags = flags;
    f->fd = fd;
    f->ctr = 0;
    /* FIXME: Dynamic hash table */
    f->name_table_size = 14057;
    f->name_table = (struct node **)
        calloc(1, sizeof(struct node *) * f->name_table_size);
    f->ino_table_size = 14057;
    f->ino_table = (struct node **)
        calloc(1, sizeof(struct node *) * f->ino_table_size);
    pthread_mutex_init(&f->lock, NULL);
    f->numworker = 0;
    f->numavail = 0;
    f->op = *op;
    f->getcontext = NULL;
    f->context.uid = 0;
    f->context.gid = 0;
    f->exited = 0;

    root = (struct node *) calloc(1, sizeof(struct node));
    root->mode = 0;
    root->rdev = 0;
    root->name = strdup("/");
    root->parent = 0;
    hash_ino(f, root, FUSE_ROOT_INO);

    return f;
}

void fuse_destroy(struct fuse *f)
{
    size_t i;
    for(i = 0; i < f->ino_table_size; i++) {
        struct node *node;
        struct node *next;
        for(node = f->ino_table[i]; node != NULL; node = next) {
            next = node->ino_next;
            free_node(node);
        }
    }
    free(f->ino_table);
    free(f->name_table);
    pthread_mutex_destroy(&f->lock);
    free(f);
}
