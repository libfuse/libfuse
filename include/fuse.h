/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

/* This file defines the library interface of FUSE */

#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>

struct fuse;
typedef struct fuse_dirhandle *fuse_dirh_t;

typedef int (*fuse_dirfil_t) (fuse_dirh_t, const char *, int type);

struct fuse_cred {
    uid_t uid;
    gid_t gid;
};

struct fuse_operations {
    int (*getattr)  (struct fuse_cred *, const char *, struct stat *);
    int (*readlink) (struct fuse_cred *, const char *, char *, size_t);
    int (*getdir)   (struct fuse_cred *, const char *, fuse_dirh_t, fuse_dirfil_t);
    int (*mknod)    (struct fuse_cred *, const char *, mode_t, dev_t);
    int (*mkdir)    (struct fuse_cred *, const char *, mode_t);
    int (*unlink)   (struct fuse_cred *, const char *);
    int (*rmdir)    (struct fuse_cred *, const char *);
    int (*symlink)  (struct fuse_cred *, const char *, const char *);
    int (*rename)   (struct fuse_cred *, const char *, const char *);
    int (*link)     (struct fuse_cred *, const char *, const char *);
    int (*chmod)    (struct fuse_cred *, const char *, mode_t);
    int (*chown)    (struct fuse_cred *, const char *, uid_t, gid_t);
    int (*truncate) (struct fuse_cred *, const char *, off_t);
    int (*utime)    (struct fuse_cred *, const char *, struct utimbuf *);
    int (*open)     (struct fuse_cred *, const char *, int);
    int (*read)     (struct fuse_cred *, const char *, char *, size_t, off_t);
    int (*write)    (struct fuse_cred *, const char *, const char *, size_t, off_t);
};

#define FUSE_MULTITHREAD (1 << 0)

struct fuse *fuse_new(int flags);

int fuse_mount(struct fuse *f, const char *dir);

void fuse_set_operations(struct fuse *f, const struct fuse_operations *op);

void fuse_loop(struct fuse *f);

int fuse_unmount(struct fuse *f);

void fuse_destroy(struct fuse *f);
