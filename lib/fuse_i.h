/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"
#include "fuse_compat.h"
#include <stdio.h>
#include <pthread.h>

/* FUSE flags: */

/** Enable debuging output */
#define FUSE_DEBUG       (1 << 1)

/** If a file is removed but it's still open, don't hide the file but
    remove it immediately */
#define FUSE_HARD_REMOVE (1 << 2)

/** Use st_ino field in getattr instead of generating inode numbers  */
#define FUSE_USE_INO     (1 << 3)


typedef unsigned long nodeid_t;

struct node {
    struct node *name_next;
    struct node *id_next;
    nodeid_t nodeid;
    unsigned int generation;
    nodeid_t parent;
    char *name;
    int mode;
    int rdev;
    unsigned long ino;
    int version;
    int open_count;
    int is_hidden;
};

struct fuse_operations_i {
    int (*getattr)     (const char *, struct stat *);
    int (*readlink)    (const char *, char *, size_t);
    int (*getdir)      (const char *, fuse_dirh_t, fuse_dirfil_t);
    int (*mknod)       (const char *, mode_t, dev_t);
    int (*mkdir)       (const char *, mode_t);
    int (*unlink)      (const char *);
    int (*rmdir)       (const char *);
    int (*symlink)     (const char *, const char *);
    int (*rename)      (const char *, const char *);
    int (*link)        (const char *, const char *);
    int (*chmod)       (const char *, mode_t);
    int (*chown)       (const char *, uid_t, gid_t);
    int (*truncate)    (const char *, off_t);
    int (*utime)       (const char *, struct utimbuf *);
    union {
        int (*curr)    (const char *, struct fuse_file_info *);
        int (*compat2) (const char *, int);
    } open;
    int (*read)        (const char *, char *, size_t, off_t,
                        struct fuse_file_info *);
    int (*write)       (const char *, const char *, size_t, off_t,
                        struct fuse_file_info *);
    union {
        int (*curr)    (const char *, struct statfs *);
        int (*compat1) (struct fuse_statfs_compat1 *);
    } statfs;
    int (*flush)       (const char *, struct fuse_file_info *);
    union {
        int (*curr)    (const char *, struct fuse_file_info *);
        int (*compat2) (const char *, int);
    } release;
    int (*fsync)       (const char *, int, struct fuse_file_info *);
    int (*setxattr)    (const char *, const char *, const char *, size_t, int);
    int (*getxattr)    (const char *, const char *, char *, size_t);
    int (*listxattr)   (const char *, char *, size_t);
    int (*removexattr) (const char *, const char *);
};

struct fuse {
    int flags;
    int fd;
    struct fuse_operations_i op;
    int compat;
    struct node **name_table;
    size_t name_table_size;
    struct node **id_table;
    size_t id_table_size;
    nodeid_t ctr;
    unsigned int generation;
    unsigned int hidectr;
    pthread_mutex_t lock;
    int numworker;
    int numavail;
    volatile int exited;
    int majorver;
    int minorver;
};

struct fuse_dirhandle {
    struct fuse *fuse;
    nodeid_t dir;
    FILE *fp;
};

struct fuse_cmd {
    char *buf;
    size_t buflen;
};

struct fuse *fuse_new_common(int fd, const char *opts,
                             const struct fuse_operations *op,
                             size_t op_size, int compat);
