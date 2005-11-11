/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

/* these definitions provide source compatibility to prior versions.
   Do not include this file directly! */

#include <sys/statfs.h>

struct fuse_file_info_compat22 {
    int flags;
    unsigned long fh;
    int writepage;
    unsigned int direct_io : 1;
    unsigned int keep_cache : 1;
};

struct fuse_operations_compat22 {
    int (*getattr) (const char *, struct stat *);
    int (*readlink) (const char *, char *, size_t);
    int (*getdir) (const char *, fuse_dirh_t, fuse_dirfil_t);
    int (*mknod) (const char *, mode_t, dev_t);
    int (*mkdir) (const char *, mode_t);
    int (*unlink) (const char *);
    int (*rmdir) (const char *);
    int (*symlink) (const char *, const char *);
    int (*rename) (const char *, const char *);
    int (*link) (const char *, const char *);
    int (*chmod) (const char *, mode_t);
    int (*chown) (const char *, uid_t, gid_t);
    int (*truncate) (const char *, off_t);
    int (*utime) (const char *, struct utimbuf *);
    int (*open) (const char *, struct fuse_file_info_compat22 *);
    int (*read) (const char *, char *, size_t, off_t,
                 struct fuse_file_info_compat22 *);
    int (*write) (const char *, const char *, size_t, off_t,
                  struct fuse_file_info_compat22 *);
    int (*statfs) (const char *, struct statfs *);
    int (*flush) (const char *, struct fuse_file_info_compat22 *);
    int (*release) (const char *, struct fuse_file_info_compat22 *);
    int (*fsync) (const char *, int, struct fuse_file_info_compat22 *);
    int (*setxattr) (const char *, const char *, const char *, size_t, int);
    int (*getxattr) (const char *, const char *, char *, size_t);
    int (*listxattr) (const char *, char *, size_t);
    int (*removexattr) (const char *, const char *);
    int (*opendir) (const char *, struct fuse_file_info_compat22 *);
    int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t,
                    struct fuse_file_info_compat22 *);
    int (*releasedir) (const char *, struct fuse_file_info_compat22 *);
    int (*fsyncdir) (const char *, int, struct fuse_file_info_compat22 *);
    void *(*init) (void);
    void (*destroy) (void *);
};

struct fuse *fuse_new_compat22(int fd, const char *opts,
                               const struct fuse_operations_compat22 *op,
                               size_t op_size);

struct fuse *fuse_setup_compat22(int argc, char *argv[],
                                 const struct fuse_operations_compat22 *op,
                                 size_t op_size, char **mountpoint,
                                 int *multithreaded, int *fd);

int fuse_main_real_compat22(int argc, char *argv[],
                            const struct fuse_operations_compat22 *op,
                            size_t op_size);

typedef int (*fuse_dirfil_t_compat) (fuse_dirh_t h, const char *name, int type);
struct fuse_operations_compat2 {
    int (*getattr)     (const char *, struct stat *);
    int (*readlink)    (const char *, char *, size_t);
    int (*getdir)      (const char *, fuse_dirh_t, fuse_dirfil_t_compat);
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
    int (*open)        (const char *, int);
    int (*read)        (const char *, char *, size_t, off_t);
    int (*write)       (const char *, const char *, size_t, off_t);
    int (*statfs)      (const char *, struct statfs *);
    int (*flush)       (const char *);
    int (*release)     (const char *, int);
    int (*fsync)       (const char *, int);
    int (*setxattr)    (const char *, const char *, const char *, size_t, int);
    int (*getxattr)    (const char *, const char *, char *, size_t);
    int (*listxattr)   (const char *, char *, size_t);
    int (*removexattr) (const char *, const char *);
};

int fuse_main_compat2(int argc, char *argv[], const struct fuse_operations_compat2 *op);

struct fuse *fuse_new_compat2(int fd, const char *opts, const struct fuse_operations_compat2 *op);

struct fuse *fuse_setup_compat2(int argc, char *argv[], const struct fuse_operations_compat2 *op, char **mountpoint, int *multithreaded, int *fd);

struct fuse_statfs_compat1 {
    long block_size;
    long blocks;
    long blocks_free;
    long files;
    long files_free;
    long namelen;
};

struct fuse_operations_compat1 {
    int (*getattr)  (const char *, struct stat *);
    int (*readlink) (const char *, char *, size_t);
    int (*getdir)   (const char *, fuse_dirh_t, fuse_dirfil_t_compat);
    int (*mknod)    (const char *, mode_t, dev_t);
    int (*mkdir)    (const char *, mode_t);
    int (*unlink)   (const char *);
    int (*rmdir)    (const char *);
    int (*symlink)  (const char *, const char *);
    int (*rename)   (const char *, const char *);
    int (*link)     (const char *, const char *);
    int (*chmod)    (const char *, mode_t);
    int (*chown)    (const char *, uid_t, gid_t);
    int (*truncate) (const char *, off_t);
    int (*utime)    (const char *, struct utimbuf *);
    int (*open)     (const char *, int);
    int (*read)     (const char *, char *, size_t, off_t);
    int (*write)    (const char *, const char *, size_t, off_t);
    int (*statfs)   (struct fuse_statfs_compat1 *);
    int (*release)  (const char *, int);
    int (*fsync)    (const char *, int);
};

#define FUSE_DEBUG_COMPAT1       (1 << 1)

int fuse_mount_compat1(const char *mountpoint, const char *args[]);

struct fuse *fuse_new_compat1(int fd, int flags, const struct fuse_operations_compat1 *op);

void fuse_main_compat1(int argc, char *argv[], const struct fuse_operations_compat1 *op);
