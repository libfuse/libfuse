/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#ifndef _FUSE_H_
#define _FUSE_H_

/* This file defines the library interface of FUSE */

/* IMPORTANT: you should define FUSE_USE_VERSION before including this
   header.  To use the new API define it to 22 (recommended for any
   new application), to use the old API define it to 21, to use the
   even older 1.X API define it to 11. */

#ifndef FUSE_USE_VERSION
#warning FUSE_USE_VERSION not defined, defaulting to 21
#define FUSE_USE_VERSION 21
#endif

/** Major version of FUSE library interface */
#define FUSE_MAJOR_VERSION 2

/** Minor version of FUSE library interface */
#define FUSE_MINOR_VERSION 2

/* This interface uses 64 bit off_t */
#if _FILE_OFFSET_BITS != 64
#error Please add -D_FILE_OFFSET_BITS=64 to your compile flags!
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <utime.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------- *
 * Basic FUSE API                                              *
 * ----------------------------------------------------------- */

/** Handle for a FUSE filesystem */
struct fuse;

/** Handle for a getdir() operation */
typedef struct fuse_dirhandle *fuse_dirh_t;

/** Function to add an entry in a getdir() operation
 * 
 * @param h the handle passed to the getdir() operation
 * @param name the file name of the directory entry
 * @param type the file type (0 if unknown)  see <dirent.h>
 * @param ino the inode number, ignored if "use_ino" mount option is
 *            not specified
 * @return 0 on success, -errno on error
 */
typedef int (*fuse_dirfil_t) (fuse_dirh_t h, const char *name, int type,
                              ino_t ino);

/** Information about open files */
struct fuse_file_info {
    /** Open flags.  Available in open() and release() */
    int flags;

    /** File handle.  May be filled in by filesystem in open().
        Available in all other file operations */
    unsigned long fh;
};

/**
 * The file system operations:
 *
 * Most of these should work very similarly to the well known UNIX
 * file system operations.  Exceptions are:
 * 
 *  - All operations should return the negated error value (-errno) on
 *  error.
 * 
 *  - Getattr() doesn't need to fill in the following fields:
 *      st_ino
 *      st_dev
 *      st_blksize
 * 
 *  - readlink() should fill the buffer with a null terminated string.  The
 *  buffer size argument includes the space for the terminating null
 *  character.  If the linkname is too long to fit in the buffer, it should
 *  be truncated.  The return value should be 0 for success.
 *
 *  - getdir() is the opendir(), readdir(), ..., closedir() sequence
 *  in one call. For each directory entry the filldir parameter should
 *  be called. 
 *
 *  - There is no create() operation, mknod() will be called for
 *  creation of all non directory, non symlink nodes.
 *
 *  - open() should not return a filehandle, but 0 on success.  No
 *  creation, or trunctation flags (O_CREAT, O_EXCL, O_TRUNC) will be
 *  passed to open().  Open should only check if the operation is
 *  permitted for the given flags.
 * 
 *  - read(), write() are not passed a filehandle, but rather a
 *  pathname.  The offset of the read and write is passed as the last
 *  argument, like the pread() and pwrite() system calls.  (NOTE:
 *  read() should always return the number of bytes requested, except
 *  at end of file)
 * 
 *  - release() is called when an open file has:
 *       1) all file descriptors closed
 *       2) all memory mappings unmapped
 *  For every open() call there will be exactly one release() call
 *  with the same flags.  It is possible to have a file opened more
 *  than once, in which case only the last release will mean, that no
 *  more reads/writes will happen on the file.  The return value of
 *  release is ignored.  Implementing this method is optional.
 * 
 *  - flush() is called when close() has been called on an open file.
 *  NOTE: this does not mean that the file is released (e.g. after
 *  fork() an open file will have two references which both must be
 *  closed before the file is released).  The flush() method may be
 *  called more than once for each open().  The return value of
 *  flush() is passed on to the close() system call.  Implementing
 *  this method is optional.
 * 
 *  - fsync() has a boolean 'datasync' parameter which if TRUE then do
 *  an fdatasync() operation.  Implementing this method is optional.
 */
struct fuse_operations {
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
    int (*open)        (const char *, struct fuse_file_info *);
    int (*read)        (const char *, char *, size_t, off_t,
                        struct fuse_file_info *);
    int (*write)       (const char *, const char *, size_t, off_t,
                        struct fuse_file_info *);
    int (*statfs)      (const char *, struct statfs *);
    int (*flush)       (const char *, struct fuse_file_info *);
    int (*release)     (const char *, struct fuse_file_info *);
    int (*fsync)       (const char *, int, struct fuse_file_info *);
    int (*setxattr)    (const char *, const char *, const char *, size_t, int);
    int (*getxattr)    (const char *, const char *, char *, size_t);
    int (*listxattr)   (const char *, char *, size_t);
    int (*removexattr) (const char *, const char *);
};

/** Extra context that may be needed by some filesystems */
struct fuse_context {
    struct fuse *fuse;
    uid_t uid;
    gid_t gid;
    pid_t pid;
    void *private_data;
};

/*
 * Main function of FUSE.
 *
 * This is for the lazy.  This is all that has to be called from the
 * main() function.
 * 
 * This function does the following:
 *   - parses command line options (-d -s and -h)
 *   - passes relevant mount options to the fuse_mount()
 *   - installs signal handlers for INT, HUP, TERM and PIPE
 *   - registers an exit handler to unmount the filesystem on program exit
 *   - creates a fuse handle
 *   - registers the operations
 *   - calls either the single-threaded or the multi-threaded event loop
 *
 * Note: this is currently implemented as a macro.
 *
 * @param argc the argument counter passed to the main() function
 * @param argv the argument vector passed to the main() function
 * @param op the file system operation 
 * @return 0 on success, nonzero on failure
 */
/* int fuse_main(int argc, char *argv[], const struct fuse_operations *op); */
#define fuse_main(argc, argv, op) __fuse_main(argc, argv, op, sizeof(*(op)))

/* ----------------------------------------------------------- *
 * More detailed API                                           *
 * ----------------------------------------------------------- */

/*
 * Create a FUSE mountpoint
 *
 * Returns a control file descriptor suitable for passing to
 * fuse_new()
 *
 * @param mountpoint the mount point path
 * @param opts a comma separated list of mount options.  Can be NULL.
 * @return the control file descriptor on success, -1 on failure
 */
int fuse_mount(const char *mountpoint, const char *opts);

/*
 * Umount a FUSE mountpoint
 *
 * @param mountpoint the mount point path
 */
void fuse_unmount(const char *mountpoint);

/**
 * Create a new FUSE filesystem.
 *
 * @param fd the control file descriptor
 * @param opts mount options to be used by the library
 * @param op the operations
 * @param op_size the size of the fuse_operations structure
 * @return the created FUSE handle
 */
struct fuse *fuse_new(int fd, const char *opts, 
                      const struct fuse_operations *op, size_t op_size);

/**
 * Destroy the FUSE handle. 
 *
 * The filesystem is not unmounted.
 *
 * @param f the FUSE handle
 */
void fuse_destroy(struct fuse *f);

/**
 * FUSE event loop.
 *
 * Requests from the kernel are processed, and the apropriate
 * operations are called. 
 *
 * @param f the FUSE handle
 * @return 0 if no error occured, -1 otherwise
 */
int fuse_loop(struct fuse *f);

/**
 * Exit from event loop
 *
 * @param f the FUSE handle
 */
void fuse_exit(struct fuse *f);

/**
 * FUSE event loop with multiple threads
 *
 * Requests from the kernel are processed, and the apropriate
 * operations are called.  Request are processed in parallel by
 * distributing them between multiple threads.
 *
 * Calling this function requires the pthreads library to be linked to
 * the application.
 *
 * @param f the FUSE handle
 * @return 0 if no error occured, -1 otherwise
 */
int fuse_loop_mt(struct fuse *f);

/**
 * Get the current context
 * 
 * The context is only valid for the duration of a filesystem
 * operation, and thus must not be stored and used later.
 *
 * @param f the FUSE handle
 * @return the context 
 */
struct fuse_context *fuse_get_context(void);

/**
 * Invalidate cached data of a file.
 *
 * Useful if the 'kernel_cache' mount option is given, since in that
 * case the cache is not invalidated on file open.
 *
 * @return 0 on success or -errno on failure
 */
int fuse_invalidate(struct fuse *f, const char *path);

/**
 * Check whether a mount option should be passed to the kernel or the
 * library
 *
 * @param opt the option to check
 * @return 1 if it is a library option, 0 otherwise
 */
int fuse_is_lib_option(const char *opt);

/**
 * The real main function
 * 
 * Do not call this directly, use fuse_main()
 */
int __fuse_main(int argc, char *argv[], const struct fuse_operations *op,
                size_t op_size);

/* ----------------------------------------------------------- *
 * Advanced API for event handling, don't worry about this...  *
 * ----------------------------------------------------------- */

struct fuse_cmd;
typedef void (*fuse_processor_t)(struct fuse *, struct fuse_cmd *, void *);
struct fuse *__fuse_setup(int argc, char *argv[],
                          const struct fuse_operations *op, size_t op_size,
                          char **mountpoint, int *multithreaded, int *fd);
void __fuse_teardown(struct fuse *fuse, int fd, char *mountpoint);
struct fuse_cmd *__fuse_read_cmd(struct fuse *f);
void __fuse_process_cmd(struct fuse *f, struct fuse_cmd *cmd);
int __fuse_loop_mt(struct fuse *f, fuse_processor_t proc, void *data);
int __fuse_exited(struct fuse* f);
void __fuse_set_getcontext_func(struct fuse_context *(*func)(void));

/* ----------------------------------------------------------- *
 * Compatibility stuff                                         *
 * ----------------------------------------------------------- */

#if FUSE_USE_VERSION == 21 || FUSE_USE_VERSION == 11
#  include <fuse_compat.h>
#  define fuse_dirfil_t _fuse_dirfil_t_compat
#  undef fuse_main
#  undef FUSE_MINOR_VERSION
#  undef FUSE_MAJOR_VERSION
#  if FUSE_USE_VERSION == 21
#    define FUSE_MAJOR_VERSION 2
#    define FUSE_MINOR_VERSION 1
#    define fuse_operations _fuse_operations_compat2
#    define fuse_main _fuse_main_compat2
#    define fuse_new _fuse_new_compat2
#    define __fuse_setup _fuse_setup_compat2
#  else
#    define FUSE_MAJOR_VERSION 1
#    define FUSE_MINOR_VERSION 1
#    define fuse_statfs _fuse_statfs_compat1
#    define fuse_operations _fuse_operations_compat1
#    define fuse_main _fuse_main_compat1
#    define fuse_new _fuse_new_compat1
#    define fuse_mount _fuse_mount_compat1
#    define FUSE_DEBUG _FUSE_DEBUG_COMPAT1
#  endif
#elif FUSE_USE_VERSION < 22
#  error Compatibility with API version other than 21 and 11 not supported
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_H_ */
