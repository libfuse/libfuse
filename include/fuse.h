/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#ifndef _FUSE_H_
#define _FUSE_H_

/* This file defines the library interface of FUSE */

/* IMPORTANT: you should define FUSE_USE_VERSION before including this
   header.  To use the new API define it to 22 (recommended for any
   new application), to use the old API define it to 21 (this is the
   default), to use the even older 1.X API define it to 11. */

#ifndef FUSE_USE_VERSION
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

    /** In case of a write operation indicates if this was caused by a
        writepage */
    int writepage;
};

/**
 * The file system operations:
 *
 * Most of these should work very similarly to the well known UNIX
 * file system operations.  A major exception is that instead of
 * returning an error in 'errno', the operation should return the
 * negated error value (-errno) directly.
 *
 * All methods are optional, but some are essential for a useful
 * filesystem (e.g. getattr).  Flush, release and fsync are special
 * purpose methods, without which a full featured filesystem can still
 * be implemented.
 */
struct fuse_operations {
    /** Get file attributes.
     *
     * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
     * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
     * mount option is given.
     */
    int (*getattr) (const char *, struct stat *);

    /** Read the target of a symbolic link
     *
     * The buffer should be filled with a null terminated string.  The
     * buffer size argument includes the space for the terminating
     * null character.  If the linkname is too long to fit in the
     * buffer, it should be truncated.  The return value should be 0
     * for success.
     */
    int (*readlink) (const char *, char *, size_t);

    /** Read the contents of a directory
     *
     * This operation is the opendir(), readdir(), ..., closedir()
     * sequence in one call. For each directory entry the filldir
     * function should be called.
     */
    int (*getdir) (const char *, fuse_dirh_t, fuse_dirfil_t);

    /** Create a file node
     *
     * There is no create() operation, mknod() will be called for
     * creation of all non-directory, non-symlink nodes.
     */
    int (*mknod) (const char *, mode_t, dev_t);

    /** Create a directory */
    int (*mkdir) (const char *, mode_t);

    /** Remove a file */
    int (*unlink) (const char *);

    /** Remove a directory */
    int (*rmdir) (const char *);

    /** Create a symbolic link */
    int (*symlink) (const char *, const char *);

    /** Rename a file */
    int (*rename) (const char *, const char *);

    /** Create a hard link to a file */
    int (*link) (const char *, const char *);

    /** Change the permission bits of a file */
    int (*chmod) (const char *, mode_t);

    /** Change the owner and group of a file */
    int (*chown) (const char *, uid_t, gid_t);

    /** Change the size of a file */
    int (*truncate) (const char *, off_t);

    /** Change the access and/or modification times of a file */
    int (*utime) (const char *, struct utimbuf *);

    /** File open operation
     *
     * No creation, or trunctation flags (O_CREAT, O_EXCL, O_TRUNC)
     * will be passed to open().  Open should check if the operation
     * is permitted for the given flags.  Optionally open may also
     * return an arbitary filehandle in the fuse_file_info structure,
     * which will be passed to all file operations.
     */
    int (*open) (const char *, struct fuse_file_info *);

    /** Read data from an open file
     *
     * Read should return exactly the number of bytes requested except
     * on EOF or error, otherwise the rest of the data will be
     * substituted with zeroes.  An exception to this is when the
     * 'direct_io' mount option is specified, in which case the return
     * value of the read system call will reflect the return value of
     * this operation.
     */
    int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);

    /** Write data to an open file
     *
     * Write should return exactly the number of bytes requested
     * except on error.  An exception to this is when the 'direct_io'
     * mount option is specified (see read operation).
     */
    int (*write) (const char *, const char *, size_t, off_t,
                  struct fuse_file_info *);

    /** Get file system statistics
     *
     * The 'f_type' and 'f_fsid' fields are ignored
     */
    int (*statfs) (const char *, struct statfs *);

    /** Possibly flush cached data
     *
     * BIG NOTE: This is not equivalent to fsync().  It's not a
     * request to sync dirty data.
     *
     * Flush is called on each close() of a file descriptor.  So if a
     * filesystem wants to return write errors in close() and the file
     * has cached dirty data, this is a good place to write back data
     * and return any errors.  Since many applications ignore close()
     * errors this is not always useful.
     *
     * NOTE: The flush() method may be called more than once for each
     * open().  This happens if more than one file descriptor refers
     * to an opened file due to dup(), dup2() or fork() calls.  It is
     * not possible to determine if a flush is final, so each flush
     * should be treated equally.  Multiple write-flush sequences are
     * relatively rare, so this shouldn't be a problem.
     */
    int (*flush) (const char *, struct fuse_file_info *);

    /** Release an open file
     *
     * Release is called when there are no more references to an open
     * file: all file descriptors are closed and all memory mappings
     * are unmapped.
     *
     * For every open() call there will be exactly one release() call
     * with the same flags and file descriptor.  It is possible to
     * have a file opened more than once, in which case only the last
     * release will mean, that no more reads/writes will happen on the
     * file.  The return value of release is ignored.
     */
    int (*release) (const char *, struct fuse_file_info *);

    /** Synchronize file contents
     *
     * If the datasync parameter is non-zero, then only the user data
     * should be flushed, not the meta data.
     */
    int (*fsync) (const char *, int, struct fuse_file_info *);

    /** Set extended attributes */
    int (*setxattr) (const char *, const char *, const char *, size_t, int);

    /** Get extended attributes */
    int (*getxattr) (const char *, const char *, char *, size_t);

    /** List extended attributes */
    int (*listxattr) (const char *, char *, size_t);

    /** Remove extended attributes */
    int (*removexattr) (const char *, const char *);
};

/** Extra context that may be needed by some filesystems
 *
 * The uid, gid and pid fields are not filled in case of a writepage
 * operation.
 */
struct fuse_context {
    /** Pointer to the fuse object */
    struct fuse *fuse;

    /** User ID of the calling process */
    uid_t uid;

    /** Group ID of the calling process */
    gid_t gid;

    /** Thread ID of the calling process */
    pid_t pid;

    /** Currently unused */
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
/*
int fuse_main(int argc, char *argv[], const struct fuse_operations *op);
*/
#define fuse_main(argc, argv, op) \
            fuse_main_real(argc, argv, op, sizeof(*(op)))

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
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
                   size_t op_size);

/* ----------------------------------------------------------- *
 * Advanced API for event handling, don't worry about this...  *
 * ----------------------------------------------------------- */

/** Structure containing a raw command */
struct fuse_cmd;

/** Function type used to process commands */
typedef void (*fuse_processor_t)(struct fuse *, struct fuse_cmd *, void *);

/** This is the part of fuse_main() before the event loop */
struct fuse *fuse_setup(int argc, char *argv[],
                        const struct fuse_operations *op, size_t op_size,
                          char **mountpoint, int *multithreaded, int *fd);

/** This is the part of fuse_main() after the event loop */
void fuse_teardown(struct fuse *fuse, int fd, char *mountpoint);

/** Read a single command.  If none are read, return NULL */
struct fuse_cmd *fuse_read_cmd(struct fuse *f);

/** Process a single command */
void fuse_process_cmd(struct fuse *f, struct fuse_cmd *cmd);

/** Multi threaded event loop, which calls the custom command
    processor function */
int fuse_loop_mt_proc(struct fuse *f, fuse_processor_t proc, void *data);

/** Return the exited flag, which indicates if fuse_exit() has been
    called */
int fuse_exited(struct fuse* f);

/** Set function which can be used to get the current context */
void fuse_set_getcontext_func(struct fuse_context *(*func)(void));

/* ----------------------------------------------------------- *
 * Compatibility stuff                                         *
 * ----------------------------------------------------------- */

#if FUSE_USE_VERSION == 21 || FUSE_USE_VERSION == 11
#  include "fuse_compat.h"
#  define fuse_dirfil_t fuse_dirfil_t_compat
#  define __fuse_read_cmd fuse_read_cmd
#  define __fuse_process_cmd fuse_process_cmd
#  define __fuse_loop_mt fuse_loop_mt_proc
#  undef fuse_main
#  undef FUSE_MINOR_VERSION
#  undef FUSE_MAJOR_VERSION
#  if FUSE_USE_VERSION == 21
#    define FUSE_MAJOR_VERSION 2
#    define FUSE_MINOR_VERSION 1
#    define fuse_operations fuse_operations_compat2
#    define fuse_main fuse_main_compat2
#    define fuse_new fuse_new_compat2
#    define __fuse_setup fuse_setup_compat2
#    define __fuse_teardown fuse_teardown
#    define __fuse_exited fuse_exited
#    define __fuse_set_getcontext_func fuse_set_getcontext_func
#  else
#    define FUSE_MAJOR_VERSION 1
#    define FUSE_MINOR_VERSION 1
#    define fuse_statfs fuse_statfs_compat1
#    define fuse_operations fuse_operations_compat1
#    define fuse_main fuse_main_compat1
#    define fuse_new fuse_new_compat1
#    define fuse_mount fuse_mount_compat1
#    define FUSE_DEBUG FUSE_DEBUG_COMPAT1
#  endif
#elif FUSE_USE_VERSION < 22
#  error Compatibility with API version other than 21 and 11 not supported
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_H_ */
