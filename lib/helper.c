/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse_i.h"
#include "fuse_opt.h"
#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

static void usage(const char *progname)
{
    if (progname)
        fprintf(stderr,
                "usage: %s mountpoint [FUSE options]\n\n", progname);

    fprintf(stderr,
            "FUSE options:\n"
            "    -d                     enable debug output (implies -f)\n"
            "    -f                     foreground operation\n"
            "    -s                     disable multi-threaded operation\n"
            "    -r                     mount read only (equivalent to '-o ro')\n"
            "    -o opt,[opt...]        mount options\n"
            "    -h                     print help\n"
            "\n"
            "Mount options:\n"
            "    default_permissions    enable permission checking\n"
            "    allow_other            allow access to other users\n"
            "    allow_root             allow access to root\n"
            "    kernel_cache           cache files in kernel\n"
            "    large_read             issue large read requests (2.4 only)\n"
            "    direct_io              use direct I/O\n"
            "    max_read=N             set maximum size of read requests\n"
            "    hard_remove            immediate removal (don't hide files)\n"
            "    debug                  enable debug output\n"
            "    fsname=NAME            set filesystem name in mtab\n"
            "    use_ino                let filesystem set inode numbers\n"
            "    readdir_ino            try to fill in d_ino in readdir\n"
            "    nonempty               allow mounts over non-empty file/dir\n"
            "    umask=M                set file permissions (octal)\n"
            "    uid=N                  set file owner\n"
            "    gid=N                  set file group\n"
            );
}

enum  {
    KEY_HELP,
    KEY_HELP_NOHEADER,
    KEY_KEEP,
};

struct helper_opts {
    int singlethread;
    int foreground;
    int fsname;
    char *mountpoint;
};

#define FUSE_HELPER_OPT(t, p) { t, offsetof(struct helper_opts, p), 1 }

static const struct fuse_opt fuse_helper_opts[] = {
    FUSE_HELPER_OPT("-d",          foreground),
    FUSE_HELPER_OPT("debug",       foreground),
    FUSE_HELPER_OPT("-f",	   foreground),
    FUSE_HELPER_OPT("-s",	   singlethread),
    FUSE_HELPER_OPT("fsname=",     fsname),

    FUSE_OPT_KEY("-h",          KEY_HELP),
    FUSE_OPT_KEY("--help",      KEY_HELP),
    FUSE_OPT_KEY("-ho",         KEY_HELP_NOHEADER),
    FUSE_OPT_KEY("-d",          KEY_KEEP),
    FUSE_OPT_KEY("debug",       KEY_KEEP),
    FUSE_OPT_END
};

static int fuse_helper_opt_proc(void *data, const char *arg, int key,
                                struct fuse_args *outargs)
{
    struct helper_opts *hopts = data;

    switch (key) {
    case KEY_HELP:
    case KEY_HELP_NOHEADER:
        usage(key == KEY_HELP ? outargs->argv[0] : NULL);
        exit(1);

    case FUSE_OPT_KEY_NONOPT:
        if (!hopts->mountpoint)
            return fuse_opt_add_opt(&hopts->mountpoint, arg);

        /* fall through */

    default:
    case KEY_KEEP:
        return 1;
    }
}

static int add_default_fsname(const char *progname, struct fuse_args *args)
{
    int res;
    char *fsname_opt;
    const char *basename = strrchr(progname, '/');
    if (basename == NULL)
        basename = progname;
    else if (basename[1] != '\0')
        basename++;

    fsname_opt = (char *) malloc(strlen(basename) + 64);
    if (fsname_opt == NULL) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        return -1;
    }
    sprintf(fsname_opt, "-ofsname=%s", basename);
    res = fuse_opt_add_arg(args, fsname_opt);
    free(fsname_opt);
    return res;
}

int fuse_parse_cmdline(struct fuse_args *args, char **mountpoint,
                       int *multithreaded, int *foreground)
{
    int res;
    struct helper_opts hopts;

    memset(&hopts, 0, sizeof(hopts));
    res = fuse_opt_parse(args, &hopts, fuse_helper_opts, fuse_helper_opt_proc);
    if (res == -1)
        return -1;

    if (!hopts.fsname) {
        res = add_default_fsname(args->argv[0], args);
        if (res == -1)
            goto err;
    }
    if (mountpoint)
        *mountpoint = hopts.mountpoint;
    else
        free(hopts.mountpoint);

    if (multithreaded)
        *multithreaded = !hopts.singlethread;
    if (foreground)
        *foreground = hopts.foreground;
    return 0;

 err:
    free(hopts.mountpoint);
    return -1;
}

static struct fuse *fuse_setup_common(struct fuse_args *args,
                                      const struct fuse_operations *op,
                                      size_t op_size,
                                      char **mountpoint,
                                      int *multithreaded,
                                      int *fd,
                                      int compat)
{
    struct fuse *fuse;
    int foreground;
    int res;

    res = fuse_parse_cmdline(args, mountpoint, multithreaded, &foreground);
    if (res == -1)
        return NULL;

    *fd = fuse_mount(*mountpoint, args);
    if (*fd == -1)
        goto err_free;

    fuse = fuse_new_common(*fd, args, op, op_size, compat);
    if (fuse == NULL)
        goto err_unmount;

    if (!foreground) {
        res = daemon(0, 0);
        if (res == -1) {
            perror("fuse: failed to daemonize program\n");
            goto err_destroy;
        }
    } else {
        /* Ensure consistant behavior across debug and normal modes */
        res = chdir("/");
        if (res == -1) {
            perror("fuse: failed to change working directory to /\n");
            goto err_destroy;
        }
    }

    res = fuse_set_signal_handlers(fuse_get_session(fuse));
    if (res == -1)
        goto err_destroy;

    return fuse;

 err_destroy:
    fuse_destroy(fuse);
 err_unmount:
    fuse_unmount(*mountpoint);
 err_free:
    free(*mountpoint);
    return NULL;
}

struct fuse *fuse_setup(struct fuse_args *args,
                        const struct fuse_operations *op,
                        size_t op_size, char **mountpoint,
                        int *multithreaded, int *fd)
{
    return fuse_setup_common(args, op, op_size, mountpoint, multithreaded, fd,
                             0);
}

void fuse_teardown(struct fuse *fuse, int fd, char *mountpoint)
{
    (void) fd;

    fuse_remove_signal_handlers(fuse_get_session(fuse));
    fuse_unmount(mountpoint);
    fuse_destroy(fuse);
    free(mountpoint);
}

static int fuse_main_common(struct fuse_args *args,
                            const struct fuse_operations *op, size_t op_size,
                            int compat)
{
    struct fuse *fuse;
    char *mountpoint;
    int multithreaded;
    int res;
    int fd;

    fuse = fuse_setup_common(args, op, op_size, &mountpoint, &multithreaded,
                             &fd, compat);
    if (fuse == NULL)
        return 1;

    if (multithreaded)
        res = fuse_loop_mt(fuse);
    else
        res = fuse_loop(fuse);

    fuse_teardown(fuse, fd, mountpoint);
    if (res == -1)
        return 1;

    return 0;
}

int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
                   size_t op_size)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int res = fuse_main_common(&args, op, op_size, 0);
    fuse_opt_free_args(&args);
    return res;
}

#undef fuse_main
int fuse_main(void)
{
    fprintf(stderr, "fuse_main(): This function does not exist\n");
    return -1;
}

#ifndef __FreeBSD__

#include "fuse_compat.h"

struct fuse *fuse_setup_compat22(int argc, char *argv[],
                                 const struct fuse_operations_compat22 *op,
                                 size_t op_size, char **mountpoint,
                                 int *multithreaded, int *fd)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse *f =
        fuse_setup_common(&args, (struct fuse_operations *) op,
                          op_size, mountpoint, multithreaded, fd, 22);
    fuse_opt_free_args(&args);
    return f;
}

struct fuse *fuse_setup_compat2(int argc, char *argv[],
                                 const struct fuse_operations_compat2 *op,
                                 char **mountpoint, int *multithreaded,
                                 int *fd)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse *f =
        fuse_setup_common(&args, (struct fuse_operations *) op,
                          sizeof(struct fuse_operations_compat2),
                          mountpoint, multithreaded, fd, 21);
    fuse_opt_free_args(&args);
    return f;
}

int fuse_main_real_compat22(int argc, char *argv[],
                            const struct fuse_operations_compat22 *op,
                            size_t op_size)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int res =
        fuse_main_common(&args, (struct fuse_operations *) op, op_size, 22);
    fuse_opt_free_args(&args);
    return res;
}

void fuse_main_compat1(int argc, char *argv[],
                      const struct fuse_operations_compat1 *op)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    fuse_main_common(&args, (struct fuse_operations *) op,
                     sizeof(struct fuse_operations_compat1), 11);
    fuse_opt_free_args(&args);
}

int fuse_main_compat2(int argc, char *argv[],
                      const struct fuse_operations_compat2 *op)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int res =
        fuse_main_common(&args, (struct fuse_operations *) op,
                         sizeof(struct fuse_operations_compat2), 21);
    fuse_opt_free_args(&args);
    return res;
}

__asm__(".symver fuse_setup_compat2,__fuse_setup@");
__asm__(".symver fuse_setup_compat22,fuse_setup@FUSE_2.2");
__asm__(".symver fuse_teardown,__fuse_teardown@");
__asm__(".symver fuse_main_compat2,fuse_main@");
__asm__(".symver fuse_main_real_compat22,fuse_main_real@FUSE_2.2");

#endif /* __FreeBSD__ */
