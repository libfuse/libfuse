/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "config.h"
#include "fuse_i.h"
#include "fuse_opt.h"
#include "fuse_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

enum  {
    KEY_HELP,
    KEY_HELP_NOHEADER,
    KEY_VERSION,
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
    FUSE_HELPER_OPT("-f",          foreground),
    FUSE_HELPER_OPT("-s",          singlethread),
    FUSE_HELPER_OPT("fsname=",     fsname),

    FUSE_OPT_KEY("-h",          KEY_HELP),
    FUSE_OPT_KEY("--help",      KEY_HELP),
    FUSE_OPT_KEY("-ho",         KEY_HELP_NOHEADER),
    FUSE_OPT_KEY("-V",          KEY_VERSION),
    FUSE_OPT_KEY("--version",   KEY_VERSION),
    FUSE_OPT_KEY("-d",          FUSE_OPT_KEY_KEEP),
    FUSE_OPT_KEY("debug",       FUSE_OPT_KEY_KEEP),
    FUSE_OPT_KEY("fsname=",     FUSE_OPT_KEY_KEEP),
    FUSE_OPT_END
};

static void usage(const char *progname)
{
    fprintf(stderr,
            "usage: %s mountpoint [options]\n\n", progname);
    fprintf(stderr,
            "general options:\n"
            "    -o opt,[opt...]        mount options\n"
            "    -h   --help            print help\n"
            "    -V   --version         print version\n"
            "\n");
}

static void helper_help(void)
{
    fprintf(stderr,
            "FUSE options:\n"
            "    -d   -o debug          enable debug output (implies -f)\n"
            "    -f                     foreground operation\n"
            "    -s                     disable multi-threaded operation\n"
            "\n"
            );
}

static void helper_version(void)
{
    fprintf(stderr, "FUSE library version: %s\n", PACKAGE_VERSION);
}

static int fuse_helper_opt_proc(void *data, const char *arg, int key,
                                struct fuse_args *outargs)
{
    struct helper_opts *hopts = data;

    switch (key) {
    case KEY_HELP:
        usage(outargs->argv[0]);
        /* fall through */

    case KEY_HELP_NOHEADER:
        helper_help();
        return fuse_opt_add_arg(outargs, "-h");

    case KEY_VERSION:
        helper_version();
        return 1;

    case FUSE_OPT_KEY_NONOPT:
        if (!hopts->mountpoint)
            return fuse_opt_add_opt(&hopts->mountpoint, arg);
        else {
            fprintf(stderr, "fuse: invalid argument `%s'\n", arg);
            return -1;
        }

    default:
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

static int fuse_daemonize(int foreground)
{
    int res;

    if (!foreground) {
        res = daemon(0, 0);
        if (res == -1) {
            perror("fuse: failed to daemonize program\n");
            return -1;
        }
    } else {
        /* Ensure consistant behavior across debug and normal modes */
        res = chdir("/");
        if (res == -1) {
            perror("fuse: failed to change working directory to /\n");
            return -1;
        }
    }
    return 0;
}

static struct fuse *fuse_setup_common(int argc, char *argv[],
                                      const struct fuse_operations *op,
                                      size_t op_size,
                                      char **mountpoint,
                                      int *multithreaded,
                                      int *fd,
                                      int compat)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse *fuse;
    int foreground;
    int res;

    res = fuse_parse_cmdline(&args, mountpoint, multithreaded, &foreground);
    if (res == -1)
        return NULL;

    *fd = fuse_mount(*mountpoint, &args);
    if (*fd == -1) {
        fuse_opt_free_args(&args);
        goto err_free;
    }

    fuse = fuse_new_common(*fd, &args, op, op_size, compat);
    fuse_opt_free_args(&args);
    if (fuse == NULL)
        goto err_unmount;

    res = fuse_daemonize(foreground);
    if (res == -1)
        goto err_destroy;

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

struct fuse *fuse_setup(int argc, char *argv[],
                        const struct fuse_operations *op,
                        size_t op_size, char **mountpoint,
                        int *multithreaded, int *fd)
{
    return fuse_setup_common(argc, argv, op, op_size, mountpoint,
                             multithreaded, fd, 0);
}

void fuse_teardown(struct fuse *fuse, int fd, char *mountpoint)
{
    (void) fd;

    fuse_remove_signal_handlers(fuse_get_session(fuse));
    fuse_unmount(mountpoint);
    fuse_destroy(fuse);
    free(mountpoint);
}

static int fuse_main_common(int argc, char *argv[],
                            const struct fuse_operations *op, size_t op_size,
                            int compat)
{
    struct fuse *fuse;
    char *mountpoint;
    int multithreaded;
    int res;
    int fd;

    fuse = fuse_setup_common(argc, argv, op, op_size, &mountpoint,
                             &multithreaded, &fd, compat);
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
    return fuse_main_common(argc, argv, op, op_size, 0);
}

#undef fuse_main
int fuse_main(void)
{
    fprintf(stderr, "fuse_main(): This function does not exist\n");
    return -1;
}

#include "fuse_compat.h"

#ifndef __FreeBSD__

struct fuse *fuse_setup_compat22(int argc, char *argv[],
                                 const struct fuse_operations_compat22 *op,
                                 size_t op_size, char **mountpoint,
                                 int *multithreaded, int *fd)
{
    return fuse_setup_common(argc, argv, (struct fuse_operations *) op,
                             op_size, mountpoint, multithreaded, fd, 22);
}

struct fuse *fuse_setup_compat2(int argc, char *argv[],
                                 const struct fuse_operations_compat2 *op,
                                 char **mountpoint, int *multithreaded,
                                 int *fd)
{
    return fuse_setup_common(argc, argv, (struct fuse_operations *) op,
                             sizeof(struct fuse_operations_compat2),
                             mountpoint, multithreaded, fd, 21);
}

int fuse_main_real_compat22(int argc, char *argv[],
                            const struct fuse_operations_compat22 *op,
                            size_t op_size)
{
    return fuse_main_common(argc, argv, (struct fuse_operations *) op, op_size,
                            22);
}

void fuse_main_compat1(int argc, char *argv[],
                      const struct fuse_operations_compat1 *op)
{
    fuse_main_common(argc, argv, (struct fuse_operations *) op,
                     sizeof(struct fuse_operations_compat1), 11);
}

int fuse_main_compat2(int argc, char *argv[],
                      const struct fuse_operations_compat2 *op)
{
    return fuse_main_common(argc, argv, (struct fuse_operations *) op,
                            sizeof(struct fuse_operations_compat2), 21);
}

__asm__(".symver fuse_setup_compat2,__fuse_setup@");
__asm__(".symver fuse_setup_compat22,fuse_setup@FUSE_2.2");
__asm__(".symver fuse_teardown,__fuse_teardown@");
__asm__(".symver fuse_main_compat2,fuse_main@");
__asm__(".symver fuse_main_real_compat22,fuse_main_real@FUSE_2.2");

#endif /* __FreeBSD__ */


struct fuse *fuse_setup_compat25(int argc, char *argv[],
                                 const struct fuse_operations_compat25 *op,
                                 size_t op_size, char **mountpoint,
                                 int *multithreaded, int *fd)
{
    return fuse_setup_common(argc, argv, (struct fuse_operations *) op,
                             op_size, mountpoint, multithreaded, fd, 25);
}

int fuse_main_real_compat25(int argc, char *argv[],
                            const struct fuse_operations_compat25 *op,
                            size_t op_size)
{
    return fuse_main_common(argc, argv, (struct fuse_operations *) op, op_size,
                            25);
}

__asm__(".symver fuse_setup_compat25,fuse_setup@FUSE_2.5");
__asm__(".symver fuse_main_real_compat25,fuse_main_real@FUSE_2.5");
