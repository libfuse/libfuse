/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <signal.h>

static struct fuse *fuse_instance;

static void usage(const char *progname)
{
    fprintf(stderr,
            "usage: %s mountpoint [options]\n"
            "Options:\n"
            "    -d                  enable debug output (implies -f)\n"
            "    -f                  foreground operation\n"
            "    -s                  disable multithreaded operation\n"
            "    -o opt,[opt...]     mount options\n"
            "    -h                  print help\n"
            "\n"
            "Mount options:\n"
            "    default_permissions    enable permission checking\n"
            "    allow_other            allow access to other users\n"
            "    kernel_cache           cache files in kernel\n"
            "    large_read             issue large read requests (2.4 only)\n"
            "    direct_io              use direct I/O\n"
            "    max_read=N             set maximum size of read requests\n"
            "    hard_remove            immediate removal (don't hide files)\n"
            "    debug                  enable debug output\n"
            "    fsname=NAME            set filesystem name in mtab\n",
            progname);
}

static void invalid_option(const char *argv[], int argctr)
{
    fprintf(stderr, "fuse: invalid option: %s\n\n", argv[argctr]);
    usage(argv[0]);
}

static void exit_handler()
{
    if (fuse_instance != NULL)
        fuse_exit(fuse_instance);
}

static int set_one_signal_handler(int signal, void (*handler)(int))
{
    struct sigaction sa;
    struct sigaction old_sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(signal, NULL, &old_sa) == -1) {
        perror("FUSE: cannot get old signal handler");
        return -1;
    }
        
    if (old_sa.sa_handler == SIG_DFL &&
        sigaction(signal, &sa, NULL) == -1) {
        perror("Cannot set signal handler");
        return -1;
    }
    return 0;
}

static int set_signal_handlers()
{
    if (set_one_signal_handler(SIGHUP, exit_handler) == -1 ||
        set_one_signal_handler(SIGINT, exit_handler) == -1 ||
        set_one_signal_handler(SIGTERM, exit_handler) == -1 ||
        set_one_signal_handler(SIGPIPE, SIG_IGN) == -1)
        return -1;

    return 0;
}

static int add_option_to(const char *opt, char **optp)
{
    unsigned len = strlen(opt);
    if (*optp) {
        unsigned oldlen = strlen(*optp);
        *optp = realloc(*optp, oldlen + 1 + len + 1);
        if (*optp == NULL)
            return -1;
        (*optp)[oldlen] = ',';
        strcpy(*optp + oldlen + 1, opt);
    } else {
        *optp = malloc(len + 1);
        if (*optp == NULL)
            return -1;
        strcpy(*optp, opt);
    }
    return 0;
}

static int add_options(char **lib_optp, char **kernel_optp, const char *opts)
{
    char *xopts = strdup(opts);
    char *s = xopts;
    char *opt;

    if (xopts == NULL) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        return -1;
    }

    while((opt = strsep(&s, ",")) != NULL) {
        int res;
        if (fuse_is_lib_option(opt))
            res = add_option_to(opt, lib_optp);
        else
            res = add_option_to(opt, kernel_optp);
        if (res == -1) {
            fprintf(stderr, "fuse: memory allocation failed\n");
            return -1;
        }
    }
    free(xopts);
    return 0;
}

static int fuse_parse_cmdline(int argc, const char *argv[], char **kernel_opts,
                              char **lib_opts, char **mountpoint,
                              int *multithreaded, int *background)
{
    int res;
    int argctr;
    const char *basename;
    char *fsname_opt;
    
    *kernel_opts = NULL;
    *lib_opts = NULL;
    *mountpoint = NULL;
    *multithreaded = 1;
    *background = 1;

    basename = strrchr(argv[0], '/');
    if (basename == NULL)
        basename = argv[0];
    else if (basename[1] != '\0')
        basename++;

    fsname_opt = malloc(strlen(basename) + 64);
    if (fsname_opt == NULL) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        return -1;
    }
    sprintf(fsname_opt, "fsname=%s", basename);
    res = add_options(lib_opts, kernel_opts, fsname_opt);
    free(fsname_opt);
    if (res == -1)
        goto err;
    
    for (argctr = 1; argctr < argc; argctr ++) {
        if (argv[argctr][0] == '-') {
            if (strlen(argv[argctr]) == 2)
                switch (argv[argctr][1]) {
                case 'o':
                    if (argctr + 1 == argc || argv[argctr+1][0] == '-') {
                        fprintf(stderr, "missing option after -o\n\n");
                        usage(argv[0]);
                        goto err;
                    }
                    argctr ++;
                    res = add_options(lib_opts, kernel_opts, argv[argctr]);
                    if (res == -1)
                        goto err;
                    break;
                    
                case 'd':
                    res = add_options(lib_opts, kernel_opts, "debug");
                    if (res == -1)
                        goto err;
                    *background = 0;
                    break;
                    
                case 'f':
                    *background = 0;
                    break;

                case 's':
                    *multithreaded = 0;
                    break;
                    
                case 'h':
                    usage(argv[0]);
                    goto err;
                    
                default:
                    invalid_option(argv, argctr);
                    goto err;
                }
            else {
                if (argv[argctr][1] == 'o') {
                    res = add_options(lib_opts, kernel_opts, &argv[argctr][2]);
                    if (res == -1)
                        goto err;
                }
                else {
                    invalid_option(argv, argctr);
                    goto err;
                }
            }
        } else if (*mountpoint == NULL) {
            *mountpoint = strdup(argv[argctr]);
            if (*mountpoint == NULL) {
                fprintf(stderr, "fuse: memory allocation failed\n");
                goto err;
            }
        }
        else {
            invalid_option(argv, argctr);
            goto err;
        }
    }

    if (*mountpoint == NULL) {
        fprintf(stderr, "missing mountpoint\n\n");
        usage(argv[0]);
        goto err;
    }
    return 0;

 err:
    free(*kernel_opts);
    free(*lib_opts);
    free(*mountpoint);
    return -1;
}
                              

struct fuse *__fuse_setup(int argc, char *argv[],
                          const struct fuse_operations *op,
                          char **mountpoint, int *multithreaded, int *fd)
{
    struct fuse *fuse;
    int background;
    char *kernel_opts;
    char *lib_opts;
    int res;
    
    if (fuse_instance != NULL) {
        fprintf(stderr, "fuse: __fuse_setup() called twice\n");
        return NULL;
    }

    res = fuse_parse_cmdline(argc, (const char **) argv, &kernel_opts,
                             &lib_opts, mountpoint, multithreaded,
                             &background);
    if (res == -1)
        return NULL;

    *fd = fuse_mount(*mountpoint, kernel_opts);
    if (*fd == -1)
        goto err_free;

    fuse = fuse_new(*fd, lib_opts, op);
    if (fuse == NULL)
        goto err_unmount;

    if (background) {
        res = daemon(0, 0);
        if (res == -1) {
            perror("fuse: failed to daemonize program\n");
            goto err_destroy;
        }
    }

    fuse_instance = fuse;
    res = set_signal_handlers();
    if (res == -1)
        goto err_destroy;

    free(kernel_opts);
    free(lib_opts);
    return fuse;

 err_destroy:
    fuse_destroy(fuse);
 err_unmount:
    fuse_unmount(*mountpoint);
 err_free:
    free(kernel_opts);
    free(lib_opts);
    free(*mountpoint);
    return NULL;
}

void __fuse_teardown(struct fuse *fuse, int fd, char *mountpoint)
{
    if (fuse_instance != fuse)
        fprintf(stderr, "fuse: __fuse_teardown() with unknown fuse object\n");
    else
        fuse_instance = NULL;

    fuse_destroy(fuse);
    close(fd);
    fuse_unmount(mountpoint);
    free(mountpoint);
}


int fuse_main(int argc, char *argv[], const struct fuse_operations *op)
{
    struct fuse *fuse;
    char *mountpoint;
    int multithreaded;
    int res;
    int fd;

    fuse = __fuse_setup(argc, argv, op, &mountpoint, &multithreaded, &fd);
    if (fuse == NULL)
        return 1;
    
    if (multithreaded)
        res = fuse_loop_mt(fuse);
    else
        res = fuse_loop(fuse);
    
    __fuse_teardown(fuse, fd, mountpoint);
    if (res == -1)
        return 1;
    
    return 0;
}

