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

static struct fuse *fuse;

static void usage(char *progname)
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
    exit(1);
}

static void invalid_option(char *argv[], int argctr)
{
    fprintf(stderr, "invalid option: %s\n\n", argv[argctr]);
    usage(argv[0]);
}

static void exit_handler()
{
    if (fuse != NULL)
        fuse_exit(fuse);
}

static void set_one_signal_handler(int signal, void (*handler)(int))
{
    struct sigaction sa;
    struct sigaction old_sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(signal, NULL, &old_sa) == -1) {
        perror("FUSE: cannot get old signal handler");
        exit(1);
    }
        
    if (old_sa.sa_handler == SIG_DFL &&
        sigaction(signal, &sa, NULL) == -1) {
        perror("Cannot set signal handler");
        exit(1);
    }
}

static void set_signal_handlers()
{
    set_one_signal_handler(SIGHUP, exit_handler);
    set_one_signal_handler(SIGINT, exit_handler);
    set_one_signal_handler(SIGTERM, exit_handler);
    set_one_signal_handler(SIGPIPE, SIG_IGN);
}

static int fuse_do(int fuse_fd, const char *opts, int multithreaded,
                      int background, const struct fuse_operations *op)
{
    int pid;
    int res;

    fuse = fuse_new(fuse_fd, opts, op);
    if (fuse == NULL)
        return 1;
    
    if (background) {
        pid = fork();
        if (pid == -1)
            return 1;

        if (pid)
            exit(0);
    }

    set_signal_handlers();

    if (multithreaded)
        res = fuse_loop_mt(fuse);
    else
        res = fuse_loop(fuse);
    
    fuse_destroy(fuse);

    if (res == -1)
        return 1;

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

static void add_options(char **lib_optp, char **kernel_optp, const char *opts)
{
    char *xopts = strdup(opts);
    char *s = xopts;
    char *opt;

    if (xopts == NULL) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        exit(1);
    }

    while((opt = strsep(&s, ",")) != NULL) {
        int res;
        if (fuse_is_lib_option(opt))
            res = add_option_to(opt, lib_optp);
        else
            res = add_option_to(opt, kernel_optp);
        if (res == -1) {
            fprintf(stderr, "fuse: memory allocation failed\n");
            exit(1);
        }
    }
    free(xopts);
}

void fuse_main(int argc, char *argv[], const struct fuse_operations *op)
{
    int argctr;
    int multithreaded;
    int background;
    int fuse_fd;
    char *fuse_mountpoint = NULL;
    char *basename;
    char *kernel_opts = NULL;
    char *lib_opts = NULL;
    char *fsname_opt;
    int err;

    basename = strrchr(argv[0], '/');
    if (basename == NULL)
        basename = argv[0];
    else if (basename[1] != '\0')
        basename++;

    fsname_opt = malloc(strlen(basename) + 64);
    if (fsname_opt == NULL) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        exit(1);
    }
    sprintf(fsname_opt, "fsname=%s", basename);
    add_options(&lib_opts, &kernel_opts, fsname_opt);
    free(fsname_opt);
    
    multithreaded = 1;
    background = 1;
    for (argctr = 1; argctr < argc; argctr ++) {
        if (argv[argctr][0] == '-') {
            if (strlen(argv[argctr]) == 2)
                switch (argv[argctr][1]) {
                case 'o':
                    if (argctr + 1 == argc || argv[argctr+1][0] == '-') {
                        fprintf(stderr, "missing option after -o\n\n");
                        usage(argv[0]);
                    }
                    argctr ++;
                    add_options(&lib_opts, &kernel_opts, argv[argctr]);
                    break;
                    
                case 'd':
                    add_options(&lib_opts, &kernel_opts, "debug");
                    background = 0;
                    break;
                    
                case 'f':
                    background = 0;
                    break;

                case 's':
                    multithreaded = 0;
                    break;
                    
                case 'h':
                    usage(argv[0]);
                    break;
                    
                default:
                    invalid_option(argv, argctr);
                }
            else {
                if (argv[argctr][1] == 'o')
                    add_options(&lib_opts, &kernel_opts, &argv[argctr][2]);
                else
                    invalid_option(argv, argctr);
            }
        } else if (fuse_mountpoint == NULL) {
            fuse_mountpoint = strdup(argv[argctr]);
            if (fuse_mountpoint == NULL) {
                fprintf(stderr, "fuse: memory allocation failed\n");
                exit(1);
            }
        }
        else
            invalid_option(argv, argctr);
    }

    if (fuse_mountpoint == NULL) {
        fprintf(stderr, "missing mountpoint\n\n");
        usage(argv[0]);
    }
    
    fuse_fd = fuse_mount(fuse_mountpoint, kernel_opts);
    if (fuse_fd == -1)
        exit(1);
    if (kernel_opts)
        free(kernel_opts);

    err = fuse_do(fuse_fd, lib_opts, multithreaded, background, op);
    if (lib_opts)
        free(lib_opts);
    close(fuse_fd);
    fuse_unmount(fuse_mountpoint);
    if (err)
        exit(err);
}

