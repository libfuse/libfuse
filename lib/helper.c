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

struct fuse *fuse_get(void)
{
    return fuse;
}

static void usage(char *progname)
{
    fprintf(stderr,
            "usage: %s mountpoint [options] [-- [fusermount options]]\n"
            "Options:\n"
            "    -d      enable debug output (implies -f)\n"
            "    -f      foreground operation\n"
            "    -s      disable multithreaded operation\n"
            "    -i      immediate removal (don't delay until last release)\n"
            "    -h      print help\n"
            "\n"
            "Fusermount options:\n"
            "            see 'fusermount -h'\n",
            progname);
    exit(1);
}

static void invalid_option(char *argv[], int argctr)
{
    fprintf(stderr, "invalid option: %s\n", argv[argctr]);
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

static int fuse_start(int fuse_fd, int flags, int multithreaded,
                      int background, const struct fuse_operations *op)
{
    int pid;

    fuse = fuse_new(fuse_fd, flags, op);
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
        fuse_loop_mt(fuse);
    else
        fuse_loop(fuse);
    
    fuse_destroy(fuse);

    return 0;
}

void fuse_main(int argc, char *argv[], const struct fuse_operations *op)
{
    int argctr;
    int flags;
    int multithreaded;
    int background;
    int fuse_fd;
    char *fuse_mountpoint = NULL;
    char **fusermount_args = NULL;
    char *newargs[3];
    char *basename;
    int err;
    
    flags = 0;
    multithreaded = 1;
    background = 1;
    for (argctr = 1; argctr < argc && !fusermount_args; argctr ++) {
        if (argv[argctr][0] == '-') {
            if (strlen(argv[argctr]) == 2)
                switch (argv[argctr][1]) {
                case 'd':
                    flags |= FUSE_DEBUG;
                    background = 0;
                    break;
                    
                case 'i':
                    flags |= FUSE_HARD_REMOVE;
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
                    
                case '-':
                    fusermount_args = &argv[argctr+1];
                    break;
                    
                default:
                    invalid_option(argv, argctr);
                }
            else
                invalid_option(argv, argctr);
        } else if (fuse_mountpoint == NULL)
            fuse_mountpoint = strdup(argv[argctr]);
        else
            invalid_option(argv, argctr);
    }

    if (fuse_mountpoint == NULL) {
        fprintf(stderr, "missing mountpoint\n");
        usage(argv[0]);
    }
    if (fusermount_args != NULL)
        fusermount_args -= 2; /* Hack! */
    else {
        fusermount_args = newargs;
        fusermount_args[2] = NULL;
    }
    
    basename = strrchr(argv[0], '/');
    if (basename == NULL)
        basename = argv[0];
    else if (basename[1] != '\0')
        basename++;

    fusermount_args[0] = "-n";
    fusermount_args[1] = basename;

    fuse_fd = fuse_mount(fuse_mountpoint, (const char **) fusermount_args);
    if (fuse_fd == -1)
        exit(1);

    err = fuse_start(fuse_fd, flags, multithreaded, background, op);
    close(fuse_fd);
    fuse_unmount(fuse_mountpoint);
    if (err)
        exit(err);
}

