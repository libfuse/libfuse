/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>

#define FUSE_MOUNTED_ENV     "_FUSE_MOUNTED"
#define FUSE_UMOUNT_CMD_ENV  "_FUSE_UNMOUNT_CMD"

static void usage(char *progname)
{
    fprintf(stderr,
            "usage: %s mountpoint [options] \n"
            "Options:\n"
            "    -d      enable debug output\n"
            "    -s      disable multithreaded operation\n"
            "    -h      print help\n",
            progname);
    exit(1);
}

static void fuse_unmount()
{
    close(0);
    system(getenv(FUSE_UMOUNT_CMD_ENV));
}

static int fuse_mount(int *argcp, char **argv)
{
    char *isreexec = getenv(FUSE_MOUNTED_ENV);

    if(isreexec == NULL) {
        int i;
        int argc = *argcp;
        char *mountprog = "fusermount";
        char **newargv = (char **) malloc((1 + argc + 1) * sizeof(char *));

        if(argc < 2 || argv[1][0] == '-')
            usage(argv[0]);
        
        /* oldargs: "PROG MOUNTPOINT ARGS..."
           newargs: "fusermount MOUNTPOINT PROG ARGS..." */

        newargv[0] = mountprog;
        newargv[1] = argv[1];
        newargv[2] = argv[0];
        for(i = 2; i < argc; i++)
            newargv[i+1] = argv[i];
        newargv[i+1] = NULL;

        execvp(mountprog, newargv);
        fprintf(stderr, "fuse: failed to exec %s: %s\n", mountprog,
                strerror(errno));
        return -1;
    }
    unsetenv(FUSE_MOUNTED_ENV);
    
    /* The actual file descriptor is stdin */
    return 0;
}


static void exit_handler()
{
    exit(0);
}

static void set_signal_handlers()
{
    struct sigaction sa;

    sa.sa_handler = exit_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(SIGHUP, &sa, NULL) == -1 || 
	sigaction(SIGINT, &sa, NULL) == -1 || 
	sigaction(SIGTERM, &sa, NULL) == -1) {
	
	perror("Cannot set exit signal handlers");
        exit(1);
    }

    sa.sa_handler = SIG_IGN;
    
    if(sigaction(SIGPIPE, &sa, NULL) == -1) {
	perror("Cannot set ignored signals");
        exit(1);
    }
}

void fuse_main(int argc, char *argv[], const struct fuse_operations *op)
{
    int fd;
    int argctr;
    int flags;
    int multithreaded;
    struct fuse *fuse;

    fd = fuse_mount(&argc, argv);
    if(fd == -1)
        exit(1);

    atexit(fuse_unmount);
    set_signal_handlers();

    argctr = 1;
    flags = 0;
    multithreaded = 1;
    for(; argctr < argc && argv[argctr][0] == '-'; argctr ++) {
        switch(argv[argctr][1]) {
        case 'd':
            flags |= FUSE_DEBUG;
            break;

        case 's':
            multithreaded = 0;
            break;

        case 'h':
            usage(argv[0]);
            break;

        default:
            fprintf(stderr, "invalid option: %s\n", argv[argctr]);
            exit(1);
        }
    }
    if(argctr != argc) {
        fprintf(stderr, "missing or surplus argument\n");
        exit(1);
    }

    fuse = fuse_new(fd, flags, op);

    if(multithreaded)
        fuse_loop_mt(fuse);
    else
        fuse_loop(fuse);
}

