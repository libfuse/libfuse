/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

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

#define FUSE_MOUNTED_ENV        "_FUSE_MOUNTED"
#define FUSE_UMOUNT_CMD_ENV     "_FUSE_UNMOUNT_CMD"

static struct fuse *fuse;

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

static void exit_handler()
{
    if(fuse != NULL)
        fuse_exit(fuse);
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
    int argctr = 1;
    int flags;
    int multithreaded;
    char *isreexec = getenv(FUSE_MOUNTED_ENV);
    int fuse_fd;
    char *fuse_mountpoint = NULL;
    char umount_cmd[1024] = "";

    if(isreexec == NULL) {
        if(argc < 2 || argv[1][0] == '-')
            usage(argv[0]);

        fuse_mountpoint = strdup(argv[1]);
        fuse_fd = fuse_mount(fuse_mountpoint, NULL);
        if(fuse_fd == -1)
            exit(1);

        argctr++;
    }
    else {
        char *tmpstr;

        /* Old (obsolescent) way of doing the mount: 
           
             fusermount [options] mountpoint [program [args ...]]

           fusermount execs this program and passes the control file
           descriptor dup()-ed to stdin */
        fuse_fd = 0;
        
        tmpstr = getenv(FUSE_UMOUNT_CMD_ENV);
        if(tmpstr != NULL)
            strncpy(umount_cmd, tmpstr, sizeof(umount_cmd) - 1);
    }

    set_signal_handlers();

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

    fuse = fuse_new(fuse_fd, flags, op);

    if(multithreaded)
        fuse_loop_mt(fuse);
    else
        fuse_loop(fuse);

    close(fuse_fd);
    if(fuse_mountpoint != NULL)
        fuse_unmount(fuse_mountpoint);
    else if(umount_cmd[0] != '\0')
        system(umount_cmd);
}

