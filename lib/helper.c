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
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/wait.h>

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

static int fuse_mount_obsolete(int *argcp, char **argv)
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

int receive_fd(int fd) {
    struct msghdr msg;
    struct iovec iov;
    char buf[1];
    int rv;
    int connfd = -1;
    char ccmsg[CMSG_SPACE(sizeof(connfd))];
    struct cmsghdr *cmsg;

    iov.iov_base = buf;
    iov.iov_len = 1;

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    /* old BSD implementations should use msg_accrights instead of
     * msg_control; the interface is different. */
    msg.msg_control = ccmsg;
    msg.msg_controllen = sizeof(ccmsg);

    rv = recvmsg(fd, &msg, 0);
    if (rv == -1) {
        perror("recvmsg");
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg->cmsg_type == SCM_RIGHTS) {
        fprintf(stderr, "got control message of unknown type %d\n",
                cmsg->cmsg_type);
        return -1;
    }
    return *(int*)CMSG_DATA(cmsg);
}

int fuse_mount(const char *mountpoint, const char *mount_args)
{
    int fds[2], pid;
    int rv, fd;
    char env[10];
    
    /* FIXME: parse mount_args (or just pass it to fusermount ???) */
    mount_args = mount_args;

    if(socketpair(PF_UNIX,SOCK_DGRAM,0,fds)) {
        fprintf(stderr,"fuse: failed to socketpair()\n");
        return -1;
    }
    pid = fork();
    if(pid < 0) {
        fprintf(stderr,"fuse: failed to fork()\n");
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if(pid == 0) {
        close(fds[1]);
        fcntl(fds[0],F_SETFD,0);
        snprintf(env,sizeof(env),"%i",fds[0]);
        setenv("_FUSE_IOSLAVE_FD",env,1);
        execlp("fusermount","fusermount",mountpoint,"fuse_ioslave",NULL);
        fprintf(stderr,"fuse: failed to exec fusermount\n");
        exit(1);
    }

    fd = fds[1];
    close(fds[0]);
    while((rv = receive_fd(fd)) < 0)
        sleep(1);
    close(fd);
    while(wait(NULL) != pid); /* bury zombie */
    return rv;
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

    fd = fuse_mount_obsolete(&argc, argv);
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

