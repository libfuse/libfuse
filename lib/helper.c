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

#define FUSE_MOUNTED_ENV        "_FUSE_MOUNTED"
#define FUSE_UMOUNT_CMD_ENV     "_FUSE_UNMOUNT_CMD"
#define FUSE_COMMFD_ENV         "_FUSE_COMMFD"

#define FUSERMOUNT_PROG         "fusermount"

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

static char umount_cmd[1024];
static int fuse_fd;

static void fuse_unmount()
{
    close(fuse_fd);
    if(umount_cmd[0] != '\0')
        system(umount_cmd);
}

/* return value:
 * >= 0  => fd
 * -1    => error
 */
static int receive_fd(int fd)
{
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

    while(((rv = recvmsg(fd, &msg, 0)) == -1) && errno == EINTR);
    if (rv == -1) {
        perror("recvmsg");
        return -1;
    }
    if(!rv) {
        /* EOF */
        fprintf(stderr, "got EOF\n");
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

int fuse_mount(const char *mountpoint, const char *args[])
{
    const char *mountprog = FUSERMOUNT_PROG;
    int fds[2], pid;
    int res;
    int rv;

    snprintf(umount_cmd, sizeof(umount_cmd) - 1, "%s -u %s", mountprog,
             mountpoint);
    
    res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
    if(res == -1) {
        perror("fuse: socketpair() failed");
        return -1;
    }

    pid = fork();
    if(pid == -1) {
        perror("fuse: fork() failed");
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    if(pid == 0) {
        char env[10];
        char **newargv;
        int numargs = 0;
        int actr;
        int i;

        if(args != NULL) 
            while(args[numargs] != NULL)
                numargs ++;

        newargv = (char **) malloc((1 + numargs + 2) * sizeof(char *));
        actr = 0;
        newargv[actr++] = strdup(mountprog);
        for(i = 0; i < numargs; i++)
            newargv[actr++] = strdup(args[i]);
        newargv[actr++] = strdup(mountpoint);
        newargv[actr++] = NULL;

        close(fds[1]);
        fcntl(fds[0], F_SETFD, 0);
        snprintf(env, sizeof(env), "%i", fds[0]);
        setenv(FUSE_COMMFD_ENV, env, 1);
        execvp(mountprog, newargv);
        perror("fuse: failed to exec fusermount");
        exit(1);
    }

    close(fds[0]);
    rv = receive_fd(fds[1]);
    close(fds[1]);
    waitpid(pid, NULL, 0); /* bury zombie */

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
    int argctr = 1;
    int flags;
    int multithreaded;
    struct fuse *fuse;
    char *isreexec = getenv(FUSE_MOUNTED_ENV);

    if(isreexec == NULL) {
        if(argc < 2 || argv[1][0] == '-')
            usage(argv[0]);

        fuse_fd = fuse_mount(argv[1], NULL);
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

    atexit(fuse_unmount);
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
}

