/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"
#include "fuse_opt.h"
#include "fuse_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#define FUSERMOUNT_PROG         "fusermount"
#define FUSE_COMMFD_ENV         "_FUSE_COMMFD"

enum {
    KEY_KERN,
    KEY_ALLOW_ROOT,
    KEY_RO,
    KEY_HELP,
    KEY_VERSION,
};

struct mount_opts {
    int allow_other;
    int allow_root;
    int ishelp;
    char *kernel_opts;
};

static const struct fuse_opt fuse_mount_opts[] = {
    { "allow_other", offsetof(struct mount_opts, allow_other), 1 },
    { "allow_root", offsetof(struct mount_opts, allow_root), 1 },
    FUSE_OPT_KEY("allow_other",         KEY_KERN),
    FUSE_OPT_KEY("allow_root",          KEY_ALLOW_ROOT),
    FUSE_OPT_KEY("nonempty",            KEY_KERN),
    FUSE_OPT_KEY("default_permissions", KEY_KERN),
    FUSE_OPT_KEY("fsname=",             KEY_KERN),
    FUSE_OPT_KEY("large_read",          KEY_KERN),
    FUSE_OPT_KEY("max_read=",           KEY_KERN),
    FUSE_OPT_KEY("-r",                  KEY_RO),
    FUSE_OPT_KEY("ro",                  KEY_KERN),
    FUSE_OPT_KEY("rw",                  KEY_KERN),
    FUSE_OPT_KEY("suid",                KEY_KERN),
    FUSE_OPT_KEY("nosuid",              KEY_KERN),
    FUSE_OPT_KEY("dev",                 KEY_KERN),
    FUSE_OPT_KEY("nodev",               KEY_KERN),
    FUSE_OPT_KEY("exec",                KEY_KERN),
    FUSE_OPT_KEY("noexec",              KEY_KERN),
    FUSE_OPT_KEY("async",               KEY_KERN),
    FUSE_OPT_KEY("sync",                KEY_KERN),
    FUSE_OPT_KEY("atime",               KEY_KERN),
    FUSE_OPT_KEY("noatime",             KEY_KERN),
    FUSE_OPT_KEY("-h",                  KEY_HELP),
    FUSE_OPT_KEY("--help",              KEY_HELP),
    FUSE_OPT_KEY("-V",                  KEY_VERSION),
    FUSE_OPT_KEY("--version",           KEY_VERSION),
    FUSE_OPT_END
};

static void mount_help(void)
{
    fprintf(stderr,
            "    -o allow_other         allow access to other users\n"
            "    -o allow_root          allow access to root\n"
            "    -o nonempty            allow mounts over non-empty file/dir\n"
            "    -o default_permissions enable permission checking by kernel\n"
            "    -o fsname=NAME         set filesystem name\n"
            "    -o large_read          issue large read requests (2.4 only)\n"
            "    -o max_read=N          set maximum size of read requests\n"
            "\n"
            );
}

static void mount_version(void)
{
    system(FUSERMOUNT_PROG " --version");
}

static int fuse_mount_opt_proc(void *data, const char *arg, int key,
                               struct fuse_args *outargs)
{
    struct mount_opts *mo = data;

    switch (key) {
    case KEY_ALLOW_ROOT:
        if (fuse_opt_add_opt(&mo->kernel_opts, "allow_other") == -1 ||
            fuse_opt_add_arg(outargs, "-oallow_root") == -1)
            return -1;
        return 0;

    case KEY_RO:
        arg = "ro";
        /* fall through */

    case KEY_KERN:
        return fuse_opt_add_opt(&mo->kernel_opts, arg);

    case KEY_HELP:
        mount_help();
        mo->ishelp = 1;
        break;

    case KEY_VERSION:
        mount_version();
        mo->ishelp = 1;
        break;
    }
    return 1;
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

void fuse_unmount(const char *mountpoint)
{
    const char *mountprog = FUSERMOUNT_PROG;
    int pid;

    if (!mountpoint)
        return;

#ifdef HAVE_FORK
    pid = fork();
#else
    pid = vfork();
#endif
    if(pid == -1)
        return;

    if(pid == 0) {
        const char *argv[32];
        int a = 0;

        argv[a++] = mountprog;
        argv[a++] = "-u";
        argv[a++] = "-q";
        argv[a++] = "-z";
        argv[a++] = "--";
        argv[a++] = mountpoint;
        argv[a++] = NULL;

        execvp(mountprog, (char **) argv);
        exit(1);
    }
    waitpid(pid, NULL, 0);
}

int fuse_mount_compat22(const char *mountpoint, const char *opts)
{
    const char *mountprog = FUSERMOUNT_PROG;
    int fds[2], pid;
    int res;
    int rv;

    if (!mountpoint) {
        fprintf(stderr, "fuse: missing mountpoint\n");
        return -1;
    }

    res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
    if(res == -1) {
        perror("fuse: socketpair() failed");
        return -1;
    }

#ifdef HAVE_FORK
    pid = fork();
#else
    pid = vfork();
#endif
    if(pid == -1) {
        perror("fuse: fork() failed");
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    if(pid == 0) {
        char env[10];
        const char *argv[32];
        int a = 0;

        argv[a++] = mountprog;
        if (opts) {
            argv[a++] = "-o";
            argv[a++] = opts;
        }
        argv[a++] = "--";
        argv[a++] = mountpoint;
        argv[a++] = NULL;

        close(fds[1]);
        fcntl(fds[0], F_SETFD, 0);
        snprintf(env, sizeof(env), "%i", fds[0]);
        setenv(FUSE_COMMFD_ENV, env, 1);
        execvp(mountprog, (char **) argv);
        perror("fuse: failed to exec fusermount");
        exit(1);
    }

    close(fds[0]);
    rv = receive_fd(fds[1]);
    close(fds[1]);
    waitpid(pid, NULL, 0); /* bury zombie */

    return rv;
}

int fuse_mount(const char *mountpoint, struct fuse_args *args)
{
    struct mount_opts mo;
    int res = -1;

    memset(&mo, 0, sizeof(mo));

    if (args &&
        fuse_opt_parse(args, &mo, fuse_mount_opts, fuse_mount_opt_proc) == -1)
        return -1;

    if (mo.allow_other && mo.allow_root) {
        fprintf(stderr, "fuse: 'allow_other' and 'allow_root' options are mutually exclusive\n");
        goto out;
    }
    if (mo.ishelp)
        return 0;

    res = fuse_mount_compat22(mountpoint, mo.kernel_opts);
 out:
    free(mo.kernel_opts);
    return res;
}

int fuse_mount_compat1(const char *mountpoint, const char *args[])
{
    /* just ignore mount args for now */
    (void) args;
    return fuse_mount_compat22(mountpoint, NULL);
}

__asm__(".symver fuse_mount_compat22,fuse_mount@");
