/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "config.h"
#include "fuse_i.h"
#include "fuse_opt.h"
#include "fuse_common_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/mount.h>

#define FUSERMOUNT_PROG         "fusermount"
#define FUSE_COMMFD_ENV         "_FUSE_COMMFD"

#ifndef HAVE_FORK
#define fork() vfork()
#endif

#ifndef MS_DIRSYNC
#define MS_DIRSYNC 128
#endif

enum {
    KEY_KERN_FLAG,
    KEY_KERN_OPT,
    KEY_FUSERMOUNT_OPT,
    KEY_MTAB_OPT,
    KEY_ALLOW_ROOT,
    KEY_RO,
    KEY_HELP,
    KEY_VERSION,
};

struct mount_opts {
    int allow_other;
    int allow_root;
    int ishelp;
    int flags;
    int nonempty;
    int blkdev;
    int large_read;
    char *fsname;
    char *mtab_opts;
    char *fusermount_opts;
    char *kernel_opts;
};

#define FUSE_MOUNT_OPT(t, p) { t, offsetof(struct mount_opts, p), 1 }

static const struct fuse_opt fuse_mount_opts[] = {
    FUSE_MOUNT_OPT("allow_other",       allow_other),
    FUSE_MOUNT_OPT("allow_root",        allow_root),
    FUSE_MOUNT_OPT("nonempty",          nonempty),
    FUSE_MOUNT_OPT("blkdev",            blkdev),
    FUSE_MOUNT_OPT("fsname=%s",         fsname),
    FUSE_MOUNT_OPT("large_read",        large_read),
    FUSE_OPT_KEY("allow_other",         KEY_KERN_OPT),
    FUSE_OPT_KEY("allow_root",          KEY_ALLOW_ROOT),
    FUSE_OPT_KEY("nonempty",            KEY_FUSERMOUNT_OPT),
    FUSE_OPT_KEY("blkdev",              KEY_FUSERMOUNT_OPT),
    FUSE_OPT_KEY("fsname=",             KEY_FUSERMOUNT_OPT),
    FUSE_OPT_KEY("large_read",          KEY_FUSERMOUNT_OPT),
    FUSE_OPT_KEY("blksize=",            KEY_KERN_OPT),
    FUSE_OPT_KEY("default_permissions", KEY_KERN_OPT),
    FUSE_OPT_KEY("max_read=",           KEY_KERN_OPT),
    FUSE_OPT_KEY("max_read=",           FUSE_OPT_KEY_KEEP),
    FUSE_OPT_KEY("user=",               KEY_MTAB_OPT),
    FUSE_OPT_KEY("-r",                  KEY_RO),
    FUSE_OPT_KEY("ro",                  KEY_KERN_FLAG),
    FUSE_OPT_KEY("rw",                  KEY_KERN_FLAG),
    FUSE_OPT_KEY("suid",                KEY_KERN_FLAG),
    FUSE_OPT_KEY("nosuid",              KEY_KERN_FLAG),
    FUSE_OPT_KEY("dev",                 KEY_KERN_FLAG),
    FUSE_OPT_KEY("nodev",               KEY_KERN_FLAG),
    FUSE_OPT_KEY("exec",                KEY_KERN_FLAG),
    FUSE_OPT_KEY("noexec",              KEY_KERN_FLAG),
    FUSE_OPT_KEY("async",               KEY_KERN_FLAG),
    FUSE_OPT_KEY("sync",                KEY_KERN_FLAG),
    FUSE_OPT_KEY("dirsync",             KEY_KERN_FLAG),
    FUSE_OPT_KEY("atime",               KEY_KERN_FLAG),
    FUSE_OPT_KEY("noatime",             KEY_KERN_FLAG),
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

static void exec_fusermount(const char *argv[])
{
    execv(FUSERMOUNT_DIR "/" FUSERMOUNT_PROG, (char **) argv);
    execvp(FUSERMOUNT_PROG, (char **) argv);
}

static void mount_version(void)
{
    int pid = fork();
    if (!pid) {
        const char *argv[] = { FUSERMOUNT_PROG, "--version", NULL };
        exec_fusermount(argv);
        _exit(1);
    } else if (pid != -1)
        waitpid(pid, NULL, 0);
}

struct mount_flags {
    const char *opt;
    unsigned long flag;
    int on;
};

static struct mount_flags mount_flags[] = {
    {"rw",      MS_RDONLY,      0},
    {"ro",      MS_RDONLY,      1},
    {"suid",    MS_NOSUID,      0},
    {"nosuid",  MS_NOSUID,      1},
    {"dev",     MS_NODEV,       0},
    {"nodev",   MS_NODEV,       1},
    {"exec",    MS_NOEXEC,      0},
    {"noexec",  MS_NOEXEC,      1},
    {"async",   MS_SYNCHRONOUS, 0},
    {"sync",    MS_SYNCHRONOUS, 1},
    {"atime",   MS_NOATIME,     0},
    {"noatime", MS_NOATIME,     1},
    {"dirsync", MS_DIRSYNC,     1},
    {NULL,      0,              0}
};

static void set_mount_flag(const char *s, int *flags)
{
    int i;

    for (i = 0; mount_flags[i].opt != NULL; i++) {
        const char *opt = mount_flags[i].opt;
        if (strcmp(opt, s) == 0) {
            if (mount_flags[i].on)
                *flags |= mount_flags[i].flag;
            else
                *flags &= ~mount_flags[i].flag;
            return;
        }
    }
    fprintf(stderr, "fuse: internal error, can't find mount flag\n");
    abort();
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
    case KEY_KERN_FLAG:
        set_mount_flag(arg, &mo->flags);
        return 0;

    case KEY_KERN_OPT:
        return fuse_opt_add_opt(&mo->kernel_opts, arg);

    case KEY_FUSERMOUNT_OPT:
        return fuse_opt_add_opt(&mo->fusermount_opts, arg);

    case KEY_MTAB_OPT:
        return fuse_opt_add_opt(&mo->mtab_opts, arg);

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
    size_t ccmsg[CMSG_SPACE(sizeof(int)) / sizeof(size_t)];
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

void fuse_kern_unmount(const char *mountpoint, int fd)
{
    int res;
    int pid;

    if (!mountpoint)
        return;

    if (fd != -1) {
        struct pollfd pfd;

        pfd.fd = fd;
        pfd.events = 0;
        res = poll(&pfd, 1, 0);
        /* If file poll returns POLLERR on the device file descriptor,
           then the filesystem is already unmounted */
        if (res == 1 && (pfd.revents & POLLERR))
            return;
    }

    res = umount2(mountpoint, 2);
    if (res == 0)
        return;

    pid = fork();
    if(pid == -1)
        return;

    if(pid == 0) {
        const char *argv[] =
            { FUSERMOUNT_PROG, "-u", "-q", "-z", "--", mountpoint, NULL };

        exec_fusermount(argv);
        _exit(1);
    }
    waitpid(pid, NULL, 0);
}

void fuse_unmount_compat22(const char *mountpoint)
{
    fuse_kern_unmount(mountpoint, -1);
}

int fuse_mount_compat22(const char *mountpoint, const char *opts)
{
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

    pid = fork();
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

        argv[a++] = FUSERMOUNT_PROG;
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
        exec_fusermount(argv);
        perror("fuse: failed to exec fusermount");
        _exit(1);
    }

    close(fds[0]);
    rv = receive_fd(fds[1]);
    close(fds[1]);
    waitpid(pid, NULL, 0); /* bury zombie */

    return rv;
}

static int add_mount(const char *fsname, const char *mnt, const char *type,
                     const char *opts)
{
    int res;
    int status;

    res = fork();
    if (res == -1) {
        perror("fork");
        return -1;
    }
    if (res == 0) {
        setuid(geteuid());
        execl("/bin/mount", "/bin/mount", "-i", "-f", "-t", type, "-o", opts,
              fsname, mnt, NULL);
        perror("execl /bin/mount");
        exit(1);
    }
    res = waitpid(res, &status, 0);
    if (res == -1) {
        perror("waitpid");
        return -1;
    }
    if (status != 0)
        return -1;

    return 0;
}

static int fuse_mount_sys(const char *mnt, struct mount_opts *mo,
                          const char *mnt_opts)
{
    const char *type = mo->blkdev ? "fuseblk" : "fuse";
    char tmp[128];
    const char *devname = "/dev/fuse";
    struct stat stbuf;
    int fd;
    int res;

    /* For now silently fall back to fusermount if something doesn't work */

    /* FIXME: check non-empty mountpoint*/

    if (mo->large_read)
        return -1;

    res = lstat(mnt, &stbuf);
    if (res == -1)
        return -1;

    fd = open(devname, O_RDWR);
    if (fd == -1)
        return -1;

    if (mo->fsname)
        devname = mo->fsname;

    snprintf(tmp, sizeof(tmp),  "fd=%i,rootmode=%o,user_id=%i,group_id=%i", fd,
             stbuf.st_mode & S_IFMT, getuid(), getgid());

    if (fuse_opt_add_opt(&mo->kernel_opts, tmp) == -1) {
        close(fd);
        return -1;
    }
    res = mount(devname, mnt, type, mo->flags, mo->kernel_opts);
    if (res == -1) {
        close(fd);
        return -1;
    }
    if (geteuid() == 0) {
        res = add_mount(devname, mnt, type, mnt_opts);
        if (res == -1) {
            umount2(mnt, 2); /* lazy umount */
            close(fd);
            return -1;
        }
    }
    return fd;
}

static int get_mnt_flag_opts(char **mnt_optsp, int flags)
{
    int i;

    if (!(flags & MS_RDONLY) && fuse_opt_add_opt(mnt_optsp, "rw") == -1)
        return -1;

    for (i = 0; mount_flags[i].opt != NULL; i++) {
        if (mount_flags[i].on && (flags & mount_flags[i].flag) &&
            fuse_opt_add_opt(mnt_optsp, mount_flags[i].opt) == -1)
            return -1;
    }
    return 0;
}

int fuse_kern_mount(const char *mountpoint, struct fuse_args *args)
{
    struct mount_opts mo;
    int res = -1;
    char *mnt_opts = NULL;

    memset(&mo, 0, sizeof(mo));
    mo.flags = MS_NOSUID | MS_NODEV;

    if (args &&
        fuse_opt_parse(args, &mo, fuse_mount_opts, fuse_mount_opt_proc) == -1)
        return -1;

    if (mo.allow_other && mo.allow_root) {
        fprintf(stderr, "fuse: 'allow_other' and 'allow_root' options are mutually exclusive\n");
        goto out;
    }
    res = 0;
    if (mo.ishelp)
        goto out;

    res = -1;
    if (get_mnt_flag_opts(&mnt_opts, mo.flags) == -1)
        goto out;
    if (mo.kernel_opts && fuse_opt_add_opt(&mnt_opts, mo.kernel_opts) == -1)
        goto out;
    if (mo.mtab_opts &&  fuse_opt_add_opt(&mnt_opts, mo.mtab_opts) == -1)
        goto out;

    res = fuse_mount_sys(mountpoint, &mo, mnt_opts);
    if (res == -1) {
        if (mo.fusermount_opts && 
            fuse_opt_add_opt(&mnt_opts, mo.fusermount_opts) == -1)
            goto out;

        res = fuse_mount_compat22(mountpoint, mnt_opts);
    }
 out:
    free(mnt_opts);
    free(mo.fsname);
    free(mo.fusermount_opts);
    free(mo.kernel_opts);
    free(mo.mtab_opts);
    return res;
}

__asm__(".symver fuse_mount_compat22,fuse_mount@FUSE_2.2");
__asm__(".symver fuse_unmount_compat22,fuse_unmount@FUSE_2.2");
