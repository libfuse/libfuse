/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse_i.h"
#include "fuse_opt.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <signal.h>

static struct fuse *fuse_instance;

static void usage(const char *progname)
{
    if (progname)
        fprintf(stderr,
                "usage: %s mountpoint [FUSE options]\n\n", progname);

    fprintf(stderr,
            "FUSE options:\n"
            "    -d                     enable debug output (implies -f)\n"
            "    -f                     foreground operation\n"
            "    -s                     disable multi-threaded operation\n"
            "    -r                     mount read only (equivalent to '-o ro')\n"
            "    -o opt,[opt...]        mount options\n"
            "    -h                     print help\n"
            "\n"
            "Mount options:\n"
            "    default_permissions    enable permission checking\n"
            "    allow_other            allow access to other users\n"
            "    allow_root             allow access to root\n"
            "    kernel_cache           cache files in kernel\n"
            "    large_read             issue large read requests (2.4 only)\n"
            "    direct_io              use direct I/O\n"
            "    max_read=N             set maximum size of read requests\n"
            "    hard_remove            immediate removal (don't hide files)\n"
            "    debug                  enable debug output\n"
            "    fsname=NAME            set filesystem name in mtab\n"
            "    use_ino                let filesystem set inode numbers\n"
            "    readdir_ino            try to fill in d_ino in readdir\n"
            "    nonempty               allow mounts over non-empty file/dir\n"
            "    umask=M                set file permissions (octal)\n"
            "    uid=N                  set file owner\n"
            "    gid=N                  set file group\n"
            );
}

static void exit_handler(int sig)
{
    (void) sig;
    if (fuse_instance != NULL)
        fuse_exit(fuse_instance);
}

static int set_one_signal_handler(int sig, void (*handler)(int))
{
    struct sigaction sa;
    struct sigaction old_sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(sig, NULL, &old_sa) == -1) {
        perror("FUSE: cannot get old signal handler");
        return -1;
    }

    if (old_sa.sa_handler == SIG_DFL &&
        sigaction(sig, &sa, NULL) == -1) {
        perror("Cannot set signal handler");
        return -1;
    }
    return 0;
}

static int set_signal_handlers(void)
{
    if (set_one_signal_handler(SIGHUP, exit_handler) == -1 ||
        set_one_signal_handler(SIGINT, exit_handler) == -1 ||
        set_one_signal_handler(SIGTERM, exit_handler) == -1 ||
        set_one_signal_handler(SIGPIPE, SIG_IGN) == -1)
        return -1;

    return 0;
}

enum  {
    KEY_HELP,
    KEY_HELP_NOHEADER,
    KEY_DEBUG,
    KEY_KERN,
    KEY_ALLOW_ROOT,
    KEY_RO,
};

struct helper_opts {
    const char *progname;
    int singlethread;
    int foreground;
    int allow_other;
    int allow_root;
    int fsname;
    char *kernel_opts;
    char *lib_opts;
    char *mountpoint;
};

#define FUSE_HELPER_OPT(t, p) { t, offsetof(struct helper_opts, p), 1 }
#define FUSE_HELPER_KEY(t, k)    { t, FUSE_OPT_OFFSET_KEY, k }

static const struct fuse_opt fuse_helper_opts[] = {
    FUSE_HELPER_OPT("-d",                       foreground),
    FUSE_HELPER_OPT("debug",                    foreground),
    FUSE_HELPER_OPT("-f",			foreground),
    FUSE_HELPER_OPT("-s",			singlethread),
    FUSE_HELPER_OPT("allow_other",              allow_other),
    FUSE_HELPER_OPT("allow_root",               allow_root),
    FUSE_HELPER_OPT("fsname=",                  fsname),

    FUSE_HELPER_KEY("-h",                       KEY_HELP),
    FUSE_HELPER_KEY("--help",                   KEY_HELP),
    FUSE_HELPER_KEY("-ho",                      KEY_HELP_NOHEADER),
    FUSE_HELPER_KEY("-d",                       KEY_DEBUG),
    FUSE_HELPER_KEY("debug",                    KEY_DEBUG),
    FUSE_HELPER_KEY("allow_other",              KEY_KERN),
    FUSE_HELPER_KEY("allow_root",               KEY_ALLOW_ROOT),
    FUSE_HELPER_KEY("nonempty",                 KEY_KERN),
    FUSE_HELPER_KEY("default_permissions",      KEY_KERN),
    FUSE_HELPER_KEY("fsname=",                  KEY_KERN),
    FUSE_HELPER_KEY("large_read",               KEY_KERN),
    FUSE_HELPER_KEY("max_read=",                KEY_KERN),
    FUSE_HELPER_KEY("-r",                       KEY_RO),
    FUSE_HELPER_KEY("ro",                       KEY_KERN),
    FUSE_HELPER_KEY("rw",                       KEY_KERN),
    FUSE_HELPER_KEY("suid",                     KEY_KERN),
    FUSE_HELPER_KEY("nosuid",                   KEY_KERN),
    FUSE_HELPER_KEY("dev",                      KEY_KERN),
    FUSE_HELPER_KEY("nodev",                    KEY_KERN),
    FUSE_HELPER_KEY("exec",                     KEY_KERN),
    FUSE_HELPER_KEY("noexec",                   KEY_KERN),
    FUSE_HELPER_KEY("async",                    KEY_KERN),
    FUSE_HELPER_KEY("sync",                     KEY_KERN),
    FUSE_HELPER_KEY("atime",                    KEY_KERN),
    FUSE_HELPER_KEY("noatime",                  KEY_KERN),
    FUSE_OPT_END
};

static int fuse_helper_opt_proc(void *data, const char *arg, int key,
                                struct fuse_args *outargs)
{
    struct helper_opts *hopts = data;

    (void) outargs;

    switch (key) {
    case KEY_HELP:
    case KEY_HELP_NOHEADER:
        usage(key == KEY_HELP ? hopts->progname : NULL);
        exit(1);

    case FUSE_OPT_KEY_OPT:
        return fuse_opt_add_opt(&hopts->lib_opts, arg);

    case FUSE_OPT_KEY_NONOPT:
        if (hopts->mountpoint)
            break;

        return fuse_opt_add_opt(&hopts->mountpoint, arg);

    case KEY_DEBUG:
        return fuse_opt_add_opt(&hopts->lib_opts, "debug");

    case KEY_ALLOW_ROOT:
        if (fuse_opt_add_opt(&hopts->kernel_opts, "allow_other") == -1 ||
            fuse_opt_add_opt(&hopts->lib_opts, "allow_root") == -1)
            return -1;
        return 0;

    case KEY_RO:
        arg = "ro";
        /* fall through */

    case KEY_KERN:
        return fuse_opt_add_opt(&hopts->kernel_opts, arg);
    }

    fprintf(stderr, "fuse: invalid option `%s'\n", arg);
    return -1;
}

static int fuse_parse_cmdline(int argc, const char *argv[],
                              struct helper_opts *hopts)
{
    int res;

    hopts->progname = argv[0];
    res = fuse_opt_parse(argc, (char **) argv, hopts, fuse_helper_opts,
                         fuse_helper_opt_proc, NULL);
    if (res == -1)
        return -1;

    if (hopts->allow_other && hopts->allow_root) {
        fprintf(stderr, "fuse: 'allow_other' and 'allow_root' options are mutually exclusive\n");
        return -1;
    }

    if (!hopts->fsname) {
        char *fsname_opt;
        const char *basename = strrchr(argv[0], '/');
        if (basename == NULL)
            basename = argv[0];
        else if (basename[1] != '\0')
            basename++;

        fsname_opt = (char *) malloc(strlen(basename) + 64);
        if (fsname_opt == NULL) {
            fprintf(stderr, "fuse: memory allocation failed\n");
            return -1;
        }
        sprintf(fsname_opt, "fsname=%s", basename);
        res = fuse_opt_add_opt(&hopts->kernel_opts, fsname_opt);
        free(fsname_opt);
        if (res == -1)
            return -1;
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
    struct fuse *fuse;
    struct helper_opts hopts;
    int res;

    if (fuse_instance != NULL) {
        fprintf(stderr, "fuse: fuse_setup() called twice\n");
        return NULL;
    }

    memset(&hopts, 0, sizeof(hopts));
    res = fuse_parse_cmdline(argc, (const char **) argv, &hopts);
    if (res == -1)
        goto err_free;

    *fd = fuse_mount(hopts.mountpoint, hopts.kernel_opts);
    if (*fd == -1)
        goto err_free;

    fuse = fuse_new_common(*fd, hopts.lib_opts, op, op_size, compat);
    if (fuse == NULL)
        goto err_unmount;

    if (!hopts.foreground) {
        res = daemon(0, 0);
        if (res == -1) {
            perror("fuse: failed to daemonize program\n");
            goto err_destroy;
        }
    } else {
        /* Ensure consistant behavior across debug and normal modes */
        res = chdir("/");
        if (res == -1) {
            perror("fuse: failed to change working directory to /\n");
            goto err_destroy;
        }
    }

    res = set_signal_handlers();
    if (res == -1)
        goto err_destroy;

    *mountpoint = hopts.mountpoint;
    *multithreaded = !hopts.singlethread;
    fuse_instance = fuse;
    free(hopts.kernel_opts);
    free(hopts.lib_opts);
    return fuse;

 err_destroy:
    fuse_destroy(fuse);
 err_unmount:
    fuse_unmount(hopts.mountpoint);
 err_free:
    free(hopts.mountpoint);
    free(hopts.kernel_opts);
    free(hopts.lib_opts);
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

    if (fuse_instance != fuse)
        fprintf(stderr, "fuse: fuse_teardown() with unknown fuse object\n");
    else
        fuse_instance = NULL;

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

#ifndef __FreeBSD__

#include "fuse_compat.h"

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
    return fuse_main_common(argc, argv, (struct fuse_operations *) op,
                            op_size, 22);
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
