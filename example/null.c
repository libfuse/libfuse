/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define UNUSED __attribute__((unused))

static int null_getattr(const char *path, struct stat *stbuf)
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;
    
    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_size = (1 << 30); /* 1G */
    stbuf->st_blocks = 0;
    stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

    return 0;
}

static int null_truncate(const char *path, off_t UNUSED(size))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return 0;
}

static int null_open(const char *path, int UNUSED(flags))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return 0;
}

static int null_read(const char *path, char *UNUSED(buf), size_t size,
                     off_t UNUSED(offset))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return size;
}

static int null_write(const char *path, const char *UNUSED(buf), size_t size,
                     off_t UNUSED(offset))
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return size;
}


static struct fuse_operations null_oper = {
    getattr:	null_getattr,
    readlink:	NULL,
    getdir:     NULL,
    mknod:	NULL,
    mkdir:	NULL,
    symlink:	NULL,
    unlink:	NULL,
    rmdir:	NULL,
    rename:     NULL,
    link:	NULL,
    chmod:	NULL,
    chown:	NULL,
    truncate:	null_truncate,
    utime:	NULL,
    open:	null_open,
    read:	null_read,
    write:	null_write,
};

static void cleanup()
{
    close(0);
    system(getenv("FUSE_UNMOUNT_CMD"));
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

int main(int argc, char *argv[])
{
    int argctr;
    int flags;
    int multithreaded;
    struct fuse *fuse;

    argctr = 1;

    atexit(cleanup);
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
            fprintf(stderr,
                    "usage: %s [options] \n"
                    "Options:\n"
                    "    -d      enable debug output\n"
                    "    -s      disable multithreaded operation\n"
                    "    -h      print help\n",
                    argv[0]);
            exit(1);
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

    fuse = fuse_new(0, flags);
    fuse_set_operations(fuse, &null_oper);

    if(multithreaded)
        fuse_loop_mt(fuse);
    else
        fuse_loop(fuse);

    return 0;
}
