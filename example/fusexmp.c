#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

/* For setgroups() */
#define _BSD_SOURCE

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <utime.h>
#include <fcntl.h>

static char *unmount_cmd;

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;

    res = lstat(path, stbuf);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if(res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int xmp_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    DIR *dp;
    struct dirent *de;
    int res = 0;

    dp = opendir(path);
    if(dp == NULL)
        return -errno;

    while((de = readdir(dp)) != NULL) {
        res = filler(h, de->d_name, de->d_type);
        if(res != 0)
            break;
    }

    closedir(dp);
    return res;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    res = mknod(path, mode, rdev);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;

    res = unlink(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if(res == -1)
        return -errno;
    
    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = lchown(path, uid, gid);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    int res;
    
    res = truncate(path, size);
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_utime(const char *path, struct utimbuf *buf)
{
    int res;
    
    res = utime(path, buf);
    if(res == -1)
        return -errno;

    return 0;
}


static int xmp_open(const char *path, int flags)
{
    int res;

    res = open(path, flags);
    if(res == -1) 
        return -errno;

    close(res);
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset)
{
    int fd;
    int res;

    fd = open(path, O_RDONLY);
    if(fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if(res == -1)
        res = -errno;
    
    close(fd);
    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset)
{
    int fd;
    int res;

    fd = open(path, O_WRONLY);
    if(fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if(res == -1)
        res = -errno;
    
    close(fd);
    return res;
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

static struct fuse_operations xmp_oper = {
    getattr:	xmp_getattr,
    readlink:	xmp_readlink,
    getdir:     xmp_getdir,
    mknod:	xmp_mknod,
    mkdir:	xmp_mkdir,
    symlink:	xmp_symlink,
    unlink:	xmp_unlink,
    rmdir:	xmp_rmdir,
    rename:     xmp_rename,
    link:	xmp_link,
    chmod:	xmp_chmod,
    chown:	xmp_chown,
    truncate:	xmp_truncate,
    utime:	xmp_utime,
    open:	xmp_open,
    read:	xmp_read,
    write:	xmp_write,
};

static void cleanup()
{
    close(0);
    system(unmount_cmd);    
}

int main(int argc, char *argv[])
{
    int argctr;
    int flags;
    struct fuse *fuse;

    if(argc < 2) {
        fprintf(stderr,
                "usage: %s unmount_cmd [options] \n"
                "Options:\n"
                "    -d      enable debug output\n"
                "    -s      disable multithreaded operation\n",
                argv[0]);
        exit(1);
    }

    argctr = 1;
    unmount_cmd = argv[argctr++];

    set_signal_handlers();
    atexit(cleanup);

    flags = FUSE_MULTITHREAD;
    for(; argctr < argc && argv[argctr][0] == '-'; argctr ++) {
        switch(argv[argctr][1]) {
        case 'd':
            flags |= FUSE_DEBUG;
            break;

        case 's':
            flags &= ~FUSE_MULTITHREAD;
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
    fuse_set_operations(fuse, &xmp_oper);
    fuse_loop(fuse);

    return 0;
}
