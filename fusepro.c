#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <utime.h>
#include <fcntl.h>

static struct fuse *pro_fuse;

static int pro_getattr(const char *path, struct stat *stbuf)
{
    int res;

    res = lstat(path, stbuf);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if(res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int pro_getdir(const char *path, struct fuse_dh *h, dirfiller_t filler)
{
    DIR *dp;
    struct dirent *de;
    int res;

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

static int pro_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    res = mknod(path, mode, rdev);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_unlink(const char *path)
{
    int res;

    res = unlink(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if(res == -1)
        return -errno;
    
    return 0;
}

static int pro_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = chown(path, uid, gid);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_truncate(const char *path, off_t size)
{
    int res;
    
    res = truncate(path, size);
    if(res == -1)
        return -errno;

    return 0;
}

static int pro_utime(const char *path, struct utimbuf *buf)
{
    int res;
    
    res = utime(path, buf);
    if(res == -1)
        return -errno;

    return 0;
}


static int pro_open(const char *path, int flags)
{
    int res;

    res = open(path, flags);
    if(res == -1) 
        return -errno;

    close(res);
    return 0;
}

static int pro_pread(const char *path, char *buf, size_t size, off_t offset)
{
    int fd;
    int res;

    fd = open(path, 0);
    if(fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
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

static void cleanup()
{
    fuse_unmount(pro_fuse);
    fuse_destroy(pro_fuse);
}

static struct fuse_operations pro_oper = {
    getattr:	pro_getattr,
    readlink:	pro_readlink,
    getdir:     pro_getdir,
    mknod:	pro_mknod,
    mkdir:	pro_mkdir,
    symlink:	pro_symlink,
    unlink:	pro_unlink,
    rmdir:	pro_rmdir,
    rename:     pro_rename,
    link:	pro_link,
    chmod:	pro_chmod,
    chown:	pro_chown,
    truncate:	pro_truncate,
    utime:	pro_utime,
    open:	pro_open,
    pread:	pro_pread,
};

int main(int argc, char *argv[])
{
    int res;
    if(argc != 2) {
        fprintf(stderr, "usage: %s mount_dir\n", argv[0]);
        exit(1);
    }

    set_signal_handlers();
    atexit(cleanup);

    pro_fuse = fuse_new();
    res = fuse_mount(pro_fuse, argv[1]);
    if(res == -1)
        exit(1);
        
    fuse_set_operations(pro_fuse, &pro_oper);
    fuse_loop(pro_fuse);

    return 0;
}
