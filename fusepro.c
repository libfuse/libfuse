#include <fuse.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>

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

static int pro_mknod(const char *path, int mode, int rdev)
{
    int res;

    res = mknod(path, mode, rdev);
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

static int pro_mkdir(const char *path, int mode)
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
};

int main(int argc, char *argv[])
{
    if(argc != 2) {
        fprintf(stderr, "usage: %s mount_dir\n", argv[0]);
        exit(1);
    }

    set_signal_handlers();
    atexit(cleanup);

    pro_fuse = fuse_new();
    fuse_mount(pro_fuse, argv[1]);
    fuse_set_operations(pro_fuse, &pro_oper);
    fuse_loop(pro_fuse);

    return 0;
}
