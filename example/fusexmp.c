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
#include <grp.h>
#include <sys/fsuid.h>

static char *mount_point;

static int set_creds(struct fuse_cred *cred)
{
    int res;

    res = setfsuid(cred->uid);
    if(res == -1)
        return -errno;

    res = setfsgid(cred->gid);
    if(res == -1)
        return -errno;

    return 0;
}

static void restore_creds()
{
    setfsuid(getuid());
    setfsgid(getgid());
}

static int xmp_getattr(struct fuse_cred *cred, const char *path,
                       struct stat *stbuf)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = lstat(path, stbuf);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(struct fuse_cred *cred, const char *path, char *buf,
                        size_t size)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = readlink(path, buf, size - 1);
    restore_creds();
    if(res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int xmp_getdir(struct fuse_cred *cred, const char *path, fuse_dirh_t h,
                      fuse_dirfil_t filler)
{
    DIR *dp;
    struct dirent *de;
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    dp = opendir(path);
    restore_creds();
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

static int xmp_mknod(struct fuse_cred *cred, const char *path, mode_t mode,
                     dev_t rdev)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = mknod(path, mode, rdev);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(struct fuse_cred *cred, const char *path, mode_t mode)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = mkdir(path, mode);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(struct fuse_cred *cred, const char *path)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = unlink(path);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(struct fuse_cred *cred, const char *path)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = rmdir(path);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(struct fuse_cred *cred, const char *from,
                       const char *to)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = symlink(from, to);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(struct fuse_cred *cred, const char *from, const char *to)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = rename(from, to);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_link(struct fuse_cred *cred, const char *from, const char *to)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = link(from, to);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(struct fuse_cred *cred, const char *path, mode_t mode)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = chmod(path, mode);
    restore_creds();
    if(res == -1)
        return -errno;
    
    return 0;
}

static int xmp_chown(struct fuse_cred *cred, const char *path, uid_t uid,
                     gid_t gid)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = lchown(path, uid, gid);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(struct fuse_cred *cred, const char *path, off_t size)
{
    int res;
    
    res = set_creds(cred);
    if(res)
        return res;
    res = truncate(path, size);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}

static int xmp_utime(struct fuse_cred *cred, const char *path,
                     struct utimbuf *buf)
{
    int res;
    
    res = set_creds(cred);
    if(res)
        return res;
    res = utime(path, buf);
    restore_creds();
    if(res == -1)
        return -errno;

    return 0;
}


static int xmp_open(struct fuse_cred *cred, const char *path, int flags)
{
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    res = open(path, flags);
    restore_creds();
    if(res == -1) 
        return -errno;

    close(res);
    return 0;
}

static int xmp_read(struct fuse_cred *cred, const char *path, char *buf,
                    size_t size, off_t offset)
{
    int fd;
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    fd = open(path, O_RDONLY);
    restore_creds();
    if(fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if(res == -1)
        res = -errno;
    
    close(fd);
    return res;
}

static int xmp_write(struct fuse_cred *cred, const char *path, const char *buf,
                     size_t size, off_t offset)
{
    int fd;
    int res;

    res = set_creds(cred);
    if(res)
        return res;
    fd = open(path, O_WRONLY);
    restore_creds();
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
    char *buf = (char *) malloc(strlen(mount_point) + 128);
    sprintf(buf, "fusermount -u %s", mount_point);
    system(buf);
    free(buf);
}

int main(int argc, char *argv[])
{
    int argctr;
    int flags;
    struct fuse *fuse;

    if(argc < 2) {
        fprintf(stderr,
                "usage: %s mount_dir [options] \n"
                "Options:\n"
                "    -d      enable debug output\n"
                "    -s      disable multithreaded operation\n",
                argv[0]);
        exit(1);
    }

    argctr = 1;
    mount_point = argv[argctr++];

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

    setgroups(0, NULL);

    fuse = fuse_new(0, flags);
    fuse_set_operations(fuse, &xmp_oper);
    fuse_loop(fuse);

    return 0;
}
