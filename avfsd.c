#include <fuse.h>
#include <virtual.h>

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static int check_cred(struct fuse_cred *cred)
{
    if(cred->uid != getuid())
        return -EACCES;
    else
        return 0;
}

static int avfs_getattr(struct fuse_cred *cred, const char *path,
                        struct stat *stbuf)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_lstat(path, stbuf);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_readlink(struct fuse_cred *cred, const char *path, char *buf,
                         size_t size)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_readlink(path, buf, size - 1);
    if(res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int avfs_getdir(struct fuse_cred *cred, const char *path,
                       fuse_dirh_t h, fuse_dirfil_t filler)
{
    DIR *dp;
    struct dirent *de;
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    dp = virt_opendir(path);
    if(dp == NULL)
        return -errno;

    while((de = virt_readdir(dp)) != NULL) {
        res = filler(h, de->d_name, de->d_type);
        if(res != 0)
            break;
    }

    virt_closedir(dp);
    return res;
}

static int avfs_mknod(struct fuse_cred *cred, const char *path, mode_t mode,
                      dev_t rdev)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_mknod(path, mode, rdev);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_mkdir(struct fuse_cred *cred, const char *path, mode_t mode)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_mkdir(path, mode);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_unlink(struct fuse_cred *cred, const char *path)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_unlink(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_rmdir(struct fuse_cred *cred, const char *path)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_rmdir(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_symlink(struct fuse_cred *cred, const char *from,
                        const char *to)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_symlink(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_rename(struct fuse_cred *cred, const char *from,
                       const char *to)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_rename(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_link(struct fuse_cred *cred, const char *from, const char *to)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_link(from, to);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_chmod(struct fuse_cred *cred, const char *path, mode_t mode)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_chmod(path, mode);
    if(res == -1)
        return -errno;
    
    return 0;
}

static int avfs_chown(struct fuse_cred *cred, const char *path, uid_t uid,
                       gid_t gid)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_lchown(path, uid, gid);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_truncate(struct fuse_cred *cred, const char *path, off_t size)
{
    int res;
    
    res = check_cred(cred);
    if(res)
        return res;

    res = virt_truncate(path, size);
    if(res == -1)
        return -errno;

    return 0;
}

static int avfs_utime(struct fuse_cred *cred, const char *path,
                      struct utimbuf *buf)
{
    int res;
    
    res = check_cred(cred);
    if(res)
        return res;

    res = virt_utime(path, buf);
    if(res == -1)
        return -errno;

    return 0;
}


static int avfs_open(struct fuse_cred *cred, const char *path, int flags)
{
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    res = virt_open(path, flags, 0);
    if(res == -1) 
        return -errno;

    virt_close(res);
    return 0;
}

static int avfs_read(struct fuse_cred *cred, const char *path, char *buf,
                     size_t size, off_t offset)
{
    int fd;
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    fd = virt_open(path, O_RDONLY, 0);
    if(fd == -1)
        return -errno;

    res = virt_lseek(fd, offset, SEEK_SET);
    if(res == -1)
        res = -errno;
    else {
        res = virt_read(fd, buf, size);
        if(res == -1)
            res = -errno;
    }
    
    virt_close(fd);
    return res;
}

static int avfs_write(struct fuse_cred *cred, const char *path,
                      const char *buf, size_t size, off_t offset)
{
    int fd;
    int res;

    res = check_cred(cred);
    if(res)
        return res;

    fd = virt_open(path, O_WRONLY, 0);
    if(fd == -1)
        return -errno;

    res = virt_lseek(fd, offset, SEEK_SET);
    if(res == -1)
        res = -errno;
    else {
        res = virt_write(fd, buf, size);
        if(res == -1)
            res = -errno;
    }
    
    virt_close(fd);
    return res;
}

static struct fuse_operations avfs_oper = {
    getattr:	avfs_getattr,
    readlink:	avfs_readlink,
    getdir:     avfs_getdir,
    mknod:	avfs_mknod,
    mkdir:	avfs_mkdir,
    symlink:	avfs_symlink,
    unlink:	avfs_unlink,
    rmdir:	avfs_rmdir,
    rename:     avfs_rename,
    link:	avfs_link,
    chmod:	avfs_chmod,
    chown:	avfs_chown,
    truncate:	avfs_truncate,
    utime:	avfs_utime,
    open:	avfs_open,
    read:	avfs_read,
    write:	avfs_write,
};


void avfs_main(struct fuse *fuse)
{
    fuse_set_operations(fuse, &avfs_oper);
    fuse_loop(fuse);
}

#if 0
int main(int argc, char *argv[])
{
    int res;
    const char *avfs_dir;
    struct fuse *fuse;

    if(argc != 2) {
        fprintf(stderr, "usage: %s mount_dir\n", argv[0]);
        exit(1);
    }
    
    avfs_dir = argv[1];

    fuse = fuse_new(0);
    res = fuse_mount(fuse, avfs_dir);
    if(res == -1)
        exit(1);
        
    avfs_main(fuse);

    return 0;
}
#endif
