/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/fuse.h>
#include <sys/capability.h>

#define FUSE_DEV "/proc/fs/fuse/dev"

const char *progname;

static int do_mount(const char *dev, const char *mnt, const char *type,
                    mode_t rootmode, int fd)
{
    int res;
    struct fuse_mount_data data;
    
    data.version = FUSE_KERNEL_VERSION;
    data.fd = fd;
    data.rootmode = rootmode;

    res = mount(dev, mnt, type, MS_MGC_VAL | MS_NOSUID | MS_NODEV, &data);
    if(res == -1) {
        fprintf(stderr, "%s: mount failed: %s\n", progname, strerror(errno));
	return -1;
    }
    
    return 0;
}

static int check_perm(const char *mnt, struct stat *stbuf)
{
    int res;
   
    res = lstat(mnt, stbuf);
    if(res == -1) {
        fprintf(stderr, "%s: failed to access mountpoint %s: %s\n",
                progname, mnt, strerror(errno));
        return -1;
    }

    if(!S_ISDIR(stbuf->st_mode) && !S_ISREG(stbuf->st_mode)) {
        fprintf(stderr, "%s: mountpoint %s is a special file\n",
                progname, mnt);
        return -1;
    }

    if(getuid() != 0) {
        if(stbuf->st_uid != getuid()) {
            fprintf(stderr, "%s: mountpoint %s not owned by user\n",
                    progname, mnt);
            return -1;
        }

        res = access(mnt, R_OK | W_OK | (S_ISDIR(stbuf->st_mode) ? X_OK : 0));
        if(res == -1) {
            fprintf(stderr, "%s: user has no full access to mountpoint %s\n",
                    progname, mnt);
            return -1;
        }
    }
    
    return 0;
}

static int mount_fuse(const char *mnt)
{
    int res;
    int fd;
    const char *dev = FUSE_DEV;
    const char *type = "fuse";
    struct stat stbuf;

    res = check_perm(mnt, &stbuf);
    if(res == -1)
        return -1;

    fd = open(dev, O_RDWR);
    if(fd == -1) {
        fprintf(stderr, "%s: unable to open fuse device %s: %s\n", progname,
                dev, strerror(errno));
        return -1;
    }
 
    res = do_mount(dev, mnt, type, stbuf.st_mode & S_IFMT, fd);
    if(res == -1)
        return -1;

    return fd;
}

static void usage()
{
    fprintf(stderr,
            "%s: [options] mountpoint program [args ...]\n"
            "Options:\n"
            " -h    print help\n",
            progname);
    exit(1);
}

int main(int argc, char *argv[])
{
    int a;
    const char *mnt = NULL;
    char **userprog;
    pid_t pid;
    int fd;
    int status;
    int res;

    progname = argv[0];
    
    for(a = 1; a < argc; a++) {
        if(argv[a][0] != '-')
            break;

        switch(argv[a][1]) {
        case 'h':
            usage();
            break;
            
        default:
            fprintf(stderr, "%s: Unknown option %s\n", progname, argv[a]);
            exit(1);
        }
    }
    
    if(a == argc) {
        fprintf(stderr, "%s: Missing mountpoint argument\n", progname);
        exit(1);
    }

    mnt = argv[a++];
    
    if(a == argc) {
        fprintf(stderr, "%s: Missing program argument\n", progname);
        exit(1);
    }
    
    userprog = argv + a;
    
    fd = mount_fuse(mnt);
    if(fd == -1)
        exit(1);

    /* Dup the file descriptor to stdin */
    if(fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    
    pid = fork();
    if(pid == -1) {
        fprintf(stderr, "%s: Unable to fork: %s\n", progname, strerror(errno));
        umount(mnt);
        exit(1);
    }
    
    if(pid == 0) {
        /* Drop setuid/setgid permissions */
        setuid(getuid());
        setgid(getgid());
        
        execv(userprog[0], userprog);
        fprintf(stderr, "%s: failed to exec %s: %s\n", progname, userprog[0],
                strerror(errno));
        exit(1);
    }

    close(0);
    res = waitpid(pid, &status, 0);
    if(res == -1) {
        fprintf(stderr, "%s: failed to wait for child: %s\n", progname,
                strerror(errno));
        exit(1);
    }
    res = umount(mnt);
    if(res == -1) {
        fprintf(stderr, "%s: failed to unmount %s: %s\n", progname, mnt,
                strerror(errno));
        exit(1);
    }
    
    return 0;
}
