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
#include <pwd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/fuse.h>
#include <sys/capability.h>

#define FUSE_DEV "/proc/fs/fuse/dev"

const char *progname;
const char *fusermnt = "/etc/fusermnt";
const char *fusermnt_temp = "/etc/fusermnt~";

#define FUSE_USERNAME_MAX 256
#define FUSE_PATH_MAX 4096
#define FUSEMNT_LINE_MAX (FUSE_USERNAME_MAX + 1 + FUSE_PATH_MAX + 1)

static const char *get_user_name()
{
    struct passwd *pw = getpwuid(getuid());
    if(pw != NULL && pw->pw_name != NULL)
        return pw->pw_name;
    else {
        fprintf(stderr, "%s: could not determine username\n", progname);
        return NULL;
    }
}

static int fusermnt_lock()
{
    int res;
    const char *lockfile = fusermnt;
    int fd = open(lockfile, O_WRONLY | O_CREAT, 0644);
    if(fd == -1) {
        fprintf(stderr, "%s: failed to open lockfile %s: %s\n", progname,
                lockfile, strerror(errno));
        return -1;
    }
    res = lockf(fd, F_LOCK, 0);
    if(res == -1) {
        fprintf(stderr, "%s: failed to lock file %s: %s\n", progname,
                lockfile, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static void fusermnt_unlock(int fd)
{
    lockf(fd, F_UNLCK, 0);
    close(fd);
}


static int add_mount(const char *mnt)
{
    FILE *fp;
    int lockfd;
    const char *user = get_user_name();
    if(user == NULL)
        return -1;

    lockfd = fusermnt_lock();
    if(lockfd == -1)
        return -1;

    fp = fopen(fusermnt, "a");
    if(fp == NULL) {
        fprintf(stderr, "%s: could not open %s for writing: %s\n", progname,
                fusermnt, strerror(errno));
        return -1;
    }
    fprintf(fp, "%s %s\n", user, mnt);
    fclose(fp);

    fusermnt_unlock(lockfd);
    return 0;
}

static int remove_mount(const char *mnt)
{
    FILE *fp;
    FILE *newfp;
    int lockfd;
    int found;
    char buf[FUSEMNT_LINE_MAX + 1];
    const char *user = get_user_name();
    if(user == NULL)
        return -1;

    lockfd = fusermnt_lock();
    if(lockfd == -1)
        return -1;

    fp = fopen(fusermnt, "r");
    if(fp == NULL) {
        fprintf(stderr, "%s: could not open %s for reading: %s\n", progname,
                fusermnt, strerror(errno));
        fusermnt_unlock(lockfd);
        return -1;
    }

    newfp = fopen(fusermnt_temp, "w");
    if(newfp == NULL) {
        fprintf(stderr, "%s: could not open %s for writing: %s\n", progname,
                fusermnt_temp, strerror(errno));
        fclose(fp);
        fusermnt_unlock(lockfd);
        return -1;
    }
    
    found = 0;
    while(fgets(buf, sizeof(buf), fp) != NULL) {
        char *end = buf + strlen(buf) - 1;
        char *p;
        if(*end != '\n') {
            fprintf(stderr, "%s: line too long in file %s\n", progname,
                    fusermnt);
            while(fgets(buf, sizeof(buf), fp) != NULL) {
                char *end = buf + strlen(buf) - 1;
                if(*end == '\n')
                    break;
            }
            continue;
        }
        *end = '\0';

        for(p = buf; *p != '\0' && *p != ' '; p++);
        if(*p == '\0') {
            fprintf(stderr, "%s: malformed line in file %s\n", progname,
                    fusermnt);
            continue;
        }
        *p = '\0';
        p++;
        if(strcmp(user, buf) == 0 && strcmp(mnt, p) == 0)
            found = 1;
        else
            fprintf(newfp, "%s %s\n", buf, p);
    }

    fclose(fp);
    fclose(newfp);

    if(found) {
        int res;
        res = rename(fusermnt_temp, fusermnt);
        if(res == -1) {
            fprintf(stderr, "%s: failed to rename %s to %s: %s\n",
                    progname, fusermnt_temp, fusermnt, strerror(errno));
            fusermnt_unlock(lockfd);
            return -1;
        }
    }
    else {
        fprintf(stderr, "%s: entry for %s not found in %s\n", progname, mnt,
                fusermnt);
        unlink(fusermnt_temp);
        fusermnt_unlock(lockfd);
        return -1;
    }

    fusermnt_unlock(lockfd);
    return 0;
}


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

    res = add_mount(mnt);
    if(res == -1) {
        umount(mnt);
        return -1;
    }

    return fd;
}

static int do_umount(const char *mnt)
{
    int res;

    res = remove_mount(mnt);
    if(res == -1)
        return -1;

    umount(mnt);
    return 0;
}

static void usage()
{
    fprintf(stderr,
            "%s: [options] mountpoint [program [args ...]]\n"
            "Options:\n"
            " -h    print help\n"
            " -u    umount\n",
            progname);
    exit(1);
}

int main(int argc, char *argv[])
{
    int a;
    int fd;
    int res;
    const char *mnt = NULL;
    int umount = 0;
    char **userprog;

    progname = argv[0];
    
    for(a = 1; a < argc; a++) {
        if(argv[a][0] != '-')
            break;

        switch(argv[a][1]) {
        case 'h':
            usage();
            break;

        case 'u':
            umount = 1;
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
    
    if(umount) {
        res = do_umount(mnt);
        if(res == -1)
            exit(1);
        
        return 0;
    }

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

    /* Drop setuid/setgid permissions */
    setuid(getuid());
    setgid(getgid());
    
    execv(userprog[0], userprog);
    fprintf(stderr, "%s: failed to exec %s: %s\n", progname, userprog[0],
            strerror(errno));

    execl("/proc/self/exe", progname, "-u", mnt, NULL);
    fprintf(stderr, "%s: failed to exec self: %s\n", progname,
            strerror(errno));
    exit(1);
}
