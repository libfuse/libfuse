/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
/* This program does the mounting and unmounting of FUSE filesystems */

/* 
 * NOTE: This program should be part of (or be called from) /bin/mount
 * 
 * Unless that is done, operations on /etc/mtab are not under lock, and so
 * data in it may be lost. (I will _not_ reimplement that locking, and
 * anyway that should be done in libc, if possible.  But probably it is
 * not).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <mntent.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/fsuid.h>
#include <linux/fuse.h>

#define CHECK_PERMISSION 1

#ifndef MS_PERMISSION
#define MS_PERMISSION	128
#endif

#define FUSE_DEV "/proc/fs/fuse/dev"

const char *progname;

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

static int add_mount(const char *dev, const char *mnt, const char *type)
{
    int res;
    const char *mtab = _PATH_MOUNTED;
    struct mntent ent;
    FILE *fp;
    char *opts;

    fp = setmntent(mtab, "a");
    if(fp == NULL) {
	fprintf(stderr, "%s failed to open %s: %s\n", progname, mtab,
		strerror(errno));
	return -1;
    }
    
    if(getuid() != 0) {
        const char *user = get_user_name();
        if(user == NULL)
            return -1;
        
        opts = malloc(strlen(user) + 128);
        if(opts != NULL)
            sprintf(opts, "rw,nosuid,nodev,user=%s", user);
    }
    else
        opts = strdup("rw,nosuid,nodev");
    
    if(opts == NULL)
        return -1;
    
    ent.mnt_fsname = (char *) dev;
    ent.mnt_dir = (char *) mnt;
    ent.mnt_type = (char *) type;
    ent.mnt_opts = opts;
    ent.mnt_freq = 0;
    ent.mnt_passno = 0;
    res = addmntent(fp, &ent);
    if(res != 0) {
        fprintf(stderr, "%s: failed to add entry to %s: %s\n", progname,
                mtab, strerror(errno));
        return -1;
    }
    
    endmntent(fp);
    return 0;
}

static int remove_mount(const char *mnt)
{
    int res;
    const char *mtab = _PATH_MOUNTED;
    const char *mtab_new = _PATH_MOUNTED "~";
    struct mntent *entp;
    FILE *fp;
    FILE *newfp;
    const char *user = NULL;
    int found;

    fp = setmntent(mtab, "r");
    if(fp == NULL) {
	fprintf(stderr, "%s failed to open %s: %s\n", progname, mtab,
		strerror(errno));
	return -1;
    }
    
    newfp = setmntent(mtab_new, "w");
    if(newfp == NULL) {
	fprintf(stderr, "%s failed to open %s: %s\n", progname, mtab_new,
		strerror(errno));
	return -1;
    }
    
    if(getuid() != 0) {
        user = get_user_name();
        if(user == NULL)
            return -1;
    }

    found = 0;
    while((entp = getmntent(fp)) != NULL) {
        int remove = 0;
        if(!found && strcmp(entp->mnt_dir, mnt) == 0 &&
           strcmp(entp->mnt_type, "fuse") == 0) {
            if(user == NULL)
                remove = 1;
            else {
                char *p = strstr(entp->mnt_opts, "user=");
                if(p != NULL && strcmp(p + 5, user) == 0)
                    remove = 1;
            }
        }
        if(remove) {
            res = umount(mnt);
            if(res == -1) {
                fprintf(stderr, "%s: failed to unmount %s: %s\n", progname,
                        mnt, strerror(errno));
                found = -1;
                break;
            }
            found = 1;
        }
        else {
            res = addmntent(newfp, entp);
            if(res != 0) {
                fprintf(stderr, "%s: failed to add entry to %s: %s", progname,
                        mtab_new, strerror(errno));
                
            }
        }
    }
    
    endmntent(fp);
    endmntent(newfp);

    if(found == 1) {
        res = rename(mtab_new, mtab);
        if(res == -1) {
            fprintf(stderr, "%s: failed to rename %s to %s: %s\n", progname,
                    mtab_new, mtab, strerror(errno));
            return -1;
        }
    }
    else {
        if(!found)
            fprintf(stderr, "%s: entry for %s not found in %s\n", progname,
                    mnt, mtab);
        unlink(mtab_new);
        return -1;
    }

    return 0;
}

#define _LINUX_CAPABILITY_VERSION  0x19980330

typedef struct __user_cap_header_struct {
    unsigned int version;
    int pid;
} *cap_user_header_t;
 
typedef struct __user_cap_data_struct {
    unsigned int effective;
    unsigned int permitted;
    unsigned int inheritable;
} *cap_user_data_t;
  
int capget(cap_user_header_t header, cap_user_data_t data);
int capset(cap_user_header_t header, cap_user_data_t data);

#define CAP_SYS_ADMIN        21

static uid_t oldfsuid;
static gid_t oldfsgid;
static struct __user_cap_data_struct oldcaps;

static int drop_privs()
{
    int res;
    struct __user_cap_header_struct head;
    struct __user_cap_data_struct newcaps;

    head.version = _LINUX_CAPABILITY_VERSION;
    head.pid = 0;
    res = capget(&head, &oldcaps);
    if(res == -1) {
        fprintf(stderr, "%s: failed to get capabilities: %s\n", progname,
                strerror(errno));
        return -1;
    }

    oldfsuid = setfsuid(getuid());
    oldfsgid = setfsgid(getgid());
    newcaps = oldcaps;
    /* Keep CAP_SYS_ADMIN for mount */
    newcaps.effective &= (1 << CAP_SYS_ADMIN);

    head.version = _LINUX_CAPABILITY_VERSION;
    head.pid = 0;
    res = capset(&head, &newcaps);
    if(res == -1) {
        fprintf(stderr, "%s: failed to set capabilities: %s\n", progname,
                strerror(errno));
        return -1;
    }
    return 0;
}

static void restore_privs()
{
    struct __user_cap_header_struct head;
    int res;

    head.version = _LINUX_CAPABILITY_VERSION;
    head.pid = 0;
    res = capset(&head, &oldcaps);
    if(res == -1)
        fprintf(stderr, "%s: failed to restore capabilities: %s\n", progname,
                strerror(errno));
    
    setfsuid(oldfsuid);
    setfsgid(oldfsgid);
}

static int do_mount(const char *dev, const char *mnt, const char *type,
                    mode_t rootmode, int fd)
{
    int res;
    struct fuse_mount_data data;
    int flags = MS_NOSUID | MS_NODEV;

    if(getuid() != 0) {
        res = drop_privs();
        if(res == -1)
            return -1;

        flags |= MS_PERMISSION;
    }
    
    data.version = FUSE_KERNEL_VERSION;
    data.fd = fd;
    data.rootmode = rootmode;
    data.uid = getuid();
    data.flags = 0;

    res = mount(dev, mnt, type, flags, &data);
    if(res == -1)
        fprintf(stderr, "%s: mount failed: %s\n", progname, strerror(errno));

    if(getuid() != 0)
        restore_privs();
    
    return res;
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

/* Should be done by the kernel */
#ifdef CHECK_PERMISSION
    if(getuid() != 0) {
        if((stbuf->st_mode & S_ISVTX) && stbuf->st_uid != getuid()) {
            fprintf(stderr, "%s: mountpoint %s not owned by user\n",
                    progname, mnt);
            return -1;
        }

        res = access(mnt, W_OK);
        if(res == -1) {
            fprintf(stderr, "%s: user has no write access to mountpoint %s\n",
                    progname, mnt);
            return -1;
        }
    }
#endif    

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
        int status;
        pid_t pid = fork();
        if(pid == 0) {
            setuid(0);
            execl("/sbin/modprobe", "modprobe", "fuse", NULL);
            exit(1);
        }
        if(pid != -1)
            waitpid(pid, &status, 0);

        fd = open(dev, O_RDWR);
    }
    if(fd == -1) {
        fprintf(stderr, "%s: unable to open fuse device %s: %s\n", progname,
                dev, strerror(errno));
        return -1;
    }
 
    res = do_mount(dev, mnt, type, stbuf.st_mode & S_IFMT, fd);
    if(res == -1)
        return -1;

    res = add_mount(dev, mnt, type);
    if(res == -1) {
        umount(mnt);
        return -1;
    }

    return fd;
}

static char *resolve_path(const char *orig, int unmount)
{
    char buf[PATH_MAX];

    /* Resolving at unmount can only be done very carefully, not touching
       the mountpoint... So for the moment it's not done.  */
    if(unmount)
        return strdup(orig);

    if(realpath(orig, buf) == NULL) {
        fprintf(stderr, "%s: Bad mount point %s: %s\n", progname, orig,
                strerror(errno));
        return NULL;
    }

    return strdup(buf);
}

static void usage()
{
    fprintf(stderr,
            "%s: [options] mountpoint [program [args ...]]\n"
            "Options:\n"
            " -h    print help\n"
            " -u    unmount\n",
            progname);
    exit(1);
}

int main(int argc, char *argv[])
{
    int a;
    int fd;
    int res;
    char *origmnt;
    char *mnt;
    int unmount = 0;
    char **userprog;
    int numargs;
    char **newargv;
    char mypath[PATH_MAX];
    char *unmount_cmd;

    progname = argv[0];
    
    for(a = 1; a < argc; a++) {
        if(argv[a][0] != '-')
            break;

        switch(argv[a][1]) {
        case 'h':
            usage();
            break;

        case 'u':
            unmount = 1;
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

    origmnt = argv[a++];

    if(getpid() != 0)
        drop_privs();

    mnt = resolve_path(origmnt, unmount);
    if(mnt == NULL)
        exit(1);

    if(getpid() != 0)
        restore_privs();
    
    if(unmount) {
        res = remove_mount(mnt);
        if(res == -1)
            exit(1);
        
        return 0;
    }

    if(a == argc) {
        fprintf(stderr, "%s: Missing program argument\n", progname);
        exit(1);
    }
    
    userprog = argv + a;
    numargs = argc - a;
    
    fd = mount_fuse(mnt);
    if(fd == -1)
        exit(1);

    /* Dup the file descriptor to stdin */
    if(fd != 0) {
        dup2(fd, 0);
        close(fd);
    }

    /* Strangely this doesn't work after dropping permissions... */
    res = readlink("/proc/self/exe", mypath, sizeof(mypath) - 1);
    if(res == -1) {
        fprintf(stderr, "%s: failed to determine self path: %s\n",
                progname, strerror(errno));
        strcpy(mypath, "fusermount");
        fprintf(stderr, "using %s as the default\n", mypath);
    }
    else 
        mypath[res] = '\0';

    /* Drop setuid/setgid permissions */
    setuid(getuid());
    setgid(getgid());

    unmount_cmd = (char *) malloc(strlen(mypath) + strlen(mnt) + 64);
    sprintf(unmount_cmd, "%s -u %s", mypath, mnt);

    newargv = (char **) malloc(sizeof(char *) * (numargs + 2));
    newargv[0] = userprog[0];
    newargv[1] = unmount_cmd;
    for(a = 1; a < numargs; a++)
        newargv[a+1] = userprog[a];
    newargv[numargs+1] = NULL;

    execvp(userprog[0], newargv);
    fprintf(stderr, "%s: failed to exec %s: %s\n", progname, userprog[0],
            strerror(errno));

    close(0);
    system(unmount_cmd);
    return 1;
}
