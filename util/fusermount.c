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
 * data in this file may be lost. (I will _not_ reimplement that locking,
 * and anyway that should be done in libc, if possible.  But probably it
 * isn't).  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <mntent.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/fsuid.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/fuse.h>

#define CHECK_PERMISSION 1

#ifndef MS_PERMISSION
#define MS_PERMISSION	128
#endif

#define FUSE_DEV "/proc/fs/fuse/dev"

#define FUSE_MOUNTED_ENV        "_FUSE_MOUNTED"
#define FUSE_UMOUNT_CMD_ENV     "_FUSE_UNMOUNT_CMD"
#define FUSE_KERNEL_VERSION_ENV "_FUSE_KERNEL_VERSION"
#define FUSE_COMMFD_ENV         "_FUSE_COMMFD"

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

/* use a lock file so that multiple fusermount processes don't try and
   modify the mtab file at once! */
static int lock_mtab()
{
    const char *mtab_lock = _PATH_MOUNTED ".fuselock";
    int mtablock;
    int res;

    mtablock = open(mtab_lock, O_RDWR | O_CREAT, 0600);
    if(mtablock >= 0) {
        res = lockf(mtablock, F_LOCK, 0);
        if(res < 0)
            perror("error getting lock");
    } else
        fprintf(stderr, "unable to open fuse lock file, continuing anyway\n");

    return mtablock;
}

static void unlock_mtab(int mtablock)
{
    if(mtablock >= 0) {
	lockf(mtablock, F_ULOCK, 0);
	close(mtablock);
    }
}

static int add_mount(const char *fsname, const char *mnt, const char *type)
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
    
    ent.mnt_fsname = (char *) fsname;
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

static int remove_mount(const char *mnt, int quiet)
{
    int res;
    const char *mtab = _PATH_MOUNTED;
    const char *mtab_new = _PATH_MOUNTED "~fuse~";
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
        if(remove)
            found = 1;
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
    
    if(found) {
        res = umount2(mnt, 2);  /* Lazy umount */
        if(res == -1) {
            fprintf(stderr, "%s: failed to unmount %s: %s\n", progname, mnt,
                    strerror(errno));
            found = -1;
        }
    }

    if(found == 1) {
        res = rename(mtab_new, mtab);
        if(res == -1) {
            fprintf(stderr, "%s: failed to rename %s to %s: %s\n", progname,
                    mtab_new, mtab, strerror(errno));
            return -1;
        }
    }
    else {
        if(!found && !quiet)
            fprintf(stderr, "%s: entry for %s not found in %s\n", progname,
                    mnt, mtab);
        unlink(mtab_new);
        return -1;
    }

    return 0;
}

/* Until there is a nice interface for capabilities in _libc_, this will
remain here.  I don't think it is fair to expect users to compile libcap
for this program.  And anyway what's all this fuss about versioning the
kernel interface?  It is quite good as is.  */
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
                    mode_t rootmode, int fd, int fuseflags)
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
    data.flags = fuseflags;

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

static int mount_fuse(const char *mnt, int flags, const char *fsname)
{
    int res;
    int fd;
    const char *dev = FUSE_DEV;
    const char *type = "fuse";
    struct stat stbuf;
    int mtablock;

    res = check_perm(mnt, &stbuf);
    if(res == -1)
        return -1;

    fd = open(dev, O_RDWR);
    if(fd == -1) {
        int status;
        pid_t pid = fork();
        if(pid == 0) {
            setuid(0);
            execl("/sbin/modprobe", "/sbin/modprobe", "fuse", NULL);
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
 
    if(fsname == NULL)
        fsname = dev;

    res = do_mount(fsname, mnt, type, stbuf.st_mode & S_IFMT, fd, flags);
    if(res == -1)
        return -1;
    
    mtablock = lock_mtab();
    res = add_mount(fsname, mnt, type);
    unlock_mtab(mtablock);
    if(res == -1) {
        umount(mnt);
        return -1;
    }

    return fd;
}

static char *resolve_path(const char *orig, int unmount)
{
    char buf[PATH_MAX];

    if(unmount) {
        /* Resolving at unmount can only be done very carefully, not touching
           the mountpoint... So for the moment it's not done. 
           
           Just remove trailing slashes instead.
        */
        char *dst = strdup(orig);
        char *end;
        for(end = dst + strlen(dst) - 1; end > dst && *end == '/'; end --)
            *end = '\0';

        return dst;
    }

    if(realpath(orig, buf) == NULL) {
        fprintf(stderr, "%s: Bad mount point %s: %s\n", progname, orig,
                strerror(errno));
        return NULL;
    }

    return strdup(buf);
}

static int send_fd(int sock_fd, int fd) 
{
    int retval;
    struct msghdr msg;
    struct cmsghdr *p_cmsg;
    struct iovec vec;
    char cmsgbuf[CMSG_SPACE(sizeof(fd))];
    int *p_fds;
    char sendchar = 0;

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    p_cmsg = CMSG_FIRSTHDR(&msg);
    p_cmsg->cmsg_level = SOL_SOCKET;
    p_cmsg->cmsg_type = SCM_RIGHTS;
    p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    p_fds = (int *) CMSG_DATA(p_cmsg);
    *p_fds = fd;
    msg.msg_controllen = p_cmsg->cmsg_len;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    /* "To pass file descriptors or credentials you need to send/read at
     * least one byte" (man 7 unix) */
    vec.iov_base = &sendchar;
    vec.iov_len = sizeof(sendchar);
    while((retval = sendmsg(sock_fd, &msg, 0)) == -1 && errno == EINTR);
    if (retval != 1) {
        perror("sending file descriptor");
        return -1;
    }
    return 0;
}

static void usage()
{
    fprintf(stderr,
            "%s: [options] mountpoint [program [args ...]]\n"
            "Options:\n"
            " -h       print help\n"
            " -u       unmount\n"
            " -p       check default permissions on files\n"
            " -c       cache in kernel space if possible\n"
            " -x       allow other users to access the files (only for root)\n"
            " -n name  add 'name' as the filesystem name to mtab\n"
            " -l       issue large reads\n"
            " -q       quiet: don't complain if unmount fails\n",
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
    char mypath[PATH_MAX];
    char *unmount_cmd;
    char *commfd;
    const char *fsname = NULL;
    char verstr[128];
    int flags = 0;
    int quiet = 0;

    progname = argv[0];
    
    for(a = 1; a < argc; a++) {
        if(argv[a][0] != '-')
            break;

        switch(argv[a][1]) {
        case 'c':
            flags |= FUSE_KERNEL_CACHE;
            break;

        case 'h':
            usage();
            break;

        case 'u':
            unmount = 1;
            break;
            
        case 'p':
            flags |= FUSE_DEFAULT_PERMISSIONS;
            break;
            
        case 'x':
            if(getuid() != 0) {
                fprintf(stderr, "%s: option %s is allowed only for root\n",
                        progname, argv[a]);
                exit(1);
            }
            flags |= FUSE_ALLOW_OTHER;
            break;
            
        case 'n':
            a++;
            if(a == argc) {
                fprintf(stderr, "%s: Missing argument to -n\n", progname);
                exit(1);
            }
            fsname = argv[a];
            break;

        case 'l':
            flags |= FUSE_LARGE_READ;
            break;
            
        case 'q':
            quiet = 1;
            break;

        default:
            fprintf(stderr, "%s: Unknown option %s\n", progname, argv[a]);
            fprintf(stderr, "Try `%s -h' for more information\n", progname);
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
        int mtablock = lock_mtab();
        res = remove_mount(mnt, quiet);
        unlock_mtab(mtablock);
        if(res == -1)
            exit(1);
        
        return 0;
    }

    commfd = getenv(FUSE_COMMFD_ENV);

    if(a == argc && commfd == NULL) {
        fprintf(stderr, "%s: Missing program argument\n", progname);
        exit(1);
    }
    
    userprog = argv + a;
    numargs = argc - a;
    
    fd = mount_fuse(mnt, flags, fsname);
    if(fd == -1)
        exit(1);

    if(commfd != NULL) {
        int cfd = atoi(commfd);
        res = send_fd(cfd, fd);
        if(res == -1)
            exit(1);
        exit(0);
    }

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
    sprintf(unmount_cmd, "%s -u -q %s", mypath, mnt);
    setenv(FUSE_UMOUNT_CMD_ENV, unmount_cmd, 1);
    sprintf(verstr, "%i", FUSE_KERNEL_VERSION);
    setenv(FUSE_KERNEL_VERSION_ENV, verstr, 1);
    setenv(FUSE_MOUNTED_ENV, "", 1);

    execvp(userprog[0], userprog);
    fprintf(stderr, "%s: failed to exec %s: %s\n", progname, userprog[0],
            strerror(errno));

    close(0);
    system(unmount_cmd);
    return 1;
}
