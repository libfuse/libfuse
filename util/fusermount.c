/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

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

#include <config.h>

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

#define FUSE_DEV "/proc/fs/fuse/dev"

#define FUSE_COMMFD_ENV         "_FUSE_COMMFD"

const char *progname;

static const char *get_user_name()
{
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_name != NULL)
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
    if (mtablock >= 0) {
        res = lockf(mtablock, F_LOCK, 0);
        if (res < 0)
            perror("error getting lock");
    } else
        fprintf(stderr, "unable to open fuse lock file, continuing anyway\n");

    return mtablock;
}

static void unlock_mtab(int mtablock)
{
    if (mtablock >= 0) {
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
    if (fp == NULL) {
	fprintf(stderr, "%s: failed to open %s: %s\n", progname, mtab,
		strerror(errno));
	return -1;
    }
    
    if (getuid() != 0) {
        const char *user = get_user_name();
        if (user == NULL)
            return -1;
        
        opts = malloc(strlen(user) + 128);
        if (opts != NULL)
            sprintf(opts, "rw,nosuid,nodev,user=%s", user);
    }
    else
        opts = strdup("rw,nosuid,nodev");
    
    if (opts == NULL) {
        fprintf(stderr, "%s: failed to allocate memory\n", progname);
        return -1;
    }
    
    ent.mnt_fsname = (char *) fsname;
    ent.mnt_dir = (char *) mnt;
    ent.mnt_type = (char *) type;
    ent.mnt_opts = opts;
    ent.mnt_freq = 0;
    ent.mnt_passno = 0;
    res = addmntent(fp, &ent);
    if (res != 0) {
        fprintf(stderr, "%s: failed to add entry to %s: %s\n", progname,
                mtab, strerror(errno));
        return -1;
    }
    
    endmntent(fp);
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
    if (res == -1) {
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
    if (res == -1) {
        setfsuid(oldfsuid);
        setfsgid(oldfsgid);
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
    if (res == -1)
        fprintf(stderr, "%s: failed to restore capabilities: %s\n", progname,
                strerror(errno));
    
    setfsuid(oldfsuid);
    setfsgid(oldfsgid);
}

static int remove_mount(const char *mnt, int quiet, int lazy)
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
    if (fp == NULL) {
	fprintf(stderr, "%s failed to open %s: %s\n", progname, mtab,
		strerror(errno));
	return -1;
    }
    
    newfp = setmntent(mtab_new, "w");
    if (newfp == NULL) {
	fprintf(stderr, "%s failed to open %s: %s\n", progname, mtab_new,
		strerror(errno));
	return -1;
    }
    
    if (getuid() != 0) {
        user = get_user_name();
        if (user == NULL)
            return -1;
    }

    found = 0;
    while ((entp = getmntent(fp)) != NULL) {
        int remove = 0;
        if (!found && strcmp(entp->mnt_dir, mnt) == 0 &&
           strcmp(entp->mnt_type, "fuse") == 0) {
            if (user == NULL)
                remove = 1;
            else {
                char *p = strstr(entp->mnt_opts, "user=");
                if (p != NULL && strcmp(p + 5, user) == 0)
                    remove = 1;
            }
        }
        if (remove)
            found = 1;
        else {
            res = addmntent(newfp, entp);
            if (res != 0) {
                fprintf(stderr, "%s: failed to add entry to %s: %s", progname,
                        mtab_new, strerror(errno));
                
            }
        }
    }
    
    endmntent(fp);
    endmntent(newfp);
    
    if (found) {
        if (getuid() != 0) {
            res = drop_privs();
            if (res == -1) {
                unlink(mtab_new);
                return -1;
            }
        }

        res = umount2(mnt, lazy ? 2 : 0);
        if (res == -1) {
            if (!quiet)
                fprintf(stderr, "%s: failed to unmount %s: %s\n",
                        progname, mnt,strerror(errno));
            found = -1;
        }
        if (getuid() != 0)
            restore_privs();
    }

    if (found == 1) {
        res = rename(mtab_new, mtab);
        if (res == -1) {
            fprintf(stderr, "%s: failed to rename %s to %s: %s\n", progname,
                    mtab_new, mtab, strerror(errno));
            return -1;
        }
    }
    else {
        if (!found && !quiet)
            fprintf(stderr, "%s: entry for %s not found in %s\n", progname,
                    mnt, mtab);
        unlink(mtab_new);
        return -1;
    }

    return 0;
}

static int begins_with(const char *s, const char *beg)
{
    if (strncmp(s, beg, strlen(beg)) == 0)
        return 1;
    else
        return 0;
}

static int do_mount(const char *mnt, const char *type, mode_t rootmode,
                    int fd, const char *opts, char **fsnamep)
{
    int res;
    int flags = MS_NOSUID | MS_NODEV;
    char *optbuf;
    const char *s;
    char *d;
    char *fsname = NULL;
    
    optbuf = malloc(strlen(opts) + 64);
    if (!optbuf) {
        fprintf(stderr, "%s: failed to allocate memory\n", progname);
        return -1;
    }
    
    for (s = opts, d = optbuf; *s;) {
        unsigned len;
        const char *fsname_str = "fsname=";
        for (len = 0; s[len] && s[len] != ','; len++);
        if (begins_with(s, fsname_str)) {
            unsigned fsname_str_len = strlen(fsname_str);
            if (fsname)
                free(fsname);
            fsname = malloc(len - fsname_str_len + 1);
            if (!fsname) {
                fprintf(stderr, "%s: failed to allocate memory\n", progname);
                free(optbuf);
                return -1;
            }
            memcpy(fsname, s + fsname_str_len, len - fsname_str_len);
            fsname[len - fsname_str_len] = '\0';
        } else if (!begins_with(s, "fd=") &&
                   !begins_with(s, "rootmode=") &&
                   !begins_with(s, "uid=")) {
            memcpy(d, s, len);
            d += len;
            *d++ = ',';
        }
        s += len;
        if (*s)
            s++;
    }
    sprintf(d, "fd=%i,rootmode=%o,uid=%i", fd, rootmode, getuid());
    if (fsname == NULL) {
        fsname = strdup(FUSE_DEV);
        if (!fsname) {
            fprintf(stderr, "%s: failed to allocate memory\n", progname);
            free(optbuf);
            return -1;
        }
    }

    res = mount(fsname, mnt, type, flags, optbuf);
    free(optbuf);
    if (res == -1) {
        fprintf(stderr, "%s: mount failed: %s\n", progname, strerror(errno));
        free(fsname);
    }
    *fsnamep = fsname;

    return res;
}

static int check_perm(const char **mntp, struct stat *stbuf, int *currdir_fd)
{
    int res;
    const char *mnt = *mntp;
   
    res = lstat(mnt, stbuf);
    if (res == -1) {
        fprintf(stderr, "%s: failed to access mountpoint %s: %s\n",
                progname, mnt, strerror(errno));
        return -1;
    }

    /* No permission checking is done for root */
    if (getuid() == 0)
        return 0;

    if (!S_ISDIR(stbuf->st_mode)) {
        fprintf(stderr, "%s: mountpoint %s is not a directory\n",
                progname, mnt);
        return -1;
    }

    *currdir_fd = open(".", O_RDONLY);
    if (*currdir_fd == -1) {
        fprintf(stderr, "%s: failed to open current directory: %s\n",
                progname, strerror(errno));
        return -1;
    }
    res = chdir(mnt);
    if (res == -1) {
        fprintf(stderr, "%s: failed to chdir to mountpoint: %s\n",
                progname, strerror(errno));
        return -1;
    }
    mnt = *mntp = ".";
    res = lstat(mnt, stbuf);
    if (res == -1) {
        fprintf(stderr, "%s: failed to access mountpoint %s: %s\n",
                progname, mnt, strerror(errno));
        return -1;
    }

    if ((stbuf->st_mode & S_ISVTX) && stbuf->st_uid != getuid()) {
        fprintf(stderr, "%s: mountpoint %s not owned by user\n",
                progname, mnt);
        return -1;
    }
    
    res = access(mnt, W_OK);
    if (res == -1) {
        fprintf(stderr, "%s: user has no write access to mountpoint %s\n",
                progname, mnt);
        return -1;
    }

    return 0;
}

static int mount_fuse(const char *mnt, const char *opts)
{
    int res;
    int fd;
    const char *dev = FUSE_DEV;
    const char *type = "fuse";
    struct stat stbuf;
    int mtablock;
    char *fsname;
    const char *real_mnt = mnt;
    int currdir_fd = -1;

    fd = open(dev, O_RDWR);
    if (fd == -1 
#ifndef AUTO_MODPROBE
        && getuid() == 0
#endif
        ) {
        int status;
        pid_t pid = fork();
        if (pid == 0) {
            setuid(0);
            execl("/sbin/modprobe", "/sbin/modprobe", "fuse", NULL);
            exit(1);
        }
        if (pid != -1)
            waitpid(pid, &status, 0);

        fd = open(dev, O_RDWR);
    }
    if (fd == -1) {
        fprintf(stderr, "%s: unable to open fuse device %s: %s\n", progname,
                dev, strerror(errno));
        return -1;
    }
 
    if (getuid() != 0) {
        res = drop_privs();
        if (res == -1)
            return -1;
    }

    res = check_perm(&real_mnt, &stbuf, &currdir_fd);
    if (res != -1)
        res = do_mount(real_mnt, type, stbuf.st_mode & S_IFMT, fd, opts,
                       &fsname);
    if (getuid() != 0)
        restore_privs();

    if (res == -1)
        return -1;

    if (currdir_fd != -1) {
        fchdir(currdir_fd);
        close(currdir_fd);
    }

    if (geteuid() == 0) {
        mtablock = lock_mtab();
        res = add_mount(fsname, mnt, type);
        free(fsname);
        unlock_mtab(mtablock);
        if (res == -1) {
            umount2(mnt, 2); /* lazy umount */
            return -1;
        }
    } else
        free(fsname);

    return fd;
}

static char *resolve_path(const char *orig, int unmount)
{
    char buf[PATH_MAX];
    char *dst;
    
    if (unmount) {
        char *end;
        /* Resolving at unmount can only be done very carefully, not touching
           the mountpoint... So for the moment it's not done. 

           Just remove trailing slashes instead.
        */
        dst = strdup(orig);
        if (dst == NULL) {
            fprintf(stderr, "%s: failed to allocate memory\n", progname);
            return NULL;
        }

        for (end = dst + strlen(dst) - 1; end > dst && *end == '/'; end --)
            *end = '\0';

        return dst;
    }

    if (realpath(orig, buf) == NULL) {
        fprintf(stderr, "%s: Bad mount point %s: %s\n", progname, orig,
                strerror(errno));
        return NULL;
    }
    
    dst = strdup(buf);
    if (dst == NULL)
        fprintf(stderr, "%s: failed to allocate memory\n", progname);
    return dst;
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
    while ((retval = sendmsg(sock_fd, &msg, 0)) == -1 && errno == EINTR);
    if (retval != 1) {
        perror("sending file descriptor");
        return -1;
    }
    return 0;
}

static void usage()
{
    fprintf(stderr,
            "%s: [options] mountpoint\n"
            "Options:\n"
            " -h                print help\n"
            " -o opt[,opt...]   mount options\n"
            " -u                unmount\n"
            " -q                quiet\n"
            " -z                lazy unmount\n",
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
    int lazy = 0;
    char *commfd;
    int quiet = 0;
    int cfd;
    const char *opts = "";

    progname = argv[0];
    
    for (a = 1; a < argc; a++) {
        if (argv[a][0] != '-')
            break;

        switch (argv[a][1]) {
        case 'h':
            usage();
            break;

        case 'o':
            a++;
            if (a == argc) {
                fprintf(stderr, "%s: Missing argument to -o\n", progname);
                exit(1);
            }
            opts = argv[a];
            break;

        case 'u':
            unmount = 1;
            break;

        case 'z':
            lazy = 1;
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
    
    if (a == argc) {
        fprintf(stderr, "%s: Missing mountpoint argument\n", progname);
        exit(1);
    }

    origmnt = argv[a++];

    if (getuid() != 0) {
        res = drop_privs();
        if (res == -1)
            exit(1);
    }

    mnt = resolve_path(origmnt, unmount);
    if (mnt == NULL)
        exit(1);

    if (getuid() != 0)
        restore_privs();
    
    if (unmount) {
        if (geteuid() == 0) {
            int mtablock = lock_mtab();
            res = remove_mount(mnt, quiet, lazy);
            unlock_mtab(mtablock);
        } else {
            res = umount2(mnt, lazy ? 2 : 0);
            if (res == -1) {
                if (!quiet)
                    fprintf(stderr, "%s: failed to unmount %s: %s\n",
                            progname, mnt, strerror(errno));
            }
        }
        if (res == -1)
            exit(1);
        return 0;
    }

    commfd = getenv(FUSE_COMMFD_ENV);
    if (commfd == NULL) {
        fprintf(stderr, "%s: old style mounting not supported\n", progname);
        exit(1);
    }

    fd = mount_fuse(mnt, opts);
    if (fd == -1)
        exit(1);

    cfd = atoi(commfd);
    res = send_fd(cfd, fd);
    if (res == -1)
        exit(1);

    return 0;
}
