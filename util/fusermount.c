/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

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
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <mntent.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/fsuid.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>

#define FUSE_COMMFD_ENV         "_FUSE_COMMFD"

#define FUSE_DEV_OLD "/proc/fs/fuse/dev"
#define FUSE_DEV_NEW "/dev/fuse"
#define FUSE_VERSION_FILE_OLD "/proc/fs/fuse/version"
#define FUSE_CONF "/etc/fuse.conf"

static const char *progname;

static int user_allow_other = 0;
static int mount_max = 1000;

static const char *get_user_name(void)
{
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_name != NULL)
        return pw->pw_name;
    else {
        fprintf(stderr, "%s: could not determine username\n", progname);
        return NULL;
    }
}

static uid_t oldfsuid;
static gid_t oldfsgid;

static void drop_privs(void)
{
    if (getuid() != 0) {
        oldfsuid = setfsuid(getuid());
        oldfsgid = setfsgid(getgid());
    }
}

static void restore_privs(void)
{
    if (getuid() != 0) {
        setfsuid(oldfsuid);
        setfsgid(oldfsgid);
    }
}

static int do_unmount(const char *mnt, int quiet, int lazy)
{
    int res = umount2(mnt, lazy ? 2 : 0);
    if (res == -1) {
        if (!quiet)
            fprintf(stderr, "%s: failed to unmount %s: %s\n",
                    progname, mnt, strerror(errno));
    }
    return res;
}

#ifndef USE_UCLIBC
/* use a lock file so that multiple fusermount processes don't try and
   modify the mtab file at once! */
static int lock_mtab(void)
{
    const char *mtab_lock = _PATH_MOUNTED ".fuselock";
    int mtablock;
    int res;

    mtablock = open(mtab_lock, O_RDWR | O_CREAT, 0600);
    if (mtablock >= 0) {
        res = lockf(mtablock, F_LOCK, 0);
        if (res < 0)
            fprintf(stderr, "%s: error getting lock", progname);
    } else
        fprintf(stderr, "%s: unable to open fuse lock file\n", progname);

    return mtablock;
}

static void unlock_mtab(int mtablock)
{
    if (mtablock >= 0) {
	lockf(mtablock, F_ULOCK, 0);
	close(mtablock);
    }
}

static int add_mount(const char *fsname, const char *mnt, const char *type,
                     const char *opts)
{
    int res;
    const char *mtab = _PATH_MOUNTED;
    struct mntent ent;
    FILE *fp;

    fp = setmntent(mtab, "a");
    if (fp == NULL) {
	fprintf(stderr, "%s: failed to open %s: %s\n", progname, mtab,
		strerror(errno));
	return -1;
    }

    ent.mnt_fsname = (char *) fsname;
    ent.mnt_dir = (char *) mnt;
    ent.mnt_type = (char *) type;
    ent.mnt_opts = (char *) opts;
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

static int remove_mount(const char *mnt, int quiet, const char *mtab,
                        const char *mtab_new)
{
    int res;
    struct mntent *entp;
    FILE *fp;
    FILE *newfp;
    const char *user = NULL;
    char uidstr[32];
    unsigned uidlen = 0;
    int found;

    fp = setmntent(mtab, "r");
    if (fp == NULL) {
	fprintf(stderr, "%s: failed to open %s: %s\n", progname, mtab,
		strerror(errno));
	return -1;
    }

    newfp = setmntent(mtab_new, "w");
    if (newfp == NULL) {
	fprintf(stderr, "%s: failed to open %s: %s\n", progname, mtab_new,
		strerror(errno));
	return -1;
    }

    if (getuid() != 0) {
        user = get_user_name();
        if (user == NULL)
            return -1;

        uidlen = sprintf(uidstr, "%u", getuid());
    }

    found = 0;
    while ((entp = getmntent(fp)) != NULL) {
        int removed = 0;
        if (!found && strcmp(entp->mnt_dir, mnt) == 0 &&
           strcmp(entp->mnt_type, "fuse") == 0) {
            if (user == NULL)
                removed = 1;
            else {
                char *p = strstr(entp->mnt_opts, "user=");
                if (p && (p == entp->mnt_opts || *(p-1) == ',') &&
                    strcmp(p + 5, user) == 0)
                    removed = 1;
                /* /etc/mtab is a link pointing to /proc/mounts: */
                else if ((p = strstr(entp->mnt_opts, "user_id=")) && 
                         (p == entp->mnt_opts || *(p-1) == ',') &&
                         strncmp(p + 8, uidstr, uidlen) == 0 &&
                         (*(p+8+uidlen) == ',' || *(p+8+uidlen) == '\0'))
                    removed = 1;
            }
        }
        if (removed)
            found = 1;
        else {
            res = addmntent(newfp, entp);
            if (res != 0) {
                fprintf(stderr, "%s: failed to add entry to %s: %s\n",
                        progname, mtab_new, strerror(errno));
            }
        }
    }

    endmntent(fp);
    endmntent(newfp);

    if (!found) {
        if (!quiet)
            fprintf(stderr, "%s: entry for %s not found in %s\n", progname,
                    mnt, mtab);
        unlink(mtab_new);
        return -1;
    }

    return 0;
}

static int count_fuse_fs(void)
{
    struct mntent *entp;
    int count = 0;
    const char *mtab = _PATH_MOUNTED;
    FILE *fp = setmntent(mtab, "r");
    if (fp == NULL) {
        fprintf(stderr, "%s: faild to open %s: %s\n", progname, mtab,
                strerror(errno));
        return -1;
    }
    while ((entp = getmntent(fp)) != NULL) {
        if (strcmp(entp->mnt_type, "fuse") == 0)
            count ++;
    }
    endmntent(fp);
    return count;
}

static int unmount_rename(const char *mnt, int quiet, int lazy,
                          const char *mtab, const char *mtab_new)
{
    int res;
    struct stat sbuf;

    drop_privs();
    res = do_unmount(mnt, quiet, lazy);
    restore_privs();
    if (res == -1)
        return -1;

    if (stat(mtab, &sbuf) == 0)
        chown(mtab_new, sbuf.st_uid, sbuf.st_gid);

    res = rename(mtab_new, mtab);
    if (res == -1) {
        fprintf(stderr, "%s: failed to rename %s to %s: %s\n", progname,
                mtab_new, mtab, strerror(errno));
        return -1;
    }
    return 0;
}

static int unmount_fuse(const char *mnt, int quiet, int lazy)
{
    int res;
    const char *mtab = _PATH_MOUNTED;
    const char *mtab_new = _PATH_MOUNTED "~fuse~";

    res = remove_mount(mnt, quiet, mtab, mtab_new);
    if (res == -1)
        return -1;

    res = unmount_rename(mnt, quiet, lazy, mtab, mtab_new);
    if (res == -1) {
        unlink(mtab_new);
        return -1;
    }
    return 0;
}
#else /* USE_UCLIBC */
static int lock_mtab()
{
    return 0;
}

static void unlock_mtab(int mtablock)
{
    (void) mtablock;
}

static int count_fuse_fs()
{
    return 0;
}

static int add_mount(const char *fsname, const char *mnt, const char *type,
                     const char *opts)
{
    (void) fsname;
    (void) mnt;
    (void) type;
    (void) opts;
    return 0;
}

static int unmount_fuse(const char *mnt, int quiet, int lazy)
{
    return do_unmount(mnt, quiet, lazy);
}
#endif

static void strip_line(char *line)
{
    char *s = strchr(line, '#');
    if (s != NULL)
        s[0] = '\0';
    for (s = line + strlen(line) - 1; s >= line && isspace((unsigned char) *s); s--);
    s[1] = '\0';
    for (s = line; isspace((unsigned char) *s); s++);
    if (s != line)
        memmove(line, s, strlen(s)+1);
}

static void parse_line(char *line, int linenum)
{
    int tmp;
    if (strcmp(line, "user_allow_other") == 0)
        user_allow_other = 1;
    else if (sscanf(line, "mount_max = %i", &tmp) == 1)
        mount_max = tmp;
    else if(line[0])
        fprintf(stderr, "%s: unknown parameter in %s at line %i: '%s'\n",
                progname, FUSE_CONF, linenum, line);
}

static void read_conf(void)
{
    FILE *fp = fopen(FUSE_CONF, "r");
    if (fp != NULL) {
        int linenum = 1;
        char line[256];
        int isnewline = 1;
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (isnewline) {
                if (line[strlen(line)-1] == '\n') {
                    strip_line(line);
                    parse_line(line, linenum);
                } else {
                    fprintf(stderr, "%s: reading %s: line %i too long\n",
                            progname, FUSE_CONF, linenum);
                    isnewline = 0;
                }
            } else if(line[strlen(line)-1] == '\n')
                isnewline = 1;
            if (isnewline)
                linenum ++;
        }
        fclose(fp);
    } else if (errno != ENOENT) {
        fprintf(stderr, "%s: failed to open %s: %s\n", progname, FUSE_CONF,
                strerror(errno));
    }
}

static int begins_with(const char *s, const char *beg)
{
    if (strncmp(s, beg, strlen(beg)) == 0)
        return 1;
    else
        return 0;
}

struct mount_flags {
    const char *opt;
    unsigned long flag;
    int on;
    int safe;
};

static struct mount_flags mount_flags[] = {
    {"rw",      MS_RDONLY,      0, 1},
    {"ro",      MS_RDONLY,      1, 1},
    {"suid",    MS_NOSUID,      0, 0},
    {"nosuid",  MS_NOSUID,      1, 1},
    {"dev",     MS_NODEV,       0, 0},
    {"nodev",   MS_NODEV,       1, 1},
    {"exec",    MS_NOEXEC,      0, 1},
    {"noexec",  MS_NOEXEC,      1, 1},
    {"async",   MS_SYNCHRONOUS, 0, 1},
    {"sync",    MS_SYNCHRONOUS, 1, 1},
    {"atime",   MS_NOATIME,     0, 1},
    {"noatime", MS_NOATIME,     1, 1},
    {NULL,      0,              0, 0}
};

static int find_mount_flag(const char *s, unsigned len, int *on, int *flag)
{
    int i;

    for (i = 0; mount_flags[i].opt != NULL; i++) {
        const char *opt = mount_flags[i].opt;
        if (strlen(opt) == len && strncmp(opt, s, len) == 0) {
            *on = mount_flags[i].on;
            *flag = mount_flags[i].flag;
            if (!mount_flags[i].safe && getuid() != 0) {
                *flag = 0;
                fprintf(stderr, "%s: unsafe option %s ignored\n",
                        progname, opt);
            }
            return 1;
        }
    }
    return 0;
}

static int add_option(char **optsp, const char *opt, unsigned expand)
{
    char *newopts;
    if (*optsp == NULL)
        newopts = strdup(opt);
    else {
        unsigned oldsize = strlen(*optsp);
        unsigned newsize = oldsize + 1 + strlen(opt) + expand + 1;
        newopts = (char *) realloc(*optsp, newsize);
        if (newopts)
            sprintf(newopts + oldsize, ",%s", opt);
    }
    if (newopts == NULL) {
        fprintf(stderr, "%s: failed to allocate memory\n", progname);
        return -1;
    }
    *optsp = newopts;
    return 0;
}

static int get_mnt_opts(int flags, char *opts, char **mnt_optsp)
{
    int i;
    int l;

    if (!(flags & MS_RDONLY) && add_option(mnt_optsp, "rw", 0) == -1)
        return -1;

    for (i = 0; mount_flags[i].opt != NULL; i++) {
        if (mount_flags[i].on && (flags & mount_flags[i].flag) &&
            add_option(mnt_optsp, mount_flags[i].opt, 0) == -1)
            return -1;
    }

    if (add_option(mnt_optsp, opts, 0) == -1)
        return -1;
    /* remove comma from end of opts*/
    l = strlen(*mnt_optsp);
    if ((*mnt_optsp)[l-1] == ',')
        (*mnt_optsp)[l-1] = '\0';
    if (getuid() != 0) {
        const char *user = get_user_name();
        if (user == NULL)
            return -1;

        if (add_option(mnt_optsp, "user=", strlen(user)) == -1)
            return -1;
        strcat(*mnt_optsp, user);
    }
    return 0;
}

static int opt_eq(const char *s, unsigned len, const char *opt)
{
    if(strlen(opt) == len && strncmp(s, opt, len) == 0)
        return 1;
    else
        return 0;
}

static int check_mountpoint_empty(const char *mnt, mode_t rootmode,
                                  off_t rootsize)
{
    int isempty = 1;

    if (S_ISDIR(rootmode)) {
        struct dirent *ent;
        DIR *dp = opendir(mnt);
        if (dp == NULL) {
            fprintf(stderr, "%s: failed to mountpoint for reading: %s\n",
                    progname, strerror(errno));
            return -1;
        }
        while ((ent = readdir(dp)) != NULL) {
            if (strcmp(ent->d_name, ".") != 0 &&
                strcmp(ent->d_name, "..") != 0) {
                isempty = 0;
                break;
            }
        }
        closedir(dp);
    } else if (rootsize)
        isempty = 0;

    if (!isempty) {
        fprintf(stderr, "%s: mountpoint is not empty\n", progname);
        fprintf(stderr, "%s: if you are sure this is safe, use the 'nonempty' mount option\n", progname);
        return -1;
    }
    return 0;
}

static int do_mount(const char *mnt, const char *type, mode_t rootmode,
                    int fd, const char *opts, const char *dev, char **fsnamep,
                    char **mnt_optsp, off_t rootsize)
{
    int res;
    int flags = MS_NOSUID | MS_NODEV;
    char *optbuf;
    char *mnt_opts = NULL;
    const char *s;
    char *d;
    char *fsname = NULL;
    int check_empty = 1;

    optbuf = (char *) malloc(strlen(opts) + 128);
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
            fsname = (char *) malloc(len - fsname_str_len + 1);
            if (!fsname) {
                fprintf(stderr, "%s: failed to allocate memory\n", progname);
                goto err;
            }
            memcpy(fsname, s + fsname_str_len, len - fsname_str_len);
            fsname[len - fsname_str_len] = '\0';
        } else if (opt_eq(s, len, "nonempty")) {
            check_empty = 0;
        } else if (!begins_with(s, "fd=") &&
                   !begins_with(s, "rootmode=") &&
                   !begins_with(s, "user_id=") &&
                   !begins_with(s, "group_id=")) {
            int on;
            int flag;
            int skip_option = 0;
            if (opt_eq(s, len, "large_read")) {
                struct utsname utsname;
                unsigned kmaj, kmin;
                res = uname(&utsname);
                if (res == 0 &&
                    sscanf(utsname.release, "%u.%u", &kmaj, &kmin) == 2 &&
                    (kmaj > 2 || (kmaj == 2 && kmin > 4))) {
                    fprintf(stderr, "%s: note: 'large_read' mount option is deprecated for %i.%i kernels\n", progname, kmaj, kmin);
                    skip_option = 1;
                }
            }
            if (getuid() != 0 && !user_allow_other &&
                (opt_eq(s, len, "allow_other") ||
                 opt_eq(s, len, "allow_root"))) {
                fprintf(stderr, "%s: option %.*s only allowed if 'user_allow_other' is set in /etc/fuse.conf\n", progname, len, s);
                goto err;
            }
            if (!skip_option) {
                if (find_mount_flag(s, len, &on, &flag)) {
                    if (on)
                        flags |= flag;
                    else
                        flags  &= ~flag;
                } else {
                    memcpy(d, s, len);
                    d += len;
                    *d++ = ',';
                }
            }
        }
        s += len;
        if (*s)
            s++;
    }
    *d = '\0';
    res = get_mnt_opts(flags, optbuf, &mnt_opts);
    if (res == -1)
        goto err;

    sprintf(d, "fd=%i,rootmode=%o,user_id=%i,group_id=%i",
            fd, rootmode, getuid(), getgid());
    if (fsname == NULL) {
        fsname = strdup(dev);
        if (!fsname) {
            fprintf(stderr, "%s: failed to allocate memory\n", progname);
            goto err;
        }
    }

    if (check_empty && check_mountpoint_empty(mnt, rootmode, rootsize) == -1)
        goto err;

    res = mount(fsname, mnt, type, flags, optbuf);
    if (res == -1 && errno == EINVAL) {
        /* It could be an old version not supporting group_id */
        sprintf(d, "fd=%i,rootmode=%o,user_id=%i", fd, rootmode, getuid());
        res = mount(fsname, mnt, type, flags, optbuf);
    }
    if (res == -1) {
        fprintf(stderr, "%s: mount failed: %s\n", progname, strerror(errno));
        goto err;
    } else {
        *fsnamep = fsname;
        *mnt_optsp = mnt_opts;
    }
    free(optbuf);

    return res;

 err:
    free(fsname);
    free(mnt_opts);
    free(optbuf);
    return -1;
}

static int check_version(const char *dev)
{
    int res;
    int majorver;
    int minorver;
    const char *version_file;
    FILE *vf;

    if (strcmp(dev, FUSE_DEV_OLD) != 0)
        return 0;

    version_file = FUSE_VERSION_FILE_OLD;
    vf = fopen(version_file, "r");
    if (vf == NULL) {
        fprintf(stderr, "%s: kernel interface too old\n", progname);
        return -1;
    }
    res = fscanf(vf, "%i.%i", &majorver, &minorver);
    fclose(vf);
    if (res != 2) {
        fprintf(stderr, "%s: error reading %s\n", progname, version_file);
        return -1;
    }
     if (majorver < 3) {
        fprintf(stderr, "%s: kernel interface too old\n", progname);
        return -1;
    }
    return 0;
}

static int check_perm(const char **mntp, struct stat *stbuf, int *currdir_fd,
                      int *mountpoint_fd)
{
    int res;
    const char *mnt = *mntp;
    const char *origmnt = mnt;

    res = lstat(mnt, stbuf);
    if (res == -1) {
        fprintf(stderr, "%s: failed to access mountpoint %s: %s\n",
                progname, mnt, strerror(errno));
        return -1;
    }

    /* No permission checking is done for root */
    if (getuid() == 0)
        return 0;

    if (S_ISDIR(stbuf->st_mode)) {
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
                    progname, origmnt, strerror(errno));
            return -1;
        }

        if ((stbuf->st_mode & S_ISVTX) && stbuf->st_uid != getuid()) {
            fprintf(stderr, "%s: mountpoint %s not owned by user\n",
                    progname, origmnt);
            return -1;
        }

        res = access(mnt, W_OK);
        if (res == -1) {
            fprintf(stderr, "%s: user has no write access to mountpoint %s\n",
                    progname, origmnt);
            return -1;
        }
    } else if (S_ISREG(stbuf->st_mode)) {
        static char procfile[256];
        *mountpoint_fd = open(mnt, O_WRONLY);
        if (*mountpoint_fd == -1) {
            fprintf(stderr, "%s: failed to open %s: %s\n", progname, mnt,
                    strerror(errno));
            return -1;
        }
        res = fstat(*mountpoint_fd, stbuf);
        if (res == -1) {
            fprintf(stderr, "%s: failed to access mountpoint %s: %s\n",
                    progname, mnt, strerror(errno));
            return -1;
        }
        if (!S_ISREG(stbuf->st_mode)) {
            fprintf(stderr, "%s: mountpoint %s is no longer a regular file\n",
                    progname, mnt);
            return -1;
        }

        sprintf(procfile, "/proc/self/fd/%i", *mountpoint_fd);
        *mntp = procfile;
    } else {
        fprintf(stderr,
                "%s: mountpoint %s is not a directory or a regular file\n",
                progname, mnt);
        return -1;
    }


    return 0;
}

static int try_open(const char *dev, char **devp, int silent)
{
    int fd = open(dev, O_RDWR);
    if (fd != -1) {
        *devp = strdup(dev);
        if (*devp == NULL) {
            fprintf(stderr, "%s: failed to allocate memory\n", progname);
            close(fd);
            fd = -1;
        }
    } else if (errno == ENODEV)
        return -2;
    else if (!silent) {
        fprintf(stderr, "%s: failed to open %s: %s\n", progname, dev,
                strerror(errno));
    }
    return fd;
}

static int try_open_fuse_device(char **devp)
{
    int fd;

    drop_privs();
    fd = try_open(FUSE_DEV_NEW, devp, 1);
    restore_privs();
    if (fd >= 0)
        return fd;

    fd = try_open(FUSE_DEV_OLD, devp, 1);
    if (fd >= 0)
        return fd;

    return -1;
}

static int open_fuse_device(char **devp)
{
    int fd = try_open_fuse_device(devp);
    if (fd >= 0)
        return fd;

    fprintf(stderr, "%s: fuse device not found, try 'modprobe fuse' first\n",
            progname);
    return -1;
}


static int mount_fuse(const char *mnt, const char *opts)
{
    int res;
    int fd;
    char *dev;
    const char *type = "fuse";
    struct stat stbuf;
    char *fsname = NULL;
    char *mnt_opts = NULL;
    const char *real_mnt = mnt;
    int currdir_fd = -1;
    int mountpoint_fd = -1;
    int mtablock = -1;

    fd = open_fuse_device(&dev);
    if (fd == -1)
        return -1;

    if (geteuid() == 0) {
        mtablock = lock_mtab();
        if (mtablock < 0) {
            close(fd);
            return -1;
        }
    }

    drop_privs();
    read_conf();

    if (getuid() != 0 && mount_max != -1) {
        int mount_count = count_fuse_fs();
        if (mount_count >= mount_max) {
            fprintf(stderr, "%s: too many FUSE filesystems mounted; mount_max=N can be set in /etc/fuse.conf\n", progname);
            close(fd);
            unlock_mtab(mtablock);
            return -1;
        }
    }

    res = check_version(dev);
    if (res != -1) {
        res = check_perm(&real_mnt, &stbuf, &currdir_fd, &mountpoint_fd);
        restore_privs();
        if (res != -1)
            res = do_mount(real_mnt, type, stbuf.st_mode & S_IFMT, fd, opts,
                           dev, &fsname, &mnt_opts, stbuf.st_size);
    } else
        restore_privs();

    if (currdir_fd != -1) {
        fchdir(currdir_fd);
        close(currdir_fd);
    }
    if (mountpoint_fd != -1)
        close(mountpoint_fd);

    if (res == -1) {
        close(fd);
        unlock_mtab(mtablock);
        return -1;
    }

    if (geteuid() == 0) {
        res = add_mount(fsname, mnt, type, mnt_opts);
        unlock_mtab(mtablock);
        if (res == -1) {
            umount2(mnt, 2); /* lazy umount */
            close(fd);
            return -1;
        }
    }

    free(fsname);
    free(mnt_opts);
    free(dev);

    return fd;
}

static char *resolve_path(const char *orig)
{
    char buf[PATH_MAX];
    char *copy;
    char *dst;
    char *end;
    char *lastcomp;
    const char *toresolv;

    if (!orig[0]) {
        fprintf(stderr, "%s: invalid mountpoint '%s'\n", progname, orig);
        return NULL;
    }

    copy = strdup(orig);
    if (copy == NULL) {
        fprintf(stderr, "%s: failed to allocate memory\n", progname);
        return NULL;
    }

    toresolv = copy;
    lastcomp = NULL;
    for (end = copy + strlen(copy) - 1; end > copy && *end == '/'; end --);
    if (end[0] != '/') {
        char *tmp;
        end[1] = '\0';
        tmp = strrchr(copy, '/');
        if (tmp == NULL) {
            lastcomp = copy;
            toresolv = ".";
        } else {
            lastcomp = tmp + 1;
            if (tmp == copy)
                toresolv = "/";
        }
        if (strcmp(lastcomp, ".") == 0 || strcmp(lastcomp, "..") == 0) {
            lastcomp = NULL;
            toresolv = copy;
        }
        else if (tmp)
            tmp[0] = '\0';
    }
    if (realpath(toresolv, buf) == NULL) {
        fprintf(stderr, "%s: bad mount point %s: %s\n", progname, orig,
                strerror(errno));
        free(copy);
        return NULL;
    }
    if (lastcomp == NULL)
        dst = strdup(buf);
    else {
        dst = (char *) malloc(strlen(buf) + 1 + strlen(lastcomp) + 1);
        if (dst) {
            unsigned buflen = strlen(buf);
            if (buflen && buf[buflen-1] == '/')
                sprintf(dst, "%s%s", buf, lastcomp);
            else
                sprintf(dst, "%s/%s", buf, lastcomp);
        }
    }
    free(copy);
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

static void usage(void)
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

static void show_version(void)
{
    printf("%s\n", PACKAGE_STRING);
    exit(0);
}

int main(int argc, char *argv[])
{
    int ch;
    int fd;
    int res;
    char *origmnt;
    char *mnt;
    static int unmount = 0;
    static int lazy = 0;
    static int quiet = 0;
    char *commfd;
    int cfd;
    const char *opts = "";

    static const struct option long_opts[] = {
        {"unmount", no_argument, NULL, 'u'},
        {"lazy",    no_argument, NULL, 'z'},
        {"quiet",   no_argument, NULL, 'q'},
        {"help",    no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {0, 0, 0, 0}};

    progname = strdup(argv[0]);
    if (progname == NULL) {
        fprintf(stderr, "%s: failed to allocate memory\n", argv[0]);
        exit(1);
    }

    while ((ch = getopt_long(argc, argv, "hvo:uzq", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'h':
            usage();
            break;

        case 'v':
            show_version();
            break;

        case 'o':
            opts = optarg;
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
            exit(1);
        }
    }

    if (lazy && !unmount) {
        fprintf(stderr, "%s: -z can only be used with -u\n", progname);
        exit(1);
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: missing mountpoint argument\n", progname);
        exit(1);
    }

    origmnt = argv[optind];

    drop_privs();
    mnt = resolve_path(origmnt);
    restore_privs();
    if (mnt == NULL)
        exit(1);

    umask(033);
    if (unmount) {
        if (geteuid() == 0) {
            int mtablock = lock_mtab();
            res = unmount_fuse(mnt, quiet, lazy);
            unlock_mtab(mtablock);
        } else
            res = do_unmount(mnt, quiet, lazy);
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
