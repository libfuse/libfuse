/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"
#include <linux/fuse.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <mntent.h>

static int do_mount(const char *dev, const char *dir, const char *type,
                    mode_t rootmode, int fd)
{
    int res;
    struct fuse_mount_data data;
    
    data.version = FUSE_KERNEL_VERSION;
    data.fd = fd;
    data.rootmode = rootmode;

    res = mount(dev, dir, type, MS_MGC_VAL | MS_NOSUID | MS_NODEV, &data);
    if(res == -1) {
        perror("mount failed");
	return -1;
    }
    
    return 0;
}

static void add_mntent(const char *dev, const char *dir, const char *type)
{
    int res;
    FILE *fp;
    struct mntent ent;
    
    fp = setmntent("/etc/mtab", "a");
    if(fp == NULL) {
        perror("setmntent");
	return;
    }
    
    ent.mnt_fsname = (char *) dev;
    ent.mnt_dir = (char *) dir;
    ent.mnt_type = (char *) type;
    ent.mnt_opts = "rw,nosuid,nodev";
    ent.mnt_freq = 0;
    ent.mnt_passno = 0;
    res = addmntent(fp, & ent);
    if(res != 0)
	perror("addmntent");
    
    endmntent(fp);

}

static void remove_mntent(const char *dir)
{
    int res;
    FILE *fdold, *fdnew;
    struct mntent *entp;
        
    fdold = setmntent("/etc/mtab", "r");
    if(fdold == NULL) {
        perror("/etc/mtab");
	return;
    }

    fdnew = setmntent("/etc/mtab~", "w");
    if(fdnew == NULL) {
        perror("/etc/mtab~");
	return;
    }

    do {
	entp = getmntent(fdold);
	if(entp != NULL && strcmp(entp->mnt_dir, dir) != 0) {
            res = addmntent(fdnew, entp);
            if(res != 0)
                perror("addmntent");
        }
    } while(entp != NULL);

    endmntent(fdold);
    endmntent(fdnew);

    res = rename("/etc/mtab~", "/etc/mtab");
    if(res == -1)
        perror("renameing /etc/mtab~ to /etc/mtab");
}

int fuse_mount(struct fuse *f, const char *dir)
{
    int res;
    const char *dev = FUSE_DEV;
    const char *type = "fuse";

    if(f->mnt != NULL)
        return 0;

    f->fd = open(dev, O_RDWR);
    if(f->fd == -1) {
        perror(dev);
        return -1;
    }
    
    res = do_mount(dev, dir, type, f->rootmode, f->fd);
    if(res == -1)
        return -1;

    add_mntent(dev, dir, type);
    f->mnt = g_strdup(dir);
    
    return 0;
}

int fuse_unmount(struct fuse *f)
{
    int res;

    if(f->mnt == NULL)
        return 0;

    close(f->fd);
    f->fd = -1;

    res = umount(f->mnt);
    if(res == -1)
        perror("umount failed");
    else
        remove_mntent(f->mnt);

    g_free(f->mnt);
    f->mnt = NULL;

    return res;
}
