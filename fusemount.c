/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <mntent.h>

static void loop(int devfd)
{
    int res;
    struct fuse_param param;
    
    while(1) {
        res = read(devfd, &param, sizeof(param));
        if(res == -1) {
            perror("read");
            exit(1);
        }
        
        printf("unique: %i, opcode: %i\n", param.unique, param.u.i.opcode);
        param.u.o.result = 0;
        
        res = write(devfd, &param, sizeof(param));
        if(res == -1) {
            perror("write");
            exit(1);
        }
    }
}

static int mount_fuse(const char *dev, const char *dir, int devfd)
{
    int res;
    const char *type;
    FILE *fd;
    struct mntent ent;
    struct fuse_mount_data data;
    
    data.version = FUSE_MOUNT_VERSION;
    data.fd = devfd;

    type = "fuse";
    res = mount(dev, dir, type, MS_MGC_VAL | MS_NOSUID | MS_NODEV, &data);
    
    if(res == -1) {
        fprintf(stderr, "mount failed: %s\n", strerror(errno));
	return -1;
    }
    
    fd = setmntent("/etc/mtab", "a");
    if(fd == NULL) {
	fprintf(stderr, "setmntent(\"/etc/mtab\") failed: %s\n",
		strerror(errno));
	return -1;
    }
    
    ent.mnt_fsname = (char *) dev;
    ent.mnt_dir = (char *) dir;
    ent.mnt_type = (char *) type;
    ent.mnt_opts = "rw,nosuid,nodev";
    ent.mnt_freq = 0;
    ent.mnt_passno = 0;
    res = addmntent(fd, & ent);
    if(res != 0)
	fprintf(stderr, "addmntent() failed: %s\n", strerror(errno));
    
    endmntent(fd);
    
    return 0;
}

int main(int argc, char *argv[])
{
    const char *dev;
    const char *dir;
    int devfd;

    if(argc < 3) {
        fprintf(stderr, "usage: %s dev dir\n", argv[0]);
        exit(1);
    }

    dev = argv[1];
    dir = argv[2];

    devfd = open(dev, O_RDWR);
    if(devfd == -1) {
        fprintf(stderr, "failed to open %s: %s\n", dev, strerror(errno));
        exit(1);
    }

    mount_fuse(dev, dir, devfd);

    loop(devfd);
    
    return 0;
}
