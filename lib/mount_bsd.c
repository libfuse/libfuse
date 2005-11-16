/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2005 Csaba Henk <csaba.henk@creo.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>

#define FUSERMOUNT_PROG         "mount_fusefs"

void fuse_unmount(const char *mountpoint)
{
    char dev[128];
    char *ssc, *umount_cmd;
    FILE *sf;
    int rv;
    char *seekscript =
    "/usr/bin/fstat  /dev/fuse* |\n"
    "/usr/bin/awk '{if ($3 == %d) print $10}' |\n"
    "/usr/bin/sort |\n"
    "/usr/bin/uniq |\n"
    "/usr/bin/awk '{ i+=1; if(i > 1){ exit (1); }; printf; }; END{if (i==0) exit (1)}'";

    asprintf(&ssc, seekscript, getpid());

    errno = 0;
    sf = popen(ssc, "r");
    if (! sf)
        return;

    fgets(dev, sizeof(dev), sf);
    rv = pclose(sf);
    if (rv)
        return;

    asprintf(&umount_cmd, "/sbin/umount %s", dev);
    system(umount_cmd);
}

int fuse_mount(const char *mountpoint, const char *opts)
{
    const char *mountprog = FUSERMOUNT_PROG;
    int fd;
    char *fdnam, *dev;
    int pid;

    fdnam = getenv("FUSE_DEV_FD");

    if (fdnam) {
        char *ep;

        fd = strtol(fdnam, &ep, 10);

        if (*ep != '\0') {
            fprintf(stderr, "invalid value given in FUSE_DEV_FD");
            return -1;
        }

        if (fd < 0)
            return -1;

        goto mount;
    }

    dev = getenv("FUSE_DEV_NAME");

    if (! dev)
	dev = "/dev/fuse";

    if ((fd = open(dev, O_RDWR)) < 0) {
        perror("fuse: failed to open fuse device");
        return -1;
    }

mount:
    if (getenv("FUSE_NO_MOUNT") || ! mountpoint)
        goto out;

    pid = fork();

    if (pid == -1) {
        perror("fuse: fork() failed");
        close(fd);
        return -1;
    }

    if (pid == 0) {
        pid = fork();

        if (pid == -1) {
            perror("fuse: fork() failed");
            close(fd);
            exit(1);
        }

        if (pid == 0) {
            const char *argv[32];
            int a = 0;

            if (! fdnam)
                asprintf(&fdnam, "%d", fd);

            argv[a++] = mountprog;
            if (opts) {
                argv[a++] = "-o";
                argv[a++] = opts;
            }
            argv[a++] = fdnam;
            argv[a++] = mountpoint;
            argv[a++] = NULL;
            setenv("MOUNT_FUSEFS_SAFE", "1", 1);
            execvp(mountprog, (char **) argv);
            perror("fuse: failed to exec mount program");
            exit(1);
        }

        exit(0);
    }

    waitpid(pid, NULL, 0);

out:
    return fd;
}
