/* -*- indent-tabs-mode: t; c-basic-offset: 8; -*- */
/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/


#define FUSE_MOUNT_VERSION 1

struct fuse_mount_data {
	int version;
	int fd;
};

