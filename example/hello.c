/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *hello_str = "Hello World!\n";
static const char *hello_path = "/hello";

static int hello_getattr(const char *path, struct stat *stbuf)
{
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));
    if(strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else if(strcmp(path, hello_path) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(hello_str);
    }
    else
        res = -ENOENT;

    return res;
}

static int hello_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    filler(h, ".", 0);
    filler(h, "..", 0);
    filler(h, hello_path + 1, 0);

    return 0;
}

static int hello_open(const char *path, int flags)
{
    if(strcmp(path, hello_path) != 0)
        return -ENOENT;

    if((flags & 3) != O_RDONLY)
        return -EACCES;

    return 0;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset)
{
    if(strcmp(path, hello_path) != 0)
        return -ENOENT;
    
    memcpy(buf, hello_str + offset, size);
    return size;
}

static struct fuse_operations hello_oper = {
    .getattr	= hello_getattr,
    .getdir	= hello_getdir,
    .open	= hello_open,
    .read	= hello_read,
};

int main(int argc, char *argv[])
{
    fuse_main(argc, argv, &hello_oper);
    return 0;
}
