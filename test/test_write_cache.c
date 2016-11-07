/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/


#define FUSE_USE_VERSION 30

#include <config.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/limits.h>

#define FILE_INO 2
#define FILE_NAME "write_me"

/* Command line parsing */
struct options {
    int writeback;
    int data_size;
} options = {
    .writeback = 0,
    .data_size = 4096,
};

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("writeback_cache", writeback),
    OPTION("--data-size=%d", data_size),
    FUSE_OPT_END
};
static int got_write;

static void tfs_init (void *userdata, struct fuse_conn_info *conn)
{
    (void) userdata;

    if(options.writeback) {
        assert(conn->capable & FUSE_CAP_WRITEBACK_CACHE);
        conn->want |= FUSE_CAP_WRITEBACK_CACHE;
    }
}

static int tfs_stat(fuse_ino_t ino, struct stat *stbuf) {
    stbuf->st_ino = ino;
    if (ino == FUSE_ROOT_ID) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 1;
    }

    else if (ino == FILE_INO) {
        stbuf->st_mode = S_IFREG | 0222;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0;
    }

    else
        return -1;

    return 0;
}

static void tfs_lookup(fuse_req_t req, fuse_ino_t parent,
                       const char *name) {
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    if (parent != FUSE_ROOT_ID)
        goto err_out;
    else if (strcmp(name, FILE_NAME) == 0)
        e.ino = FILE_INO;
    else
        goto err_out;

    if (tfs_stat(e.ino, &e.attr) != 0)
        goto err_out;
    fuse_reply_entry(req, &e);
    return;

err_out:
    fuse_reply_err(req, ENOENT);
}

static void tfs_getattr(fuse_req_t req, fuse_ino_t ino,
                        struct fuse_file_info *fi) {
    struct stat stbuf;

    (void) fi;

    memset(&stbuf, 0, sizeof(stbuf));
    if (tfs_stat(ino, &stbuf) != 0)
        fuse_reply_err(req, ENOENT);
    else
        fuse_reply_attr(req, &stbuf, 5);
}

static void tfs_open(fuse_req_t req, fuse_ino_t ino,
                     struct fuse_file_info *fi) {
    if (ino == FUSE_ROOT_ID)
        fuse_reply_err(req, EISDIR);
    else {
        assert(ino == FILE_INO);
        fuse_reply_open(req, fi);
    }
}

static void tfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                      size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi; (void) buf; (void) off;
    size_t expected;

    assert(ino == FILE_INO);
    expected = options.data_size;
    if(options.writeback)
        expected *= 2;

    if(size != expected)
        fprintf(stderr, "ERROR: Expected %zd bytes, got %zd\n!",
                expected, size);
    else
        got_write = 1;
    fuse_reply_write(req, size);
}

static struct fuse_lowlevel_ops tfs_oper = {
    .init       = tfs_init,
    .lookup	= tfs_lookup,
    .getattr	= tfs_getattr,
    .open	= tfs_open,
    .write	= tfs_write,
};

static void* run_fs(void *data) {
    struct fuse_session *se = (struct fuse_session*) data;
    assert(fuse_session_loop(se) == 0);
    return NULL;
}

static void test_fs(char *mountpoint) {
    char fname[PATH_MAX];
    char *buf;
    size_t dsize = options.data_size;
    int fd;

    buf = malloc(dsize);
    assert(buf != NULL);
    assert((fd = open("/dev/urandom", O_RDONLY)) != -1);
    assert(read(fd, buf, dsize) == dsize);
    close(fd);

    assert(snprintf(fname, PATH_MAX, "%s/" FILE_NAME,
                     mountpoint) > 0);
    fd = open(fname, O_WRONLY);
    if (fd == -1) {
        perror(fname);
        assert(0);
    }

    assert(write(fd, buf, dsize) == dsize);
    assert(write(fd, buf, dsize) == dsize);
    close(fd);
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts fuse_opts;
    pthread_t fs_thread;

    assert(fuse_opt_parse(&args, &options, option_spec, NULL) == 0);
    assert(fuse_parse_cmdline(&args, &fuse_opts) == 0);
    assert(fuse_opt_add_arg(&args, "-oauto_unmount") == 0);
    se = fuse_session_new(&args, &tfs_oper,
                          sizeof(tfs_oper), NULL);
    assert (se != NULL);
    assert(fuse_set_signal_handlers(se) == 0);
    assert(fuse_session_mount(se, fuse_opts.mountpoint) == 0);

    /* Start file-system thread */
    assert(pthread_create(&fs_thread, NULL, run_fs, (void *)se) == 0);

    /* Write test data */
    test_fs(fuse_opts.mountpoint);

    /* Stop file system */
    assert(pthread_cancel(fs_thread) == 0);

    fuse_session_unmount(se);
    assert(got_write == 1);
    fuse_remove_signal_handlers(se);
    fuse_session_destroy(se);

    printf("Test completed successfully.\n");
    return 0;
}


/**
 * Local Variables:
 * mode: c
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * End:
 */
