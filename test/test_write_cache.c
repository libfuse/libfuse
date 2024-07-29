/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/


#define FUSE_USE_VERSION 30

#include <fuse_config.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdatomic.h>

#ifndef __linux__
#include <limits.h>
#else
#include <linux/limits.h>
#endif

#define FILE_INO 2
#define FILE_NAME "write_me"

/* Command line parsing */
struct options {
    int writeback;
    int data_size;
    int delay_ms;
} options = {
    .writeback = 0,
    .data_size = 2048,
    .delay_ms = 0,
};

#define WRITE_SYSCALLS 64

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("writeback_cache", writeback),
    OPTION("--data-size=%d", data_size),
    OPTION("--delay_ms=%d", delay_ms),
    FUSE_OPT_END
};
static int got_write;
static atomic_int write_cnt;

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int write_start, write_done;

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
        /* Test close(rofd) does not block waiting for pending writes */
        fi->noflush = !options.writeback && options.delay_ms &&
                      (fi->flags & O_ACCMODE) == O_RDONLY;
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

    write_cnt++;

   if(size != expected && !options.writeback)
       fprintf(stderr, "ERROR: Expected %zd bytes, got %zd\n!",
               expected, size);
   else
      got_write = 1;

    /* Simulate waiting for pending writes */
    if (options.delay_ms) {
        pthread_mutex_lock(&lock);
        write_start = 1;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);

        usleep(options.delay_ms * 1000);

        pthread_mutex_lock(&lock);
        write_done = 1;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
    }

    fuse_reply_write(req, size);
}

static struct fuse_lowlevel_ops tfs_oper = {
    .init       = tfs_init,
    .lookup	= tfs_lookup,
    .getattr	= tfs_getattr,
    .open	= tfs_open,
    .write	= tfs_write,
};

static void* close_rofd(void *data) {
    int rofd = (int)(long) data;

    /* Wait for first write to start */
    pthread_mutex_lock(&lock);
    while (!write_start && !write_done)
        pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);

    close(rofd);
    printf("rofd closed. write_start: %d write_done: %d\n", write_start, write_done);

    /* First write should not have been completed */
    if (write_done)
        fprintf(stderr, "ERROR: close(rofd) blocked on write!\n");

    return NULL;
}

static void* run_fs(void *data) {
    struct fuse_session *se = (struct fuse_session*) data;
    assert(fuse_session_loop(se) == 0);
    return NULL;
}

static void test_fs(char *mountpoint) {
    char fname[PATH_MAX];
    char *buf;
    const size_t iosize = options.data_size;
    const size_t dsize = options.data_size * WRITE_SYSCALLS;
    int fd, rofd;
    pthread_t rofd_thread;
    off_t off = 0;

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

    if (options.delay_ms) {
        /* Verify that close(rofd) does not block waiting for pending writes */
        rofd = open(fname, O_RDONLY);
        assert(pthread_create(&rofd_thread, NULL, close_rofd, (void *)(long)rofd) == 0);
        /* Give close_rofd time to start */
        usleep(options.delay_ms * 1000);
    }

    for (int cnt = 0; cnt < WRITE_SYSCALLS; cnt++) {
        assert(pwrite(fd, buf + off, iosize, off) == iosize);
        off += iosize;
        assert(off <= dsize);
    }
    free(buf);
    close(fd);

    if (options.delay_ms) {
        printf("rwfd closed. write_start: %d write_done: %d\n", write_start, write_done);
        assert(pthread_join(rofd_thread, NULL) == 0);
    }
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts fuse_opts;
    pthread_t fs_thread;

    assert(fuse_opt_parse(&args, &options, option_spec, NULL) == 0);
    assert(fuse_parse_cmdline(&args, &fuse_opts) == 0);
#ifndef __FreeBSD__    
    assert(fuse_opt_add_arg(&args, "-oauto_unmount") == 0);
#endif
    se = fuse_session_new(&args, &tfs_oper,
                          sizeof(tfs_oper), NULL);
    fuse_opt_free_args(&args);
    assert (se != NULL);
    assert(fuse_set_signal_handlers(se) == 0);
    assert(fuse_session_mount(se, fuse_opts.mountpoint) == 0);

    /* Start file-system thread */
    assert(pthread_create(&fs_thread, NULL, run_fs, (void *)se) == 0);

    /* Write test data */
    test_fs(fuse_opts.mountpoint);
    free(fuse_opts.mountpoint);

    /* Stop file system */
    fuse_session_exit(se);
    fuse_session_unmount(se);
    assert(pthread_join(fs_thread, NULL) == 0);

    assert(got_write == 1);

    /*
     * when writeback cache is enabled, kernel side can merge requests, but
     * memory pressure, system 'sync' might trigger data flushes before - flush
     * might happen in between write syscalls - merging subpage writes into
     * a single page and pages into large fuse requests might or might not work.
     * Though we can expect that that at least some (but maybe all) write
     * system calls can be merged.
     */
    if (options.writeback)
        assert(write_cnt < WRITE_SYSCALLS);
    else
        assert(write_cnt == WRITE_SYSCALLS);

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
