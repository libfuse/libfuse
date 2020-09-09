/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * This example implements a file system with a single file whose
 * contents change dynamically: it always contains the current time.
 *
 * While notify_store_retrieve.c uses fuse_lowlevel_notify_store() to
 * actively push the updated data into the kernel cache, this example
 * uses fuse_lowlevel_notify_inval_inode() to notify the kernel that
 * the cache has to be invalidated - but the kernel still has to
 * explicitly request the updated data on the next read.
 *
 * To see the effect, first start the file system with the
 *  ``--no-notify`` option:
 *
 *     $ notify_inval_inode --update-interval=1 --no-notify mnt/
 *
 * Observe that the output never changes, even though the file system
 * updates it once per second. This is because the contents are cached
 * in the kernel:
 *
 *     $ for i in 1 2 3 4 5; do
 *     >     cat mnt/current_time
 *     >     sleep 1
 *     > done
 *     The current time is 15:58:18
 *     The current time is 15:58:18
 *     The current time is 15:58:18
 *     The current time is 15:58:18
 *     The current time is 15:58:18
 *
 * If you instead enable the notification functions, the changes become
 * visible:
 *
 *      $ notify_inval_inode --update-interval=1 mnt/
 *      $ for i in 1 2 3 4 5; do
 *      >     cat mnt/current_time
 *      >     sleep 1
 *      > done
 *      The current time is 15:58:40
 *      The current time is 15:58:41
 *      The current time is 15:58:42
 *      The current time is 15:58:43
 *      The current time is 15:58:44
 *
 * ## Compilation ##
 *
 *     gcc -Wall notify_inval_inode.c `pkg-config fuse3 --cflags --libs` -o notify_inval_inode
 *
 * ## Source code ##
 * \include notify_inval_inode.c
 */


#define FUSE_USE_VERSION 34

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

/* We can't actually tell the kernel that there is no
   timeout, so we just send a big value */
#define NO_TIMEOUT 500000

#define MAX_STR_LEN 128
#define FILE_INO 2
#define FILE_NAME "current_time"
static char file_contents[MAX_STR_LEN];
static int lookup_cnt = 0;
static size_t file_size;

/* Command line parsing */
struct options {
    int no_notify;
    int update_interval;
};
static struct options options = {
    .no_notify = 0,
    .update_interval = 1,
};

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--no-notify", no_notify),
    OPTION("--update-interval=%d", update_interval),
    FUSE_OPT_END
};

static int tfs_stat(fuse_ino_t ino, struct stat *stbuf) {
    stbuf->st_ino = ino;
    if (ino == FUSE_ROOT_ID) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 1;
    }

    else if (ino == FILE_INO) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = file_size;
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
    else if (strcmp(name, FILE_NAME) == 0) {
        e.ino = FILE_INO;
        lookup_cnt++;
    } else
        goto err_out;

    e.attr_timeout = NO_TIMEOUT;
    e.entry_timeout = NO_TIMEOUT;
    if (tfs_stat(e.ino, &e.attr) != 0)
        goto err_out;
    fuse_reply_entry(req, &e);
    return;

err_out:
    fuse_reply_err(req, ENOENT);
}

static void tfs_forget (fuse_req_t req, fuse_ino_t ino,
                        uint64_t nlookup) {
    (void) req;
    if(ino == FILE_INO)
        lookup_cnt -= nlookup;
    else
        assert(ino == FUSE_ROOT_ID);
    fuse_reply_none(req);
}

static void tfs_getattr(fuse_req_t req, fuse_ino_t ino,
                        struct fuse_file_info *fi) {
    struct stat stbuf;

    (void) fi;

    memset(&stbuf, 0, sizeof(stbuf));
    if (tfs_stat(ino, &stbuf) != 0)
        fuse_reply_err(req, ENOENT);
    else
        fuse_reply_attr(req, &stbuf, NO_TIMEOUT);
}

struct dirbuf {
    char *p;
    size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
                       fuse_ino_t ino) {
    struct stat stbuf;
    size_t oldsize = b->size;
    b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
    b->p = (char *) realloc(b->p, b->size);
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;
    fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
                      b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
                             off_t off, size_t maxsize) {
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off,
                              min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

static void tfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                        off_t off, struct fuse_file_info *fi) {
    (void) fi;

    if (ino != FUSE_ROOT_ID)
        fuse_reply_err(req, ENOTDIR);
    else {
        struct dirbuf b;

        memset(&b, 0, sizeof(b));
        dirbuf_add(req, &b, FILE_NAME, FILE_INO);
        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

static void tfs_open(fuse_req_t req, fuse_ino_t ino,
                     struct fuse_file_info *fi) {

    /* Make cache persistent even if file is closed,
       this makes it easier to see the effects */
    fi->keep_cache = 1;

    if (ino == FUSE_ROOT_ID)
        fuse_reply_err(req, EISDIR);
    else if ((fi->flags & O_ACCMODE) != O_RDONLY)
        fuse_reply_err(req, EACCES);
    else if (ino == FILE_INO)
        fuse_reply_open(req, fi);
    else {
        // This should not happen
        fprintf(stderr, "Got open for non-existing inode!\n");
        fuse_reply_err(req, ENOENT);
    }
}

static void tfs_read(fuse_req_t req, fuse_ino_t ino, size_t size,
                     off_t off, struct fuse_file_info *fi) {
    (void) fi;

    assert(ino == FILE_INO);
    reply_buf_limited(req, file_contents, file_size, off, size);
}

static const struct fuse_lowlevel_ops tfs_oper = {
    .lookup	= tfs_lookup,
    .getattr	= tfs_getattr,
    .readdir	= tfs_readdir,
    .open	= tfs_open,
    .read	= tfs_read,
    .forget     = tfs_forget,
};

static void update_fs(void) {
    struct tm *now;
    time_t t;
    t = time(NULL);
    now = localtime(&t);
    assert(now != NULL);

    file_size = strftime(file_contents, MAX_STR_LEN,
                         "The current time is %H:%M:%S\n", now);
    assert(file_size != 0);
}

static void* update_fs_loop(void *data) {
    struct fuse_session *se = (struct fuse_session*) data;

    while(1) {
        update_fs();
        if (!options.no_notify && lookup_cnt) {
            /* Only send notification if the kernel
               is aware of the inode */
            assert(fuse_lowlevel_notify_inval_inode
                   (se, FILE_INO, 0, 0) == 0);
        }
        sleep(options.update_interval);
    }
    return NULL;
}

static void show_help(const char *progname)
{
    printf("usage: %s [options] <mountpoint>\n\n", progname);
    printf("File-system specific options:\n"
               "    --update-interval=<secs>  Update-rate of file system contents\n"
               "    --no-notify            Disable kernel notifications\n"
               "\n");
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config config;
    pthread_t updater;
    int ret = -1;

    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
        return 1;

    if (fuse_parse_cmdline(&args, &opts) != 0) {
        ret = 1;
        goto err_out1;
    }

    if (opts.show_help) {
        show_help(argv[0]);
        fuse_cmdline_help();
        fuse_lowlevel_help();
        ret = 0;
        goto err_out1;
    } else if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        ret = 0;
        goto err_out1;
    }

    /* Initial contents */
    update_fs();

    se = fuse_session_new(&args, &tfs_oper,
                          sizeof(tfs_oper), NULL);
    if (se == NULL)
        goto err_out1;

    if (fuse_set_signal_handlers(se) != 0)
        goto err_out2;

    if (fuse_session_mount(se, opts.mountpoint) != 0)
        goto err_out3;

    fuse_daemonize(opts.foreground);

    /* Start thread to update file contents */
    ret = pthread_create(&updater, NULL, update_fs_loop, (void *)se);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed with %s\n",
                strerror(ret));
        goto err_out3;
    }

    /* Block until ctrl+c or fusermount -u */
    if (opts.singlethread)
        ret = fuse_session_loop(se);
    else {
        config.clone_fd = opts.clone_fd;
        config.max_idle_threads = opts.max_idle_threads;
        ret = fuse_session_loop_mt(se, &config);
    }

    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    fuse_opt_free_args(&args);
    free(opts.mountpoint);

    return ret ? 1 : 0;
}


/**
 * Local Variables:
 * mode: c
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * End:
 */
