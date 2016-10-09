/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  This example implements a file system with a single file whose
  file name changes dynamically to reflect the current time.

  It illustrates the use of the fuse_lowlevel_notify_inval_entry()
  function.

  To see the effect, first start the file system with the
  ``--no-notify``

      $ timefs --update-interval=1 --timeout 30 --no-notify mnt/

  Observe that `ls` always prints the correct directory contents
  (since `readdir` output is not cached)::

      $ ls mnt; sleep 1; ls mnt; sleep 1; ls mnt
      Time_is_15h_48m_33s  current_time
      Time_is_15h_48m_34s  current_time
      Time_is_15h_48m_35s  current_time

  However, if you try to access a file by name the kernel will
  report that it still exists:

      $ file=$(ls mnt/); echo $file
      Time_is_15h_50m_09s
      $ sleep 5; stat mnt/$file
        File: ‘mnt/Time_is_15h_50m_09s’
        Size: 32                Blocks: 0          IO Block: 4096   regular file
      Device: 2ah/42d	Inode: 3           Links: 1
      Access: (0444/-r--r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
      Access: 1969-12-31 16:00:00.000000000 -0800
      Modify: 1969-12-31 16:00:00.000000000 -0800
      Change: 1969-12-31 16:00:00.000000000 -0800
       Birth: -

  Only once the kernel cache timeout has been reached will the stat
  call fail:

      $ sleep 30; stat mnt/$file
      stat: cannot stat ‘mnt/Time_is_15h_50m_09s’: No such file or directory

  In contrast, if you enable notifications you will be unable to stat
  the file as soon as the file system updates its name:

      $ timefs --update-interval=1 --timeout 30 --no-notify mnt/
      $ file=$(ls mnt/); stat mnt/$file
        File: ‘mnt/Time_is_20h_42m_11s’
        Size: 0                 Blocks: 0          IO Block: 4096   regular empty file
      Device: 2ah/42d	Inode: 2           Links: 1
      Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)
      Access: 1969-12-31 16:00:00.000000000 -0800
      Modify: 1969-12-31 16:00:00.000000000 -0800
      Change: 1969-12-31 16:00:00.000000000 -0800
       Birth: -
      $ sleep 1; stat mnt/$file
      stat: cannot stat ‘mnt/Time_is_20h_42m_11s’: No such file or directory

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

#define MAX_STR_LEN 128
static char file_name[MAX_STR_LEN];
static fuse_ino_t file_ino = 2;
static int lookup_cnt = 0;

/* Command line parsing */
struct options {
    int no_notify;
    float timeout;
    int update_interval;
};
static struct options options = {
    .timeout = 5,
    .no_notify = 0,
    .update_interval = 1,
};

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--no-notify", no_notify),
    OPTION("--update-interval=%d", update_interval),
    OPTION("--timeout=%f", timeout),
    FUSE_OPT_END
};

static int opt_proc(void *data, const char *arg, int key,
                    struct fuse_args *outargs) {
    (void) outargs; (void) data; (void) arg;
    (void) key;
    return 1;
}

static int tfs_stat(fuse_ino_t ino, struct stat *stbuf) {
    stbuf->st_ino = ino;
    if (ino == FUSE_ROOT_ID) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 1;
    }

    else if (ino == file_ino) {
        stbuf->st_mode = S_IFREG | 0000;
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
    else if (strcmp(name, file_name) == 0) {
        e.ino = file_ino;
        lookup_cnt++;
    } else
        goto err_out;

    e.attr_timeout = options.timeout;
    e.entry_timeout = options.timeout;
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
    assert(ino == file_ino || ino == FUSE_ROOT_ID);
    lookup_cnt -= nlookup;
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
        fuse_reply_attr(req, &stbuf, options.timeout);
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
        dirbuf_add(req, &b, file_name, file_ino);
        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

static struct fuse_lowlevel_ops tfs_oper = {
    .lookup	= tfs_lookup,
    .getattr	= tfs_getattr,
    .readdir	= tfs_readdir,
    .forget     = tfs_forget,
};

static void* update_fs(void *data) {
    struct fuse_session *se = (struct fuse_session*) data;
    struct tm *now;
    char *old_name;
    time_t t;
    ssize_t ret;

    while(1) {
        t = time(NULL);
        now = localtime(&t);
        assert(now != NULL);

        old_name = strdup(file_name);
        ret = strftime(file_name, MAX_STR_LEN,
                       "Time_is_%Hh_%Mm_%Ss", now);
        assert(ret != 0);

        if (!options.no_notify && lookup_cnt)
            assert(fuse_lowlevel_notify_inval_entry
                   (se, FUSE_ROOT_ID, old_name, strlen(old_name)) == 0);
        free(old_name);
        sleep(options.update_interval);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    pthread_t updater;
    int ret = -1;

    if (fuse_opt_parse(&args, &options, option_spec,
                       opt_proc) == -1)
        return 1;

    if (fuse_parse_cmdline(&args, &opts) != 0)
        return 1;
    if (opts.show_help || opts.show_version) {
        ret = 1;
        goto err_out1;
    }

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
    ret = pthread_create(&updater, NULL, update_fs, (void *)se);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed with %s\n",
                strerror(ret));
        goto err_out3;
    }

    /* Block until ctrl+c or fusermount -u */
    if (opts.singlethread)
        ret = fuse_session_loop(se);
    else
        ret = fuse_session_loop_mt(se);

    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    return ret ? 1 : 0;
}


/**
 * Local Variables:
 * mode: c
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * End:
 */
