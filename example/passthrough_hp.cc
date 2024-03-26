/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2017       Nikolaus Rath <Nikolaus@rath.org>
  Copyright (C) 2018       Valve, Inc

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * This is a "high-performance" version of passthrough_ll.c. While
 * passthrough_ll.c is designed to be as simple as possible, this
 * example intended to be as efficient and correct as possible.
 *
 * passthrough_hp.cc mirrors a specified "source" directory under a
 * specified the mountpoint with as much fidelity and performance as
 * possible.
 *
 * If --nocache is specified, the source directory may be changed
 * directly even while mounted and the filesystem will continue
 * to work correctly.
 *
 * Without --nocache, the source directory is assumed to be modified
 * only through the passthrough filesystem. This enables much better
 * performance, but if changes are made directly to the source, they
 * may not be immediately visible under the mountpoint and further
 * access to the mountpoint may result in incorrect behavior,
 * including data-loss.
 *
 * On its own, this filesystem fulfills no practical purpose. It is
 * intended as a template upon which additional functionality can be
 * built.
 *
 * Unless --nocache is specified, is only possible to write to files
 * for which the mounting user has read permissions. This is because
 * the writeback cache requires the kernel to be able to issue read
 * requests for all files (which the passthrough filesystem cannot
 * satisfy if it can't read the file in the underlying filesystem).
 *
 * ## Source code ##
 * \include passthrough_hp.cc
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 12)

// C includes
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>

// C++ includes
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <list>
#include "cxxopts.hpp"
#include <mutex>
#include <fstream>
#include <thread>
#include <iomanip>
#include "passthrough_hp_common.hpp"


static void print_usage(char *prog_name) {
    cout << "Usage: " << prog_name << " --help\n"
         << "       " << prog_name << " [options] <source> <mountpoint>\n";
}


int main(int argc, char *argv[]) {
    struct fuse_loop_config *loop_config = NULL;
    int ret = -1;
    // Parse command line options
    auto options {parse_options(argc, argv, print_usage)};
    fs.timeout = options.count("nocache") ? 0 : 86400.0;
    // We need an fd for every dentry in our the filesystem that the
    // kernel knows about. This is way more than most processes need,
    // so try to get rid of any resource softlimit.
    maximize_fd_limit();

    fuse_args args = FUSE_ARGS_INIT(0, nullptr);
    if (fuse_opt_add_arg(&args, argv[0]) ||
        fuse_opt_add_arg(&args, "-o") ||
        fuse_opt_add_arg(&args, fs.fuse_mount_options.c_str()) ||
        (fs.debug_fuse && fuse_opt_add_arg(&args, "-odebug")))
        errx(3, "ERROR: Out of memory");

    // Initialize filesystem root
		auto se = init_passthrough_fs(&args);
    if (se == nullptr)
        goto err_out1;
    if (fuse_set_signal_handlers(se) != 0)
        goto err_out2;

    // Don't apply umask, use modes exactly as specified
    umask(0);

    // Mount and run main loop
    loop_config = fuse_loop_cfg_create();

    if (fs.num_threads != -1)
        fuse_loop_cfg_set_max_threads(loop_config, fs.num_threads);

    fuse_loop_cfg_set_clone_fd(loop_config, fs.clone_fd);
	
    if (fuse_session_mount(se, argv[2]) != 0)
        goto err_out3;

    fuse_daemonize(fs.foreground);

    if (options.count("single"))
        ret = fuse_session_loop(se);
    else
        ret = fuse_session_loop_mt(se, loop_config);


    fuse_session_unmount(se);

err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:

    fuse_loop_cfg_destroy(loop_config);
    fuse_opt_free_args(&args);

    return ret ? 1 : 0;
}


