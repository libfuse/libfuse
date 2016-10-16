Unreleased Changes
==================

* The chmod, chown, truncate, utimens and getattr handlers of the
  high-level API now all receive an additional struct fuse_file_info
  pointer. This pointer is NULL if the file is not currently open.

  The fgetattr and ftruncate handlers have become obsolote and have
  been removed.

* The `fuse_session_new` function no longer accepts the ``-o
  clone_fd`` option. Instead, this has become a parameter of the
  `fuse_session_loop_mt` and ``fuse_loop_mt` functions.

* For low-level file systems that implement the `write_buf` handler,
  the `splice_read` option is now enabled by default. As usual, this
  can be changed in the file system's `init` handler.

* The treatment of low-level options has been made more consistent:

  Options that can be set in the init() handler (via the
  fuse_conn_info parameter) can now be set only here,
  i.e. fuse_session_new() no longer accepts arguments that change the
  fuse_conn_info object before or after the call do init(). As a side
  effect, this removes the ambiguity where some options can be
  overwritten by init(), while others overwrite the choices made by
  init().

  For file systems that wish to offer command line options for these
  settings, the new fuse_parse_conn_info_opts() and
  fuse_apply_conn_info_opts() functions are available.

  Consequently, the fuse_lowlevel_help() method has been dropped.

* The `async_read` field in `struct fuse_conn_info` has been
  removed. To determine if the kernel supports asynchronous reads,
  file systems should check the `FUSE_CAP_ASYNC_READ` bit of the
  `capable` field. To enable/disable asynchronous reads, file systems
  should set the flag in the `wanted` field.

* The `fuse_parse_cmdline` function no longer prints out help when the
  ``--verbose`` or ``--help`` flags are given. This needs to be done
  by the file system (e.g. using the `fuse_cmdline_help()` and
  `fuse_mount_help()` functions).

* Added ``example/cuse_client.c`` to test ``example/cuse.c``.

* Removed ``example/null.c``. This has not been working for a while
  for unknown reasons -- maybe because it tries to treat the
  mountpoint as a file rather than a directory?

* There are several new examples that demonstrate the use of
  the ``fuse_lowlevel_notify_*`` functions:

  - ``example/notify_store_retrieve.c``
  - ``example/notify_inval_inode.c``
  - ``example/notify_inval_entry.c``

* The ``-o big_writes`` mount option has been removed. It is now
  always active. File systems that want to limit the size of write
  requests should use the ``-o max_write=<N>`` option instead.

FUSE 3.0.0pre0 (2016-10-03)
============================

* This is a preview release. Functionality and API may still change
  before the 3.0.0 release.

* The `fuse_lowlevel_new` function has been renamed to
  `fuse_session_new` and no longer interprets the --version or --help
  options. To print help or version information, use the new
  `fuse_lowlevel_help` and `fuse_lowlevel_version` functions.

* There are new `fuse_session_unmount` and `fuse_session_mount`
  functions that should be used in the low-level API. The `fuse_mount`
  and `fuse_unmount` functions should be used with the high-level API
  only.

* Neither `fuse_mount` nor `fuse_session_mount` take struct fuse_opts
  parameters anymore. Mount options are parsed by `fuse_new` (for the
  high-level API) and `fuse_session_new` (for the low-level API)
  instead. To print help or version information, use the new
  `fuse_mount_help` and `fuse_mount_version` functions.

* The ``fuse_lowlevel_notify_*`` functions now all take a `struct
  fuse_session` parameter instead of a `struct fuse_chan`.

* The channel interface (``fuse_chan_*`` functions) has been made
  private. As a result, the typical initialization sequence of a
  low-level file system has changed from ::

        ch = fuse_mount(mountpoint, &args);
        se = fuse_lowlevel_new(&args, &lo_oper, sizeof(lo_oper), &lo);
        fuse_set_signal_handlers(se);
        fuse_session_add_chan(se, ch);
        fuse_daemonize(fg);
        if (mt)
            fuse_session_loop_mt(se);
        else
            fuse_session_loop(se);
        fuse_remove_signal_handlers(se);
        fuse_session_remove_chan(ch);
        fuse_session_destroy(se);
        fuse_unmount(mountpoint, ch);

  to ::

        se = fuse_session_new(&args, &ll_ops, sizeof(ll_ops), NULL);
        fuse_set_signal_handlers(se);
        fuse_session_mount(se, mountpoint);
        fuse_daemonize(fg);
        if (mt)
            fuse_session_loop_mt(se);
        else
            fuse_session_loop(se);
        fuse_remove_signal_handlers(se);
        fuse_session_unmount(se);
        fuse_lowlevel_destroy(se);

  The typical high-level setup has changed from ::

        ch = fuse_mount(*mountpoint, &args);
        fuse = fuse_new(ch, &args, op, op_size, user_data);
        se = fuse_get_session(fuse);
        fuse_set_signal_handlers(se);
        fuse_daemonize(fg);
        if (mt)
            fuse_loop_mt(fuse);
        else
            fuse_loop(fuse);
        fuse_remove_signal_handlers(se);
        fuse_unmount(mountpoint, ch);
        fuse_destroy(fuse);

  to ::

        fuse = fuse_new(&args, op, op_size, user_data);
        se = fuse_get_session(fuse);
        fuse_set_signal_handlers(se);
        fuse_mount(se, mountpoint);
        fuse_daemonize(fg);
         if (mt)
            fuse_loop_mt(fuse);
        else
            fuse_loop(fuse);
        fuse_remove_signal_handlers(se);
        fuse_unmount(se);
        fuse_destroy(fuse);

  File systems that use `fuse_main` are not affected by this change.

  For integration with custom event loops, the new `fuse_session_fd`
  function provides the file descriptor that's used for communication
  with the kernel.

* Added *clone_fd* option.  This creates a separate device file
  descriptor for each processing thread, which might improve
  performance.

* Added *writeback_cache* option. With kernel 3.14 and newer this
  enables write-back caching which can significantly improve
  performance.

* Added *async_dio* option. With kernel 3.13 and newer, this allows
  direct I/O to be done asynchronously.

* The (high- and low-level) `rename` handlers now takes a *flags*
  parameter (with values corresponding to the *renameat2* system call
  introduced in Linux 3.15).

* The "ulockmgr_server" has been dropped.

* There is a new (low-level) `readdirplus` handler, with a
  corresponding example in ``examples/fuse_lo-plus.c`` and a new
  `fuse_add_direntry_plus` API function.

* The (high-level) `readdir` handler now takes a *flags* argument.

* The (high-level) `filler` function passed to `readdir` now takes an
  additional *flags* argument.

* The (high-level) `getdir` handler has been dropped.

* The *flag_nullpath_ok* and *flag_utime_omit_ok* flags have been
  dropped.

* The (high-level) *utime* handler has been dropped.

* The `fuse_invalidate` function has been removed.

* The `fuse_is_lib_option` function has been removed.

* The *fh_old* member of `struct fuse_file_info` has been dropped.

* The type of the *writepage* member of `struct fuse_file_info` was
  changed from *int* to *unsigned int*.

* The `struct fuse_file_info` gained a new *poll_events* member.

* There is a new `fuse_pkgversion` function.

* The *fuse_off_t* and *fuse_ino_t* changed from *unsigned long* to
  *uint64_t*, i.e. they are now 64 bits also on 32-bit systems.

* The type of the *generation* member of `struct fuse_entry_param*
  changed from *unsigned* to *uint64_t*.

* The (low-level) `setattr` handler gained a *FUSE_SET_ATTR_CTIME* bit
  *for its *to_set* parameter.

* The `struct fuse_session_ops` data structure has been dropped.

* The documentation has been clarified and improved in many places.


FUSE 2.9.7 (2016-06-20)
=======================

* Added SELinux support.
* Fixed race-condition when session is terminated right after starting
  a FUSE file system.

FUSE 2.9.6 (2016-04-23)
=======================

* Tarball now includes documentation.
* Shared-object version has now been bumped correctly.

FUSE 2.9.5 (2016-01-14)
=======================

* New maintainer: Nikolaus Rath <Nikolaus@rath.org>. Many thanks to
  Miklos Szeredi <miklos@szeredi.hu> for bringing FUSE to where it is
  now!

* fix warning in mount.c:receive_fd().  Reported by Albert Berger

* fix possible memory leak.  Reported by Jose R. Guzman

FUSE 2.9.4 (2015-05-22)
=======================

* fix exec environment for mount and umount.  Found by Tavis Ormandy
  (CVE-2015-3202).

* fix fuse_remove_signal_handlers() to properly restore the default
  signal handler.  Reported by: Chris Johnson

* highlevel API: fix directory file handle passed to ioctl() method.
  Reported by Eric Biggers

* libfuse: document deadlock avoidance for fuse_notify_inval_entry()
  and fuse_notify_delete()

* fusermount, libfuse: send value as unsigned in "user_id=" and
  "group_id=" options.  Uids/gids larger than 2147483647 would result
  in EINVAL when mounting the filesystem.  This also needs a fix in
  the kernel.

* Initilaize stat buffer passed to ->getattr() and ->fgetattr() to
  zero in all cases.  Reported by Daniel Iwan

* libfuse: Add missing includes.  This allows compiling fuse with
  musl.  Patch by Daniel Thau


Older Versions (before 2013-01-01)
==================================

Please see Git history, e.g. at
https://github.com/libfuse/libfuse/blob/fuse_2_9_3/ChangeLog.
