libfuse 3.14.1 (2023-03-26)
===========================

* The extended attribute name passed to the setxattr() handler is no longer
  truncated at the beginning (bug introduced in 3.13.0).
  
* As a result of the above, the additional setattr() flags introduced in 3.14 are no
  longer available for now. They will hopefully be reintroduced in the next release.

* Further improvements of configuration header handling.


libfuse 3.14.0 (2023-02-17)
===========================

* Properly fix the header installation issue. The fix in 3.13.1 resulted
  in conflicts with other packages.

* Introduce additional setattr() flags (FORCE, KILL_SUID, KILL_SGID, FILE, KILL_PRIV,
  OPEN, TIMES_SET)


libfuse 3.13.1 (2023-02-03)
===========================

* Fixed an issue that resulted in errors when attempting to compile against
  installed libfuse headers (because libc symbol versioning support was not
  detected correctly in this case).

libfuse 3.13.0 (2023-01-13)
===========================

* There is a new low-level API function `fuse_session_custom_io` that allows to implement
  a daemon with a custom io. This can be used to create a daemon that can process incoming
  FUSE requests to other destinations than `/dev/fuse`.

* A segfault when loading custom FUSE modules has been fixed.

* There is a new `fuse_notify_expire_entry` function.

* A deadlock when resolving paths in the high-level API has been fixed.

* libfuse can now be build explicitly for C libraries without symbol versioning support.

libfuse 3.12.0 (2022-09-08)
===========================

* There is a new build parameter to specify where the SysV init script should be
  installed.
  
* The *max_idle_threads* parameter has been deprecated in favor of the new max_threads*
  parameter (which avoids the excessive overhead of creating and destructing threads).
  Using max_threads == 1 and calling fuse_session_loop_mt() will run single threaded
  similar to fuse_session_loop().

The following changes apply when using the most recent API (-DFUSE_USE_VERSION=312,
see `example/passthrough_hp.cc` for an example for how to usse the new API):

* `struct fuse_loop_config` is now private and has to be constructed using
  *fuse_loop_cfg_create()* and destroyed with *fuse_loop_cfg_destroy()*.  Parameters can be
  changed using `fuse_loop_cfg_set_*()` functions.

* *fuse_session_loop_mt()* now accepts `struct fuse_loop_config *` as NULL pointer.

* *fuse_parse_cmdline()* now accepts a *max_threads* option.


libfuse 3.11.0 (2022-05-02)
===========================

* Add support for flag FOPEN_NOFLUSH for avoiding flush on close.
* Fixed returning an error condition to ioctl(2)


libfuse 3.10.5 (2021-09-06)
===========================

* Various improvements to make unit tests more robust.


libfuse 3.10.4 (2021-06-09)
===========================

* Building of unit tests is now optional.
* Fixed a test failure when running tests under XFS.
* Fixed memory leaks in examples.
* Minor documentation fixes.  

libfuse 3.10.3 (2021-04-12)
===========================

* Fix returning d_ino and d_type from readdir(3) in non-plus mode
  
libfuse 3.10.2 (2021-02-05)
===========================

* Allow "nonempty" as a mount option, for backwards compatibility with fusermount 2. The
  option has no effect since mounting over non-empty directories is allowed by default.
* Fix returning inode numbers from readdir() in offset==0 mode.
* FUSE filesystems can now be mounted underneath EXFAT mountpoints.
* Various minor bugfixes.  

libfuse 3.10.1 (2020-12-07)
===========================

* Various minor bugfixes.

libfuse 3.10.0 (2020-10-09)
===========================

* Add FUSE_CAP_CACHE_SYMLINKS: allow caching symlinks in kernel page cache.
* Various minor bugfixes and improvements.  

libfuse 3.9.4 (2020-08-09)
==========================

This was an "accidental" release, it is equivalent to 3.9.3.

libfuse 3.9.3 (2020-08-09)
==========================

* Fixed compilation under OS X and µClibc.
* Minor bugfixes and doc updates.

libfuse 3.9.2 (2020-06-12)
==========================

* Remove obsolete workarounds in examples.
* Do not require C++ compiler for building.
* Minor bugfixes.

libfuse 3.9.1 (2020-03-19)
===========================

* Fixed memory leak in fuse_session_new().
* Fixed an issue with the linker version script.
* Make ioctl prototype conditional on FUSE_USE_VERSION.  Define FUSE_USE_VERSION < 35 to
  get old ioctl prototype with int commands; define FUSE_USE_VERSION >= 35 to get new
  ioctl prototype with unsigned int commands.
* Various small bugfixes.

libfuse 3.9.0 (2019-12-14)
==========================

* Added support for FUSE_EXPLICIT_INVAL_DATA to enable
  only invalidate cached pages on explicit request.

libfuse 3.8.0 (2019-11-03)
==========================

* Added support for FUSE_LSEEK operation which can be used to report holes
  in sparse files.

libfuse 3.7.0 (2019-09-27)
==========================

* Added UFSD to whitelist (so users can now mount FUSE filesystems
  on mountpoints within UFSD filesystems).
* Added custom log message handler function support so that libfuse
  applications can direct messages to syslog(3) or other logging systems.
  stderr remains the default.  See `fuse_log.h` for the new API.

libfuse 3.6.2 (2019-07-09)
==========================

* The init script is now installed to /etc/ rather than /usr/local/etc
  by default.

libfuse 3.6.1 (2019-06-13)
==========================

* Fixed version number (release 3.6.0 was shipped with a declared
  version of 3.0.0).

libfuse 3.6.0 (2019-06-13)
==========================

* Added a new example (passthrough_hp). The functionality is similar
  to passthrough_ll, but the implementation focuses on performance and
  correctness rather than simplicity.
* Added support for fuse kernel feature `max_pages` which allows to increase
  the maximum number of pages that can be used per request. This feature was
  introduced in kernel 4.20. `max_pages` is set based on the value in
  `max_write`. By default `max_write` will be 1MiB now for kernels that support
  `max_pages`. If you want smaller buffers or writes you have to set
  `max_write` manually.

libfuse 3.5.0 (2019-04-16)
==========================

* Changed ioctl commands to "unsigned int" in order to support commands
  which do not fit into a signed int. Commands issued by applications
  are still truncated to 32 bits.
* Added SMB2 to whitelist (so users can now mount FUSE filesystems
  on mountpoints within SMB 2.0 filesystems).
* Added a new `cache_readdir` flag to `fuse_file_info` to enable
  caching of readdir results. Supported by kernels 4.20 and newer.
* Add support and documentation for FUSE_CAP_NO_OPENDIR_SUPPORT.

libfuse 3.4.2 (2019-03-09)
==========================

* Fixed a memory leak in `examples/passthrough_ll.c`.
* Added OpenAFS to whitelist (so users can now mount FUSE filesystems
  on mountpoints within OpenAFS filesystems).
* Added HFS+ to whitelist (so users can now mount FUSE filesystems
  on mountpoints within HFS+ filesystems).
* Documentation improvements.

libfuse 3.4.1 (2018-12-22)
==========================

* The `examples/passthrough_ll.c` example filesystem has been
  significantly extended.
* Support for `copy_file_range` has been added.
* Build system updates for non-Linux systems.

libfuse 3.4.0
=============

* Add `copy_file_range()` to support efficient copying of data from one file to
  an other.

libfuse 3.3.0 (2018-11-06)
==========================

* The `auto_unmount` mode now works correctly in combination with
  autofs.

* The FUSE_CAP_READDIRPLUS_AUTO capability is no longer enabled by
  default unless the file system defines both a readdir() and a
  readdirplus() handler.

* The description of the FUSE_CAP_READDIRPLUS_AUTO flag has been
  improved.

* Allow open `/dev/fuse` file descriptors to be passed via mountpoints of the
  special format `/dev/fd/%u`. This allows mounting to be handled by the parent
  so the FUSE filesystem process can run fully unprivileged.

* Add a `drop_privileges` option to mount.fuse3 which causes it to open
  `/dev/fuse` and mount the file system itself, then run the FUSE file
  filesystem fully unprivileged and unable to re-acquire privilege via setuid,
  fscaps, etc.

* Documented under which conditions the `fuse_lowlevel_notify_*`
  functions may block.

libfuse 3.2.6 (2018-08-31)
==========================

* The fuse_main() function now returns more fine-grained error codes.
* FUSE filesystems may now be mounted on mountpoint within
  bcachefs, aufs and FAT filesystems.
* libfuse may now be used as a Meson subproject.
* Fix a few low-impact memory leaks.
* The `fuse.conf` file is no longer looked for in `/etc`, but in the
  *sysconfdir* directory (which can be set with `meson configure`). By
  default, the location is thus `/usr/local/etc/fuse.conf`.

libfuse 3.2.5 (2018-07-24)
==========================

* SECURITY UPDATE: In previous versions of libfuse it was possible to
  for unprivileged users to specify the `allow_other` option even when
  this was forbidden in `/etc/fuse.conf`.  The vulnerability is
  present only on systems where SELinux is active (including in
  permissive mode).
* The fusermount binary has been hardened in several ways to reduce
  potential attack surface. Most importantly, mountpoints and mount
  options must now match a hard-coded whitelist. It is expected that
  this whitelist covers all regular use-cases.
* Added a test of `seekdir` to test_syscalls.
* Fixed `readdir` bug when non-zero offsets are given to filler and the
  filesystem client, after reading a whole directory, re-reads it from a
  non-zero offset e. g. by calling `seekdir` followed by `readdir`.

libfuse 3.2.4 (2018-07-11)
==========================

* Fixed `rename` deadlock on FreeBSD.

libfuse 3.2.3 (2018-05-11)
==========================

* Fixed a number of compiler warnings.  

libfuse 3.2.2 (2018-03-31)
==========================

* Added example fuse.conf file.
* Added "support" for -o nofail mount option (the option is accepted
  and ignored).
* Various small bugfixes.  

libfuse 3.2.1 (2017-11-14)
==========================

* Various small bugfixes.

libfuse 3.2.0 (2017-09-12)
==========================

* Support for building with autotools has been dropped.

* Added new `fuse_invalidate_path()` routine for cache invalidation
  from the high-level FUSE API, along with an example and tests.

* There's a new `printcap` example that can be used to determine the
  capabilities of the running kernel.

* `fuse_loop_mt()` now returns the minus the actual errno if there was
  an error (instead of just -1).

* `fuse_loop()` no longer returns a positive value if the filesystem
  loop was terminated without errors or signals.

* Improved documentation of `fuse_lowlevel_notify_*` functions.

* `fuse_lowlevel_notify_inval_inode()` and
  `fuse_lowlevel_notify_inval_entry()` now return -ENOSYS instead of
  an undefined error if the function is not supported by the kernel.

* Documented the special meaning of the *zero* offset for the
  fuse_fill_dir_t function.

* The `passthrough_fh` example now works under FreeBSD.

* libfuse can now be build without libiconv.

* Fixed support for `FUSE_CAP_POSIX_ACL`: setting this capability
  flag had no effect in the previous versions of libfuse 3.x;
  now ACLs should actually work.

* Fixed a number of compilation problems under FreeBSD.

* Fixed installation directory for udev rules.

* Fixed compilation with LTO.

libfuse 3.1.1 (2017-08-06)
==========================

* Documentation: clarified how filesystems are supposed to process
  open() and create() flags (see include/fuse_lowlevel.h).

* Fixed a compilation problem of the passthrough_ll example on
  32 bit systems (wrong check and wrong error message).

* pkg-config is now used to determine the proper directory for
  udev rules.

* Fixed a symbol versioning problem that resulted in very strange
  failures (segfaults, unexpected behavior) in different situations.

* Fixed a test failure when /tmp is on btrfs.

* The maximum number of idle worker threads used by `fuse_loop_mt()`
  is now configurable.

* `fuse_loop_mt()` and `fuse_session_loop_mt()` now take a
  `struct fuse_loop_config` parameter that supersedes the *clone_fd*
  parameter.

* Incorporated several patches from the FreeBSD port. libfuse should
  now compile under FreeBSD without the need for patches.

* The passthrough_ll example now supports writeback caching.

libfuse 3.1.0 (2017-07-08)
==========================

* Added new `fuse_lib_help()` function. File-systems that previously
  passed a ``--help`` option to `fuse_new()` must now process the
  ``--help`` option internally and call `fuse_lib_help()` to print the
  help for generic FUSE options.
* Fixed description of the `fuse_conn_info->time_gran`. The default
  value of zero actually corresponds to full nanosecond resolution,
  not one second resolution.
* The init script is now installed into the right location
  (``$DESTDIR/etc/init.d`` rather than ``$prefix/$sysconfdir/init.d``)
* The `example/passthrough_ll` filesystem now supports creating
  and writing to files.
* `fuse_main()` / `fuse_remove_signal_handlers()`: do not reset
  `SIGPIPE` handler to `SIG_DFL` if it was not set by us.
* Documented the `RENAME_EXCHANGE` and `RENAME_NOREPLACE` flags that
  may be passed to the `rename` handler of both the high- and
  low-level API. Filesystem authors are strongly encouraged to check
  that these flags are handled correctly.

libfuse 3.0.2 (2017-05-24)
==========================

* Option parsing for the high-level API now works correctly
  (previously, default values would override specified values).
* Tests should now build (and run) under FreeBSD.
* Improved documentation of `struct fuse_context`
* Internal: calculate request buffer size from page size and kernel
  page limit instead of using hardcoded 128 kB limit.


libfuse 3.0.1 (2017-04-10)
==========================

* Re-introduced *examples/null.c*.
* Added experimental support for building with Meson.
* Document that `-o auto_unmount` implies `-o nodev,nosuid`.
* Document that the *use_ino* option of the high-level interface does
  not affect the inode that libfuse and the kernel use internally.
* Fixed test cases for passthrough* examples (they weren't actually
  testing the examples).
* Fixed several bugs in the passthrough* examples.

libfuse 3.0.0 (2016-12-08)
==========================

* NOTE TO PACKAGERS:

  libfuse 3 is designed to be co-installable with libfuse 2. However,
  some files will be installed by both libfuse 2 and libfuse 3
  (e.g. /etc/fuse.conf, the udev and init scripts, and the
  mount.fuse(8) manpage). These files should be taken from
  libfuse 3. The format/content is guaranteed to remain backwards
  compatible with libfuse 2.

  We recommend to ship libfuse2 and libfuse3 in three separate
  packages: a libfuse-common package that contains files shared by
  libfuse 2+3 (taken from the libfuse3 tarball), and libfuse2 and
  libfuse3 packages that contain the shared library and helper
  programs for the respective version.

* Fixed test errors when running tests as root.

* Made check for util-linux version more robust.

* Added documentation for all fuse capability flags (`FUSE_CAP_*`) and
  `struct fuse_conn_info` fields.

* fuse_loop(), fuse_loop_mt(), fuse_session_loop() and
  fuse_session_loop_mt() now return more detailed error codes instead
  of just -1. See the documentation of fuse_session_loop() for details.

* The FUSE main loop is now aborted if the file-system requests
  capabilities that are not supported by the kernel. In this case, the
  session loop is exited with a return code of ``-EPROTO``.

* Most file-system capabilities that were opt-in in libfuse2 are now
  enabled by default. Filesystem developers are encouraged to review
  the documentation of the FUSE_CAP_* features to ensure that their
  filesystem is compatible with the new semantics. As before, a
  particular capability can still be disabled by unsetting the
  corresponding bit of `fuse_conn_info.wants` in the init() handler.

* Added FUSE_CAP_PARALLEL_DIROPS and FUSE_CAP_POSIX_ACL,
  FUSE_HANDLE_KILLPRIV feature flags.

* FUSE filesystems are now responsible for unsetting the setuid/setgid
  flags when a file is written, truncated, or its owner
  changed. Previously, this was handled by the kernel but subject to
  race conditions.

* The fusermount and mount.fuse binaries have been renamed to
  fusermount3 and mount.fuse3 to allow co-installation of libfuse 2.x
  and 3.x

* Added a `max_read` field to `struct fuse_conn_info`. For the time
  being, the maximum size of read requests has to be specified both
  there *and* passed to fuse_session_new() using the ``-o
  max_read=<n>`` mount option. At some point in the future, specifying
  the mount option will no longer be necessary.

* Documentation: clarified that the fuse_argv structure that is passed
  to `fuse_new()` and `fuse_lowlevel_new()` must always contain at
  least one element.

* The high-level init() handler now receives an additional struct
  fuse_config pointer that can be used to adjust high-level API
  specific configuration options.

* The `nopath_flag` field of struct fuse_operations has been
  removed. Instead, a new `nullpath_ok` flag can now be set
  in struct fuse_config.

* File systems that use the low-level API and support lookup requests
  for '.' and '..' should continue make sure to set the
  FUSE_CAP_EXPORT_SUPPORT bit in fuse_conn_info->want.

  (This has actually always been the case, but was not very obvious
  from the documentation).

* The help text generated by fuse_lowlevel_help(), fuse_new() (and
  indirectly fuse_main()) no longer includes options that are unlikely
  to be of interest to end-users. The full list of accepted options is
  now included in the respective function's documentation (located in
  the fuse.h/fuse_lowlevel.h and doc/html).

* The ``-o nopath`` option has been dropped - it never actually did
  anything (since it is unconditionally overwritten with the value of
  the `nopath` flag in `struct fuse_operations`).

* The ``-o large_read`` mount option has been dropped. Hopefully no
  one uses a Linux 2.4 kernel anymore.

* The `-o nonempty` mount point has been removed, mounting over
  non-empty directories is now always allowed. This brings the
  behavior of FUSE file systems in-line with the behavior of the
  regular `mount` command.

  File systems that do not want to allow mounting to non-empty
  directories should perform this check themselves before handing
  control to libfuse.

* The chmod, chown, truncate, utimens and getattr handlers of the
  high-level API now all receive an additional struct fuse_file_info
  pointer (which, however, may be NULL even if the file is currently
  open).

  The fgetattr and ftruncate handlers have become obsolete and have
  been removed.

* The `fuse_session_new` function no longer accepts the ``-o
  clone_fd`` option. Instead, this has become a parameter of the
  `fuse_session_loop_mt` and `fuse_loop_mt` functions.

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
  `fuse_lowlevel_help()` functions).

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

* The `fuse_lowlevel_new` function has been renamed to
  `fuse_session_new` and no longer interprets the --version or --help
  options. To print help or version information, use the new
  `fuse_lowlevel_help` and `fuse_lowlevel_version` functions.

* The ``allow_other`` and ``allow_root`` mount options (accepted by
  `fuse_session_new()`) may now be specified together. In this case,
  ``allow_root`` takes precedence.

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
        fuse_mount(fuse, mountpoint);
        fuse_daemonize(fg);
         if (mt)
            fuse_loop_mt(fuse);
        else
            fuse_loop(fuse);
        fuse_remove_signal_handlers(se);
        fuse_unmount(fuse);
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

* The type of the *generation* member of `struct fuse_entry_param*`
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

* Initialize stat buffer passed to ->getattr() and ->fgetattr() to
  zero in all cases.  Reported by Daniel Iwan

* libfuse: Add missing includes.  This allows compiling fuse with
  musl.  Patch by Daniel Thau


Older Versions (before 2013-01-01)
==================================

Please see Git history, e.g. at
https://github.com/libfuse/libfuse/blob/fuse_2_9_3/ChangeLog.
