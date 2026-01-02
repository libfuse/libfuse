==================================
libfuse API Changes (3.0 to 3.19)
==================================

This document describes API changes between FUSE_USE_VERSION values.
Set FUSE_USE_VERSION before including fuse.h or fuse_lowlevel.h.

Version 3.1 (FUSE_MAKE_VERSION(3, 1))
=====================================

New Functions
-------------
* ``fuse_lib_help()`` - Print help for generic high-level FUSE options
* ``fuse_invalidate_path()`` - Cache invalidation from high-level API

Changed Functions
-----------------
* ``fuse_new()`` signature changed; applications should call ``fuse_lib_help()``
  for --help instead of passing it to fuse_new()

Version 3.2 (FUSE_MAKE_VERSION(3, 2))
=====================================

Changed Functions
-----------------
* ``fuse_loop_mt()`` and ``fuse_session_loop_mt()`` now take a
  ``struct fuse_loop_config *`` parameter instead of a *clone_fd* boolean.
  The struct is public and can be directly initialized.

Note: This change was implemented in libfuse release 3.1.1, but the API version
that enables it is 32.

Version 3.3 (FUSE_MAKE_VERSION(3, 3))
=====================================

New Functions
-------------
* ``fuse_open_channel()`` - Open a FUSE file descriptor and set up mount
  (allows passing open /dev/fuse fd via ``/dev/fd/%u`` mountpoint format)

Version 3.4 (FUSE_MAKE_VERSION(3, 4))
=====================================

New Operations
--------------
* ``copy_file_range`` - Efficient server-side file copying

New Functions
-------------
* ``fuse_fs_copy_file_range()`` - High-level API wrapper

Version 3.5 (FUSE_MAKE_VERSION(3, 5))
=====================================

Changed Prototypes
------------------
* ``ioctl`` handler: cmd parameter changed from ``int`` to ``unsigned int``

  - Use FUSE_USE_VERSION < 35 for old ``int cmd`` prototype
  - Use FUSE_USE_VERSION >= 35 for new ``unsigned int cmd`` prototype

Version 3.7 (FUSE_MAKE_VERSION(3, 7))
=====================================

New Functions
-------------
* ``fuse_set_log_func()`` - Install custom log message handler
* ``fuse_log()`` - Emit log messages (replaces direct stderr writes)

Version 3.8 (FUSE_MAKE_VERSION(3, 8))
=====================================

New Operations
--------------
* ``lseek`` - Find next data or hole in sparse files (SEEK_DATA/SEEK_HOLE)

New Functions
-------------
* ``fuse_fs_lseek()`` - High-level API wrapper
* ``fuse_reply_lseek()`` - Low-level reply function

Version 3.12 (FUSE_MAKE_VERSION(3, 12))
=======================================

Major Changes
-------------
* ``struct fuse_loop_config`` is now **private** (opaque pointer)
* Loop configuration must use accessor functions instead of direct struct access
* The public struct from version 3.2-3.11 is renamed to ``struct fuse_loop_config_v1``

New Functions
-------------
* ``fuse_loop_cfg_create()`` - Create loop configuration
* ``fuse_loop_cfg_destroy()`` - Free loop configuration
* ``fuse_loop_cfg_set_idle_threads()`` - Set max idle threads
* ``fuse_loop_cfg_set_max_threads()`` - Set max total threads
* ``fuse_loop_cfg_set_clone_fd()`` - Enable/disable clone_fd
* ``fuse_loop_cfg_convert()`` - Convert old config (v1) to new format
* ``fuse_lowlevel_notify_expire_entry()`` - Expire dentry without full invalidation

Changed Functions
-----------------
* ``fuse_session_loop_mt()`` now accepts NULL config pointer
* ``fuse_parse_cmdline()`` now accepts ``max_threads`` option

Deprecated
----------
* ``max_idle_threads`` parameter (use ``max_threads`` instead)

Version 3.17 (FUSE_MAKE_VERSION(3, 17))
=======================================

New Functions
-------------
* ``fuse_set_fail_signal_handlers()`` - Handle fatal signals with backtrace
* ``fuse_log_enable_syslog()`` - Redirect fuse_log() to syslog
* ``fuse_log_close_syslog()`` - Close syslog connection
* ``fuse_passthrough_open()`` - Setup passthrough backing file
* ``fuse_passthrough_close()`` - Close passthrough connection
* ``fuse_session_custom_io()`` - Custom I/O for FUSE daemon (signature extended)

New Capabilities
----------------
* ``FUSE_CAP_PASSTHROUGH`` - Enable passthrough read/write to backing file
* ``FUSE_CAP_HANDLE_KILLPRIV_V2`` - Support for KILLPRIV_V2

New Mount Options
-----------------
* ``fmask`` - umask applied to non-directories (high-level API)
* ``dmask`` - umask applied to directories (high-level API)

Version 3.17.3
==============

New Functions
-------------
* ``fuse_set_feature_flag()`` - Set capability in want_ext field
* ``fuse_unset_feature_flag()`` - Unset capability in want_ext field
* ``fuse_get_feature_flag()`` - Query capability in want_ext field

Note: These replace direct manipulation of conn->want for 64-bit capability support.

Version 3.18 (FUSE_MAKE_VERSION(3, 18))
=======================================

New Operations
--------------
* ``statx`` - Extended file attributes (struct statx support)

New Functions
-------------
* ``fuse_fs_statx()`` - High-level API wrapper
* ``fuse_reply_statx()`` - Low-level reply function
* ``fuse_req_is_uring()`` - Check if request uses fuse-over-io-uring
* ``fuse_req_get_payload()`` - Get request payload buffer (io-uring only)
* ``fuse_lowlevel_notify_increment_epoch()`` - Increment epoch counter

New Features
------------
* fuse-over-io-uring communication support
* Request timeouts for hung operation prevention

Version 3.19 (FUSE_MAKE_VERSION(3, 19))
=======================================

(Reserved for future use)

Migration Notes
===============

When upgrading FUSE_USE_VERSION:

1. **3.0 → 3.1**: Handle --help in filesystem code, call fuse_lib_help()
2. **3.1 → 3.2**: Update fuse_loop_mt() calls to use struct fuse_loop_config
3. **< 3.5 → 3.5+**: Change ioctl cmd from int to unsigned int
4. **< 3.12 → 3.12+**: Use fuse_loop_cfg_*() functions instead of direct struct access
5. **< 3.17 → 3.17+**: Use fuse_set_feature_flag() instead of conn->want for new caps

