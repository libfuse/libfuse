libfuse
=======

About
-----

FUSE (Filesystem in Userspace) is an interface for userspace programs
to export a filesystem to the Linux kernel. The FUSE project consists
of two components: the *fuse* kernel module (maintained in the regular
kernel repositories) and the *libfuse* userspace library (maintained
in this repository). libfuse provides the reference implementation
for communicating with the FUSE kernel module.

A FUSE file system is typically implemented as a standalone
application that links with libfuse. libfuse provides functions to
mount the file system, unmount it, read requests from the kernel, and
send responses back. libfuse offers two APIs: a "high-level",
synchronous API, and a "low-level" asynchronous API. In both cases,
incoming requests from the kernel are passed to the main program using
callbacks. When using the high-level API, the callbacks may work with
file names and paths instead of inodes, and processing of a request
finishes when the callback function returns. When using the low-level
API, the callbacks must work with inodes and responses must be sent
explicitly using a separate set of API functions.


Installation
------------

    ./configure
    make -j8
    make install

You may also need to add `/usr/local/lib` to `/etc/ld.so.conf` and/or
run *ldconfig*. If you're building from the git repository (instead of
using a release tarball), you also need to run `./makeconf.sh` to
create the `configure` script.

You'll also need a fuse kernel module (Linux kernels 2.6.14 or later
contain FUSE support).

For more details see the file `INSTALL`

Security implications
---------------------

If you run `make install`, the *fusermount* program is installed
set-user-id to root.  This is done to allow normal users to mount
their own filesystem implementations.

There must however be some limitations, in order to prevent Bad User from
doing nasty things.  Currently those limitations are:

  - The user can only mount on a mountpoint, for which it has write
    permission

  - The mountpoint is not a sticky directory which isn't owned by the
    user (like /tmp usually is)

  - No other user (including root) can access the contents of the mounted
    filesystem (though this can be relaxed)


Building your own filesystem
------------------------------

FUSE comes with several example file systems in the `examples`
directory. For example, the *fusexmp* example mirrors the contents of
the root directory under the mountpoint. Start from there and adapt
the code!

The documentation of the API functions and necessary callbacks is
mostly contained in the files `include/fuse.h` (for the high-level
API) and `include/fuse_lowlevel.h` (for the low-level API).


Getting Help
------------

If you need help, please ask on the <fuse-devel@lists.sourceforge.net>
mailing list (subscribe at
https://lists.sourceforge.net/lists/listinfo/fuse-devel).

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/main/issues.


Credits
-------

libfuse is currently maintained by Nikolaus Rath.

The CUSE feature was added by Tejun Heo.

FUSE (both libfuse and the kernel module) was written by Miklos
Szeredi.


