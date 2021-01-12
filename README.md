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


Development Status
------------------

libfuse is shipped by all major Linux distributions and has been in
production use across a wide range of systems for many years. However,
at present libfuse does not have any active, regular contributors. The
current maintainer continues to apply pull requests and makes regular
releases, but unfortunately has no capacity to do any development
beyond addressing high-impact issues. When reporting bugs, please
understand that unless you are including a pull request or are
reporting a critical issue, you will probably not get a response. If
you are using libfuse, please consider contributing to the project.


Supported Platforms
-------------------

* Linux (fully)
* BSD (mostly/best-effort)
* For OS-X, please use [OSXFUSE](https://osxfuse.github.io/)
  

Installation
------------

You can download libfuse from
https://github.com/libfuse/libfuse/releases. To build and install, you
must use [Meson](http://mesonbuild.com/) and
[Ninja](https://ninja-build.org).  After extracting the libfuse
tarball, create a (temporary) build directory and run Meson:

    $ mkdir build; cd build
    $ meson ..

Normally, the default build options will work fine. If you
nevertheless want to adjust them, you can do so with the
*meson configure* command:

    $ meson configure # list options
    $ meson configure -D disable-mtab=true # set an option

To build, test, and install libfuse, you then use Ninja:

    $ ninja
    $ sudo python3 -m pytest test/
    $ sudo ninja install

Running the tests requires the [py.test](http://www.pytest.org/)
Python module. Instead of running the tests as root, the majority of
tests can also be run as a regular user if *util/fusermount3* is made
setuid root first:

    $ sudo chown root:root util/fusermount3
    $ sudo chmod 4755 util/fusermount3
    $ python3 -m pytest test/

Security implications
---------------------

The *fusermount3* program is installed setuid root. This is done to
allow normal users to mount their own filesystem implementations.

To limit the harm that malicious users can do this way, *fusermount3*
enforces the following limitations:

  - The user can only mount on a mountpoint for which they have write
    permission

  - The mountpoint must not be a sticky directory which isn't owned by
    the user (like /tmp usually is)

  - No other user (including root) can access the contents of the
    mounted filesystem (though this can be relaxed by allowing the use
    of the *allow_other* and *allow_root* mount options in
    */etc/fuse.conf*)


If you intend to use the *allow_other* mount options, be aware that
FUSE has an unresolved [security
bug](https://github.com/libfuse/libfuse/issues/15): if the
*default_permissions* mount option is not used, the results of the
first permission check performed by the file system for a directory
entry will be re-used for subsequent accesses as long as the inode of
the accessed entry is present in the kernel cache - even if the
permissions have since changed, and even if the subsequent access is
made by a different user. This is of little concern if the filesystem
is accessible only to the mounting user (which has full access to the
filesystem anyway), but becomes a security issue when other users are
allowed to access the filesystem (since they can exploit this to
perform operations on the filesystem that they do not actually have
permissions for).

This bug needs to be fixed in the Linux kernel and has been known
since 2006 but unfortunately no fix has been applied yet. If you
depend on correct permission handling for FUSE file systems, the only
workaround is to use `default_permissions` (which does not currently
support ACLs), or to completely disable caching of directory entry
attributes.

Building your own filesystem
------------------------------

FUSE comes with several example file systems in the `example`
directory. For example, the *passthrough* examples mirror the contents
of the root directory under the mountpoint. Start from there and adapt
the code!

The documentation of the API functions and necessary callbacks is
mostly contained in the files `include/fuse.h` (for the high-level
API) and `include/fuse_lowlevel.h` (for the low-level API). An
autogenerated html version of the API is available in the `doc/html`
directory and at http://libfuse.github.io/doxygen.


Getting Help
------------

If you need help, please ask on the <fuse-devel@lists.sourceforge.net>
mailing list (subscribe at
https://lists.sourceforge.net/lists/listinfo/fuse-devel).

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/libfuse/issues.
