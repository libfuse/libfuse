#!/usr/bin/env python3
"""Everything the shell tests check that shell cannot express exactly.

Shell is the dispatch unit, not the implementation language: a test calls this
module like any other command and it exits 0 on success, non-zero with a
diagnostic on stderr on failure. One subcommand per check, each named
fuse_test_* so a test script cannot mistake it for a system command.

Re-expressing these in coreutils would silently weaken them -- an errno becomes
a strerror string match, an ftruncate on a held fd has no shell equivalent, a
nanosecond utimensat becomes whatever `touch -d` rounds to, and a
/proc/self/mountinfo parser becomes an awk script that gets the separator field
or the \\040 escapes subtly wrong.
"""

import argparse
import errno
import filecmp
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
from enum import Enum
from os.path import join as pjoin
from tempfile import NamedTemporaryFile


class CheckFailed(Exception):
    """An assertion inside a subcommand did not hold; message goes to stderr."""


class InodeCheck(Enum):
    EXACT = 1
    NONZERO = 2


TEST_FILE = os.path.abspath(__file__)

with open(TEST_FILE, 'rb') as _fh:
    TEST_DATA = _fh.read()


def name_generator():
    """A file name no other invocation in this test will produce.

    Each check is its own process, so the pid goes into the name -- a plain
    counter would make the second subcommand collide with the files the first
    one left behind.
    """
    name_generator.counter += 1
    return 'testfile_%d_%d' % (os.getpid(), name_generator.counter)


name_generator.counter = 0


def _require(condition, message):
    if not condition:
        raise CheckFailed(message)


def readdir_inode(path):
    """Sorted "<inode> <name>" lines, from the test/readdir_inode helper."""
    binary = pjoin(os.environ['FUSE_TEST_BIN_DIR'], 'readdir_inode')
    with subprocess.Popen([binary, path], stdout=subprocess.PIPE,
                          universal_newlines=True) as proc:
        lines = proc.communicate()[0].splitlines()
    lines.sort()
    return lines


def check_inode(inode_check, actual, expected):
    if inode_check == InodeCheck.EXACT:
        _require(expected == actual,
                 'inode mismatch: got %d, want %d' % (actual, expected))
    elif inode_check == InodeCheck.NONZERO:
        _require(actual != 0, 'inode is zero')


def _inode_check(name):
    return InodeCheck.EXACT if name == 'exact' else InodeCheck.NONZERO


class _open_fd:
    """os.open() as a context manager."""

    def __init__(self, name, flags):
        self.fd = os.open(name, flags)

    def __enter__(self):
        return self.fd

    def __exit__(self, *_exc):
        os.close(self.fd)


def os_create(name):
    os.close(os.open(name, os.O_CREAT | os.O_RDWR))


def expect_enoent(path):
    """Require that stat(path) fails with ENOENT."""
    try:
        os.stat(path)
    except OSError as exc:
        _require(exc.errno == errno.ENOENT,
                 '%s: expected ENOENT, got %s' % (path, exc.strerror))
        return
    raise CheckFailed('%s: expected ENOENT, but it exists' % path)


# ----------------------------------------------------------- POSIX operations

def cmd_unlink(mnt_dir, src_dir=None):
    name = name_generator()
    fullname = mnt_dir + "/" + name
    srcname = fullname
    if src_dir is not None:
        srcname = pjoin(src_dir, name)
    with open(srcname, 'wb') as fh:
        fh.write(b'hello')
    _require(name in os.listdir(mnt_dir), '%s did not appear' % name)
    os.unlink(fullname)
    expect_enoent(fullname)
    _require(name not in os.listdir(mnt_dir), '%s still listed' % name)


def cmd_mkdir(mnt_dir):
    dirname = name_generator()
    fullname = mnt_dir + "/" + dirname
    os.mkdir(fullname)
    fstat = os.stat(fullname)
    _require(stat.S_ISDIR(fstat.st_mode), '%s is not a directory' % fullname)
    _require(os.listdir(fullname) == [], '%s is not empty' % fullname)
    # Some filesystems (e.g. BTRFS) don't track st_nlink for directories
    _require(fstat.st_nlink in (1, 2), 'st_nlink is %d' % fstat.st_nlink)
    _require(dirname in os.listdir(mnt_dir), '%s did not appear' % dirname)


def cmd_rmdir(mnt_dir, src_dir=None):
    name = name_generator()
    fullname = mnt_dir + "/" + name
    srcname = fullname
    if src_dir is not None:
        srcname = pjoin(src_dir, name)
    os.mkdir(srcname)
    _require(name in os.listdir(mnt_dir), '%s did not appear' % name)
    os.rmdir(fullname)
    expect_enoent(fullname)
    _require(name not in os.listdir(mnt_dir), '%s still listed' % name)


def cmd_symlink(mnt_dir):
    linkname = name_generator()
    fullname = mnt_dir + "/" + linkname
    os.symlink("/imaginary/dest", fullname)
    fstat = os.lstat(fullname)
    _require(stat.S_ISLNK(fstat.st_mode), '%s is not a symlink' % fullname)
    _require(os.readlink(fullname) == "/imaginary/dest",
             'wrong link target: %s' % os.readlink(fullname))
    _require(fstat.st_nlink == 1, 'st_nlink is %d' % fstat.st_nlink)
    _require(linkname in os.listdir(mnt_dir), '%s did not appear' % linkname)


def cmd_create(mnt_dir):
    name = name_generator()
    fullname = pjoin(mnt_dir, name)
    expect_enoent(fullname)
    _require(name not in os.listdir(mnt_dir), '%s already listed' % name)

    os.close(os.open(fullname, os.O_CREAT | os.O_RDWR))

    _require(name in os.listdir(mnt_dir), '%s did not appear' % name)
    fstat = os.lstat(fullname)
    _require(stat.S_ISREG(fstat.st_mode), '%s is not a regular file' % fullname)
    _require(fstat.st_nlink == 1, 'st_nlink is %d' % fstat.st_nlink)
    _require(fstat.st_size == 0, 'st_size is %d' % fstat.st_size)


def cmd_chown(mnt_dir):
    filename = pjoin(mnt_dir, name_generator())
    os.mkdir(filename)
    fstat = os.lstat(filename)
    uid = fstat.st_uid
    gid = fstat.st_gid

    uid_new = uid + 1
    os.chown(filename, uid_new, -1)
    fstat = os.lstat(filename)
    _require(fstat.st_uid == uid_new, 'uid is %d' % fstat.st_uid)
    _require(fstat.st_gid == gid, 'gid changed to %d' % fstat.st_gid)

    gid_new = gid + 1
    os.chown(filename, -1, gid_new)
    fstat = os.lstat(filename)
    _require(fstat.st_uid == uid_new, 'uid changed to %d' % fstat.st_uid)
    _require(fstat.st_gid == gid_new, 'gid is %d' % fstat.st_gid)


def cmd_open_read(src_dir, mnt_dir):
    name = name_generator()
    with open(pjoin(src_dir, name), 'wb') as fh_out, \
         open(TEST_FILE, 'rb') as fh_in:
        shutil.copyfileobj(fh_in, fh_out)

    _require(filecmp.cmp(pjoin(mnt_dir, name), TEST_FILE, False),
             '%s differs from %s' % (pjoin(mnt_dir, name), TEST_FILE))


def cmd_open_write(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with open(fullname, 'wb') as fh_out, \
         open(TEST_FILE, 'rb') as fh_in:
        shutil.copyfileobj(fh_in, fh_out)

    _require(filecmp.cmp(fullname, TEST_FILE, False),
             '%s differs from %s' % (fullname, TEST_FILE))


def cmd_append(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with _open_fd(fullname, os.O_WRONLY) as fd:
        os.write(fd, b'foo\n')
    with _open_fd(fullname, os.O_WRONLY | os.O_APPEND) as fd:
        os.write(fd, b'bar\n')

    with open(fullname, 'rb') as fh:
        got = fh.read()
    _require(got == b'foo\nbar\n', 'appended file holds %r' % got)


def cmd_seek(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with _open_fd(fullname, os.O_WRONLY) as fd:
        os.lseek(fd, 1, os.SEEK_SET)
        os.write(fd, b'foobar\n')
    with _open_fd(fullname, os.O_WRONLY) as fd:
        os.lseek(fd, 4, os.SEEK_SET)
        os.write(fd, b'com')

    with open(fullname, 'rb') as fh:
        got = fh.read()
    _require(got == b'\0foocom\n', 'file holds %r' % got)


def cmd_open_unlink(mnt_dir):
    name = name_generator()
    data1 = b'foo'
    data2 = b'bar'
    fullname = pjoin(mnt_dir, name)
    with open(fullname, 'wb+', buffering=0) as fh:
        fh.write(data1)
        os.unlink(fullname)
        expect_enoent(fullname)
        _require(name not in os.listdir(mnt_dir), '%s still listed' % name)
        fh.write(data2)
        fh.seek(0)
        got = fh.read()
    _require(got == data1 + data2, 'unlinked file holds %r' % got)


def cmd_statvfs(mnt_dir):
    os.statvfs(mnt_dir)


def cmd_link(mnt_dir):
    name1 = pjoin(mnt_dir, name_generator())
    name2 = pjoin(mnt_dir, name_generator())
    shutil.copyfile(TEST_FILE, name1)
    _require(filecmp.cmp(name1, TEST_FILE, False),
             '%s differs from %s' % (name1, TEST_FILE))

    fstat1 = os.lstat(name1)
    _require(fstat1.st_nlink == 1, 'st_nlink is %d' % fstat1.st_nlink)

    os.link(name1, name2)

    fstat1 = os.lstat(name1)
    fstat2 = os.lstat(name2)
    _require(fstat1 == fstat2, 'stat of the two links differs')
    _require(fstat1.st_nlink == 2, 'st_nlink is %d' % fstat1.st_nlink)
    _require(os.path.basename(name2) in os.listdir(mnt_dir),
             '%s did not appear' % name2)
    _require(filecmp.cmp(name1, name2, False), '%s and %s differ'
             % (name1, name2))

    # Since RELEASE requests are asynchronous, it is possible that libfuse
    # still considers the file to be open at this point and (since
    # -o hard_remove is not used) renames it instead of deleting it.
    os.unlink(name2)

    _require(os.path.basename(name2) not in os.listdir(mnt_dir),
             '%s still listed' % name2)
    expect_enoent(name2)

    # See above, we may have to wait until RELEASE has been received before
    # the st_nlink value is correct.
    maxwait = time.time() + 2
    fstat1 = os.lstat(name1)
    while fstat1.st_nlink == 2 and time.time() < maxwait:
        fstat1 = os.lstat(name1)
        time.sleep(0.1)
    _require(fstat1.st_nlink == 1, 'st_nlink is %d' % fstat1.st_nlink)

    os.unlink(name1)


def cmd_readdir(src_dir, mnt_dir, inode_check='exact'):
    inode_check = _inode_check(inode_check)
    newdir = name_generator()

    src_newdir = pjoin(src_dir, newdir)
    mnt_newdir = pjoin(mnt_dir, newdir)
    file_ = src_newdir + "/" + name_generator()
    subdir = src_newdir + "/" + name_generator()
    subfile = subdir + "/" + name_generator()

    os.mkdir(src_newdir)
    shutil.copyfile(TEST_FILE, file_)
    os.mkdir(subdir)
    shutil.copyfile(TEST_FILE, subfile)

    listdir_is = sorted(os.listdir(mnt_newdir))
    listdir_should = sorted([os.path.basename(file_),
                             os.path.basename(subdir)])
    _require(listdir_is == listdir_should,
             'readdir returned %r, want %r' % (listdir_is, listdir_should))

    inodes_is = readdir_inode(mnt_newdir)
    if inode_check == InodeCheck.EXACT:
        inodes_should = readdir_inode(src_newdir)
        _require(inodes_is == inodes_should,
                 'inodes %r, want %r' % (inodes_is, inodes_should))
    else:
        _require(all(int(line.split()[0]) != 0 for line in inodes_is),
                 'a readdir inode is zero: %r' % inodes_is)

    os.unlink(file_)
    os.unlink(subfile)
    os.rmdir(subdir)
    os.rmdir(src_newdir)


def cmd_readdir_big(src_dir, mnt_dir, inode_check='exact'):
    inode_check = _inode_check(inode_check)
    # Add enough entries so that readdir needs to be called multiple times.
    fnames = []
    for i in range(500):
        fname = ('A rather long filename to make sure that we '
                 'fill up the buffer - ' * 3) + str(i)
        with open(pjoin(src_dir, fname), 'w') as fh:
            fh.write('File %d' % i)
        fnames.append(fname)

    listdir_is = sorted(os.listdir(mnt_dir))
    listdir_should = sorted(os.listdir(src_dir))
    _require(listdir_is == listdir_should,
             'mount lists %d entries, source lists %d'
             % (len(listdir_is), len(listdir_should)))

    inodes_is = readdir_inode(mnt_dir)
    if inode_check == InodeCheck.EXACT:
        inodes_should = readdir_inode(src_dir)
        _require(inodes_is == inodes_should, 'readdir inodes differ')
    else:
        _require(all(int(line.split()[0]) != 0 for line in inodes_is),
                 'a readdir inode is zero')

    for fname in fnames:
        stat_src = os.stat(pjoin(src_dir, fname))
        stat_mnt = os.stat(pjoin(mnt_dir, fname))
        check_inode(inode_check, stat_mnt.st_ino, stat_src.st_ino)
        _require(stat_src.st_mtime == stat_mnt.st_mtime, 'st_mtime differs')
        _require(stat_src.st_ctime == stat_mnt.st_ctime, 'st_ctime differs')
        _require(stat_src.st_size == stat_mnt.st_size, 'st_size differs')
        os.unlink(pjoin(src_dir, fname))


def cmd_truncate_path(mnt_dir):
    _require(len(TEST_DATA) > 1024, 'test data is too short')

    filename = pjoin(mnt_dir, name_generator())
    with open(filename, 'wb') as fh:
        fh.write(TEST_DATA)

    size = os.stat(filename).st_size
    _require(size == len(TEST_DATA), 'st_size is %d' % size)

    # Add zeros at the end
    os.truncate(filename, size + 1024)
    _require(os.stat(filename).st_size == size + 1024, 'grow failed')
    with open(filename, 'rb') as fh:
        _require(fh.read(size) == TEST_DATA, 'data changed on grow')
        _require(fh.read(1025) == b'\0' * 1024, 'grow did not zero-fill')

    # Truncate data
    os.truncate(filename, size - 1024)
    _require(os.stat(filename).st_size == size - 1024, 'shrink failed')
    with open(filename, 'rb') as fh:
        _require(fh.read(size) == TEST_DATA[:size - 1024],
                 'data changed on shrink')

    os.unlink(filename)


def cmd_truncate_fd(mnt_dir):
    _require(len(TEST_DATA) > 1024, 'test data is too short')
    with NamedTemporaryFile('w+b', 0, dir=mnt_dir) as fh:
        fd = fh.fileno()
        fh.write(TEST_DATA)
        size = os.fstat(fd).st_size
        _require(size == len(TEST_DATA), 'st_size is %d' % size)

        # Add zeros at the end
        os.ftruncate(fd, size + 1024)
        _require(os.fstat(fd).st_size == size + 1024, 'grow failed')
        fh.seek(0)
        _require(fh.read(size) == TEST_DATA, 'data changed on grow')
        _require(fh.read(1025) == b'\0' * 1024, 'grow did not zero-fill')

        # Truncate data
        os.ftruncate(fd, size - 1024)
        _require(os.fstat(fd).st_size == size - 1024, 'shrink failed')
        fh.seek(0)
        _require(fh.read(size) == TEST_DATA[:size - 1024],
                 'data changed on shrink')


def cmd_utimens(mnt_dir, ns_tol=0):
    ns_tol = int(ns_tol)
    filename = pjoin(mnt_dir, name_generator())
    os.mkdir(filename)
    fstat = os.lstat(filename)

    atime = fstat.st_atime + 42.28
    mtime = fstat.st_mtime - 42.23
    atime_ns = fstat.st_atime_ns + int(42.28 * 1e9)
    mtime_ns = fstat.st_mtime_ns - int(42.23 * 1e9)
    os.utime(filename, None, ns=(atime_ns, mtime_ns))

    fstat = os.lstat(filename)

    _require(abs(fstat.st_atime - atime) < 1, 'st_atime off by too much')
    _require(abs(fstat.st_mtime - mtime) < 1, 'st_mtime off by too much')
    _require(abs(fstat.st_atime_ns - atime_ns) <= ns_tol,
             'st_atime_ns off by %d' % abs(fstat.st_atime_ns - atime_ns))
    _require(abs(fstat.st_mtime_ns - mtime_ns) <= ns_tol,
             'st_mtime_ns off by %d' % abs(fstat.st_mtime_ns - mtime_ns))


def cmd_passthrough(src_dir, mnt_dir, inode_check='exact'):
    inode_check = _inode_check(inode_check)
    name = name_generator()
    src_name = pjoin(src_dir, name)
    mnt_name = pjoin(mnt_dir, name)

    # First: write to the source directory
    _require(name not in os.listdir(src_dir), '%s already in source' % name)
    _require(name not in os.listdir(mnt_dir), '%s already in mount' % name)
    with open(src_name, 'w') as fh:
        fh.write('Hello, world')

    start_time = time.time()
    while time.time() - start_time < 10:
        if name in os.listdir(mnt_dir):
            break
        time.sleep(0.1)
    else:
        raise CheckFailed('%s did not appear in the mount within 10s' % name)

    _require(name in os.listdir(src_dir), '%s vanished from source' % name)

    src_stat = os.stat(src_name)
    mnt_stat = os.stat(mnt_name)
    _require(src_stat.st_mode == mnt_stat.st_mode, 'st_mode differs')
    check_inode(inode_check, mnt_stat.st_ino, src_stat.st_ino)
    _require(src_stat.st_size == mnt_stat.st_size, 'st_size differs')
    _require(src_stat.st_mtime == mnt_stat.st_mtime, 'st_mtime differs')

    # Second: write to the mount directory
    name = name_generator()
    src_name = pjoin(src_dir, name)
    mnt_name = pjoin(mnt_dir, name)
    _require(name not in os.listdir(src_dir), '%s already in source' % name)
    _require(name not in os.listdir(mnt_dir), '%s already in mount' % name)
    with open(mnt_name, 'w') as fh:
        fh.write('Hello, world')
    _require(name in os.listdir(src_dir), '%s did not reach the source' % name)
    _require(name in os.listdir(mnt_dir), '%s not in the mount' % name)

    src_stat = os.stat(src_name)
    mnt_stat = os.stat(mnt_name)
    _require(src_stat.st_mode == mnt_stat.st_mode, 'st_mode differs')
    check_inode(inode_check, mnt_stat.st_ino, src_stat.st_ino)
    _require(src_stat.st_size == mnt_stat.st_size, 'st_size differs')
    _require(abs(src_stat.st_mtime - mnt_stat.st_mtime) < 0.01,
             'st_mtime differs')


def cmd_xattr(path):
    os.setxattr(path, b'hello_ll_setxattr_name', b'hello_ll_setxattr_value')
    got = os.getxattr(path, b'hello_ll_getxattr_name')
    _require(got == b'hello_ll_getxattr_value', 'getxattr returned %r' % got)
    os.removexattr(path, b'hello_ll_removexattr_name')


# ------------------------------------------------------- generic assertions

# Operations expect-errno can run. One line each; add one rather than
# approximating the check in shell.
OPS = {
    'fuse_test_open_rw': lambda path: os.close(os.open(path, os.O_RDWR)),
    'fuse_test_open_ro': lambda path: os.close(os.open(path, os.O_RDONLY)),
    'fuse_test_stat': os.stat,
}


def cmd_expect_errno(want, op, args):
    """Run one filesystem operation and require it to fail with *want*.

    Comparing OSError.errno keeps the check exact -- matching strerror text
    would be locale-dependent and would conflate distinct errnos.
    """
    code = getattr(errno, want, None)
    if code is None:
        raise CheckFailed('unknown errno name %s' % want)
    handler = OPS.get(op)
    if handler is None:
        raise CheckFailed('unknown operation %s (have: %s)'
                          % (op, ' '.join(sorted(OPS))))
    try:
        handler(*args)
    except OSError as exc:
        if exc.errno != code:
            raise CheckFailed('%s %s: expected %s, got %s'
                              % (op, ' '.join(args), want,
                                 errno.errorcode.get(exc.errno, exc.errno)))
        return
    raise CheckFailed('%s %s: expected %s, but it succeeded'
                      % (op, ' '.join(args), want))


def cmd_assert_listdir(directory, names):
    got = sorted(os.listdir(directory))
    want = sorted(names)
    _require(got == want, '%s lists %r, want %r' % (directory, got, want))


def cmd_listdir(directory):
    for name in sorted(os.listdir(directory)):
        print(name)


def cmd_listdir_first(directory):
    """Print the first entry of *directory*.

    A subcommand rather than `listdir | head -1` because pipefail is off, so a
    failing listdir in a pipeline would hand the caller an empty name instead
    of an error.
    """
    names = sorted(os.listdir(directory))
    _require(names, '%s is empty' % directory)
    print(names[0])


def cmd_size(path):
    print(os.path.getsize(path))


def cmd_ismount(path):
    """Exit 0 when *path* is a mountpoint.

    os.path.ismount() is portable; mountpoint(1) is util-linux only.
    """
    _require(os.path.ismount(path), '%s is not a mountpoint' % path)


def cmd_isbigger(path, size):
    """Exit 0 when *path* is larger than *size* bytes.

    The mount predicate for a filesystem with no mountpoint of its own: the
    null filesystem is mounted over a regular file.
    """
    _require(os.stat(path).st_size > int(size),
             '%s is not larger than %s bytes' % (path, size))


# --------------------------------------------------------------- mount state

def parse_mountinfo(mnt_dir):
    """Return the /proc/self/mountinfo entry for *mnt_dir*, or None.

    Parses the line for the mountpoint and returns a dict with keys:
      'mountpoint'    - the mount point path (str)
      'fstype'        - filesystem type as the kernel sees it,
                        e.g. 'fuse' or 'fuse.<subtype>' (str)
      'source'        - mount source field, e.g. 'hello' or
                        '<subtype>#<fsname>' fallback form (str)
      'mount_options' - per-mount options/attrs (set of str)
      'super_options' - superblock options from the filesystem (set of str)

    These fields are exactly what /proc/self/mountinfo exposes; they capture
    the post-mount state that differs between the legacy mount(2) path and the
    new fsopen/fsconfig/fsmount path.
    """
    target = os.path.realpath(mnt_dir)
    with open('/proc/self/mountinfo') as fh:
        for line in fh:
            parts = line.rstrip('\n').split(' ')
            try:
                sep = parts.index('-')
            except ValueError:
                continue
            if len(parts) < sep + 4 or sep < 6:
                continue
            mountpoint = parts[4].replace('\\040', ' ')
            if mountpoint != target:
                continue
            return {
                'mountpoint':    mountpoint,
                'fstype':        parts[sep + 1],
                'source':        parts[sep + 2].replace('\\040', ' '),
                'mount_options': set(parts[5].split(',')),
                'super_options': set(parts[sep + 3].split(',')),
            }
    return None


def _mountinfo(mnt_dir):
    info = parse_mountinfo(mnt_dir)
    if info is None:
        raise CheckFailed('%s not found in /proc/self/mountinfo' % mnt_dir)
    return info


def cmd_mountinfo(mnt_dir, field):
    """Echo one field of the mountinfo line. Empty output means not mounted."""
    info = parse_mountinfo(mnt_dir)
    if info is None:
        return
    _require(field in info,
             'no such mountinfo field: %s (have %s)'
             % (field, ' '.join(sorted(info))))
    value = info[field]
    print(','.join(sorted(value)) if isinstance(value, set) else value)


def cmd_assert_mount_opt(mnt_dir, opts):
    info = _mountinfo(mnt_dir)
    for opt in opts:
        _require(opt in info['mount_options'],
                 '%r missing from mount_options=%r'
                 % (opt, sorted(info['mount_options'])))


def cmd_refute_mount_opt(mnt_dir, opts):
    info = _mountinfo(mnt_dir)
    for opt in opts:
        _require(opt not in info['mount_options'],
                 'unexpected %r in mount_options=%r'
                 % (opt, sorted(info['mount_options'])))


def cmd_assert_super_opt(mnt_dir, opts):
    info = _mountinfo(mnt_dir)
    for opt in opts:
        _require(opt in info['super_options'],
                 '%r missing from super_options=%r'
                 % (opt, sorted(info['super_options'])))


def cmd_assert_super_opt_prefix(mnt_dir, prefixes):
    info = _mountinfo(mnt_dir)
    for prefix in prefixes:
        _require(any(o.startswith(prefix) for o in info['super_options']),
                 'no super option starts with %r: %r'
                 % (prefix, sorted(info['super_options'])))


def cmd_assert_fstype(mnt_dir, expected):
    """The fstype must be one of *expected*; several are legitimate."""
    info = _mountinfo(mnt_dir)
    _require(info['fstype'] in expected,
             'unexpected fstype %r (expected one of %r)'
             % (info['fstype'], expected))


def cmd_assert_source(mnt_dir, expected):
    """The source must be one of *expected*.

    Several are accepted because the ENODEV fallback legitimately produces
    either 'myfsname' or 'mysub#myfsname'.
    """
    info = _mountinfo(mnt_dir)
    _require(info['source'] in expected,
             'unexpected source %r (expected one of %r)'
             % (info['source'], expected))


# ------------------------------------------------------------- odds and ends

def cmd_printcap_caps(src_root):
    """Verify that the FUSE_CAP_* name table printcap uses includes every
    flag from fuse_common.h."""
    header_path = pjoin(src_root, 'include', 'fuse_common.h')
    printcap_path = pjoin(src_root, 'lib', 'fuse_cap_names_i.h')
    if not os.path.exists(header_path):
        raise CheckFailed('%s not found' % header_path)

    header_caps = set()
    with open(header_path) as fh:
        for line in fh:
            match = re.match(r'#define\s+(FUSE_CAP_\w+)\s+', line)
            if match:
                header_caps.add(match.group(1))

    printcap_caps = set()
    with open(printcap_path) as fh:
        for line in fh:
            if re.match(r'^\s*//', line):        # commented out
                continue
            match = re.search(r'\{\s*(FUSE_CAP_\w+),\s*"', line)
            if match:
                printcap_caps.add(match.group(1))

    missing = header_caps - printcap_caps
    extra = printcap_caps - header_caps
    if missing or extra:
        msg = ['%d caps in %s, %d in %s'
               % (len(header_caps), header_path,
                  len(printcap_caps), printcap_path)]
        if missing:
            msg.append('missing in %s: %s' % (printcap_path, sorted(missing)))
        if extra:
            msg.append('extra in %s: %s' % (printcap_path, sorted(extra)))
        raise CheckFailed('\n'.join(msg))


def cmd_reachable_without_caps(path):
    """Exit 0 when *path* is reachable by a process without CAP_DAC_OVERRIDE.

    mount.fuse3 execs the fs binary only after dropping all capabilities; the
    process keeps uid/gid 0 but loses CAP_DAC_OVERRIDE, so the binary and every
    directory on the way to it must be executable for it by plain permission
    bits (a user-owned mode-0700 home directory is not).
    """
    def executable_without_caps(st):
        if st.st_uid == 0:
            return st.st_mode & stat.S_IXUSR
        if st.st_gid == 0:
            return st.st_mode & stat.S_IXGRP
        return st.st_mode & stat.S_IXOTH

    path = os.path.realpath(path)
    while True:
        if not executable_without_caps(os.stat(path)):
            raise CheckFailed('%s is not reachable by the capability-less '
                              'file system process' % path)
        if path == '/':
            return
        path = os.path.dirname(path)


def cmd_elf_class(path):
    """Print the ELF class of *path*, 32 or 64.

    Reads e_ident[EI_CLASS] directly rather than grepping file(1) output for
    the string 'ELF 32-bit'.
    """
    with open(path, 'rb') as fh:
        ident = fh.read(5)
    if ident[:4] != b'\x7fELF':
        raise CheckFailed('%s is not an ELF binary' % path)
    print({1: 32, 2: 64}.get(ident[4], 0))


def cmd_cuse_roundtrip(devpath, client):
    """The binary read/write/offset exchange test_cuse performed."""
    output = subprocess.check_output([client, devpath, 's'])
    _require(output == b'0\n', 'initial size is %r' % output)

    data = b'some test data'
    off = 5
    proc = subprocess.Popen([client, devpath, 'w', str(len(data)), str(off)],
                            stdin=subprocess.PIPE)
    proc.stdin.write(data)
    proc.stdin.close()
    ret = proc.wait(timeout=10)
    _require(ret == 0, 'write client exited with %d' % ret)

    want = str(off + len(data)).encode() + b'\n'
    output = subprocess.check_output([client, devpath, 's'])
    _require(output == want, 'size is %r, want %r' % (output, want))

    out = subprocess.check_output(
        [client, devpath, 'r', str(off + len(data) + 2), '0'])
    _require(out == (b'\0' * off) + data, 'read back %r' % out)


# ------------------------------------------------------ FUSE INIT over AF_UNIX

FUSE_OP_INIT = 26
FUSE_MAJOR_VERSION = 7
FUSE_MINOR_VERSION = 38

_fuse_in_header_fmt = '<IIQQIIII'
_fuse_out_header_fmt = '<IiQ'
_fuse_init_in_fmt = '<IIIII44x'
_fuse_init_out_fmt = '<IIIIHHIIHHI28x'


def cmd_uds_init(sockpath):
    """Speak a FUSE INIT handshake over an AF_UNIX socket.

    The request is hand-built rather than relayed from the kernel, with
    flags = 0, so nothing is negotiated.
    """
    import socket

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(sockpath)
    try:
        unique_req = 10
        header = struct.pack(
            _fuse_in_header_fmt,
            struct.calcsize(_fuse_in_header_fmt) +
            struct.calcsize(_fuse_init_in_fmt),
            FUSE_OP_INIT, unique_req, 0, 0, 0, 0, 0)
        payload = struct.pack(_fuse_init_in_fmt, FUSE_MAJOR_VERSION,
                              FUSE_MINOR_VERSION, 0, 0, 0)
        sock.sendall(header + payload)

        response_header = _recvall(sock, struct.calcsize(_fuse_out_header_fmt))
        packet_len, _, unique_res = struct.unpack(_fuse_out_header_fmt,
                                                  response_header)
        _require(unique_res == unique_req,
                 'reply carries unique %d, want %d' % (unique_res, unique_req))

        response = _recvall(sock, packet_len - len(response_header))
        response = struct.unpack(_fuse_init_out_fmt, response)
        _require(response[0] == FUSE_MAJOR_VERSION,
                 'reply advertises major %d' % response[0])
    finally:
        sock.close()


def _recvall(sock, bufsize):
    buf = bytes()
    while len(buf) < bufsize:
        chunk = sock.recv(bufsize - len(buf))
        if not chunk:
            raise CheckFailed('peer closed the socket after %d bytes'
                              % len(buf))
        buf += chunk
    return buf


# ------------------------------------------------------------------ dispatch

_INODE_CHECK = {'default': 'exact', 'choices': ('exact', 'nonzero')}


def build_parser():
    """One subparser per check. Each records how to call its function, so
    adding a check is one line here and one function above."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)

    def add(name, func, *positional, **options):
        cmd = sub.add_parser(name)
        for arg in positional:
            if isinstance(arg, tuple):
                cmd.add_argument(arg[0], **arg[1])
            else:
                cmd.add_argument(arg)
        for flag, kwargs in options.items():
            cmd.add_argument('--' + flag.replace('_', '-'), dest=flag,
                             **kwargs)
        names = [a[0] if isinstance(a, tuple) else a for a in positional]
        names += list(options)
        cmd.set_defaults(call=lambda args: func(*[getattr(args, n)
                                                  for n in names]))
        return cmd

    add('fuse_test_unlink', cmd_unlink, 'mnt', src={'default': None})
    add('fuse_test_mkdir', cmd_mkdir, 'mnt')
    add('fuse_test_rmdir', cmd_rmdir, 'mnt', src={'default': None})
    add('fuse_test_symlink', cmd_symlink, 'mnt')
    add('fuse_test_create', cmd_create, 'mnt')
    add('fuse_test_chown', cmd_chown, 'mnt')
    add('fuse_test_open_read', cmd_open_read, 'src', 'mnt')
    add('fuse_test_open_write', cmd_open_write, 'src', 'mnt')
    add('fuse_test_append', cmd_append, 'src', 'mnt')
    add('fuse_test_seek', cmd_seek, 'src', 'mnt')
    add('fuse_test_open_unlink', cmd_open_unlink, 'mnt')
    add('fuse_test_statvfs', cmd_statvfs, 'mnt')
    add('fuse_test_link', cmd_link, 'mnt')
    add('fuse_test_readdir', cmd_readdir, 'src', 'mnt',
        inode_check=_INODE_CHECK)
    add('fuse_test_readdir_big', cmd_readdir_big, 'src', 'mnt',
        inode_check=_INODE_CHECK)
    add('fuse_test_truncate_path', cmd_truncate_path, 'mnt')
    add('fuse_test_truncate_fd', cmd_truncate_fd, 'mnt')
    add('fuse_test_utimens', cmd_utimens, 'mnt', ns_tol={'default': 0})
    add('fuse_test_passthrough', cmd_passthrough, 'src', 'mnt',
        inode_check=_INODE_CHECK)
    add('fuse_test_xattr', cmd_xattr, 'path')

    add('fuse_test_expect_errno', cmd_expect_errno, 'want', 'op',
        ('args', {'nargs': '*'}))
    add('fuse_test_assert_listdir', cmd_assert_listdir, 'dir',
        ('names', {'nargs': '*'}))
    add('fuse_test_listdir', cmd_listdir, 'dir')
    add('fuse_test_listdir_first', cmd_listdir_first, 'dir')
    add('fuse_test_size', cmd_size, 'path')
    add('fuse_test_ismount', cmd_ismount, 'path')
    add('fuse_test_isbigger', cmd_isbigger, 'path', 'size')

    add('fuse_test_mountinfo', cmd_mountinfo, 'mnt', 'field')
    for name, func in (('fuse_test_assert_mount_opt', cmd_assert_mount_opt),
                       ('fuse_test_refute_mount_opt', cmd_refute_mount_opt),
                       ('fuse_test_assert_super_opt', cmd_assert_super_opt),
                       ('fuse_test_assert_super_opt_prefix',
                        cmd_assert_super_opt_prefix),
                       ('fuse_test_assert_fstype', cmd_assert_fstype),
                       ('fuse_test_assert_source', cmd_assert_source)):
        add(name, func, 'mnt', ('values', {'nargs': '+'}))

    add('fuse_test_printcap_caps', cmd_printcap_caps, 'src_root')
    add('fuse_test_reachable_without_caps', cmd_reachable_without_caps, 'path')
    add('fuse_test_elf_class', cmd_elf_class, 'path')
    add('fuse_test_cuse_roundtrip', cmd_cuse_roundtrip, 'devpath', 'client')
    add('fuse_test_uds_init', cmd_uds_init, 'sockpath')
    return parser


def main(argv):
    args = build_parser().parse_args(argv)
    try:
        args.call(args)
    # struct.error is what a daemon replying with a short or overlong packet
    # raises, which is a check failing rather than this script breaking.
    except (CheckFailed, OSError, subprocess.SubprocessError,
            struct.error) as exc:
        print('checks.py %s: %s' % (args.cmd, exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
