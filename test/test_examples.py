#!/usr/bin/env python3

if __name__ == '__main__':
    import pytest
    import sys
    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
import os
import sys
import py
import pytest
import stat
import shutil
import filecmp
import tempfile
import time
import errno
import sys
import platform
import re
from packaging import version
from tempfile import NamedTemporaryFile
from contextlib import contextmanager
from util import (wait_for_mount, umount, cleanup, base_cmdline,
                  safe_sleep, basename, fuse_test_marker, test_printcap,
                  fuse_proto, fuse_caps, powerset, parse_kernel_version)
from os.path import join as pjoin
import logging

pytestmark = fuse_test_marker()

TEST_FILE = __file__

with open(TEST_FILE, 'rb') as fh:
    TEST_DATA = fh.read()

def name_generator(__ctr=[0]):
    __ctr[0] += 1
    return 'testfile_%d' % __ctr[0]

options = []
if sys.platform == 'linux':
    options.append('clone_fd')

def invoke_directly(mnt_dir, name, options):
    cmdline = base_cmdline + [ pjoin(basename, 'example', name),
                               '-f', mnt_dir, '-o', ','.join(options) ]
    if name == 'hello_ll':
        # supports single-threading only
        cmdline.append('-s')

    return cmdline

def invoke_mount_fuse(mnt_dir, name, options):
    return base_cmdline + [ pjoin(basename, 'util', 'mount.fuse3'),
                            name, mnt_dir, '-o', ','.join(options) ]

def invoke_mount_fuse_drop_privileges(mnt_dir, name, options):
    if os.getuid() != 0:
        pytest.skip('drop_privileges requires root, skipping.')

    return invoke_mount_fuse(mnt_dir, name, options + ('drop_privileges',))

class raii_tmpdir:
    def __init__(self):
        self.d = tempfile.mkdtemp()

    def __str__(self):
        return str(self.d)

    def mkdir(self, path):
        return py.path.local(str(self.d)).mkdir(path)

@pytest.fixture
def short_tmpdir():
    return raii_tmpdir()

def readdir_inode(dir):
    cmd = base_cmdline + [ pjoin(basename, 'test', 'readdir_inode'), dir ]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          universal_newlines=True) as proc:
        lines = proc.communicate()[0].splitlines()
    lines.sort()
    return lines


@pytest.mark.parametrize("cmdline_builder", (invoke_directly, invoke_mount_fuse,
                                             invoke_mount_fuse_drop_privileges))
@pytest.mark.parametrize("options", powerset(options))
@pytest.mark.parametrize("name", ('hello', 'hello_ll'))
def test_hello(tmpdir, name, options, cmdline_builder, output_checker):
    logger = logging.getLogger(__name__)
    mnt_dir = str(tmpdir)
    logger.debug(f"Mount directory: {mnt_dir}")
    cmdline = cmdline_builder(mnt_dir, name, options)
    logger.debug(f"Command line: {' '.join(cmdline)}")
    mount_process = subprocess.Popen(
        cmdline,
        stdout=output_checker.fd, stderr=output_checker.fd)
    logger.debug(f"Mount process PID: {mount_process.pid}")
    try:
        logger.debug("Waiting for mount...")
        wait_for_mount(mount_process, mnt_dir)
        logger.debug("Mount completed")
        assert os.listdir(mnt_dir) == [ 'hello' ]
        logger.debug("Verified 'hello' file exists in mount directory")
        filename = pjoin(mnt_dir, 'hello')
        with open(filename, 'r') as fh:
            assert fh.read() == 'Hello World!\n'
        logger.debug("Verified contents of 'hello' file")
        with pytest.raises(IOError) as exc_info:
            open(filename, 'r+')
        assert exc_info.value.errno == errno.EACCES
        logger.debug("Verified EACCES error when trying to open file for writing")
        with pytest.raises(IOError) as exc_info:
            open(filename + 'does-not-exist', 'r+')
        assert exc_info.value.errno == errno.ENOENT
        logger.debug("Verified ENOENT error for non-existent file")
        if name == 'hello_ll':
            logger.debug("Testing xattr for hello_ll")
            tst_xattr(mnt_dir)
            path = os.path.join(mnt_dir, 'hello')
            tst_xattr(path)
    except:
        logger.error("Exception occurred during test", exc_info=True)
        cleanup(mount_process, mnt_dir)
        raise
    else:
        logger.debug("Unmounting...")
        umount(mount_process, mnt_dir)
        logger.debug("Test completed successfully")

@pytest.mark.parametrize("writeback", (False, True))
@pytest.mark.parametrize("name", ('passthrough', 'passthrough_plus',
                           'passthrough_fh', 'passthrough_ll'))
@pytest.mark.parametrize("debug", (False, True))
def test_passthrough(short_tmpdir, name, debug, output_checker, writeback):
    # Avoid false positives from libfuse debug messages
    if debug:
        output_checker.register_output(r'^   unique: [0-9]+, error: -[0-9]+ .+$',
                                       count=0)

    # test_syscalls prints "No error" under FreeBSD
    output_checker.register_output(r"^ \d\d \[[^\]]+ message: 'No error: 0'\]",
                                   count=0)

    mnt_dir = str(short_tmpdir.mkdir('mnt'))
    src_dir = str(short_tmpdir.mkdir('src'))

    if name == 'passthrough_plus':
        cmdline = base_cmdline + \
                  [ pjoin(basename, 'example', 'passthrough'),
                    '--plus', '-f', mnt_dir ]
    else:
        cmdline = base_cmdline + \
                  [ pjoin(basename, 'example', name),
                    '-f', mnt_dir ]
    if debug:
        cmdline.append('-d')

    if writeback:
        if name != 'passthrough_ll':
            pytest.skip('example does not support writeback caching')
        cmdline.append('-o')
        cmdline.append('writeback')
        
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    try:
        wait_for_mount(mount_process, mnt_dir)
        work_dir = mnt_dir + src_dir

        tst_statvfs(work_dir)
        tst_readdir(src_dir, work_dir)
        tst_readdir_big(src_dir, work_dir)
        tst_open_read(src_dir, work_dir)
        tst_open_write(src_dir, work_dir)
        tst_create(work_dir)
        tst_passthrough(src_dir, work_dir)
        tst_append(src_dir, work_dir)
        tst_seek(src_dir, work_dir)
        tst_mkdir(work_dir)
        tst_rmdir(work_dir, src_dir)
        tst_unlink(work_dir, src_dir)
        tst_symlink(work_dir)
        if os.getuid() == 0:
            tst_chown(work_dir)

        # Underlying fs may not have full nanosecond resolution
        tst_utimens(work_dir, ns_tol=1000)

        tst_link(work_dir)
        tst_truncate_path(work_dir)
        tst_truncate_fd(work_dir)
        tst_open_unlink(work_dir)

        syscall_test_cmd = [ os.path.join(basename, 'test', 'test_syscalls'),
                             work_dir, ':' + src_dir ]
        if writeback:
            # When writeback caching is enabled, kernel has to open files for
            # reading even when userspace opens with O_WDONLY. This fails if the
            # filesystem process doesn't have special permission.
            syscall_test_cmd.append('-53')
        subprocess.check_call(syscall_test_cmd)
    except:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.parametrize("cache", (False, True))
def test_passthrough_hp(short_tmpdir, cache, output_checker):
    mnt_dir = str(short_tmpdir.mkdir('mnt'))
    src_dir = str(short_tmpdir.mkdir('src'))

    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'passthrough_hp'),
                src_dir, mnt_dir ]

    cmdline.append('--foreground')

    if not cache:
        cmdline.append('--nocache')
        
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    try:
        wait_for_mount(mount_process, mnt_dir)

        tst_statvfs(mnt_dir)
        tst_readdir(src_dir, mnt_dir)
        tst_readdir_big(src_dir, mnt_dir)
        tst_open_read(src_dir, mnt_dir)
        tst_open_write(src_dir, mnt_dir)
        tst_create(mnt_dir)
        if not cache:
            tst_passthrough(src_dir, mnt_dir)
        tst_append(src_dir, mnt_dir)
        tst_seek(src_dir, mnt_dir)
        tst_mkdir(mnt_dir)
        if cache:
            # if cache is enabled, no operations should go through
            # src_dir as the cache will become stale.
            tst_rmdir(mnt_dir)
            tst_unlink(mnt_dir)
        else:
            tst_rmdir(mnt_dir, src_dir)
            tst_unlink(mnt_dir, src_dir)
        tst_symlink(mnt_dir)
        if os.getuid() == 0:
            tst_chown(mnt_dir)

        # Underlying fs may not have full nanosecond resolution
        tst_utimens(mnt_dir, ns_tol=1000)

        tst_link(mnt_dir)
        tst_truncate_path(mnt_dir)
        tst_truncate_fd(mnt_dir)
        tst_open_unlink(mnt_dir)

        # test_syscalls assumes that changes in source directory
        # will be reflected immediately in mountpoint, so we
        # can't use it.
        if not cache:
            syscall_test_cmd = [ os.path.join(basename, 'test', 'test_syscalls'),
                             mnt_dir, ':' + src_dir ]
            # unlinked testfiles check fails without kernel fix
            # "fuse: fix illegal access to inode with reused nodeid"
            # so opt-in for this test from kernel 5.14
            if parse_kernel_version(platform.release()) >= version.parse('5.14'):
                syscall_test_cmd.append('-u')
            subprocess.check_call(syscall_test_cmd)
    except:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

        
@pytest.mark.skipif(fuse_proto < (7,11),
                    reason='not supported by running kernel')
def test_ioctl(tmpdir, output_checker):
    progname = pjoin(basename, 'example', 'ioctl')
    if not os.path.exists(progname):
        pytest.skip('%s not built' % os.path.basename(progname))
    
    mnt_dir = str(tmpdir)
    testfile = pjoin(mnt_dir, 'fioc')
    cmdline = base_cmdline + [progname, '-f', mnt_dir ]
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    try:
        wait_for_mount(mount_process, mnt_dir)

        cmdline = base_cmdline + \
                  [ pjoin(basename, 'example', 'ioctl_client'),
                    testfile ]
        assert subprocess.check_output(cmdline) == b'0\n'
        with open(testfile, 'wb') as fh:
            fh.write(b'foobar')
        assert subprocess.check_output(cmdline) == b'6\n'
        subprocess.check_call(cmdline + [ '3' ])
        with open(testfile, 'rb') as fh:
            assert fh.read()== b'foo'
    except:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

def test_poll(tmpdir, output_checker):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + [pjoin(basename, 'example', 'poll'),
               '-f', mnt_dir ]
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    try:
        wait_for_mount(mount_process, mnt_dir)
        cmdline = base_cmdline + \
                  [ pjoin(basename, 'example', 'poll_client') ]
        subprocess.check_call(cmdline, cwd=mnt_dir)
    except:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

def test_null(tmpdir, output_checker):
    progname = pjoin(basename, 'example', 'null')
    if not os.path.exists(progname):
        pytest.skip('%s not built' % os.path.basename(progname))
    
    mnt_file = str(tmpdir) + '/file'
    with open(mnt_file, 'w') as fh:
        fh.write('dummy')
    cmdline = base_cmdline + [ progname, '-f', mnt_file ]
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    def test_fn(name):
        return os.stat(name).st_size > 4000
    try:
        wait_for_mount(mount_process, mnt_file, test_fn)
        with open(mnt_file, 'rb') as fh:
            assert fh.read(382) == b'\0' * 382
        with open(mnt_file, 'wb') as fh:
            fh.write(b'whatever')
    except:
        cleanup(mount_process, mnt_file)
        raise
    else:
        umount(mount_process, mnt_file)


@pytest.mark.skipif(fuse_proto < (7,12),
                    reason='not supported by running kernel')
@pytest.mark.parametrize("only_expire", ("invalidate_entries", "expire_entries"))
@pytest.mark.parametrize("notify", (True, False))
def test_notify_inval_entry(tmpdir, only_expire, notify, output_checker):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'notify_inval_entry'),
                '-f', '--update-interval=1',
                '--timeout=5', mnt_dir ]
    if not notify:
        cmdline.append('--no-notify')
    if only_expire == "expire_entries":
        cmdline.append('--only-expire')
        if "FUSE_CAP_EXPIRE_ONLY" not in fuse_caps:
            pytest.skip('only-expire not supported by running kernel')
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    try:
        wait_for_mount(mount_process, mnt_dir)
        fname = pjoin(mnt_dir, os.listdir(mnt_dir)[0])
        try:
            os.stat(fname)
        except FileNotFoundError:
            # We may have hit a race condition and issued
            # readdir just before the name changed
            fname = pjoin(mnt_dir, os.listdir(mnt_dir)[0])
            os.stat(fname)

        safe_sleep(2)
        if not notify:
            os.stat(fname)
            safe_sleep(5)
        with pytest.raises(FileNotFoundError):
            os.stat(fname)
    except:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.parametrize("intended_user", ('root', 'non_root'))
def test_dev_auto_unmount(short_tmpdir, output_checker, intended_user):
    """Check that root can mount with dev and auto_unmount
    (but non-root cannot).
    Split into root vs non-root, so that the output of pytest
    makes clear what functionality is being tested."""
    if os.getuid() == 0 and intended_user == 'non_root':
        pytest.skip('needs to run as non-root')
    if os.getuid() != 0 and intended_user == 'root':
        pytest.skip('needs to run as root')
    mnt_dir = str(short_tmpdir.mkdir('mnt'))
    src_dir = str('/dev')
    cmdline = base_cmdline + \
                [ pjoin(basename, 'example', 'passthrough_ll'),
                '-o', f'source={src_dir},dev,auto_unmount',
                '-f', mnt_dir ]
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    try:
        wait_for_mount(mount_process, mnt_dir)
        if os.getuid() == 0:
            open(pjoin(mnt_dir, 'null')).close()
        else:
            with pytest.raises(PermissionError):
                open(pjoin(mnt_dir, 'null')).close()
    except:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.skipif(os.getuid() != 0,
                    reason='needs to run as root')
def test_cuse(output_checker):

    # Valgrind warns about unknown ioctls, that's ok
    output_checker.register_output(r'^==([0-9]+).+unhandled ioctl.+\n'
                                   r'==\1== \s{3}.+\n'
                                   r'==\1== \s{3}.+$', count=0)

    devname = 'cuse-test-%d' % os.getpid()
    devpath = '/dev/%s' % devname
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'cuse'),
                '-f', '--name=%s' % devname ]
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)

    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'cuse_client'),
                devpath ]
    try:
        wait_for_mount(mount_process, devpath,
                       test_fn=os.path.exists)
        assert subprocess.check_output(cmdline + ['s']) == b'0\n'
        data = b'some test data'
        off = 5
        proc = subprocess.Popen(cmdline + [ 'w', str(len(data)), str(off) ],
                                stdin=subprocess.PIPE)
        proc.stdin.write(data)
        proc.stdin.close()
        assert proc.wait(timeout=10) == 0
        size = str(off + len(data)).encode() + b'\n'
        assert subprocess.check_output(cmdline + ['s']) == size
        out = subprocess.check_output(
            cmdline + [ 'r', str(off + len(data) + 2), '0' ])
        assert out == (b'\0' * off) + data
    finally:
        mount_process.terminate()

def test_release_unlink_race(tmpdir, output_checker):
    """test case for Issue #746

    If RELEASE and UNLINK opcodes are sent back to back, and fuse_fs_release()
    and fuse_fs_rename() are slow to execute, UNLINK will run while RELEASE is
    still executing. UNLINK will try to rename the file and, while the rename
    is happening, the RELEASE will finish executing. As a result, RELEASE will
    not detect in time that UNLINK has happened, and UNLINK will not detect in
    time that RELEASE has happened.


    NOTE: This is triggered only when nullpath_ok is set.

    If it is NOT SET then get_path_nullok() called by fuse_lib_release() will
    call get_path_common() and lock the path, and then the fuse_lib_unlink()
    will wait for the path to be unlocked before executing and thus synchronise
    with fuse_lib_release().

    If it is SET then get_path_nullok() will just set the path to null and
    return without locking anything and thus allowing fuse_lib_unlink() to
    eventually execute unimpeded while fuse_lib_release() is still running.
    """

    fuse_mountpoint = str(tmpdir)

    fuse_binary_command = base_cmdline + \
        [ pjoin(basename, 'test', 'release_unlink_race'),
        "-f", fuse_mountpoint]

    fuse_process = subprocess.Popen(fuse_binary_command,
                                   stdout=output_checker.fd,
                                   stderr=output_checker.fd)

    try:
        wait_for_mount(fuse_process, fuse_mountpoint)

        temp_dir = tempfile.TemporaryDirectory(dir="/tmp/")
        temp_dir_path = temp_dir.name

        fuse_temp_file, fuse_temp_file_path = tempfile.mkstemp(dir=(fuse_mountpoint + temp_dir_path))

        os.close(fuse_temp_file)
        os.unlink(fuse_temp_file_path)

        # needed for slow CI/CD pipelines for unlink OP to complete processing
        safe_sleep(3)

        assert os.listdir(temp_dir_path) == []
    
    except:
        temp_dir.cleanup()
        cleanup(fuse_process, fuse_mountpoint)
        raise

    else:
        temp_dir.cleanup()
        umount(fuse_process, fuse_mountpoint)


@contextmanager
def os_open(name, flags):
    fd = os.open(name, flags)
    try:
        yield fd
    finally:
        os.close(fd)

def os_create(name):
    os.close(os.open(name, os.O_CREAT | os.O_RDWR))

def tst_unlink(mnt_dir, src_dir=None):
    name = name_generator()
    fullname = mnt_dir + "/" + name
    srcname = fullname
    if src_dir is not None:
        srcname = pjoin(src_dir, name)
    with open(srcname, 'wb') as fh:
        fh.write(b'hello')
    assert name in os.listdir(mnt_dir)
    os.unlink(fullname)
    with pytest.raises(OSError) as exc_info:
        os.stat(fullname)
    assert exc_info.value.errno == errno.ENOENT
    assert name not in os.listdir(mnt_dir)

def tst_mkdir(mnt_dir):
    dirname = name_generator()
    fullname = mnt_dir + "/" + dirname
    os.mkdir(fullname)
    fstat = os.stat(fullname)
    assert stat.S_ISDIR(fstat.st_mode)
    assert os.listdir(fullname) ==  []
    # Some filesystem (e.g. BTRFS) don't track st_nlink for directories
    assert fstat.st_nlink in (1,2)
    assert dirname in os.listdir(mnt_dir)

def tst_rmdir(mnt_dir, src_dir=None):
    name = name_generator()
    fullname = mnt_dir + "/" + name
    srcname = fullname
    if src_dir is not None:
        srcname = pjoin(src_dir, name)
    os.mkdir(srcname)
    assert name in os.listdir(mnt_dir)
    os.rmdir(fullname)
    with pytest.raises(OSError) as exc_info:
        os.stat(fullname)
    assert exc_info.value.errno == errno.ENOENT
    assert name not in os.listdir(mnt_dir)

def tst_symlink(mnt_dir):
    linkname = name_generator()
    fullname = mnt_dir + "/" + linkname
    os.symlink("/imaginary/dest", fullname)
    fstat = os.lstat(fullname)
    assert stat.S_ISLNK(fstat.st_mode)
    assert os.readlink(fullname) == "/imaginary/dest"
    assert fstat.st_nlink == 1
    assert linkname in os.listdir(mnt_dir)

def tst_create(mnt_dir):
    name = name_generator()
    fullname = pjoin(mnt_dir, name)
    with pytest.raises(OSError) as exc_info:
        os.stat(fullname)
    assert exc_info.value.errno == errno.ENOENT
    assert name not in os.listdir(mnt_dir)

    fd = os.open(fullname, os.O_CREAT | os.O_RDWR)
    os.close(fd)

    assert name in os.listdir(mnt_dir)
    fstat = os.lstat(fullname)
    assert stat.S_ISREG(fstat.st_mode)
    assert fstat.st_nlink == 1
    assert fstat.st_size == 0

def tst_chown(mnt_dir):
    filename = pjoin(mnt_dir, name_generator())
    os.mkdir(filename)
    fstat = os.lstat(filename)
    uid = fstat.st_uid
    gid = fstat.st_gid

    uid_new = uid + 1
    os.chown(filename, uid_new, -1)
    fstat = os.lstat(filename)
    assert fstat.st_uid == uid_new
    assert fstat.st_gid == gid

    gid_new = gid + 1
    os.chown(filename, -1, gid_new)
    fstat = os.lstat(filename)
    assert fstat.st_uid == uid_new
    assert fstat.st_gid == gid_new

def tst_open_read(src_dir, mnt_dir):
    name = name_generator()
    with open(pjoin(src_dir, name), 'wb') as fh_out, \
         open(TEST_FILE, 'rb') as fh_in:
        shutil.copyfileobj(fh_in, fh_out)

    assert filecmp.cmp(pjoin(mnt_dir, name), TEST_FILE, False)

def tst_open_write(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with open(fullname, 'wb') as fh_out, \
         open(TEST_FILE, 'rb') as fh_in:
        shutil.copyfileobj(fh_in, fh_out)

    assert filecmp.cmp(fullname, TEST_FILE, False)

def tst_append(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with os_open(fullname, os.O_WRONLY) as fd:
        os.write(fd, b'foo\n')
    with os_open(fullname, os.O_WRONLY|os.O_APPEND) as fd:
        os.write(fd, b'bar\n')

    with open(fullname, 'rb') as fh:
        assert fh.read() == b'foo\nbar\n'

def tst_seek(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with os_open(fullname, os.O_WRONLY) as fd:
        os.lseek(fd, 1, os.SEEK_SET)
        os.write(fd, b'foobar\n')
    with os_open(fullname, os.O_WRONLY) as fd:
        os.lseek(fd, 4, os.SEEK_SET)
        os.write(fd, b'com')
        
    with open(fullname, 'rb') as fh:
        assert fh.read() == b'\0foocom\n'
        
def tst_open_unlink(mnt_dir):
    name = pjoin(mnt_dir, name_generator())
    data1 = b'foo'
    data2 = b'bar'
    fullname = pjoin(mnt_dir, name)
    with open(fullname, 'wb+', buffering=0) as fh:
        fh.write(data1)
        os.unlink(fullname)
        with pytest.raises(OSError) as exc_info:
            os.stat(fullname)
        assert exc_info.value.errno == errno.ENOENT
        assert name not in os.listdir(mnt_dir)
        fh.write(data2)
        fh.seek(0)
        assert fh.read() == data1+data2

def tst_statvfs(mnt_dir):
    os.statvfs(mnt_dir)

def tst_link(mnt_dir):
    name1 = pjoin(mnt_dir, name_generator())
    name2 = pjoin(mnt_dir, name_generator())
    shutil.copyfile(TEST_FILE, name1)
    assert filecmp.cmp(name1, TEST_FILE, False)

    fstat1 = os.lstat(name1)
    assert fstat1.st_nlink == 1

    os.link(name1, name2)

    fstat1 = os.lstat(name1)
    fstat2 = os.lstat(name2)
    assert fstat1 == fstat2
    assert fstat1.st_nlink == 2
    assert os.path.basename(name2) in os.listdir(mnt_dir)
    assert filecmp.cmp(name1, name2, False)

    # Since RELEASE requests are asynchronous, it is possible that
    # libfuse still considers the file to be open at this point
    # and (since -o hard_remove is not used) renames it instead of
    # deleting it. In that case, the following lstat() call will
    # still report an st_nlink value of 2 (cf. issue #157).
    os.unlink(name2)

    assert os.path.basename(name2) not in os.listdir(mnt_dir)
    with pytest.raises(FileNotFoundError):
        os.lstat(name2)

    # See above, we may have to wait until RELEASE has been
    # received before the st_nlink value is correct.
    maxwait = time.time() + 2
    fstat1 = os.lstat(name1)
    while fstat1.st_nlink == 2 and time.time() < maxwait:
        fstat1 = os.lstat(name1)
        time.sleep(0.1)
    assert fstat1.st_nlink == 1

    os.unlink(name1)

def tst_readdir(src_dir, mnt_dir):
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

    listdir_is = os.listdir(mnt_newdir)
    listdir_is.sort()
    listdir_should = [ os.path.basename(file_), os.path.basename(subdir) ]
    listdir_should.sort()
    assert listdir_is == listdir_should

    inodes_is = readdir_inode(mnt_newdir)
    inodes_should = readdir_inode(src_newdir)
    assert inodes_is == inodes_should

    os.unlink(file_)
    os.unlink(subfile)
    os.rmdir(subdir)
    os.rmdir(src_newdir)

def tst_readdir_big(src_dir, mnt_dir):

    # Add enough entries so that readdir needs to be called
    # multiple times.
    fnames = []
    for i in range(500):
        fname  = ('A rather long filename to make sure that we '
                  'fill up the buffer - ' * 3) + str(i)
        with open(pjoin(src_dir, fname), 'w') as fh:
            fh.write('File %d' % i)
        fnames.append(fname)

    listdir_is = sorted(os.listdir(mnt_dir))
    listdir_should = sorted(os.listdir(src_dir))
    assert listdir_is == listdir_should

    inodes_is = readdir_inode(mnt_dir)
    inodes_should = readdir_inode(src_dir)
    assert inodes_is == inodes_should

    for fname in fnames:
        stat_src = os.stat(pjoin(src_dir, fname))
        stat_mnt = os.stat(pjoin(mnt_dir, fname))
        assert stat_src.st_ino == stat_mnt.st_ino
        assert stat_src.st_mtime == stat_mnt.st_mtime
        assert stat_src.st_ctime == stat_mnt.st_ctime
        assert stat_src.st_size == stat_mnt.st_size
        os.unlink(pjoin(src_dir, fname))

def tst_truncate_path(mnt_dir):
    assert len(TEST_DATA) > 1024

    filename = pjoin(mnt_dir, name_generator())
    with open(filename, 'wb') as fh:
        fh.write(TEST_DATA)

    fstat = os.stat(filename)
    size = fstat.st_size
    assert size == len(TEST_DATA)

    # Add zeros at the end
    os.truncate(filename, size + 1024)
    assert os.stat(filename).st_size == size + 1024
    with open(filename, 'rb') as fh:
        assert fh.read(size) == TEST_DATA
        assert fh.read(1025) == b'\0' * 1024

    # Truncate data
    os.truncate(filename, size - 1024)
    assert os.stat(filename).st_size == size - 1024
    with open(filename, 'rb') as fh:
        assert fh.read(size) == TEST_DATA[:size-1024]

    os.unlink(filename)

def tst_truncate_fd(mnt_dir):
    assert len(TEST_DATA) > 1024
    with NamedTemporaryFile('w+b', 0, dir=mnt_dir) as fh:
        fd = fh.fileno()
        fh.write(TEST_DATA)
        fstat = os.fstat(fd)
        size = fstat.st_size
        assert size == len(TEST_DATA)

        # Add zeros at the end
        os.ftruncate(fd, size + 1024)
        assert os.fstat(fd).st_size == size + 1024
        fh.seek(0)
        assert fh.read(size) == TEST_DATA
        assert fh.read(1025) == b'\0' * 1024

        # Truncate data
        os.ftruncate(fd, size - 1024)
        assert os.fstat(fd).st_size == size - 1024
        fh.seek(0)
        assert fh.read(size) == TEST_DATA[:size-1024]

def tst_utimens(mnt_dir, ns_tol=0):
    filename = pjoin(mnt_dir, name_generator())
    os.mkdir(filename)
    fstat = os.lstat(filename)

    atime = fstat.st_atime + 42.28
    mtime = fstat.st_mtime - 42.23
    if sys.version_info < (3,3):
        os.utime(filename, (atime, mtime))
    else:
        atime_ns = fstat.st_atime_ns + int(42.28*1e9)
        mtime_ns = fstat.st_mtime_ns - int(42.23*1e9)
        os.utime(filename, None, ns=(atime_ns, mtime_ns))

    fstat = os.lstat(filename)

    assert abs(fstat.st_atime - atime) < 1
    assert abs(fstat.st_mtime - mtime) < 1
    if sys.version_info >= (3,3):
        assert abs(fstat.st_atime_ns - atime_ns) <= ns_tol
        assert abs(fstat.st_mtime_ns - mtime_ns) <= ns_tol

def tst_passthrough(src_dir, mnt_dir):
    name = name_generator()
    src_name = pjoin(src_dir, name)
    mnt_name = pjoin(src_dir, name)
    assert name not in os.listdir(src_dir)
    assert name not in os.listdir(mnt_dir)
    with open(src_name, 'w') as fh:
        fh.write('Hello, world')
    assert name in os.listdir(src_dir)
    assert name in os.listdir(mnt_dir)
    assert os.stat(src_name) == os.stat(mnt_name)

    name = name_generator()
    src_name = pjoin(src_dir, name)
    mnt_name = pjoin(src_dir, name)
    assert name not in os.listdir(src_dir)
    assert name not in os.listdir(mnt_dir)
    with open(mnt_name, 'w') as fh:
        fh.write('Hello, world')
    assert name in os.listdir(src_dir)
    assert name in os.listdir(mnt_dir)
    assert os.stat(src_name) == os.stat(mnt_name)


def tst_xattr(path):
    os.setxattr(path, b'hello_ll_setxattr_name', b'hello_ll_setxattr_value')
    assert os.getxattr(path, b'hello_ll_getxattr_name') == b'hello_ll_getxattr_value'
    os.removexattr(path, b'hello_ll_removexattr_name')


# avoid warning about unused import
assert test_printcap
