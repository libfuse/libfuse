#!/usr/bin/env python3

if __name__ == '__main__':
    import pytest
    import sys
    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
import os
import sys
import pytest
import stat
import shutil
import filecmp
import errno
import platform
from distutils.version import LooseVersion
from tempfile import NamedTemporaryFile
from util import (wait_for_mount, umount, cleanup, base_cmdline,
                  safe_sleep, basename)
from os.path import join as pjoin

TEST_FILE = __file__

with open(TEST_FILE, 'rb') as fh:
    TEST_DATA = fh.read()

def name_generator(__ctr=[0]):
    __ctr[0] += 1
    return 'testfile_%d' % __ctr[0]

@pytest.mark.parametrize("name", ('hello', 'hello_ll'))
@pytest.mark.parametrize("options", ([], ['-o', 'clone_fd']))
def test_hello(tmpdir, name, options):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', name),
                '-f', mnt_dir ] + options
    if name == 'hello_ll':
        # supports single-threading only
        cmdline.append('-s')
    mount_process = subprocess.Popen(cmdline)
    try:
        wait_for_mount(mount_process, mnt_dir)
        assert os.listdir(mnt_dir) == [ 'hello' ]
        filename = pjoin(mnt_dir, 'hello')
        with open(filename, 'r') as fh:
            assert fh.read() == 'Hello World!\n'
        with pytest.raises(IOError) as exc_info:
            open(filename, 'r+')
        assert exc_info.value.errno == errno.EACCES
        with pytest.raises(IOError) as exc_info:
            open(filename + 'does-not-exist', 'r+')
        assert exc_info.value.errno == errno.ENOENT
    except:
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.parametrize("name", ('passthrough', 'passthrough_fh',
                                  'passthrough_ll'))
@pytest.mark.parametrize("debug", (True, False))
def test_passthrough(tmpdir, name, debug):
    mnt_dir = str(tmpdir.mkdir('mnt'))
    src_dir = str(tmpdir.mkdir('src'))

    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', name),
                '-f', mnt_dir ]
    if debug:
        cmdline.append('-d')
    mount_process = subprocess.Popen(cmdline)
    try:
        wait_for_mount(mount_process, mnt_dir)
        work_dir = pjoin(mnt_dir, src_dir)

        subprocess.check_call([ os.path.join(basename, 'test', 'test'),
                    work_dir, ':' + src_dir ])

        tst_write(work_dir)
        tst_mkdir(work_dir)
        tst_symlink(work_dir)
        tst_mknod(work_dir)
        if os.getuid() == 0:
            tst_chown(work_dir)
        # Underlying fs may not have full nanosecond resolution
        tst_utimens(work_dir, ns_tol=1000)
        tst_link(work_dir)
        tst_readdir(work_dir)
        tst_statvfs(work_dir)
        tst_truncate_path(work_dir)
        tst_truncate_fd(work_dir)
        tst_unlink(work_dir)
        tst_passthrough(src_dir, work_dir)
    except:
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

def test_ioctl(tmpdir):
    mnt_dir = str(tmpdir)
    testfile = pjoin(mnt_dir, 'fioc')
    cmdline = base_cmdline + \
              [pjoin(basename, 'example', 'ioctl'), '-f', mnt_dir ]
    mount_process = subprocess.Popen(cmdline)
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
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

def test_poll(tmpdir):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + [pjoin(basename, 'example', 'poll'),
               '-f', mnt_dir ]
    mount_process = subprocess.Popen(cmdline)
    try:
        wait_for_mount(mount_process, mnt_dir)
        cmdline = base_cmdline + \
                  [ pjoin(basename, 'example', 'poll_client') ]
        subprocess.check_call(cmdline, cwd=mnt_dir)
    except:
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.parametrize("name",
                         ('notify_inval_inode',
                          'notify_store_retrieve'))
@pytest.mark.parametrize("notify", (True, False))
def test_notify1(tmpdir, name, notify):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', name),
                '-f', '--update-interval=1', mnt_dir ]
    if not notify:
        cmdline.append('--no-notify')
    mount_process = subprocess.Popen(cmdline)
    try:
        wait_for_mount(mount_process, mnt_dir)
        filename = pjoin(mnt_dir, 'current_time')
        with open(filename, 'r') as fh:
            read1 = fh.read()
        safe_sleep(2)
        with open(filename, 'r') as fh:
            read2 = fh.read()
        if notify:
            assert read1 != read2
        else:
            assert read1 == read2
    except:
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.parametrize("notify", (True, False))
def test_notify_inval_entry(tmpdir, notify):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'notify_inval_entry'),
                '-f', '--update-interval=1',
                '--timeout=5', mnt_dir ]
    if not notify:
        cmdline.append('--no-notify')
    mount_process = subprocess.Popen(cmdline)
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
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.parametrize("writeback", (False, True))
def test_write_cache(tmpdir, writeback):
    if writeback and LooseVersion(platform.release()) < '3.14':
        pytest.skip('Requires kernel 3.14 or newer')
    # This test hangs under Valgrind when running close(fd)
    # test_write_cache.c:test_fs(). Most likely this is because of an internal
    # deadlock in valgrind, it probably assumes that until close() returns,
    # control does not come to the program.
    mnt_dir = str(tmpdir)
    cmdline = [ pjoin(basename, 'test', 'test_write_cache'),
                mnt_dir ]
    if writeback:
        cmdline.append('-owriteback_cache')
    subprocess.check_call(cmdline)

@pytest.mark.skipif(os.getuid() != 0,
                    reason='needs to run as root')
def test_cuse(capfd):

    # Valgrind warns about unknown ioctls, that's ok
    capfd.register_output(r'^==([0-9]+).+unhandled ioctl.+\n'
                          r'==\1== \s{3}.+\n'
                          r'==\1== \s{3}.+$', count=0)

    devname = 'cuse-test-%d' % os.getpid()
    devpath = '/dev/%s' % devname
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'cuse'),
                '-f', '--name=%s' % devname ]
    mount_process = subprocess.Popen(cmdline)

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

def checked_unlink(filename, path, isdir=False):
    fullname = pjoin(path, filename)
    if isdir:
        os.rmdir(fullname)
    else:
        os.unlink(fullname)
    with pytest.raises(OSError) as exc_info:
        os.stat(fullname)
    assert exc_info.value.errno == errno.ENOENT
    assert filename not in os.listdir(path)

def tst_mkdir(mnt_dir):
    dirname = name_generator()
    fullname = mnt_dir + "/" + dirname
    os.mkdir(fullname)
    fstat = os.stat(fullname)
    assert stat.S_ISDIR(fstat.st_mode)
    assert os.listdir(fullname) ==  []
    assert fstat.st_nlink in (1,2)
    assert dirname in os.listdir(mnt_dir)
    checked_unlink(dirname, mnt_dir, isdir=True)

def tst_symlink(mnt_dir):
    linkname = name_generator()
    fullname = mnt_dir + "/" + linkname
    os.symlink("/imaginary/dest", fullname)
    fstat = os.lstat(fullname)
    assert stat.S_ISLNK(fstat.st_mode)
    assert os.readlink(fullname) == "/imaginary/dest"
    assert fstat.st_nlink == 1
    assert linkname in os.listdir(mnt_dir)
    checked_unlink(linkname, mnt_dir)

def tst_mknod(mnt_dir):
    filename = pjoin(mnt_dir, name_generator())
    shutil.copyfile(TEST_FILE, filename)
    fstat = os.lstat(filename)
    assert stat.S_ISREG(fstat.st_mode)
    assert fstat.st_nlink == 1
    assert os.path.basename(filename) in os.listdir(mnt_dir)
    assert filecmp.cmp(TEST_FILE, filename, False)
    checked_unlink(filename, mnt_dir)

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

    checked_unlink(filename, mnt_dir, isdir=True)

def tst_write(mnt_dir):
    name = pjoin(mnt_dir, name_generator())
    shutil.copyfile(TEST_FILE, name)
    assert filecmp.cmp(name, TEST_FILE, False)
    checked_unlink(name, mnt_dir)

def tst_unlink(mnt_dir):
    name = pjoin(mnt_dir, name_generator())
    data1 = b'foo'
    data2 = b'bar'

    with open(pjoin(mnt_dir, name), 'wb+', buffering=0) as fh:
        fh.write(data1)
        checked_unlink(name, mnt_dir)
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
    os.link(name1, name2)

    fstat1 = os.lstat(name1)
    fstat2 = os.lstat(name2)

    assert fstat1 == fstat2
    assert fstat1.st_nlink == 2

    assert os.path.basename(name2) in os.listdir(mnt_dir)
    assert filecmp.cmp(name1, name2, False)
    os.unlink(name2)
    fstat1 = os.lstat(name1)
    assert fstat1.st_nlink == 1
    os.unlink(name1)

def tst_readdir(mnt_dir):
    dir_ = pjoin(mnt_dir, name_generator())
    file_ = dir_ + "/" + name_generator()
    subdir = dir_ + "/" + name_generator()
    subfile = subdir + "/" + name_generator()

    os.mkdir(dir_)
    shutil.copyfile(TEST_FILE, file_)
    os.mkdir(subdir)
    shutil.copyfile(TEST_FILE, subfile)

    listdir_is = os.listdir(dir_)
    listdir_is.sort()
    listdir_should = [ os.path.basename(file_), os.path.basename(subdir) ]
    listdir_should.sort()
    assert listdir_is == listdir_should

    os.unlink(file_)
    os.unlink(subfile)
    os.rmdir(subdir)
    os.rmdir(dir_)

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

    assert abs(fstat.st_atime - atime) < 1e-3
    assert abs(fstat.st_mtime - mtime) < 1e-3
    if sys.version_info >= (3,3):
        assert abs(fstat.st_atime_ns - atime_ns) <= ns_tol
        assert abs(fstat.st_mtime_ns - mtime_ns) <= ns_tol

    checked_unlink(filename, mnt_dir, isdir=True)

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
