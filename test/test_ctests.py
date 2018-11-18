#!/usr/bin/env python3

if __name__ == '__main__':
    import pytest
    import sys
    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
import pytest
import platform
import sys
from distutils.version import LooseVersion
from util import (wait_for_mount, umount, cleanup, base_cmdline,
                  safe_sleep, basename, fuse_test_marker, fuse_caps,
                  fuse_proto)
from os.path import join as pjoin
import os.path

pytestmark = fuse_test_marker()

@pytest.mark.skipif('FUSE_CAP_WRITEBACK_CACHE' not in fuse_caps,
                    reason='not supported by running kernel')
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


names = [ 'notify_inval_inode', 'invalidate_path' ]
if fuse_proto >= (7,15):
    names.append('notify_store_retrieve')
@pytest.mark.skipif(fuse_proto < (7,12),
                    reason='not supported by running kernel')
@pytest.mark.parametrize("name", names)
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
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

@pytest.mark.skipif(fuse_proto < (7,12),
                    reason='not supported by running kernel')
@pytest.mark.parametrize("notify", (True, False))
def test_notify_file_size(tmpdir, notify):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'invalidate_path'),
                '-f', '--update-interval=1', mnt_dir ]
    if not notify:
        cmdline.append('--no-notify')
    mount_process = subprocess.Popen(cmdline)
    try:
        wait_for_mount(mount_process, mnt_dir)
        filename = pjoin(mnt_dir, 'growing')
        size = os.path.getsize(filename)
        safe_sleep(2)
        new_size = os.path.getsize(filename)
        if notify:
            assert new_size > size
        else:
            assert new_size == size
    except:
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)
