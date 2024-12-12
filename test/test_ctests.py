#!/usr/bin/env python3

if __name__ == '__main__':
    import pytest
    import sys
    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
import pytest
import platform
import sys
import os
import logging
from packaging import version
from util import (wait_for_mount, umount, cleanup, base_cmdline,
                  safe_sleep, basename, fuse_test_marker, fuse_caps,
                  fuse_proto, create_tmpdir, parse_kernel_version)
from os.path import join as pjoin
import os.path

pytestmark = fuse_test_marker()

@pytest.mark.skipif('FUSE_CAP_WRITEBACK_CACHE' not in fuse_caps,
                    reason='not supported by running kernel')
@pytest.mark.parametrize("writeback", (False, True))
def test_write_cache(tmpdir, writeback, output_checker):
    if writeback and parse_kernel_version(platform.release()) < version.parse('3.14'):
        pytest.skip('Requires kernel 3.14 or newer')
    # This test hangs under Valgrind when running close(fd)
    # test_write_cache.c:test_fs(). Most likely this is because of an internal
    # deadlock in valgrind, it probably assumes that until close() returns,
    # control does not come to the program.
    mnt_dir = str(tmpdir)
    print("mnt_dir: '" + mnt_dir + "'")
    create_tmpdir(mnt_dir)

    cmdline = [ pjoin(basename, 'test', 'test_write_cache'),
                mnt_dir ]
    if writeback:
        cmdline.append('-owriteback_cache')
    elif parse_kernel_version(platform.release()) >= version.parse('5.16'):
        # Test that close(rofd) does not block waiting for pending writes.
        # This test requires kernel commit a390ccb316be ("fuse: add FOPEN_NOFLUSH")
        # so opt-in for this test from kernel 5.16.
        cmdline.append('--delay_ms=200')
    subprocess.check_call(cmdline, stdout=output_checker.fd, stderr=output_checker.fd)


names = [ 'notify_inval_inode', 'invalidate_path' ]
if fuse_proto >= (7,15):
    names.append('notify_store_retrieve')
@pytest.mark.skipif(fuse_proto < (7,12),
                    reason='not supported by running kernel')
@pytest.mark.parametrize("name", names)
@pytest.mark.parametrize("notify", (True, False))
def test_notify1(tmpdir, name, notify, output_checker):
    logger = logging.getLogger(__name__)
    mnt_dir = str(tmpdir)
    logger.debug(f"Mount directory: {mnt_dir}")
    create_tmpdir(mnt_dir)
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', name),
                '-f', '--update-interval=1', mnt_dir ]
    if not notify:
        cmdline.append('--no-notify')
    logger.debug(f"Command line: {' '.join(cmdline)}")
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    try:
        wait_for_mount(mount_process, mnt_dir)
        logger.debug("Mount completed")
        filename = pjoin(mnt_dir, 'current_time')
        logger.debug(f"Target filename: {filename}")
        with open(filename, 'r') as fh:
            read1 = fh.read()
        logger.debug(f"First read: {read1}")
        logger.debug("Sleeping for 2 seconds...")
        safe_sleep(2)
        logger.debug("Sleep completed")
        with open(filename, 'r') as fh:
            read2 = fh.read()
        logger.debug(f"Second read: {read2}")
        if notify:
            logger.debug("Expecting reads to be different")
            assert read1 != read2
        else:
            logger.debug("Expecting reads to be the same")
            assert read1 == read2
        logger.debug("Test completed successfully")
    except:
        logger.error(f"Failure in notify test: '{' '.join(cmdline)}'")
        logger.exception("Exception details:")
        cleanup(mount_process, mnt_dir)
        raise
    else:
        logger.debug("Unmounting...")
        try:
            umount(mount_process, mnt_dir)
            logger.debug("Umount disabled")
        except:
            logger.error(f"Failure in unmount: '{' '.join(cmdline)}'")
            cleanup(mount_process, mnt_dir)
        logger.debug("Unmount completed")

@pytest.mark.skipif(fuse_proto < (7,12),
                    reason='not supported by running kernel')
@pytest.mark.parametrize("notify", (True, False))
def test_notify_file_size(tmpdir, notify, output_checker):
    logger = logging.getLogger(__name__)
    mnt_dir = str(tmpdir)
    logger.debug(f"Mount directory: {mnt_dir}")
    create_tmpdir(mnt_dir)
    cmdline = base_cmdline + \
              [ pjoin(basename, 'example', 'invalidate_path'),
                '-f', '--update-interval=1', mnt_dir ]
    if not notify:
        cmdline.append('--no-notify')
    logger.debug(f"Command line: {' '.join(cmdline)}")
    mount_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                     stderr=output_checker.fd)
    logger.debug(f"Mount process PID: {mount_process.pid}")
    try:
        wait_for_mount(mount_process, mnt_dir)
        filename = pjoin(mnt_dir, 'growing')
        size = os.path.getsize(filename)
        logger.debug(f"Initial file size: {size}")
        logger.debug("Sleeping for 2 seconds...")
        safe_sleep(2)
        logger.debug("Sleep completed")
        new_size = os.path.getsize(filename)
        logger.debug(f"New file size: {new_size}")
        if notify:
            assert new_size > size
        else:
            assert new_size == size
        logger.debug("Test completed successfully")
    except:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        try:
            umount(mount_process, mnt_dir)
        except:
            logger.error(f"Failure in unmount: '{' '.join(cmdline)}'")
            cleanup(mount_process, mnt_dir)
        logger.debug("Unmount completed")
