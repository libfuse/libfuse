#!/usr/bin/env python3
import subprocess
import pytest
import os
import time
from os.path import join as pjoin

basename = pjoin(os.path.dirname(__file__), '..')

def wait_for_mount(mount_process, mnt_dir,
                   test_fn=os.path.ismount):
    elapsed = 0
    while elapsed < 30:
        if test_fn(mnt_dir):
            return True
        if mount_process.poll() is not None:
            pytest.fail('file system process terminated prematurely')
        time.sleep(0.1)
        elapsed += 0.1
    pytest.fail("mountpoint failed to come up")

def cleanup(mnt_dir):
    # Don't bother trying Valgrind if things already went wrong

    subprocess.call([pjoin(basename, 'util', 'fusermount3'),
                     '-z', '-u', mnt_dir],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT)

def umount(mount_process, mnt_dir):
    # fusermount3 will be setuid root, so we can only trace it with
    # valgrind if we're root
    if os.getuid() == 0:
        cmdline = base_cmdline
    else:
        cmdline = []

    cmdline = cmdline + [ pjoin(basename, 'util', 'fusermount3'),
                          '-z', '-u', mnt_dir ]
    subprocess.check_call(cmdline)
    assert not os.path.ismount(mnt_dir)

    # Give mount process a little while to terminate. Popen.wait(timeout)
    # was only added in 3.3...
    elapsed = 0
    while elapsed < 30:
        code = mount_process.poll()
        if code is not None:
            if code == 0:
                return
            pytest.fail('file system process terminated with code %s' % (code,))
        time.sleep(0.1)
        elapsed += 0.1
    pytest.fail('mount process did not terminate')


def safe_sleep(secs):
    '''Like time.sleep(), but sleep for at least *secs*

    `time.sleep` may sleep less than the given period if a signal is
    received. This function ensures that we sleep for at least the
    desired time.
    '''

    now = time.time()
    end = now + secs
    while now < end:
        time.sleep(end - now)
        now = time.time()

# If valgrind and libtool are available, use them
def has_program(name):
    try:
        ret = subprocess.call([name, '--version'],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return False
    return ret == 0

if has_program('valgrind') and has_program('libtool'):
    base_cmdline = [ 'libtool', '--mode=execute',
                     'valgrind', '-q', '--' ]
else:
    base_cmdline = []


# Try to use local fusermount3
os.environ['PATH'] = '%s:%s' % (pjoin(basename, 'util'), os.environ['PATH'])
