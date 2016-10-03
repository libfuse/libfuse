#!/usr/bin/env python3
import subprocess
import pytest
import os
import time

def wait_for_mount(mount_process, mnt_dir):
    elapsed = 0
    while elapsed < 30:
        if os.path.ismount(mnt_dir):
            return True
        if mount_process.poll() is not None:
            pytest.fail('file system process terminated prematurely')
        time.sleep(0.1)
        elapsed += 0.1
    pytest.fail("mountpoint failed to come up")

def cleanup(mnt_dir):
    subprocess.call(['fusermount', '-z', '-u', mnt_dir],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT)

def umount(mount_process, mnt_dir):
    subprocess.check_call(['fusermount', '-z', '-u', mnt_dir])
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


# If valgrind and libtool are available, use them
def has_program(name):
    return subprocess.call([name, '--version'],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0

if has_program('valgrind') and has_program('libtool'):
    base_cmdline = [ 'libtool', '--mode=execute',
                     'valgrind', '-q', '--' ]
else:
    base_cmdline = []
