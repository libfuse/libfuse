#!/usr/bin/env python3
import pytest
import sys

if __name__ == '__main__':
    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
import os
from util import wait_for_mount, umount, cleanup

basename = os.path.join(os.path.dirname(__file__), '..')

def test_fuse(tmpdir):
    mnt_dir = str(tmpdir.mkdir('mnt'))
    src_dir = str(tmpdir.mkdir('src'))

    cmdline = [ os.path.join(basename, 'example', 'fusexmp_fh'),
                '-f', '-o' , 'use_ino,readdir_ino,kernel_cache',
                mnt_dir ]
    mount_process = subprocess.Popen(cmdline)
    try:
        wait_for_mount(mount_process, mnt_dir)
        cmdline = [ os.path.join(basename, 'test', 'test'),
                    os.path.join(mnt_dir, src_dir),
                    ':' + src_dir ]
        subprocess.check_call(cmdline)
    except:
        cleanup(mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)
