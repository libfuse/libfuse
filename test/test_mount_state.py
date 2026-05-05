#!/usr/bin/env python3
'''
Tests that observable mount state (as exposed by /proc/self/mountinfo)
matches the options requested at mount time.

Existing tests check filesystem behavior (read/write/xattr/...) but
never inspect the post-mount metadata recorded by the kernel. That
metadata is populated differently by the legacy mount(2) path and the
new fsopen/fsconfig/fsmount path, so an option dropped on one path can
go undetected — the subtype regression in 5e9e16d6 is one example.
These tests assert what /proc/self/mountinfo reports for each mount,
so a parity bug between the two paths fails loudly.
'''

if __name__ == '__main__':
    import pytest
    import sys
    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import os
import subprocess
import pytest
from contextlib import contextmanager
from os.path import join as pjoin
from util import (wait_for_mount, umount, cleanup, base_cmdline, basename,
                  fuse_test_marker, parse_mountinfo)

pytestmark = fuse_test_marker()


@contextmanager
def hello_mount(tmpdir, output_checker, name, options=()):
    mnt_dir = str(tmpdir)
    cmdline = base_cmdline + [pjoin(basename, 'example', name),
                              '-f', mnt_dir]
    if name == 'hello_ll':
        cmdline.append('-s')
    if options:
        cmdline += ['-o', ','.join(options)]
    mp = subprocess.Popen(cmdline, stdout=output_checker.fd,
                          stderr=output_checker.fd)
    try:
        wait_for_mount(mp, mnt_dir)
        yield mnt_dir
    except:
        cleanup(mp, mnt_dir)
        raise
    else:
        umount(mp, mnt_dir)


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
def test_mountinfo_baseline(tmpdir, output_checker, name):
    # libfuse's add_default_subtype() (lib/helper.c) defaults the
    # subtype to basename(argv[0]) when the caller didn't pass
    # -o fsname=/-o subtype=, so the bare-mount fstype is
    # 'fuse.<example-name>', not 'fuse'. The override case is what
    # test_mountinfo_subtype below verifies; here we just assert the
    # fuse-ness and the standard kernel-side identity options.
    with hello_mount(tmpdir, output_checker, name) as mnt:
        info = parse_mountinfo(mnt)
    assert info is not None, 'mountpoint not found in /proc/self/mountinfo'
    assert info['fstype'] in ('fuse', 'fuse.' + name), \
        'unexpected fstype %r (expected fuse or fuse.%s)' % \
            (info['fstype'], name)
    assert any(o.startswith('user_id=')  for o in info['super_options'])
    assert any(o.startswith('group_id=') for o in info['super_options'])


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
def test_mountinfo_subtype(tmpdir, output_checker, name):
    # Regression guard for 5e9e16d6: the new mount API needs an
    # explicit fsconfig(SET_STRING,"subtype",...). Without it the
    # kernel records fstype=='fuse' (or whatever basename default
    # leaks through) instead of the user-requested 'fuse.<subtype>'.
    # An explicit -o subtype= must override the basename default.
    with hello_mount(tmpdir, output_checker, name,
                     ('subtype=mysub',)) as mnt:
        info = parse_mountinfo(mnt)
    assert info is not None
    assert info['fstype'] == 'fuse.mysub', \
        'explicit subtype not propagated: fstype=%r' % info['fstype']


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
def test_mountinfo_fsname(tmpdir, output_checker, name):
    with hello_mount(tmpdir, output_checker, name,
                     ('fsname=myfsname',)) as mnt:
        info = parse_mountinfo(mnt)
    assert info is not None
    assert info['source'] == 'myfsname', \
        'fsname not propagated: source=%r' % info['source']


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
def test_mountinfo_subtype_fsname(tmpdir, output_checker, name):
    with hello_mount(tmpdir, output_checker, name,
                     ('subtype=mysub', 'fsname=myfsname')) as mnt:
        info = parse_mountinfo(mnt)
    assert info is not None
    assert info['fstype'] == 'fuse.mysub'
    # 'mysub#myfsname' is the ENODEV-fallback form when the kernel
    # rejects fuse.<subtype>; accept either so the test isn't fragile.
    assert info['source'] in ('myfsname', 'mysub#myfsname'), \
        'unexpected source: %r' % info['source']


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
def test_mountinfo_unprivileged_attrs(tmpdir, output_checker, name):
    if os.getuid() == 0:
        pytest.skip('only meaningful for unprivileged mounts via fusermount3')
    with hello_mount(tmpdir, output_checker, name) as mnt:
        info = parse_mountinfo(mnt)
    assert info is not None
    assert 'nosuid' in info['mount_options']
    assert 'nodev'  in info['mount_options']
