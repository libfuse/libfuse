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
    mp = output_checker.Popen(cmdline)
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


# (label, options, must-be-in mount_options, must-NOT-be-in mount_options)
#
# Library defaults are MS_NOSUID|MS_NODEV (lib/mount.c,
# util/fusermount.c), so a no-options mount is expected to land
# with both attrs set. The negation forms (suid/dev) clear the default
# flags via lib/mount.c:set_mount_flag(), which on the new mount API
# path means MOUNT_ATTR_NOSUID/MOUNT_ATTR_NODEV are not set in the
# fsmount() call. Asserting their absence catches a routing bug where
# the negation wasn't honored.
ATTR_CASES = [
    ('default',  (),          ('rw', 'nosuid', 'nodev'), ('ro',)),
    ('ro',       ('ro',),     ('ro',),                   ('rw',)),
    ('nosuid',   ('nosuid',), ('nosuid',),               ()),
    ('nodev',    ('nodev',),  ('nodev',),                ()),
]

# suid/dev are root-only: the kernel rejects MS_NOSUID/MS_NODEV being
# cleared for unprivileged mounts, and fusermount3 hard-codes them on
# anyway (util/fusermount.c:988).
ATTR_CASES_ROOT = [
    ('suid',     ('suid',),   (),                        ('nosuid',)),
    ('dev',      ('dev',),    (),                        ('nodev',)),
]


def _check_attrs(info, must_have, must_not_have):
    assert info is not None
    for opt in must_have:
        assert opt in info['mount_options'], \
            '%r missing from mount_options=%r' % (opt, info['mount_options'])
    for opt in must_not_have:
        assert opt not in info['mount_options'], \
            'unexpected %r in mount_options=%r' % (opt, info['mount_options'])


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
@pytest.mark.parametrize('label,opts,must_have,must_not_have', ATTR_CASES,
                         ids=[c[0] for c in ATTR_CASES])
def test_mountinfo_attrs(tmpdir, output_checker, name,
                         label, opts, must_have, must_not_have):
    with hello_mount(tmpdir, output_checker, name, opts) as mnt:
        info = parse_mountinfo(mnt)
    _check_attrs(info, must_have, must_not_have)
    # ro/rw also surface in super_options; if we asked for ro the
    # superblock must agree. Catches a path that sets MOUNT_ATTR_RDONLY
    # but forgets the FSCONFIG-side MS_RDONLY (or vice versa).
    if 'ro' in must_have:
        assert 'ro' in info['super_options'], \
            'ro on mount but rw on superblock: super_options=%r' % \
                info['super_options']


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
@pytest.mark.parametrize('label,opts,must_have,must_not_have',
                         ATTR_CASES_ROOT,
                         ids=[c[0] for c in ATTR_CASES_ROOT])
def test_mountinfo_attrs_root(tmpdir, output_checker, name,
                              label, opts, must_have, must_not_have):
    if os.getuid() != 0:
        pytest.skip('clearing nosuid/nodev requires root')
    with hello_mount(tmpdir, output_checker, name, opts) as mnt:
        info = parse_mountinfo(mnt)
    _check_attrs(info, must_have, must_not_have)


@pytest.mark.parametrize('name', ('hello', 'hello_ll'))
def test_mountinfo_blkdev_with_fsname(tmpdir, output_checker, name):
    """
    Test block device mount with fsname and subtype.

    This test validates the ENODEV fallback logic for block devices with fsname.
    When mounting with blkdev=1, fsname=<device>, and subtype=mysub, the mount
    source should be the device name (fsname), not the filesystem type string.

    The ENODEV fallback has three cases:
    1. fsname + non-blkdev -> "subtype#fsname" (legacy format for regular FUSE)
    2. fsname + blkdev     -> fsname only (THIS TEST - for block devices)
    3. no fsname           -> type string

    This test catches a regression where the logic was incorrectly simplified
    from nested conditionals to a single combined condition (fsname && !blkdev),
    causing case 2 to fall through to case 3 and use 'fuseblk' instead of the
    device name.

    Requires root to create loop devices; skipped otherwise.
    """
    if os.getuid() != 0:
        pytest.skip('blkdev option requires root')

    import tempfile

    # Create a file to use as a loop device
    with tempfile.NamedTemporaryFile(mode='wb', delete=False,
                                     dir=str(tmpdir)) as f:
        loop_file = f.name
        # Create a 1MB file
        f.write(b'\0' * (1024 * 1024))

    try:
        # Create loop device from file
        result = subprocess.run(['losetup', '-f', '--show', loop_file],
                               capture_output=True, text=True, check=True)
        loop_dev = result.stdout.strip()

        try:
            # Mount with blkdev, fsname, and subtype
            # The fsname should be the loop device
            with hello_mount(tmpdir.mkdir('mnt'), output_checker, name,
                           ('blkdev', f'fsname={loop_dev}', 'subtype=mysub')) as mnt:
                info = parse_mountinfo(mnt)

            assert info is not None, 'mountpoint not found in /proc/self/mountinfo'

            # For block devices, fstype should be 'fuseblk' or 'fuseblk.mysub'
            # depending on whether the kernel supports the subtype
            assert info['fstype'] in ('fuseblk', 'fuseblk.mysub'), \
                f"unexpected fstype for blkdev: {info['fstype']}"

            # CRITICAL: Source should be the loop device name (fsname), NOT 'fuseblk'
            # This is what the fix ensures - before the fix, it would be 'fuseblk'
            # because the incorrect condition treated (fsname && blkdev) as (no fsname)
            assert info['source'] == loop_dev, \
                f"blkdev source should be fsname ({loop_dev}), got {info['source']}"

        finally:
            # Detach loop device
            subprocess.run(['losetup', '-d', loop_dev], check=False)

    finally:
        # Clean up file
        try:
            os.unlink(loop_file)
        except OSError:
            # Ignore cleanup errors - file may already be deleted or inaccessible
            pass
