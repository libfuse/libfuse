#!/usr/bin/env bash
# GROUP: mount
#
# Only the last component of a mountpoint is refused as a symlink, so a
# mountpoint reached through a symlinked parent still mounts. Guards against a
# resolution rule that rejects a symlink anywhere in the path and so breaks
# every user whose mountpoint sits below a symlinked home.

. "$TEST_LIB/common.sh"

# Root mounts with mount(2) and reaches fusermount3 only on EPERM, so the
# resolution rule under test is not on the path a root run takes.
_require_nonroot

mkdir -p "$TEST_TMP/real/mnt"
ln -s "$TEST_TMP/real" "$TEST_TMP/link"

fuse_mount_at "$TEST_TMP/link/mnt" hello -f >/dev/null

# Named through the real path, not through the symlink: what is being checked
# is that the mount landed on the inode the symlink resolved to.
_check fuse_test_ismount "$TEST_TMP/real/mnt"
_assert_listdir "$TEST_TMP/real/mnt" hello

fuse_umount
