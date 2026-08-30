#!/usr/bin/env bash
# GROUP: mount quick
#
# fusermount3 refuses a mountpoint it cannot validate. Every case here is
# rejected before mount(2) is reached, so this needs the kernel module but
# not a setuid fusermount3.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fusermount3"
# Root skips the mountpoint checks entirely and follows a symlinked mountpoint.
_require_nonroot
_require_fuse_device
_require_binary util/fusermount3

: >"$TEST_TMP/plain"
ln -s "$TEST_SRC" "$TEST_TMP/link-dir"
ln -s "$TEST_TMP/plain" "$TEST_TMP/link-reg"
ln -s "$TEST_TMP/gone" "$TEST_TMP/link-dangling"
mkfifo "$TEST_TMP/fifo"
mkdir "$TEST_TMP/nowrite"
chmod 500 "$TEST_TMP/nowrite"

# O_NOFOLLOW makes fstat() see the final symlink itself, so the target type
# cannot make a symlink acceptable as a mountpoint.
_check fuse_test_fusermount_rejects "$TEST_TMP/link-dir" not_dir_or_regular
_check fuse_test_fusermount_rejects "$TEST_TMP/link-reg" not_dir_or_regular
_check fuse_test_fusermount_rejects "$TEST_TMP/link-dangling" not_dir_or_regular

_check fuse_test_fusermount_rejects "$TEST_TMP/fifo" not_dir_or_regular
_check fuse_test_fusermount_rejects "$TEST_TMP/nowrite" no_write_access
_check fuse_test_fusermount_rejects "$TEST_TMP/missing" no_such_file
