#!/usr/bin/env bash
# GROUP: examples

. "$TEST_LIB/common.sh"

_require_binary example/ioctl_ll
_require_not_32bit_on_64 "$FUSE_EXAMPLE_DIR/ioctl_ll"

fuse_mount ioctl_ll >/dev/null

testfile=$TEST_MNT/fioc
client=$FUSE_EXAMPLE_DIR/ioctl_ll_client

# Restricted ioctls only. The unrestricted FIOC_READ/FIOC_WRITE work with
# CUSE rather than a regular FUSE mount, and are covered by examples/cuse.
_assert_eq "$("$client" get_size "$testfile")" 0 "initial size"
printf 'foobar' >"$testfile"
_assert_eq "$("$client" get_size "$testfile")" 6 "size after write"

"$client" set_size "$testfile" 3
printf 'foo' >"$TEST_TMP/expected"
_assert_file_eq "$testfile" "$TEST_TMP/expected"

fuse_umount
