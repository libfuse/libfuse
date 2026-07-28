#!/usr/bin/env bash
# GROUP: examples

. "$TEST_LIB/common.sh"

_require_binary example/ioctl
_require_not_32bit_on_64 "$FUSE_EXAMPLE_DIR/ioctl"

fuse_mount ioctl >/dev/null

testfile=$TEST_MNT/fioc
client=$FUSE_EXAMPLE_DIR/ioctl_client

_assert_eq "$("$client" "$testfile")" 0 "initial size"
printf 'foobar' >"$testfile"
_assert_eq "$("$client" "$testfile")" 6 "size after write"

# With a size argument the client truncates instead of reporting.
"$client" "$testfile" 3
printf 'foo' >"$TEST_TMP/expected"
_assert_file_eq "$testfile" "$TEST_TMP/expected"

fuse_umount
