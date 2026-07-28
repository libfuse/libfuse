#!/usr/bin/env bash
# GROUP: examples

. "$TEST_LIB/common.sh"

_require_binary example/null

# The null filesystem replaces a regular file rather than a directory, so
# there is no mountpoint to poll for; it announces itself by the size it
# reports growing past what the placeholder holds.
mnt_file=$TEST_TMP/file
printf 'dummy' >"$mnt_file"

null_is_up()
{
	python3 "$TEST_LIB/checks.py" fuse_test_isbigger "$1" 4000
}

FUSE_WAIT_PREDICATE=null_is_up
fuse_mount_at "$mnt_file" null -f >/dev/null

_check fuse_test_null_roundtrip "$mnt_file"

fuse_umount
