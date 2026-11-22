#!/usr/bin/env bash
# GROUP: examples quick

. "$TEST_LIB/common.sh"

# hello_reactor exits when fuse_uring_app_wait_submit() reports no ring.
if [ "$FUSE_URING_ENABLE" != 1 ]; then
	_notrun "hello_reactor needs io-uring (run-tests.py --io-uring)"
fi

# 1 MiB takes several FUSE requests in each direction.
head -c 1M /dev/urandom >"$TEST_TMP/backing"
fuse_mount hello_reactor --backing="$TEST_TMP/backing" >/dev/null

_assert_listdir "$TEST_MNT" hello
if ! cmp "$TEST_MNT/hello" "$TEST_TMP/backing"; then
	_fail "read through hello_reactor differs from the backing file"
fi

head -c 1M /dev/urandom >"$TEST_TMP/new"
dd if="$TEST_TMP/new" of="$TEST_MNT/hello" bs=128k conv=notrunc status=none
if ! cmp "$TEST_TMP/backing" "$TEST_TMP/new"; then
	_fail "write through hello_reactor did not reach the backing file"
fi

truncate -s 4096 "$TEST_MNT/hello"
_assert_eq "$(stat -c %s "$TEST_TMP/backing")" 4096 \
	"backing file size after truncate"

# The reactor thread returns only after it has reaped the -ENOTCONN
# completions that the umount produces.
fuse_umount
