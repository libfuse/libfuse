#!/usr/bin/env bash
# GROUP: examples serial

. "$TEST_LIB/common.sh"

# example/cuse is built on FreeBSD too, so an unbuilt binary is not a proxy
# for "cannot run": CUSE is a Linux FUSE protocol feature.
_require_linux CUSE
_require_root
_require_binary example/cuse
_require_not_32bit_on_64 "$FUSE_EXAMPLE_DIR/cuse"

# The device node is named globally, hence GROUP serial.
devname=cuse-test-$$
devpath=/dev/$devname

# cuse takes no mountpoint: it names its device with --name, and the test
# ends by terminating it rather than unmounting anything.
log=$TEST_LOGDIR/fs-0-cuse.out
"$FUSE_EXAMPLE_DIR/cuse" -f --name="$devname" >"$log" 2>&1 &
cuse_pid=$!
_at_exit "kill $cuse_pid 2>/dev/null"

_wait_for 30 "[ -e '$devpath' ]" || {
	cat "$log" >&2
	_fail "cuse did not create $devpath"
}

_check fuse_test_cuse_roundtrip "$devpath" "$FUSE_EXAMPLE_DIR/cuse_client"
