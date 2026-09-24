#!/usr/bin/env bash
# GROUP: mount
#
# The null example mounts through fuservicemount3 on a regular file.
# null has no backing file and mounts on a regular file, so it does not use
# lib/service-example.sh.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fuservicemount3"
_require_root
_require_fuse_device
_require_binary util/fuservicemount3
_require_binary example/null

. "$TEST_LIB/service.sh"

service_setup "test-null-$$"
mnt_file=$TEST_TMP/file
_at_exit "umount -l '$mnt_file' 2>/dev/null"
printf 'dummy' >"$mnt_file"

service_start "$TEST_LOGDIR/fs-null.out" "$FUSE_EXAMPLE_DIR/null"
# null takes no source, only the mount point
"$FUSE_UTIL_DIR/fuservicemount3" "$mnt_file" -t "fuse.$service_subtype" ||
	_fail "fuservicemount3 did not mount null"

_check fuse_test_null_roundtrip "$mnt_file"

umount "$mnt_file"
service_wait_exit
_assert_eq "$service_rc" 0 "null exit status"
