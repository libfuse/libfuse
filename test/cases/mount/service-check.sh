#!/usr/bin/env bash
# GROUP: mount
#
# fuservicemount3 --check succeeds only for a socket named after the subtype,
# and never for a subtype that is a path.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fuservicemount3"
_require_root
_require_binary util/fuservicemount3
_require_binary test/test_service

. "$TEST_LIB/service.sh"

subtype=test-check-$$
service_setup "$subtype"

# check_rc <fstype>
check_rc()
{
	local rc=0

	"$FUSE_UTIL_DIR/fuservicemount3" -t "$1" --check || rc=$?
	echo "$rc"
}

_assert_eq "$(check_rc "fuse.$subtype")" 1 "no socket"

touch "$service_sock"
_assert_eq "$(check_rc "fuse.$subtype")" 1 "regular file"

service_start "$TEST_LOGDIR/fs-check.out" "$FUSE_TEST_BIN_DIR/test_service" caps
_assert_eq "$(check_rc "fuse.$subtype")" 0 "listening socket"
# The same socket, named through a path
_assert_eq "$(check_rc "fuse../$subtype")" 1 "subtype ./$subtype"
service_stop
