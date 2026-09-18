#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

# The utab update runs only for a root mount; fusermount3 writes its own.
_require_root

FS_NAME=hello_ll
MOUNT_OPTS=fsname=-oro

utab_assert()
{
	# The mount still carries the fsname ...
	_assert_source "$TEST_MNT" -oro
	# ... but a mount(8) could read it as an option, so no utab record.
	_refute_utab_target "$TEST_MNT"
}

. "$TEST_LIB/utab.sh"
