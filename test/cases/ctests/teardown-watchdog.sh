#!/usr/bin/env bash
# GROUP: ctests
# The timeout thread must detect a connection abort.

. "$TEST_LIB/common.sh"

_require_linux "/sys/fs/fuse/connections"
[ -d /sys/fs/fuse/connections ] ||
	_notrun "fusectl is not mounted on /sys/fs/fuse/connections"

# An aborted connection is deliberately left mounted by fuse_session_unmount(),
# so the mount outlives the test binary.
_at_exit "fusermount3 -z -u '$TEST_MNT' >/dev/null 2>&1"

# The test says what it is about to do, in the word the log scanner watches for.
fuse_allow_output 'connection abort'

"$FUSE_TEST_BIN_DIR/test_teardown_watchdog" "$TEST_MNT"
