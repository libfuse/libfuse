#!/usr/bin/env bash
# GROUP: ctests quick
# Unit test for the mount_flags safe column -- no FUSE mount needed.

. "$TEST_LIB/common.sh"

"$FUSE_TEST_BIN_DIR/test_mount_flags"
