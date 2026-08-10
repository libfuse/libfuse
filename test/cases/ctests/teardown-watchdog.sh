#!/usr/bin/env bash
# GROUP: ctests
# The timeout thread must detect a connection abort.

. "$TEST_LIB/common.sh"

"$FUSE_TEST_BIN_DIR/test_teardown_watchdog"
