#!/usr/bin/env bash
# GROUP: ctests
# Signal handling, issue #1182.

. "$TEST_LIB/common.sh"

"$FUSE_TEST_BIN_DIR/test_signals"
