#!/usr/bin/env bash
# GROUP: ctests quick
# Unit test for fuse_loop_cfg setter interaction -- no FUSE mount needed.

. "$TEST_LIB/common.sh"

"$FUSE_TEST_BIN_DIR/test_loop_config"
