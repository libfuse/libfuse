#!/usr/bin/env bash
# GROUP: ctests

. "$TEST_LIB/common.sh"

_require_cap FUSE_CAP_WRITEBACK_CACHE

"$FUSE_TEST_BIN_DIR/test_write_cache" "$TEST_MNT" -owriteback_cache
