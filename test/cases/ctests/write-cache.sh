#!/usr/bin/env bash
# GROUP: ctests

. "$TEST_LIB/common.sh"

_require_cap FUSE_CAP_WRITEBACK_CACHE

# --delay_ms tests that close(rofd) does not block waiting for pending writes,
# which needs a390ccb316be ("fuse: add FOPEN_NOFLUSH"). The suite assumes a
# current kernel; an older target excludes this test by name.
"$FUSE_TEST_BIN_DIR/test_write_cache" "$TEST_MNT" --delay_ms=200
