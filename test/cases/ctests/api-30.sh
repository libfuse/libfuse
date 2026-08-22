#!/usr/bin/env bash
# GROUP: ctests
# Serve a filesystem built against the FUSE_USE_VERSION 30 API.

. "$TEST_LIB/common.sh"

"$FUSE_TEST_BIN_DIR/test_api_30" "$TEST_MNT"
