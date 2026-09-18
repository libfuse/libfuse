#!/usr/bin/env bash
# GROUP: ctests
# A setattr from an open fd has to carry that fd's file handle.

. "$TEST_LIB/common.sh"

"$FUSE_TEST_BIN_DIR/test_setattr" "$TEST_MNT"
