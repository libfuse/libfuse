#!/usr/bin/env bash
# GROUP: ctests
# TIMEOUT: 30
# A write to a stream file while a read on the same fd waits in the
# filesystem for that write's data. Without FOPEN_STREAM the write blocks
# on the file position lock and the test runs into the timeout.

. "$TEST_LIB/common.sh"

_require_linux FOPEN_STREAM

"$FUSE_TEST_BIN_DIR/test_stream" "$TEST_MNT"
