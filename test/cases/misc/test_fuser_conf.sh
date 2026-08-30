#!/usr/bin/env bash
# GROUP: unit quick
#
# The fuse.conf line trimmer -- no FUSE mount needed.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_binary test/test_fuser_conf

exec "$FUSE_TEST_BIN_DIR/test_fuser_conf"
