#!/usr/bin/env bash
# GROUP: unit quick
#
# The release script's publish decisions -- no FUSE mount needed.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_prog python3

exec python3 "$TEST_DIR/test_release.py"
