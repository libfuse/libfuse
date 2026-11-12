#!/usr/bin/env bash
# GROUP: examples passthrough
# Enable caching so fstat() can use the SETATTR reply.
# passthrough requires auto_cache to retain attribute timeouts.

. "$TEST_LIB/common.sh"

fuse_mount passthrough -o auto_cache,entry_timeout=30,attr_timeout=30 >/dev/null

# passthrough mirrors the real tree, so the mount's view of $TEST_TMP is
# $TEST_MNT$TEST_TMP.
_check fuse_test_open_unlink_setattr "$TEST_MNT$TEST_TMP"

fuse_umount
