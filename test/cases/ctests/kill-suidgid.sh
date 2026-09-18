#!/usr/bin/env bash
# GROUP: ctests
# KILLPRIV_V2 asks the filesystem per request to drop suid/sgid. The kernel
# only asks a caller that lacks CAP_FSETID, which the test binary gives up
# for itself, so this runs as root too.

. "$TEST_LIB/common.sh"

_require_cap FUSE_CAP_HANDLE_KILLPRIV_V2

"$FUSE_TEST_BIN_DIR/test_setattr" --kill-suidgid "$TEST_MNT"
"$FUSE_TEST_BIN_DIR/test_setattr" --kill-suidgid --write-buf "$TEST_MNT"

# A filesystem that did not negotiate KILLPRIV_V2 must never see
# fi->kill_suidgid, even though fuse_direct_io() still puts
# FUSE_WRITE_KILL_SUIDGID on the wire.
"$FUSE_TEST_BIN_DIR/test_setattr" --kill-suidgid --no-killpriv "$TEST_MNT"
