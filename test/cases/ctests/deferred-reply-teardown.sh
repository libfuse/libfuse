#!/usr/bin/env bash
# GROUP: ctests
# Teardown must drain a reply deferred past fuse_session_exit().

. "$TEST_LIB/common.sh"

# A status that is examined has to be captured in the same command.
status=0
"$FUSE_TEST_BIN_DIR/test_deferred_reply_teardown" "$TEST_MNT" || status=$?

[ "$status" -ne 77 ] || _notrun "the session did not get a ring"
[ "$status" -eq 0 ] || _fail "test_deferred_reply_teardown exited $status"
