#!/usr/bin/env bash
# GROUP: misc serial

# The protocol goes over a socket here, not /dev/fuse.
_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_binary example/hello_ll_uds

# hello_ll_uds hard-codes this path, hence GROUP serial: two copies of the
# test would fight over it.
sockpath=/tmp/libfuse-hello-ll.sock

# It never calls fuse_mount, so none of the mount verbs apply: it serves the
# FUSE protocol over an AF_UNIX socket through fuse_session_custom_io().
"$FUSE_EXAMPLE_DIR/hello_ll_uds" >"$TEST_LOGDIR/fs-0-hello_ll_uds.out" 2>&1 &
uds_pid=$!
_at_exit "rm -f '$sockpath'"
_at_exit "kill $uds_pid 2>/dev/null"

_wait_for 10 "[ -S '$sockpath' ]" || _fail "$sockpath never appeared"

_check fuse_test_uds_init "$sockpath"
