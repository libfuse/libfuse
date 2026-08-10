#!/usr/bin/env bash
# GROUP: misc

# The protocol goes over a socket here, not /dev/fuse.
_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_binary example/hello_ll_uds

# Relative, hence short: sun_path holds 108 bytes, which the run directory
# alone can exhaust. The daemon inherits this script's cwd ($TEST_LOGDIR) and
# never chdirs, and checks.py runs in it too, so a bare name is the same
# socket from both ends. A name of its own per test also keeps a second run,
# or the root pass beside the non-root one, out of the way.
sockpath=hello_ll.sock

# It never calls fuse_mount, so none of the mount verbs apply: it serves the
# FUSE protocol over an AF_UNIX socket through fuse_session_custom_io().
"$FUSE_EXAMPLE_DIR/hello_ll_uds" --socket="$sockpath" \
	>"$TEST_LOGDIR/fs-0-hello_ll_uds.out" 2>&1 &
uds_pid=$!
_at_exit "kill $uds_pid 2>/dev/null"

_wait_for 10 "[ -S '$sockpath' ]" || _fail "$sockpath never appeared"

_check fuse_test_uds_init "$sockpath"
