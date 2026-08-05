#!/usr/bin/env bash
# GROUP: notify

FS_NAME=notify_prune
NOTIFY=0
NOTIFY_MODE=prune
# There is no capability flag for FUSE_NOTIFY_PRUNE, so the gate
# is what notify_prune itself prints when the kernel refuses the
# request.
MARKER_ABSENT="not supported by kernel"

. "$TEST_LIB/notify.sh"
