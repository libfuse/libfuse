#!/usr/bin/env bash
# GROUP: notify

FS_NAME=notify_inval_entry
NOTIFY=1
NOTIFY_MODE=entry
FS_ARGS="--timeout=5 --inc-epoch"
# There is no capability flag for the epoch counter, so the gate
# is what notify_inval_entry itself prints when the kernel
# refuses the request.
MARKER_ABSENT="not supported by kernel"

. "$TEST_LIB/notify.sh"
