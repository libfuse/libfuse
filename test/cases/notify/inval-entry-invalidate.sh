#!/usr/bin/env bash
# GROUP: notify

. "$TEST_LIB/common.sh"

FS_NAME=notify_inval_entry
NOTIFY=1
NOTIFY_MODE=entry
FS_ARGS="--timeout=5"

. "$TEST_LIB/notify.sh"
