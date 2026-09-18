#!/usr/bin/env bash
# GROUP: notify

FS_NAME=notify_store_retrieve
NOTIFY=1
NOTIFY_MODE=content
# There is no capability flag for FUSE_NOTIFY_STORE, so the gate is
# what notify_store_retrieve itself prints when the kernel refuses it.
MARKER_ABSENT="not supported by kernel"

. "$TEST_LIB/notify.sh"
