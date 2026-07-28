#!/usr/bin/env bash
# GROUP: notify

. "$TEST_LIB/common.sh"

# The kernel has to support expiring an entry rather than
# invalidating it; printcap reports whether it does.
_require_cap FUSE_CAP_EXPIRE_ONLY

FS_NAME=notify_inval_entry
NOTIFY=0
NOTIFY_MODE=entry
FS_ARGS="--timeout=5 --only-expire"

. "$TEST_LIB/notify.sh"
