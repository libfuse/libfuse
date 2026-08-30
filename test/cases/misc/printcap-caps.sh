#!/usr/bin/env bash
# GROUP: misc quick

# Two headers compared as text; nothing here opens /dev/fuse.
_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

# printcap's capability table (lib/fuse_cap_names_i.h) must list every
# FUSE_CAP_* that fuse_common.h defines, or a new capability silently never
# appears in $FUSE_CAPS and every gate on it skips.
_check fuse_test_printcap_caps "$TEST_DIR/.."
