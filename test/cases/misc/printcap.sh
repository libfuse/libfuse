#!/usr/bin/env bash
# GROUP: misc quick

. "$TEST_LIB/common.sh"

_require_binary example/printcap

# The runner already ran printcap once to build $FUSE_CAPS; this is the case
# that fails rather than silently reporting no capabilities when it breaks.
"$FUSE_EXAMPLE_DIR/printcap"
[ -n "$FUSE_CAPS" ] || _fail "printcap reported no capabilities"
