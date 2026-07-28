#!/usr/bin/env bash
# GROUP: examples

. "$TEST_LIB/common.sh"

fuse_mount poll >/dev/null

# poll_client looks at files in its own working directory.
(cd "$TEST_MNT" && "$FUSE_EXAMPLE_DIR/poll_client")

fuse_umount
