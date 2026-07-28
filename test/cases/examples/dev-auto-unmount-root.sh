#!/usr/bin/env bash
# GROUP: examples

. "$TEST_LIB/common.sh"

# Root can mount with dev and auto_unmount; a non-root user cannot use the
# device nodes it exposes. Split in two so the summary says which half ran.
_require_root
_require_binary example/passthrough_ll

fuse_mount passthrough_ll -o source=/dev,dev,auto_unmount >/dev/null

cat "$TEST_MNT/null" >/dev/null

fuse_umount
