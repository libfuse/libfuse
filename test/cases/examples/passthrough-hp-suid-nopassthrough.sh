#!/usr/bin/env bash
# GROUP: examples passthrough
# The same check with the write served by the daemon rather than by a backing
# file, so both of passthrough_hp's write paths get the same assertion.

FS_ARGS="--foreground --nopassthrough"

. "$TEST_LIB/passthrough-suid.sh"
