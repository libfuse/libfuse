#!/usr/bin/env bash
# GROUP: examples passthrough
# 500-entry readdir plus test_syscalls over FUSE; the default 60s is
# not enough on a loaded runner, and -d makes it slower again.
# TIMEOUT: 300

. "$TEST_LIB/common.sh"

FS_NAME=passthrough_hp
FS_ARGS="--foreground"
PT_POSITIONAL="$TEST_SRC"
INODE_CHECK=exact
PT_MIRROR=0
# With the cache on the mount is allowed a stale view of the
# source, so nothing may be compared against it.
PT_SRC_VISIBLE=0

. "$TEST_LIB/passthrough.sh"
