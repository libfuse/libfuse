#!/usr/bin/env bash
# GROUP: examples passthrough
# 500-entry readdir plus test_syscalls over FUSE; the default 60s is
# not enough on a loaded runner, and -d makes it slower again.
# TIMEOUT: 300

. "$TEST_LIB/common.sh"

FS_NAME=passthrough_ll
FS_ARGS="-f -o timeout=0"
INODE_CHECK=exact
PT_MIRROR=1
PT_SRC_VISIBLE=1

. "$TEST_LIB/passthrough.sh"
