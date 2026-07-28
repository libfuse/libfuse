#!/usr/bin/env bash
# GROUP: examples passthrough
# 500-entry readdir plus test_syscalls over FUSE; the default 60s is
# not enough on a loaded runner, and -d makes it slower again.
# TIMEOUT: 300

. "$TEST_LIB/common.sh"

FS_NAME=passthrough_ll
FS_ARGS="-f -o timeout=0 -o writeback"
INODE_CHECK=exact
PT_MIRROR=1
PT_SRC_VISIBLE=1
# With writeback caching the kernel opens files for reading even
# when userspace asked for O_WRONLY, which fails unless the
# filesystem process has special permission.
SYSCALL_ARGS=-53

. "$TEST_LIB/passthrough.sh"
