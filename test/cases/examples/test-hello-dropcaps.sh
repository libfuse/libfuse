#!/usr/bin/env bash
# GROUP: examples quick

. "$TEST_LIB/common.sh"

FS_NAME=test/hello
FS_OPTS=
LAUNCH=mount_fuse_dropcaps

. "$TEST_LIB/hello.sh"
