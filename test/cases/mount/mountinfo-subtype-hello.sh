#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

FS_NAME=hello
MOUNT_OPTS=subtype=mysub

mountinfo_assert()
{
	_assert_fstype "$TEST_MNT" fuse.mysub
}

. "$TEST_LIB/mountinfo.sh"
