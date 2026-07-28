#!/usr/bin/env bash
# GROUP: mount

FS_NAME=hello_ll
MOUNT_OPTS=subtype=mysub

mountinfo_assert()
{
	_assert_fstype "$TEST_MNT" fuse.mysub
}

. "$TEST_LIB/mountinfo.sh"
