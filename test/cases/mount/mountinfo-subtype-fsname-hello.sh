#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

FS_NAME=hello
MOUNT_OPTS=subtype=mysub,fsname=myfsname

mountinfo_assert()
{
	_assert_fstype "$TEST_MNT" fuse.mysub
	_assert_source "$TEST_MNT" myfsname mysub#myfsname
}

. "$TEST_LIB/mountinfo.sh"
