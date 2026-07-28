#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

FS_NAME=hello_ll
MOUNT_OPTS=nosuid

mountinfo_assert()
{
	_assert_mount_opt "$TEST_MNT" nosuid
}

. "$TEST_LIB/mountinfo.sh"
