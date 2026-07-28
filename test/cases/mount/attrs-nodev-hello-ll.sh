#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

FS_NAME=hello_ll
MOUNT_OPTS=nodev

mountinfo_assert()
{
	_assert_mount_opt "$TEST_MNT" nodev
}

. "$TEST_LIB/mountinfo.sh"
