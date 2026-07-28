#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

FS_NAME=hello
MOUNT_OPTS=ro

mountinfo_assert()
{
	_assert_mount_opt "$TEST_MNT" ro
	_refute_mount_opt "$TEST_MNT" rw
	_assert_super_opt "$TEST_MNT" ro
}

. "$TEST_LIB/mountinfo.sh"
