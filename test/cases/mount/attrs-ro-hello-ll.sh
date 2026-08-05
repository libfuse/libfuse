#!/usr/bin/env bash
# GROUP: mount

FS_NAME=hello_ll
MOUNT_OPTS=ro

mountinfo_assert()
{
	_assert_mount_opt "$TEST_MNT" ro
	_refute_mount_opt "$TEST_MNT" rw
	_assert_super_opt "$TEST_MNT" ro
}

. "$TEST_LIB/mountinfo.sh"
