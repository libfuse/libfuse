#!/usr/bin/env bash
# GROUP: mount

FS_NAME=hello_ll
MOUNT_OPTS=nosuid

mountinfo_assert()
{
	_assert_mount_opt "$TEST_MNT" nosuid
}

. "$TEST_LIB/mountinfo.sh"
