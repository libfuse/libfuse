#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

_require_root

FS_NAME=hello
MOUNT_OPTS=suid

mountinfo_assert()
{
	_refute_mount_opt "$TEST_MNT" nosuid
}

. "$TEST_LIB/mountinfo.sh"
