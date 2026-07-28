#!/usr/bin/env bash
# GROUP: mount

FS_NAME=hello
MOUNT_OPTS=fsname=myfsname

mountinfo_assert()
{
	_assert_source "$TEST_MNT" myfsname
}

. "$TEST_LIB/mountinfo.sh"
