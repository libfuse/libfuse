#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

FS_NAME=hello

mountinfo_assert()
{
	_assert_fstype "$TEST_MNT" fuse.hello fuse
	_assert_super_opt_prefix "$TEST_MNT" user_id= group_id=
}

. "$TEST_LIB/mountinfo.sh"
