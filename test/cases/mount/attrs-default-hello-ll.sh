#!/usr/bin/env bash
# GROUP: mount

FS_NAME=hello_ll

mountinfo_assert()
{
	_assert_mount_opt "$TEST_MNT" rw nosuid nodev
	_refute_mount_opt "$TEST_MNT" ro
}

. "$TEST_LIB/mountinfo.sh"
