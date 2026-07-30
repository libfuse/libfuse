#!/usr/bin/env bash
# GROUP: mount

FS_NAME=hello_ll

utab_setup()
{
	MOUNT_DIR=$TEST_TMP/-evil
	mkdir "$MOUNT_DIR"
}

utab_assert()
{
	# fuse_mnt_resolve_path() makes the mountpoint absolute, so a
	# dash-prefixed basename never becomes an option-like operand.
	_assert_utab_target "$MOUNT_DIR"
}

. "$TEST_LIB/utab.sh"
