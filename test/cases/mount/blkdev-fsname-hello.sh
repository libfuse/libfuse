#!/usr/bin/env bash
# GROUP: mount serial

. "$TEST_LIB/common.sh"

_require_root
_require_prog losetup

FS_NAME=hello

mountinfo_setup()
{
	loop_file=$TEST_TMP/loop.img
	dd if=/dev/zero of="$loop_file" bs=1M count=1 status=none
	loop_dev=$(losetup -f --show "$loop_file")
	_at_exit "losetup -d '$loop_dev'"
	MOUNT_OPTS="blkdev,fsname=$loop_dev,subtype=mysub"
}

mountinfo_assert()
{
	# fstype carries the subtype only where the kernel took it.
	_assert_fstype "$TEST_MNT" fuseblk.mysub fuseblk
	# The source must be the device name, not 'fuseblk'.
	_assert_source "$TEST_MNT" "$loop_dev"
}

. "$TEST_LIB/mountinfo.sh"
