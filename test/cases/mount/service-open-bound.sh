#!/usr/bin/env bash
# GROUP: mount
#
# fuservicemount3 opens a file for the fuse server only if the path is on its
# command line, and only before the server has sent the mount point.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fuservicemount3"
_require_root
_require_fuse_device
_require_binary util/fuservicemount3
_require_binary test/test_service

. "$TEST_LIB/service.sh"

# One socket per run, so a parallel run does not connect to this one
subtype=test-open-$$
img=$TEST_SRC/img

touch "$img"
service_setup "$subtype"

# service_open_request <case> <path> <expected errno name, or 0>
# Mount $img through fuservicemount3 with the server started for <case>.
service_open_request()
{
	local case=$1 path=$2 expected=$3

	service_mount "$img" "$TEST_MNT" "$case" "$path"
	_assert_eq "$(service_result request)" "$expected" "$case $path"
}

# $img is on the command line
service_open_request open "$img" 0
# Root can read /etc/passwd, so EPERM comes from the command line check
service_open_request open /etc/passwd EPERM
# Passes the command line check, fails the block device check
service_open_request open-bdev "$img" ENOTBLK
# Not ENOTBLK: OPEN_BDEV gets the command line check first
service_open_request open-bdev /etc/passwd EPERM

# On the command line, but after MNTPT the helper runs inside $TEST_MNT
service_open_request open-after-mount "$img" EPERM
umount "$TEST_MNT"
