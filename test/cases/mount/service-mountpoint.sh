#!/usr/bin/env bash
# GROUP: mount
#
# The fuse server names the mount point, so fuservicemount3 has to refuse one
# that is not on its command line, and one of the wrong file type.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fuservicemount3"
_require_root
_require_fuse_device
_require_binary util/fuservicemount3
_require_binary test/test_service

. "$TEST_LIB/service.sh"

file=$TEST_SRC/file

touch "$file"
service_setup "test-mntpt-$$"

service_mount "$service_subtype" "$TEST_MNT" mount dir
_assert_eq "$(service_result mount)" 0 "mount dir on a directory"
_assert_fstype "$TEST_MNT" "fuse.$service_subtype" fuse
umount "$TEST_MNT"

service_mount "$service_subtype" "$TEST_MNT" mount-elsewhere "$TEST_SRC"
_assert_eq "$(service_result mount)" EINVAL \
	"mount point not on the command line"

service_mount "$service_subtype" "$TEST_MNT" mount file
_assert_eq "$(service_result mount)" EISDIR "mount file on a directory"

service_mount "$service_subtype" "$file" mount dir
_assert_eq "$(service_result mount)" ENOTDIR "mount dir on a regular file"
