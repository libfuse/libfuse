#!/usr/bin/env bash
# GROUP: mount
#
# A fuse server that exits without a goodbye makes fuservicemount3 fail, and
# leaves nothing mounted.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fuservicemount3"
_require_root
_require_fuse_device
_require_binary util/fuservicemount3
_require_binary test/test_service

. "$TEST_LIB/service.sh"

service_setup "test-exit-$$"

service_mount "$service_subtype" "$TEST_MNT" exit-early
_assert_ne "$service_helper_rc" 0 "fuservicemount3 exit status"
_assert_eq "$(mountinfo_field "$TEST_MNT" fstype)" "" "$TEST_MNT mounted"
