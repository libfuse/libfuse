#!/usr/bin/env bash
# GROUP: mount
#
# fuservicemount3 run by root offers the fuse server allow_other and fuseblk.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fuservicemount3"
_require_root
_require_fuse_device
_require_binary util/fuservicemount3
_require_binary test/test_service

. "$TEST_LIB/service.sh"

service_setup "test-caps-$$"

service_mount "$service_subtype" "$TEST_MNT" caps
_assert_eq "$(service_result caps)" "allow_other=1 fuseblk=1" "caps as root"
