#!/usr/bin/env bash
# GROUP: mount
#
# fuservicemount3 installed setuid and run by an unprivileged user mounts only
# on a directory that user can write, and never offers fuseblk.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fuservicemount3"
# Root installs the setuid copy and the socket
_require_root
_require_fuse_device
_require_binary util/fuservicemount3
_require_binary test/test_service
_require_prog setpriv
_require_prog findmnt

user=nobody
uid=$(id -u "$user") || _notrun "no user $user"
gid=$(id -g "$user")
run_as=(setpriv --reuid="$uid" --regid="$gid" --clear-groups)

helper=$TEST_WORKDIR/fuservicemount3
case ",$(findmnt -n -o OPTIONS -T "$TEST_WORKDIR")," in
*,nosuid,*) _notrun "$TEST_WORKDIR is on a nosuid mount" ;;
esac
cp "$FUSE_UTIL_DIR/fuservicemount3" "$helper"
_at_exit "rm -f '$helper'"
chmod 4755 "$helper"
"${run_as[@]}" test -x "$helper" || _notrun "$user cannot reach $helper"

. "$TEST_LIB/service.sh"

service_setup "test-nonroot-$$"
service_helper=("${run_as[@]}" "$helper")
root_dir=$TEST_WORKDIR/root-mnt
mkdir -m 0755 "$root_dir"

chown "$uid" "$TEST_MNT"
service_mount "$service_subtype" "$TEST_MNT" mount dir
_assert_eq "$(service_result mount)" 0 "mount on a directory $user owns"
umount "$TEST_MNT"

service_mount "$service_subtype" "$root_dir" mount dir
_assert_eq "$(service_result mount)" EPERM \
	"mount on a directory owned by root"

# allow_other depends on user_allow_other in the system fuse.conf
service_mount "$service_subtype" "$TEST_MNT" caps
case $(service_result caps) in
*" fuseblk=0") ;;
*) _fail "caps as $user: $(service_result caps)" ;;
esac
