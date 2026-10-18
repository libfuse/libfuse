#!/usr/bin/env bash
# GROUP: mount quick
#
# fusermount3 -u hands a path to umount2(), which unmounts whatever is on top
# there. A mount stacked over the caller's FUSE mount must make fusermount3
# refuse rather than unmount that mount instead.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "/proc/self/mountinfo"
# Root may unmount anything; the check is for the setuid helper's caller.
_require_nonroot
_require_fuse_device
_require_binary util/fusermount3
[ -u "$FUSE_UTIL_DIR/fusermount3" ] ||
	_notrun "$FUSE_UTIL_DIR/fusermount3 is not setuid"
_require_prog sudo
_require_prog unshare
sudo -n true >/dev/null 2>&1 || _notrun "needs non-interactive sudo"
# The mounts are made with mount(2) and do not show up in a regular-file mtab.
[ -L /etc/mtab ] || _notrun "/etc/mtab is not a symlink"

# Root stacks the mounts in a private mount namespace, so none of them reach
# the host, and runs the helper as this user. The namespace and every mount
# in it go away when the check exits.
sudo -n env PATH="$PATH" FUSE_UTIL_DIR="$FUSE_UTIL_DIR" \
	unshare --mount --propagation private -- \
	python3 "$TEST_LIB/checks.py" fuse_test_fusermount_overmount \
	"$FUSE_UID" "$TEST_TMP"
