#!/usr/bin/env bash
# GROUP: mount

. "$TEST_LIB/common.sh"

# Which mount path runs is decided by who mounts, not by an option, and the
# suite runs as both: a privileged mount completes in-process via fsmount()
# with no fusermount3 anywhere, so the unmount helper has to be spawned
# separately, while an unprivileged mount goes through fusermount3, which
# stays alive and does the unmount itself.
_require_linux "/proc/self/mountinfo"

fuse_mount hello -o auto_unmount,dev,suid >/dev/null

# Same predicate the teardown is checked with, so a mountpoint it never
# matched cannot pass the test vacuously.
_assert_ne "$(mountinfo_field "$TEST_MNT" fstype)" "" \
	"$TEST_MNT missing from /proc/self/mountinfo while mounted"

# mountinfo names only the restriction, so dev/suid in effect means no
# nodev/nosuid. They live in the mount flags, which do not survive the exec
# into fusermount3 - only the privileged path keeps them.
if [ "$FUSE_UID" = 0 ]; then
	_refute_mount_opt "$TEST_MNT" nodev nosuid
else
	_assert_mount_opt "$TEST_MNT" nodev nosuid
fi

# An explicit umount tears the mount down on either path; only the daemon
# dying without one tells them apart.
kill -9 "$(fuse_fs_pid)"

# Nothing of ours is left to report the unmount - fusermount3 does it once
# the dead daemon's socket closes.
_wait_for 30 '[ -z "$(mountinfo_field "$TEST_MNT" fstype)" ]' ||
	_fail "auto_unmount left $TEST_MNT mounted after the daemon died"
