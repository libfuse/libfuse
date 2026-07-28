# lib/mountinfo.sh - body for the /proc/self/mountinfo cases.
#
# Caller sets FS_NAME (hello or hello_ll), optionally MOUNT_OPTS, and defines
# mountinfo_assert(). It may also define mountinfo_setup(), which runs before
# the mount and may extend MOUNT_OPTS.
#
# These tests assert what the kernel recorded for a mount, which is what
# differs between the legacy mount(2) path and the fsopen/fsconfig/fsmount
# path: an option dropped on one of them shows up here and nowhere else.

# Every assertion below is about what /proc/self/mountinfo reports, and
# getmntinfo(3) exposes neither the subtype nor the mount/super option split
# these tests exist to check.
_require_linux "/proc/self/mountinfo"

# hello_ll supports single-threading only.
FS_EXTRA=
[ "$FS_NAME" != hello_ll ] || FS_EXTRA=-s

if declare -F mountinfo_setup >/dev/null; then
	mountinfo_setup
fi

fuse_mount "$FS_NAME" $FS_EXTRA ${MOUNT_OPTS:+-o "$MOUNT_OPTS"} >/dev/null

# While it is still mounted: the mountinfo line disappears with the mount.
mountinfo_assert

fuse_umount
