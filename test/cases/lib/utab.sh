# lib/utab.sh - body for the /run/mount/utab cases.
#
# Caller sets FS_NAME (hello or hello_ll), optionally MOUNT_OPTS, and defines
# utab_assert(). It may also define utab_setup(), which runs before the mount
# and may set MOUNT_DIR or extend MOUNT_OPTS.
#
# These tests assert what the mount left behind in /run/mount/utab, the record
# lib/mount_util.c skips for an argument a mount(8) could read as an option.

. "$TEST_LIB/common.sh"

# utab is util-linux's, and the assertions read /proc/self/mountinfo with it.
_require_linux "/run/mount/utab"
[ -e /run/mount/utab ] || _notrun "no /run/mount/utab on this host"

# hello_ll supports single-threading only.
FS_EXTRA=
[ "$FS_NAME" != hello_ll ] || FS_EXTRA=-s

if declare -F utab_setup >/dev/null; then
	utab_setup
fi

fuse_mount_at "${MOUNT_DIR:-$TEST_MNT}" "$FS_NAME" -f $FS_EXTRA \
	${MOUNT_OPTS:+-o "$MOUNT_OPTS"} >/dev/null

# While it is still mounted: the utab record goes away with the mount.
utab_assert

fuse_umount
