# lib/passthrough.sh - body for the passthrough* cases.
#
# Caller sets before sourcing:
#   FS_NAME         example to mount
#   FS_ARGS         its arguments, without the mountpoint
#   INODE_CHECK     exact | nonzero
#   PT_MIRROR       1 when the example mirrors the whole tree, so the work
#                   directory is $TEST_MNT$TEST_SRC rather than $TEST_MNT
#   PT_SRC_VISIBLE  1 when a change made directly in $TEST_SRC is expected to
#                   show up under the mount straight away
#   PT_POSITIONAL   extra trailing arguments before the mountpoint, optional
#   SYSCALL_ARGS    extra test_syscalls arguments, optional
#
# PT_SRC_VISIBLE is one flag covering three decisions the Python made
# separately, because they are the same question: with attribute caching on,
# passthrough_hp's mount must not be compared against a source directory it is
# allowed to have a stale view of.

. "$TEST_LIB/common.sh"

fuse_mount_at "$TEST_MNT" "$FS_NAME" $FS_ARGS ${PT_POSITIONAL:-} >/dev/null

if [ "$PT_MIRROR" = 1 ]; then
	work_dir=$TEST_MNT$TEST_SRC
else
	work_dir=$TEST_MNT
fi

# test_syscalls prints "No error" under FreeBSD.
fuse_allow_output "^ [0-9][0-9] \[[^]]+ message: 'No error: 0'\]"

_check fuse_test_statvfs       "$work_dir"
_check fuse_test_readdir       "$TEST_SRC" "$work_dir" --inode-check "$INODE_CHECK"
_check fuse_test_readdir_big   "$TEST_SRC" "$work_dir" --inode-check "$INODE_CHECK"
_check fuse_test_open_read     "$TEST_SRC" "$work_dir"
_check fuse_test_open_write    "$TEST_SRC" "$work_dir"
_check fuse_test_create        "$work_dir"
[ "$PT_SRC_VISIBLE" != 1 ] ||
	_check fuse_test_passthrough "$TEST_SRC" "$work_dir" --inode-check "$INODE_CHECK"
_check fuse_test_append        "$TEST_SRC" "$work_dir"
_check fuse_test_seek          "$TEST_SRC" "$work_dir"
_check fuse_test_mkdir         "$work_dir"
if [ "$PT_SRC_VISIBLE" = 1 ]; then
	_check fuse_test_rmdir  "$work_dir" --src "$TEST_SRC"
	_check fuse_test_unlink "$work_dir" --src "$TEST_SRC"
else
	# With the cache on, no operation may go through $TEST_SRC: the
	# cache would become stale.
	_check fuse_test_rmdir  "$work_dir"
	_check fuse_test_unlink "$work_dir"
fi
_check fuse_test_symlink       "$work_dir"
[ "$FUSE_UID" -ne 0 ] || _check fuse_test_chown "$work_dir"
# The underlying fs may not have full nanosecond resolution.
_check fuse_test_utimens       "$work_dir" --ns-tol 1000
[ "$INODE_CHECK" != exact ] || _check fuse_test_link "$work_dir"
_check fuse_test_truncate_path "$work_dir"
_check fuse_test_truncate_fd   "$work_dir"
_check fuse_test_open_unlink   "$work_dir"

# test_syscalls assumes a change in the source directory is reflected in the
# mountpoint immediately, so it runs only where that holds. It is an extra
# layer on top of the checks above, not a substitute for them.
if [ "$PT_SRC_VISIBLE" = 1 ]; then
	# Its socket test binds under the work directory, and sun_path holds
	# 108 bytes -- $TEST_MNT$TEST_SRC alone is longer than that. Hand it a
	# short symlink instead; a symlinked prefix resolves the same for every
	# syscall it makes. /tmp literally, since shortness is the point.
	#
	# A bare link rather than a directory to put one in: _at_exit does not
	# run when the runner's timeout kills the test, and a dangling link is
	# the smallest thing to leak outside the work directory. ln without -f,
	# so a name mktemp -u handed out twice fails here instead of silently
	# stealing another run's link.
	short_link=$(mktemp -u /tmp/fuse-pt.XXXXXX)
	_at_exit "rm -f '$short_link'"
	ln -s "$work_dir" "$short_link"
	"$FUSE_TEST_BIN_DIR/test_syscalls" "$short_link" ":$TEST_SRC" \
		${SYSCALL_ARGS:-} || _fail "test_syscalls failed"
fi

fuse_umount
