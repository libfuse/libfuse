# lib/hello.sh - body for the hello / hello_ll / test/hello cases.
#
# Caller sets FS_NAME, FS_OPTS and LAUNCH before sourcing:
#   FS_NAME   hello | hello_ll | test/hello
#   FS_OPTS   -o option list, empty for none
#   LAUNCH    direct | mount_fuse | mount_fuse_dropcaps
#
# The platform gates live here rather than in the 18 callers: three of them
# apply to whole columns of the matrix, and a caller that forgot one would
# fail on BSD instead of skipping.

# clone_fd needs the /dev/fuse clone device, which is Linux-only.
case $FS_OPTS in
*clone_fd*) _require_linux "the clone_fd mount option" ;;
esac

# hello_ll supports single-threading only.
FS_EXTRA=
[ "$FS_NAME" != hello_ll ] || FS_EXTRA=-s

case $LAUNCH in
direct)
	fuse_mount "$FS_NAME" $FS_EXTRA ${FS_OPTS:+-o "$FS_OPTS"} >/dev/null
	;;
mount_fuse)
	# util/ is not built on BSD, so there is no mount.fuse3 to invoke.
	_require_linux "mount.fuse3"
	fuse_mount_helper "$FS_NAME" ${FS_OPTS:+-o "$FS_OPTS"} >/dev/null
	;;
mount_fuse_dropcaps)
	_require_linux "mount.fuse3"
	_require_root
	# mount.fuse3 execs the fs only after dropping all capabilities, so
	# every directory on the way to the binary must be traversable by
	# plain permission bits - a mode-0700 home is not.
	_require_reachable_without_caps "$FS_NAME"
	fuse_mount_helper "$FS_NAME" \
		-o "${FS_OPTS:+$FS_OPTS,}drop_privileges" >/dev/null
	;;
*)
	_fail "unknown LAUNCH '$LAUNCH'"
	;;
esac

_assert_listdir "$TEST_MNT" hello
# Compared against a file rather than against "$(cat ...)": command
# substitution eats the trailing newline, so the shell form would not notice
# if the example stopped writing one.
printf 'Hello World!\n' >"$TEST_TMP/expected"
_assert_file_eq "$TEST_MNT/hello" "$TEST_TMP/expected"
_assert_errno EACCES fuse_test_open_rw "$TEST_MNT/hello"
_assert_errno ENOENT fuse_test_open_rw "$TEST_MNT/hello-does-not-exist"

# os.setxattr/getxattr/removexattr, which tst_xattr() used, exist only on Linux
# in CPython; FreeBSD's equivalent is extattr(2), a different API.
if [ "$FS_NAME" = hello_ll ] && _is_linux; then
	_assert_xattr_roundtrip "$TEST_MNT"
	_assert_xattr_roundtrip "$TEST_MNT/hello"
fi

fuse_umount
