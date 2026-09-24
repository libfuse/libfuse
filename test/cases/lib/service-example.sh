# lib/service-example.sh - body for the service_ll / service_hl cases.
#
# Caller sets FS_NAME and LAUNCH, and optionally CHECK, before sourcing:
#   FS_NAME   service_ll | service_hl
#   LAUNCH    fuservicemount3 | mount_fuse
#   CHECK     bytes (default) | mkfs
#
# bytes: the file the example serves has to read back as the image, and what
# is written through the mount has to reach the image.
# mkfs: mkfs.ext4 on that file has to leave an image e2fsck accepts.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

CHECK=${CHECK:-bytes}

# Before the gates: a misspelled FS_NAME would otherwise skip as "not built"
case ${FS_NAME:-} in
service_ll | service_hl) ;;
*) _fail "unknown FS_NAME '${FS_NAME:-}'" ;;
esac
case ${LAUNCH:-} in
fuservicemount3 | mount_fuse) ;;
*) _fail "unknown LAUNCH '${LAUNCH:-}'" ;;
esac
case $CHECK in
bytes | mkfs) ;;
*) _fail "unknown CHECK '$CHECK'" ;;
esac

_require_linux "fuservicemount3"
_require_root
_require_fuse_device
_require_binary util/fuservicemount3
_require_binary "example/$FS_NAME"
[ "$LAUNCH" != mount_fuse ] || _require_binary util/mount.fuse3
if [ "$CHECK" = mkfs ]; then
	_require_prog mkfs.ext4
	_require_prog e2fsck
fi

. "$TEST_LIB/service.sh"

service_setup "test-$FS_NAME-$$"
img=$TEST_SRC/img
old=$TEST_TMP/old
new=$TEST_TMP/new

# The size has to be a multiple of the page size
case $CHECK in
bytes)
	head -c 1048576 /dev/urandom >"$old"
	head -c 1048576 /dev/urandom >"$new"
	cp "$old" "$img"
	;;
mkfs)
	truncate -s 64M "$img"
	;;
esac

service_start "$TEST_LOGDIR/fs-$FS_NAME.out" "$FUSE_EXAMPLE_DIR/$FS_NAME"
case $LAUNCH in
fuservicemount3)
	"$FUSE_UTIL_DIR/fuservicemount3" "$img" "$TEST_MNT" \
		-t "fuse.$service_subtype" ||
		_fail "fuservicemount3 did not mount $FS_NAME"
	;;
mount_fuse)
	"$FUSE_UTIL_DIR/mount.fuse3" "$service_subtype#$img" "$TEST_MNT" ||
		_fail "mount.fuse3 did not mount $FS_NAME"
	;;
esac

_assert_fstype "$TEST_MNT" "fuse.$service_subtype" fuse
case $CHECK in
bytes)
	_assert_file_eq "$TEST_MNT/single_file" "$old"
	dd if="$new" of="$TEST_MNT/single_file" bs=64k conv=notrunc,fsync \
		status=none
	;;
mkfs)
	# -F: single_file is a regular file, not a block device
	mkfs.ext4 -F -q "$TEST_MNT/single_file" ||
		_fail "mkfs.ext4 through $FS_NAME failed"
	;;
esac

umount "$TEST_MNT"
service_wait_exit
_assert_eq "$service_rc" 0 "$FS_NAME exit status"
case $CHECK in
bytes)
	_assert_file_eq "$img" "$new"
	;;
mkfs)
	e2fsck -fn "$img" || _fail "e2fsck found errors in $img"
	;;
esac
