#!/usr/bin/env bash
# GROUP: unit quick

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_linux "fusermount3"
_require_binary util/fusermount3

help_output=$("$FUSE_UTIL_DIR/fusermount3" --help) || true
printf '%s\n' "$help_output" | grep -q '^ --features[[:space:]]' ||
	_fail "fusermount3 --help does not advertise --features"
printf '%s\n' "$help_output" | grep -q '^ --features=text[[:space:]]' ||
	_fail "fusermount3 --help does not advertise --features=text"

expected_features=0000000000000000
expected_features_text=
if grep -q '^#define HAVE_NEW_MOUNT_API' "$BUILD_DIR/fuse_config.h"; then
	expected_features=0000000000000003
	expected_features_text="FUSERMOUNT_FEATURE_NEW_MOUNT_API FUSERMOUNT_FEATURE_SYNC_INIT"
fi

features=$("$FUSE_UTIL_DIR/fusermount3" --features)
_assert_eq "$features" "$expected_features" "fusermount3 --features"

features_text=$("$FUSE_UTIL_DIR/fusermount3" --features=text)
_assert_eq "$features_text" "$expected_features_text" \
	"fusermount3 --features=text"
