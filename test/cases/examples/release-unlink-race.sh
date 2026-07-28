#!/usr/bin/env bash
# GROUP: examples
# Issue #746: RELEASE and UNLINK sent back to back must not race, which is
# only triggered when nullpath_ok is set.

. "$TEST_LIB/common.sh"

fuse_mount test/release_unlink_race >/dev/null

# The filesystem mirrors the real tree, so the mount's view of a directory
# is that directory prefixed with the mountpoint.
race_dir=$TEST_TMP/race
mkdir "$race_dir"

racefile=$TEST_MNT$race_dir/racefile
: >"$racefile"
rm "$racefile"

# Slow CI pipelines need this for the unlink to finish processing.
sleep 3

_assert_listdir "$race_dir"

fuse_umount
