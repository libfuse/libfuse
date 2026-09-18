#!/usr/bin/env bash
# GROUP: examples passthrough
# Issue #589: with -o remember, a rename onto a name whose file was removed
# underneath the mount aborted the daemon in unlink_node().

. "$TEST_LIB/common.sh"

fuse_mount passthrough -o remember=300 >/dev/null

# passthrough mirrors the real tree, so the mount's view of $TEST_TMP is
# $TEST_MNT$TEST_TMP.
dir=$TEST_TMP/stale
mkdir "$dir"
echo a >"$TEST_MNT$dir/a"

# Removed underneath the mount, so libfuse keeps the node under that name.
rm "$dir/a"
# entry_timeout=0 forces revalidation of the removed name.
_assert_errno ENOENT fuse_test_stat "$TEST_MNT$dir/a"

echo b >"$TEST_MNT$dir/b"
mv "$TEST_MNT$dir/b" "$TEST_MNT$dir/a"
_assert_file_eq "$TEST_MNT$dir/a" "$dir/a"

fuse_umount
