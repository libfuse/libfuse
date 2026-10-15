#!/usr/bin/env bash
# GROUP: examples passthrough
# Issue #1188: write, flush and release on an open file whose parent
# directory was removed get a NULL path, also without nullpath_ok.

. "$TEST_LIB/common.sh"

# FreeBSD sends a GETATTR without a file handle before each write, and
# libfuse fails it with ESTALE once the file has no path
_require_linux "a write after rmdir of the parent"

fuse_mount test/passthrough-hl >/dev/null

# test/passthrough-hl mirrors the whole tree
work_dir=$TEST_MNT$TEST_SRC

_check fuse_test_open_rmdir_parent "$TEST_SRC" "$work_dir"

fuse_umount

# test/passthrough-hl prints the path each of these operations got
got=$(grep -E '^(write|flush|release): path=' "$(fuse_fs_log 0)")
want="write: path=$TEST_SRC/dir/file
write: path=NULL
flush: path=NULL
release: path=NULL"
_assert_eq "$got" "$want" "paths passthrough-hl got"
