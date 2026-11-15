#!/usr/bin/env bash
# GROUP: examples passthrough
# libfuse forgets the lookup of a READDIRPLUS entry that does not fit in the
# reply. The kernel never sends a FORGET for that entry.

. "$TEST_LIB/common.sh"

# drop_caches makes the kernel evict the inodes and send FORGET
_require_root
_require_linux "/proc/sys/vm/drop_caches"

# test/passthrough-hl mirrors the whole tree
dir=$TEST_SRC/dir
work_dir=$TEST_MNT$dir

# check_forget <idx> <mode> [passthrough-hl options...]
# $1: the daemon index this mount gets from fuse_mount.
# $2: the mode name for failure messages.
# $3..: options for test/passthrough-hl.
# Reads $dir and $work_dir. Fails if a node survives the FORGET of every
# inode the directory listing returned.
check_forget()
{
	local idx=$1 mode=$2
	local log count file_idx before after name ino line
	shift 2

	fuse_mount test/passthrough-hl -d "$@" >/dev/null
	log=$(fuse_fs_log "$idx")
	# Larger requests can take the whole directory, so no entry is left over
	for line in "FUSE_INIT: max_pages=1" "FUSE_INIT: sync_init=1"; do
		if ! _wait_for 5 "grep -qx '$line' '$log'"; then
			_fail "$mode: no '$line' in $log"
		fi
	done

	# Several requests, so each request boundary has an entry that does
	# not fit
	count=$(($(getconf PAGESIZE) / 40))
	mkdir "$dir"
	for ((file_idx = 0; file_idx < count; file_idx++)); do
		touch "$dir/file$file_idx"
	done

	# The glob reads the directory through READDIRPLUS. Without use_ino,
	# st_ino is the libfuse node ID.
	before=$(stat -c '%n %i' "$work_dir"/*)
	echo 2 >/proc/sys/vm/drop_caches
	# FORGET comes over /dev/fuse and can be handled after the LOOKUP of
	# the next stat
	while read -r name ino; do
		if ! _wait_for 10 "grep -q '^FORGET $ino/' '$log'"; then
			_fail "$mode: no FORGET for $name, node $ino"
		fi
	done <<<"$before"

	# libfuse gives a forgotten name a new node ID
	after=$(stat -c '%n %i' "$work_dir"/*)
	while read -r line; do
		if grep -qxF "$line" <<<"$after"; then
			_fail "$mode: node leaked: $line"
		fi
	done <<<"$before"

	fuse_umount "$idx"
	rm -r "$dir"
}

# Without offsets libfuse serves READDIRPLUS from its cached list, with
# offsets from each readdir call
check_forget 0 "without offsets"
check_forget 1 "with offsets" --readdir-offsets
