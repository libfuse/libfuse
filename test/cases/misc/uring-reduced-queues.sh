#!/usr/bin/env bash
# GROUP: io-uring
# TIMEOUT: 180

. "$TEST_LIB/common.sh"

_require_linux "reduced io-uring queues"
if [ "$FUSE_URING_ENABLE" != 1 ]; then
	_notrun "requires an io-uring test run"
fi

skip_without_reduced_queues()
{
	_skip_if_fs_marker '^FUSE_INIT: io_uring_reduced_q=off:not_offered$' "$mount_idx"
}

for selection in count list hex; do
	queue_spec=$(_check fuse_test_reduced_queue_options "$selection")
	read -r mount_option queue_count queue_ids <<< "$queue_spec"
	if [ "$mount_option" = skip ]; then
		_notrun "requires at least two allowed CPUs"
	fi

	mount_idx=${#FUSE_FS_PID[@]}
	FAIL_CALLBACK=skip_without_reduced_queues
	fuse_mount passthrough_ll -d -o "cache=never,timeout=0,$mount_option" >/dev/null
	FAIL_CALLBACK=
	_wait_fs_marker '^FUSE_INIT: io_uring_reduced_q=on$' "$mount_idx"
	if [ "$queue_ids" = auto ]; then
		_wait_fs_marker '^FUSE_INIT: io_uring_queue=[0-9]+$' "$mount_idx"
	else
		for qid in $queue_ids; do
			_wait_fs_marker "^FUSE_INIT: io_uring_queue=$qid$" "$mount_idx"
		done
	fi

	log=$(fuse_fs_log "$mount_idx")
	_check fuse_test_reduced_queue_io "$TEST_MNT$TEST_SRC" "$log" \
		"$queue_count" "$queue_ids"
	fuse_umount "$mount_idx"
done
