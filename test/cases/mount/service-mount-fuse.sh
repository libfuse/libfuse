#!/usr/bin/env bash
# GROUP: mount
#
# mount.fuse3 mounts through the service when its socket listens, and execs a
# program named after the type when the socket refuses the connection.

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

_require_binary example/hello

FS_NAME=service_ll
LAUNCH=mount_fuse

. "$TEST_LIB/service-example.sh"

fallback=test-fallback-$$
service_setup "$fallback"

# Bound but never listening, so connect() gets ECONNREFUSED
python3 -c 'import socket, sys
socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET).bind(sys.argv[1])' \
	"$service_sock"

mkdir "$TEST_TMP/bin"
ln -s "$FUSE_EXAMPLE_DIR/hello" "$TEST_TMP/bin/$fallback"
export PATH="$TEST_TMP/bin:$PATH"

fuse_mount_helper "$fallback" >/dev/null
_assert_listdir "$TEST_MNT" hello
fuse_umount
