# lib/passthrough-suid.sh - body for the passthrough_hp setuid cases.
#
# Caller sets before sourcing:
#   FS_ARGS           passthrough_hp arguments, without source and mountpoint
#   PT_WANT_BACKING   1 when the run has to install a backing file, so writes
#                     really do bypass the daemon
#
# A write by a caller without CAP_FSETID has to clear setuid and setgid, as it
# would on a local filesystem. passthrough_hp is the interesting case: it
# issues the backing write under its own credentials, which normally hold
# CAP_FSETID, so the backing filesystem never strips the bits. They go away
# only because the FUSE kernel strips them first - in passthrough mode from
# backing_file_write_iter(), before those credentials are installed.
#
# No uid requirement here: checks.py drops CAP_FSETID for the write itself,
# which a case that needs a root daemon for passthrough could not do by
# running unprivileged.

. "$TEST_LIB/common.sh"

fuse_mount_at "$TEST_MNT" passthrough_hp $FS_ARGS "$TEST_SRC" >/dev/null

_check fuse_test_suidgid_dropped "$TEST_MNT" "$TEST_SRC"

# After fuse_test_suidgid_dropped and not before it: passthrough_hp installs
# the backing file on the first open of an inode, and that open happens inside
# the check, so a wait placed ahead of it can only ever time out.
#
# The FUSE_INIT capability list is no help either: passthrough_hp offers
# FUSE_CAP_PASSTHROUGH whatever --nopassthrough says, and only declines to
# install a backing file. passthrough_hp names that backing file under
# --debug, and a backing file is what makes a write bypass the daemon.
[ "${PT_WANT_BACKING:-0}" != 1 ] ||
	_wait_fs_marker 'setup shared backing file'

fuse_umount
