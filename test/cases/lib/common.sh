# common.sh - helper library for the libfuse shell tests.
#
# Sourced by every test script. Provides the FUSE verbs (mount, umount,
# assertions, skip protocol); it knows nothing about scheduling, which belongs
# to run-tests.py.
#
# Scripts run under errexit, imposed once by the runner (`bash -e`), so an
# unchecked command that fails ends the test instead of letting the rest of it
# run against a broken state. Two consequences show up below: a status that is
# examined must be captured in the same command, and the cleanup trap has to
# swallow each of its own failures.
#
# Nothing here is sourced, probed or defaulted: the runner puts the whole
# contract in the environment before exec'ing the script, and the variables
# below are read as given. A case is therefore not runnable by hand; replay
# logs/repro.sh, which restores the environment first.
#
#   TEST_NAME		the name the runner reports this test under
#   TEST_LIB		this directory, where checks.py is found
#   TEST_MNT		empty mount point, one per test
#   TEST_LOGDIR		where daemon logs and status files are written
#   BUILD_DIR		build tree root; _require_binary resolves against it
#   FUSE_EXAMPLE_DIR	$BUILD_DIR/example
#   FUSE_TEST_BIN_DIR	$BUILD_DIR/test
#   FUSE_UTIL_DIR	$BUILD_DIR/util, holding fusermount3 and mount.fuse3
#   FUSE_CAPS		capability names printcap reported, space separated
#   FUSE_UID		effective uid
#   FUSE_OS		uname -s
#   FUSE_URING_ENABLE	1 when the run expects the daemons to use io_uring
#   FUSE_VALGRIND	command prefix, empty unless the run is under valgrind
#
# The runner exports more for the cases themselves (TEST_SRC, TEST_TMP,
# TEST_WORKDIR); those are not read here. A case may set FUSE_WAIT_PREDICATE
# before mounting, to replace the readiness check fuse_mount waits on, and
# _fuse_no_mount_needed before sourcing this file, when it never mounts.

# --------------------------------------------------------------- result protocol

# _fail <msg...>
# Print msg to stderr with the test name, then exit 1 (FAIL).
_fail()
{
	echo "FAIL: ${TEST_NAME}: $*" >&2
	exit 1
}

# _notrun <reason...>
# Print reason to stderr, then exit 77 (SKIP). The runner records the reason.
# stderr, because fuse_mount echoes the mount index on stdout and its callers
# redirect that away; a skip raised inside it would go with it.
_notrun()
{
	echo "SKIP: $*" >&2
	exit 77
}

# _require_root
# _notrun unless the effective uid is 0.
_require_root()
{
	[ "$FUSE_UID" = 0 ] || _notrun "needs root"
}

# _require_nonroot
# _notrun unless the effective uid is not 0.
_require_nonroot()
{
	[ "$FUSE_UID" != 0 ] || _notrun "needs to run as non-root"
}

# _is_linux
# True on Linux. For conditional sections inside a shared body; a whole script
# that cannot run elsewhere calls _require_linux instead.
_is_linux()
{
	[ "$FUSE_OS" = Linux ]
}

# _require_linux <what>
# _notrun unless $FUSE_OS is Linux. <what> names the Linux-only facility, so
# the summary says which one rather than just "not linux".
_require_linux()
{
	_is_linux || _notrun "$1 is Linux-only"
}

# _require_cap <FUSE_CAP_NAME>
# _notrun unless the name appears in $FUSE_CAPS.
_require_cap()
{
	local cap=$1

	case " $FUSE_CAPS " in
	*" $cap "*) return 0 ;;
	esac
	_notrun "kernel does not offer $cap"
}

# _require_fuse
# _notrun unless this user can mount a FUSE filesystem at all: the kernel side
# has to be there, and an unprivileged user needs a setuid fusermount3. It runs
# when a case sources this file, so a build tree whose fusermount3 was never
# chmod 4755'd reports skips rather than a wall of mount failures.
_require_fuse()
{
	local fusermount

	# BSD has no fusermount3 at all; vfs.usermount decides there.
	_is_linux || return 0
	[ -e /dev/fuse ] ||
		_notrun "the FUSE kernel module does not seem to be loaded"
	[ "$FUSE_UID" != 0 ] || return 0
	fusermount=$(command -v fusermount3) ||
		_notrun "no fusermount3 on \$PATH"
	[ -u "$fusermount" ] ||
		_notrun "$fusermount is not setuid, and we are not root"
}

# _require_binary <path-relative-to-BUILD_DIR>
# _notrun unless the file exists and is executable.
_require_binary()
{
	[ -x "$BUILD_DIR/$1" ] || _notrun "$1 not built"
}

# _require_prog <name>
# _notrun unless `command -v <name>` succeeds.
_require_prog()
{
	command -v "$1" >/dev/null 2>&1 || _notrun "$1 not installed"
}

# _require_not_32bit_on_64 <path>
# _notrun for a 32-bit ELF binary on an x86_64 host.
_require_not_32bit_on_64()
{
	local class

	class=$(_check fuse_test_elf_class "$1")
	if [ "$class" = 32 ] && [ "$(uname -m)" = x86_64 ]; then
		_notrun "$1 is a 32-bit binary on a 64-bit host"
	fi
}

# _require_reachable_without_caps <fs-name>
# _notrun unless the fs binary and every directory above it are executable by
# plain permission bits. mount.fuse3 -o drop_privileges execs the fs after
# dropping CAP_DAC_OVERRIDE, so a mode-0700 home makes it unreachable.
_require_reachable_without_caps()
{
	python3 "$TEST_LIB/checks.py" fuse_test_reachable_without_caps \
		"$(_fuse_fs_binary "$1")" ||
		_notrun "$1 is not reachable without CAP_DAC_OVERRIDE"
}

# _require_fs_marker_absent <regex> [fs-index]
# _notrun if the mounted daemon's log matched <regex>. Used for runtime
# "not supported by kernel" markers.
#
# The daemon may not have written the marker yet when the test looks; the
# examples emit it during the first update interval, so poll briefly.
_require_fs_marker_absent()
{
	local regex=$1 idx=${2:-0} deadline=$((SECONDS + 3))

	while [ $SECONDS -lt $deadline ]; do
		if grep -qE -- "$regex" "$(fuse_fs_log "$idx")"; then
			_notrun "filesystem reported: $regex"
		fi
		sleep 0.2
	done
}

# ------------------------------------------------------------------- assertions

# _assert_eq <actual> <expected> [msg]
_assert_eq()
{
	[ "$1" = "$2" ] || _fail "${3:-assertion failed}: got '$1', want '$2'"
}

# _assert_ne <actual> <unexpected> [msg]
_assert_ne()
{
	[ "$1" != "$2" ] || _fail "${3:-assertion failed}: both are '$1'"
}

# _assert_file_eq <path-a> <path-b>
_assert_file_eq()
{
	cmp -s "$1" "$2" || _fail "$1 and $2 differ"
}

# _wait_for <secs> <shell-cmd>
# Poll until cmd succeeds. Returns non-zero when the deadline passes, so the
# caller decides whether that is a failure or a skip.
_wait_for()
{
	# Separate statements: one `local` expands all its words before it
	# assigns any of them, so a shared one computes the deadline from an
	# unset secs and the loop ends before it has tried once.
	local secs=$1 cmd=$2
	local deadline=$((SECONDS + secs))

	while [ $SECONDS -lt $deadline ]; do
		if eval "$cmd"; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

# Everything shell cannot express exactly goes to checks.py: an exact errno, an
# fd held across an operation, nanosecond timestamps, directory listings,
# /proc/self/mountinfo fields. Add a subcommand there rather than approximating
# a check here.

# _check <subcommand> [args...]
# Run the Python check helper. Its stdout/stderr already carry the diagnostic,
# so just propagate the failure.
_check()
{
	# Silent on success otherwise, so a step that hangs is invisible.
	# stderr: callers capture stdout for the check's value.
	echo "check: $*" >&2
	python3 "$TEST_LIB/checks.py" "$@" || _fail "checks.py $1 failed"
}

# _assert_errno <ERRNO-NAME> <op> [args...]
# op is a checks.py operation name (fuse_test_open_rw, fuse_test_open_ro,
# fuse_test_stat). The errno is compared against OSError.errno, never against
# locale-dependent strerror text.
_assert_errno()
{
	_check fuse_test_expect_errno "$@"
}

_assert_listdir()          { _check fuse_test_assert_listdir "$@"; }
_assert_xattr_roundtrip()  { _check fuse_test_xattr "$@"; }  # set/get/remove

# mountinfo_field <mnt> <fstype|source|mount_options|super_options>
# Echo one field of the /proc/self/mountinfo line for <mnt>. Empty output means
# the mountpoint is not mounted.
mountinfo_field()
{
	_check fuse_test_mountinfo "$1" "$2"
}

_assert_mount_opt()        { _check fuse_test_assert_mount_opt "$@"; }
_refute_mount_opt()        { _check fuse_test_refute_mount_opt "$@"; }
_assert_super_opt()        { _check fuse_test_assert_super_opt "$@"; }
_assert_super_opt_prefix() { _check fuse_test_assert_super_opt_prefix "$@"; }
_assert_fstype()           { _check fuse_test_assert_fstype "$@"; }
_assert_source()           { _check fuse_test_assert_source "$@"; }

# ---------------------------------------------------------------- cleanup hooks

_FUSE_ATEXIT=()

# _at_exit <command...>
# Register a command to run when the script exits, newest first. Registering is
# what installs the EXIT trap, so a test never has to write its own and cannot
# clobber the mount unwinding.
_at_exit()
{
	_FUSE_ATEXIT+=("$*")
	trap _fuse_cleanup_all EXIT
}

# _fuse_cleanup_all
# Unwind every mount still registered, newest first, then run the _at_exit
# commands. Every step swallows its own failure: under errexit one stuck umount
# would otherwise end the trap and leak the remaining mounts, which is exactly
# what the trap exists to prevent.
_fuse_cleanup_all()
{
	local idx

	for ((idx = _fuse_fs_count - 1; idx >= 0; idx--)); do
		fuse_umount_lazy "$idx" || true
	done
	for ((idx = ${#_FUSE_ATEXIT[@]} - 1; idx >= 0; idx--)); do
		eval "${_FUSE_ATEXIT[$idx]}" || true
	done
}

# ------------------------------------------------------------------ mount verbs

_fuse_fs_count=0
FUSE_FS_PID=()
FUSE_FS_LOG=()
FUSE_FS_MNT=()
FUSE_FS_NAME=()

# _fuse_fs_binary <fs-name>
# Echo the build-tree path of <fs-name>: $FUSE_TEST_BIN_DIR when the name is
# prefixed "test/", $FUSE_EXAMPLE_DIR otherwise.
_fuse_fs_binary()
{
	case $1 in
	test/*) echo "$FUSE_TEST_BIN_DIR/${1#test/}" ;;
	*)      echo "$FUSE_EXAMPLE_DIR/$1" ;;
	esac
}

# fuse_mount_at <mnt> <fs-name> [args...]
# Launch the filesystem in the foreground on <mnt> with its stdout+stderr
# redirected to logs/fs-<idx>-<fs-name>.out. Waits for the mountpoint to
# appear. Registers an EXIT trap that lazily unmounts and kills the daemon, so
# an aborting test never leaks a mount.
# Sets FUSE_FS_PID[idx] and FUSE_FS_LOG[idx]; echoes idx.
fuse_mount_at()
{
	local mnt=$1 fs=$2; shift 2
	local idx=$_fuse_fs_count
	local bin log

	bin=$(_fuse_fs_binary "$fs")
	[ -x "$bin" ] || _notrun "$fs not built"

	# Each daemon gets its own log so a multi-mount test stays readable.
	log=$TEST_LOGDIR/fs-$idx-$(basename "$fs").out
	"$bin" "$@" "$mnt" >"$log" 2>&1 &
	FUSE_FS_PID[$idx]=$!
	FUSE_FS_LOG[$idx]=$log
	FUSE_FS_MNT[$idx]=$mnt
	FUSE_FS_NAME[$idx]=$fs
	_fuse_fs_count=$((idx + 1))

	trap _fuse_cleanup_all EXIT
	fuse_wait_mount "$mnt" "${FUSE_WAIT_PREDICATE:-}" || {
		_fuse_dump_fs_log $idx
		_fail "$fs did not mount on $mnt"
	}
	echo $idx
}

# fuse_mount <fs-name> [args...]
# fuse_mount_at on $TEST_MNT, with -f so the daemon stays in the foreground.
fuse_mount()
{
	local fs=$1; shift

	fuse_mount_at "$TEST_MNT" "$fs" -f "$@"
}

# fuse_mount_helper <fs-name> [args...]
# Mount via $FUSE_UTIL_DIR/mount.fuse3 instead of exec'ing the fs directly.
#
# mount.fuse3 execs the filesystem type through /bin/sh, so an example resolves
# via $PATH but a binary in test/ has to be named by its absolute path.
fuse_mount_helper()
{
	local fs=$1; shift
	local idx=$_fuse_fs_count
	local spec=$fs log

	case $fs in
	test/*) spec=$(_fuse_fs_binary "$fs") ;;
	esac

	log=$TEST_LOGDIR/fs-$idx-$(basename "$fs").out
	"$FUSE_UTIL_DIR/mount.fuse3" "$spec" "$TEST_MNT" "$@" >"$log" 2>&1 &
	FUSE_FS_PID[$idx]=$!
	FUSE_FS_LOG[$idx]=$log
	FUSE_FS_MNT[$idx]=$TEST_MNT
	FUSE_FS_NAME[$idx]=$fs
	_fuse_fs_count=$((idx + 1))

	trap _fuse_cleanup_all EXIT
	fuse_wait_mount "$TEST_MNT" || {
		_fuse_dump_fs_log $idx
		_fail "mount.fuse3 $fs did not mount on $TEST_MNT"
	}
	echo $idx
}

# fuse_wait_mount <path> [predicate]
# Poll until `checks.py fuse_test_ismount <path>` succeeds, or until the
# caller-supplied predicate (a shell command taking <path>) succeeds. Fails if
# the daemon exits first.
fuse_wait_mount()
{
	local path=$1 predicate=${2:-}
	local idx=$((_fuse_fs_count - 1))
	local deadline=$((SECONDS + 30))
	local test_cmd

	if [ -n "$predicate" ]; then
		test_cmd="$predicate '$path'"
	else
		test_cmd="python3 '$TEST_LIB/checks.py' fuse_test_ismount '$path'"
	fi

	while [ $SECONDS -lt $deadline ]; do
		if eval "$test_cmd" >/dev/null 2>&1; then
			return 0
		fi
		if ! kill -0 "${FUSE_FS_PID[$idx]}" 2>/dev/null; then
			# The daemon may have exited *after* completing the
			# mount (mount.fuse3 does), so look once more.
			eval "$test_cmd" >/dev/null 2>&1 && return 0
			return 1
		fi
		sleep 0.1
	done
	return 1
}

# fuse_umount [idx]
# fusermount3 -u on Linux, umount(8) on BSD (no util/ is built there), then
# wait for the daemon; _fail unless it exits 0. Writes
# logs/fs-<idx>-<name>.status.
fuse_umount()
{
	local idx=${1:-0}
	local mnt=${FUSE_FS_MNT[$idx]} pid=${FUSE_FS_PID[$idx]}
	local rc

	if _is_linux; then
		"$FUSE_UTIL_DIR/fusermount3" -u "$mnt" ||
			_fail "fusermount3 -u $mnt failed"
	else
		umount "$mnt" || _fail "umount $mnt failed"
	fi
	# The daemon exits on its own once the kernel drops the connection; a
	# daemon that does not is a bug the test must report, not paper over.
	_wait_for 30 "! kill -0 $pid 2>/dev/null" ||
		_fail "${FUSE_FS_NAME[$idx]} still running 30s after umount"
	# One command, not `wait; rc=$?`: under errexit a non-zero wait would
	# abort the script before its status could be reported.
	rc=0
	wait "$pid" || rc=$?
	# Reaped: the number is free for any process to be assigned next, so
	# nothing may signal it again.
	FUSE_FS_PID[$idx]=
	echo "$rc" >"$TEST_LOGDIR/fs-$idx-$(basename "${FUSE_FS_NAME[$idx]}").status"
	[ $rc -eq 0 ] || {
		_fuse_dump_fs_log $idx
		_fail "${FUSE_FS_NAME[$idx]} exited with $rc"
	}
}

# fuse_umount_lazy [idx]
# fusermount3 -z -u (Linux) or umount -f (BSD), + SIGTERM + SIGKILL, ignoring
# errors. The trap path.
fuse_umount_lazy()
{
	local idx=${1:-0}
	local mnt=${FUSE_FS_MNT[$idx]} pid=${FUSE_FS_PID[$idx]}

	# The trap runs over every index, fuse_umount'ed ones included.
	[ -n "$pid" ] || return 0
	if _is_linux; then
		"$FUSE_UTIL_DIR/fusermount3" -z -u "$mnt" >/dev/null 2>&1 || true
	else
		umount -f "$mnt" >/dev/null 2>&1 || true
	fi
	kill "$pid" 2>/dev/null || true
	_wait_for 1 "! kill -0 $pid 2>/dev/null" || kill -9 "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	FUSE_FS_PID[$idx]=
}

fuse_fs_pid()
{
	echo "${FUSE_FS_PID[${1:-0}]}"
}

fuse_fs_log()
{
	echo "${FUSE_FS_LOG[${1:-0}]}"
}

# _fuse_dump_fs_log <idx>
# Copy that daemon's log to stderr before failing. The log file survives in
# logs/, but a failure line with the daemon's own last words beside it is what
# makes a CI log readable without downloading anything.
_fuse_dump_fs_log()
{
	local idx=${1:-0}

	echo "--- ${FUSE_FS_NAME[$idx]} log (${FUSE_FS_LOG[$idx]}) ---" >&2
	cat "${FUSE_FS_LOG[$idx]}" >&2 || true
	echo "--- end log ---" >&2
}

# --------------------------------------------------------------- output scanning

# fuse_allow_output <extended-regex>
# Append a false-positive pattern to logs/.allow, one per line. The runner
# strips every match before scanning for suspicious words.
fuse_allow_output()
{
	printf '%s\n' "$1" >>"$TEST_LOGDIR/.allow"
}

# fuse_allow_core <executable-name>
# Record that a core from <executable-name> is expected in this test.
fuse_allow_core()
{
	printf '%s\n' "$1" >>"$TEST_LOGDIR/.allow-core"
}

# ----------------------------------------------------------------- the fuse gate
# Nearly every case reaches /dev/fuse, through the mount verbs or through a
# binary that mounts itself, so this is applied on source rather than left to
# each case to remember. The few that never mount say so instead.
[ -n "${_fuse_no_mount_needed:-}" ] || _require_fuse
