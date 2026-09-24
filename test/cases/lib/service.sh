# lib/service.sh - start a fuse service server the way a systemd socket unit
# does, for the fuservicemount3 cases.
#
# Sourced after common.sh. The socket has to be in the build-time socket
# directory, so every caller runs as root.

# service_setup <subtype>
# Set service_sock. At exit remove the socket and any mount on $TEST_MNT.
service_setup()
{
	service_subtype=$1
	service_runs=0
	# A case may prefix it, to run the helper as another user
	service_helper=("$FUSE_UTIL_DIR/fuservicemount3")
	service_sock=$("$FUSE_TEST_BIN_DIR/test_service" socket-path "$1")
	# Every service script binds its own socket here; removing the
	# directory would break another script's bind()
	mkdir -p "$(dirname "$service_sock")"
	_at_exit "rm -f '$service_sock'"
	_at_exit "umount -l '$TEST_MNT' 2>/dev/null"
}

# service_start <log> <program> [args...]
# Listen on service_sock and run <program> for the first connection, with its
# output in <log>. Sets service_pid.
service_start()
{
	local log=$1; shift

	rm -f "$service_sock"
	python3 "$TEST_LIB/socket_activate.py" "$service_sock" "$@" \
		>"$log" 2>&1 &
	service_pid=$!
	_wait_for 10 "grep -q '^listening' '$log'" ||
		_fail "$service_sock never listened"
	# connect() needs write permission, and a case may run as another user
	chmod 0666 "$service_sock"
}

# service_stop
# Kill an activator that no helper connected to.
service_stop()
{
	kill "$service_pid" 2>/dev/null || true
	wait "$service_pid" 2>/dev/null || true
}

# service_wait_exit
# Reap the server and set service_rc to its exit status. A helper that never
# connected leaves the activator in accept(), which is a failure.
service_wait_exit()
{
	_wait_for 10 "! kill -0 $service_pid 2>/dev/null" || {
		kill "$service_pid" 2>/dev/null || true
		_fail "server (pid $service_pid) did not exit"
	}
	service_rc=0
	wait "$service_pid" || service_rc=$?
}

# service_mount <source> <mountpoint> <case> [args...]
# Run fuservicemount3 once against test_service <case> [args...] and reap the
# server. Sets service_log and service_helper_rc.
service_mount()
{
	local source=$1 mnt=$2; shift 2

	service_log=$TEST_LOGDIR/fs-$service_runs-$1.out
	service_runs=$((service_runs + 1))
	service_start "$service_log" "$FUSE_TEST_BIN_DIR/test_service" "$@"

	service_helper_rc=0
	"${service_helper[@]}" "$source" "$mnt" -t "fuse.$service_subtype" ||
		service_helper_rc=$?

	service_wait_exit
}

# service_result <what>
# The last server prints one "<what> result: <value>" line, for example
# "request result: EPERM". Echo <value>; fail on no such line or several.
service_result()
{
	local count

	count=$(grep -c "^$1 result: " "$service_log") || true
	if [ "$count" != 1 ]; then
		cat "$service_log" >&2
		_fail "$service_log: $count \"$1 result:\" lines, want 1"
	fi
	# -n and p: print only the line the substitution matched
	sed -n "s/^$1 result: //p" "$service_log"
}
