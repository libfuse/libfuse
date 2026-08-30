#!/bin/bash
#
# Host tuning a CI runner needs and a developer machine must not get.
#
# Cores must land in the test's own log directory, which run-tests.py makes the
# cwd of every test. ubuntu-latest ships apport, so core_pattern is a pipe and
# every core disappears into a collector the job then throws away. %p keeps two
# crashing processes in one test from overwriting each other, and %e is how the
# runner finds the binary to hand gdb.
#
# Deliberately not part of ci-build.sh: that script is also run by hand, and a
# build script has no business rewriting a global kernel tunable -- or, below,
# the permission bits on directories outside the tree it builds -- on someone's
# workstation. Locally the runner's own warning is enough, and it still fetches
# cores through coredumpctl.
#
# Usage: prepare-runner.sh <work-dir>

set -e

# Before the writes below, so a mistyped invocation leaves the host alone.
# Absolute, because the ancestor walk further down ends at / and `dirname` on
# a relative path stops at "." instead -- which is a loop, not a walk.
WORK_DIR="$(readlink -f "${1:?usage: prepare-runner.sh <work-dir>}")"
SOURCE_DIR="$(readlink -f "$(dirname "$0")/../..")"

sudo sysctl -w kernel.core_pattern=core.%e.%p
sudo sysctl -w kernel.core_uses_pid=0

# There are tests that run as root but without CAP_DAC_OVERRIDE. To allow those
# to launch built binaries, every ancestor of the work directory must be
# traversable by plain permission bits; a 0750 home is the usual culprit. This
# script does not create the work directory itself -- ci-build.sh chmods that
# and the directories below it -- only the ancestors above it.
dir="$(dirname "${WORK_DIR}")"
while [ "${dir}" != / ]; do
    if [ -z "$(find "${dir}" -maxdepth 0 -perm -001)" ]; then
        echo "making ${dir} traversable for the capability-less tests"
        chmod o+x "${dir}" 2>/dev/null || sudo chmod o+x "${dir}"
    fi
    dir="$(dirname "${dir}")"
done
# Assert it rather than trust the loop: a test that skips itself here leaves a
# green job that stopped exercising drop_privileges, which is the one outcome
# CI must not produce.
python3 "${SOURCE_DIR}/test/cases/lib/checks.py" fuse_test_reachable_without_caps \
    "$(dirname "${WORK_DIR}")" ||
    { echo "use --work-dir to build somewhere reachable"; exit 1; }
