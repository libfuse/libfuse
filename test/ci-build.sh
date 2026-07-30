#!/bin/bash
#
# Build one libfuse configuration and run the test suite against it.
#
# One invocation is one configuration. test/ci/configs.sh supplies the
# arguments for each of them, and CI runs them as parallel matrix jobs.

set -e

usage()
{
    cat >&2 <<EOF
usage: $0 --name NAME [options]

  --name NAME       label for the build, install and log directories
  --cc CC           C compiler (default: cc)
  --cxx CXX         C++ compiler; left unset when not given
  --sanitize        build with the address and undefined-behaviour sanitizers
  --valgrind        run the filesystem daemons under valgrind
  --pass PASS       which test invocation to run: default, root or io-uring
                    (default: default)
  --meson-opt OPT   extra meson option; repeatable
  --work-dir DIR    where to build and log, verbatim
EOF
    exit 1
}

need_arg()
{
    [ $# -ge 2 ] || { echo "$0: $1 needs an argument" >&2; exit 1; }
}

NAME=
CC_BIN=cc
CXX_BIN=
SANITIZE=0
VALGRIND=0
PASS=default
MESON_OPTS=()
cli_work_dir=

while [ $# -gt 0 ]; do
    case $1 in
    --name)      need_arg "$@"; NAME=$2; shift 2 ;;
    --cc)        need_arg "$@"; CC_BIN=$2; shift 2 ;;
    --cxx)       need_arg "$@"; CXX_BIN=$2; shift 2 ;;
    --meson-opt) need_arg "$@"; MESON_OPTS+=("$2"); shift 2 ;;
    --work-dir)  need_arg "$@"; cli_work_dir=$2; shift 2 ;;
    --sanitize)  SANITIZE=1; shift ;;
    --valgrind)  VALGRIND=1; shift ;;
    --pass)      need_arg "$@"; PASS=$2; shift 2 ;;
    *)           usage ;;
    esac
done
[ -n "${NAME}" ] || usage
case "${PASS}" in
default|root|io-uring) ;;
*) echo "$0: unknown --pass ${PASS}" >&2; exit 1 ;;
esac

# Make sure binaries can be accessed when invoked by root.
umask 0022

SOURCE_DIR="$(readlink -f "$(dirname "$0")/..")"

# Where this run's builds and logs go. --work-dir is used verbatim so CI can
# predict the path it later uploads; otherwise take the base from run-tests.py
# (persisted config, else /var/tmp/fuse-tests) and append a dedicated leaf.
# Asking the runner keeps the precedence in one place instead of parsing an
# INI in bash.
WORK_DIR="${cli_work_dir:-}"
if [ -z "${WORK_DIR}" ]; then
    WORK_DIR="$(python3 "${SOURCE_DIR}/test/run-tests.py" --print-base-dir)"
    WORK_DIR="${WORK_DIR}/ci-${USER:-unknown}-$(date +%y%m%d%H%M%S)"
fi
WORK_DIR="$(readlink -f "${WORK_DIR}")"   # resolve before the cd below

# Named after the configuration, so several of them share one work directory
# without colliding and the logs of a whole run stay together.
BUILD_DIR="${WORK_DIR}/build-${NAME}"
PREFIX_DIR="${WORK_DIR}/install-${NAME}"
RUN_DIR="${WORK_DIR}/run"

# A stale tree from a previous failed run would poison this one. The install
# prefix is owned by root from the last `ninja install`.
rm -rf "${BUILD_DIR}"
sudo rm -rf "${PREFIX_DIR}"
mkdir -p "${BUILD_DIR}" "${PREFIX_DIR}" "${RUN_DIR}"
# There are tests that run as root but without CAP_DAC_OVERRIDE. To allow those
# to launch built binaries, every directory on the way in must be traversable
# by plain permission bits.
chmod 0755 "${WORK_DIR}" "${BUILD_DIR}" "${PREFIX_DIR}" "${RUN_DIR}"
cd "${BUILD_DIR}"
echo "Building ${NAME} in ${BUILD_DIR}"

echo "=== System ==="
uname -a
lsb_release -a 2>/dev/null || cat /etc/os-release 2>/dev/null || true
lscpu || true
echo "==============="

export CC="${CC_BIN}"
if [ -n "${CXX_BIN}" ]; then
    export CXX="${CXX_BIN}"
else
    unset CXX
fi

# Exported rather than assigned: run-tests.py reads it from the environment of
# the process meson spawns.
if [ "${VALGRIND}" = 1 ]; then
    export TEST_WITH_VALGRIND=true
else
    export TEST_WITH_VALGRIND=false
fi

cp -v "${SOURCE_DIR}/test/lsan_suppress.txt" .
export LSAN_OPTIONS="suppressions=${BUILD_DIR}/lsan_suppress.txt"
export ASAN_OPTIONS="detect_leaks=1"
export UBSAN_OPTIONS=halt_on_error=1      # not the default

echo "=== Environment ==="
echo "Configuration: ${NAME}"
echo "CC: ${CC}"
echo "CXX: ${CXX-}"
echo "Sanitize: ${SANITIZE}"
echo "LSAN_OPTIONS: ${LSAN_OPTIONS}"
echo "ASAN_OPTIONS: ${ASAN_OPTIONS}"
echo "UBSAN_OPTIONS: ${UBSAN_OPTIONS}"
echo "Valgrind: ${TEST_WITH_VALGRIND}"
echo "Pass: ${PASS}"
echo "==================="

meson setup -Dprefix="${PREFIX_DIR}" -Dwerror=true "${MESON_OPTS[@]}" \
    "${SOURCE_DIR}" || { cat meson-logs/meson-log.txt; false; }

if [ "${SANITIZE}" = 1 ]; then
    meson configure -Db_sanitize=address,undefined
    # b_lundef=false is required to work around a clang bug, cf.
    # https://groups.google.com/forum/#!topic/mesonbuild/tgEdAXIIdC4
    meson configure -Db_lundef=false
    # Reconfigure so the build actually uses them.
    meson setup --reconfigure "${SOURCE_DIR}"
fi

meson configure --no-pager      # what was actually configured
ninja
sudo env PATH="$PATH" ninja install

# libfuse will first try the install path and then system defaults.
sudo chmod 4755 "${PREFIX_DIR}/bin/fusermount3"
if [ -x "${PREFIX_DIR}/sbin/fuservicemount3" ]; then
    sudo chmod 4755 "${PREFIX_DIR}/sbin/fuservicemount3"
fi

restore_io_uring()
{
    echo "${FUSE_URING_WAS}" | sudo tee "$1" >/dev/null
    [ -z "${IO_URING_DISABLED_WAS}" ] ||
        sudo sysctl -q -w "kernel.io_uring_disabled=${IO_URING_DISABLED_WAS}"
}

case "${PASS}" in
default)
    FUSE_TEST_RUN_DIR="${RUN_DIR}/${NAME}" timeout 1800 \
        python3 "${SOURCE_DIR}/test/run-tests.py" --build-dir . --setuid-helpers
    ;;
root)
    # No setuid helper and no meson wrapper: root needs neither, and calling
    # run-tests.py directly means its per-test results reach the job log
    # instead of being swallowed by `meson test`, which only prints a test's
    # output on failure.
    sudo env PATH="$PATH" \
        FUSE_TEST_RUN_DIR="${RUN_DIR}/${NAME}" timeout 1800 \
        python3 "${SOURCE_DIR}/test/run-tests.py" --build-dir .
    # upload-artifact has to read what root wrote.
    sudo chown -R "$(id -u):$(id -g)" "${RUN_DIR}"
    ;;
io-uring)
    # The kernel parameter is global and defaults to off, and this script is
    # also run by hand, so put back whatever the machine had. Failing to enable
    # it is fatal: run-tests.py skips its io-uring invocation where the kernel
    # does not offer the transport, which is right for a developer machine and
    # wrong here - a job that silently stops testing io-uring is what this
    # exists to prevent.
    param=/sys/module/fuse/parameters/enable_uring
    sysctl_param=/proc/sys/kernel/io_uring_disabled
    FUSE_URING_WAS="$(cat "${param}")" ||
        { echo "this kernel has no fuse io-uring support"; exit 1; }
    # Non-zero denies the daemons io_uring_setup(), which drops them back to
    # /dev/fuse. Empty before 6.6, where nothing restricts ring creation.
    IO_URING_DISABLED_WAS="$(cat "${sysctl_param}" 2>/dev/null || true)"
    # Armed before either write, so a failure between them still restores.
    trap "restore_io_uring ${param}" EXIT
    echo Y | sudo tee "${param}" >/dev/null
    [ -z "${IO_URING_DISABLED_WAS}" ] ||
        sudo sysctl -q -w kernel.io_uring_disabled=0

    FUSE_TEST_RUN_DIR="${RUN_DIR}/${NAME}" timeout 1800 \
        python3 "${SOURCE_DIR}/test/run-tests.py" --build-dir . \
            --setuid-helpers --io-uring
    ;;
esac

# Only reached when everything above passed, because of set -e: a failed run
# has to stay inspectable. The logs are kept either way, and are the product.
rm -rf "${BUILD_DIR}"
sudo rm -rf "${PREFIX_DIR}"
