#!/bin/bash -x

set -e

TEST_CMD="meson test -C . --print-errorlogs"
# Two selections rather than one: plain `meson test` runs both suites, and the
# io-uring pass is wanted once per run, not once per build and user.
TEST_CMD_DEFAULT="${TEST_CMD} --no-suite io-uring"
TEST_CMD_IO_URING="${TEST_CMD} --suite io-uring"
SAN="-Db_sanitize=address,undefined"

# not default
export UBSAN_OPTIONS=halt_on_error=1

cli_work_dir=
while [ $# -gt 0 ]; do
    case $1 in
    --work-dir) cli_work_dir=$2; shift 2 ;;
    --work-dir=*) cli_work_dir=${1#--work-dir=}; shift ;;
    *) echo "usage: $0 [--work-dir DIR]" >&2; exit 1 ;;
    esac
done

# Make sure binaries can be accessed when invoked by root.
umask 0022

# There are tests that run as root but without CAP_DAC_OVERRIDE. To allow these
# to launch built binaries, the directory tree must be accessible to the root
# user. Since the source directory isn't necessarily accessible to root, we
# build and run tests in a separate directory that we can set up to be world
# readable/executable.
SOURCE_DIR="$(readlink -f .)"

# Where this run's builds and logs go. --work-dir and $FUSE_TESTS_WORK_DIR are
# verbatim so CI can predict the path it later uploads; otherwise take the base
# from run-tests.py (persisted config, else /var/tmp/fuse-tests) and append a
# dedicated leaf, so two runs never share a directory. Asking the runner keeps
# the precedence in one place instead of parsing an INI in bash.
WORK_DIR="${cli_work_dir:-${FUSE_TESTS_WORK_DIR:-}}"
if [ -z "${WORK_DIR}" ]; then
    WORK_DIR="$(python3 "${SOURCE_DIR}/test/run-tests.py" --print-base-dir)"
    WORK_DIR="${WORK_DIR}/ci-${USER:-unknown}-$(date +%y%m%d%H%M%S)"
fi
WORK_DIR="$(readlink -f "${WORK_DIR}")"   # resolve before the cd below
TEST_DIR="${WORK_DIR}/build"
RUN_DIR="${WORK_DIR}/run"

PREFIX_DIR="$(mktemp -dt libfuse-install-XXXXXXX)"

# Builds are scratch and a stale tree would poison the run; logs are the
# product and are kept until the next run replaces them.
rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}" "${RUN_DIR}"
# Root runs tests without CAP_DAC_OVERRIDE, so every directory on the way in
# must be traversable by plain permission bits.
chmod 0755 "${WORK_DIR}" "${TEST_DIR}" "${RUN_DIR}"
cd "${TEST_DIR}"
echo "Running in ${TEST_DIR}"

cp -v "${SOURCE_DIR}/test/lsan_suppress.txt" .
export LSAN_OPTIONS="suppressions=$(pwd)/lsan_suppress.txt"
export ASAN_OPTIONS="detect_leaks=1"
export CC

# One log directory per test run. $CC alone is not unique: sanitized_build runs
# several times, all with clang, and each of those runs the suite twice. The
# counter lives in a file, not a variable: sanitized_build and
# non_sanitized_build are subshells, so an increment inside one would not
# survive it.
run_log_dir()
{
    local label=$1 seq

    seq=$(( $(cat "${RUN_DIR}/.seq" 2>/dev/null || echo 0) + 1 ))
    echo "${seq}" >"${RUN_DIR}/.seq"
    printf '%s/%02d-%s' "${RUN_DIR}" "${seq}" "${label}"
}

# The root test pass writes its per-test logs as root; upload-artifact and the
# next run both have to be able to read them.
chown_log_dir()
{
    sudo chown -R "$(id -u):$(id -g)" "${RUN_DIR}"
}

# The kernel parameter is global and defaults to off, and this script is also
# run by hand, so put back whatever the machine had. Failing to enable it is
# fatal: run-tests.py skips its io-uring invocation where the kernel does not
# offer the transport, which is right for a developer machine and wrong here -
# a job that silently stops testing io-uring is what this exists to prevent.
restore_io_uring()
{
    echo "${FUSE_URING_WAS}" | sudo tee "$1" >/dev/null
    [ -z "${IO_URING_DISABLED_WAS}" ] ||
        sudo sysctl -q -w "kernel.io_uring_disabled=${IO_URING_DISABLED_WAS}"
}

enable_fuse_uring()
{
    local param=/sys/module/fuse/parameters/enable_uring
    local sysctl_param=/proc/sys/kernel/io_uring_disabled

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
}

log_env()
{
    echo "=== Environment ==="
    echo "CC: ${CC}"
    echo "CXX: ${CXX}"
    echo "LSAN_OPTIONS: ${LSAN_OPTIONS}"
    echo "ASAN_OPTIONS: ${ASAN_OPTIONS}"
    echo "UBSAN_OPTIONS: ${UBSAN_OPTIONS}"
    echo "FUSE_URING_ENABLE: ${FUSE_URING_ENABLE}"
    echo "FUSE_URING_QUEUE_DEPTH: ${FUSE_URING_QUEUE_DEPTH}"
    echo "Valgrind: ${TEST_WITH_VALGRIND}"
    echo "==================="
}

non_sanitized_build()
(
    echo "Standard build (without sanitizers)"
    for CC in gcc gcc-9 gcc-10 clang; do
        echo "=== Building with ${CC} ==="
        mkdir build-${CC}; pushd build-${CC}
        if [ "${CC}" == "clang" ]; then
            export CXX="clang++"
            export TEST_WITH_VALGRIND=false
        else
            unset CXX
            export TEST_WITH_VALGRIND=true
        fi
        if [ ${CC} == 'gcc-7' ]; then
            build_opts='-D b_lundef=false'
        else
            build_opts=''
        fi
        if [ ${CC} == 'gcc-10' ]; then
            build_opts='-Dc_args=-flto=auto'
        else
            build_opts=''
        fi

        log_env
        meson setup -Dprefix=${PREFIX_DIR} -D werror=true ${build_opts} "${SOURCE_DIR}" || (cat meson-logs/meson-log.txt; false)
        ninja
        sudo env PATH=$PATH ninja install

        # libfuse will first try the install path and then system defaults
        sudo chmod 4755 ${PREFIX_DIR}/bin/fusermount3
        test -x "${PREFIX_DIR}/sbin/fuservicemount3" && \
                sudo chmod 4755 ${PREFIX_DIR}/sbin/fuservicemount3

        # also needed for some of the tests
        sudo chown root:root util/fusermount3
        sudo chmod 4755 util/fusermount3

        if [ -x util/fuservicemount3 ]; then
                sudo chown root:root util/fuservicemount3
                sudo chmod 4755 util/fuservicemount3
        fi

        FUSE_TEST_RUN_DIR="$(run_log_dir "${CC}")" ${TEST_CMD_DEFAULT}
        popd
        rm -fr build-${CC}
        sudo rm -fr ${PREFIX_DIR}

    done
)

sanitized_build()
(
    echo "=== Building with clang and sanitizers"

    mkdir build-san; pushd build-san

    log_env
    meson setup -Dprefix=${PREFIX_DIR} -D werror=true\
           "${SOURCE_DIR}" \
           || (cat meson-logs/meson-log.txt; false)
    meson configure $SAN

    # b_lundef=false is required to work around clang
    # bug, cf. https://groups.google.com/forum/#!topic/mesonbuild/tgEdAXIIdC4
    meson configure -D b_lundef=false

    # additional options
    if [[ $# -gt 0 ]]; then
        meson configure "$@"
    fi

    # print all options
    meson configure --no-pager

    # reconfigure to ensure it uses all additional options
    meson setup --reconfigure "${SOURCE_DIR}"
    ninja
    sudo env PATH=$PATH ninja install
    sudo chmod 4755 ${PREFIX_DIR}/bin/fusermount3
    test -x "${PREFIX_DIR}/sbin/fuservicemount3" && \
        sudo chmod 4755 ${PREFIX_DIR}/sbin/fuservicemount3

    # also needed for some of the tests
    sudo chown root:root util/fusermount3
    sudo chmod 4755 util/fusermount3

    if [ -x util/fuservicemount3 ]; then
        sudo chown root:root util/fuservicemount3
        sudo chmod 4755 util/fuservicemount3
    fi

    # Test as root and regular user. Give the root run a distinct
    # meson log basename so its meson-logs/testlog.* files don't end
    # up owned by root and block the subsequent user run from writing
    # them.
    sudo env PATH=$PATH \
        FUSE_TEST_RUN_DIR="$(run_log_dir "${CC}${VARIANT:+-$VARIANT}-root")" \
        ${TEST_CMD_DEFAULT} --logbase=testlog-root

    chown_log_dir

    FUSE_TEST_RUN_DIR="$(run_log_dir "${CC}${VARIANT:+-$VARIANT}")" \
        ${TEST_CMD_DEFAULT}

    # The transport is worth exercising with the sanitizers on, and once per
    # run rather than once per build and user: five identical io-uring passes
    # buy nothing.
    if [ "${TEST_IO_URING:-}" = 1 ]; then
        FUSE_TEST_RUN_DIR="$(run_log_dir "${CC}-iouring")" \
            ${TEST_CMD_IO_URING}
    fi

    popd
    rm -fr build-san
    sudo rm -fr ${PREFIX_DIR}
)

# run-tests.py's --io-uring invocation must not be able to skip quietly here.
enable_fuse_uring

# 32-bit sanitized build
export CC=clang
export CXX=clang++
export CFLAGS="-m32"
export CXXFLAGS="-m32"
export LDFLAGS="-m32"
export PKG_CONFIG_PATH="/usr/lib/i386-linux-gnu/pkgconfig"
TEST_WITH_VALGRIND=false
VARIANT=m32 sanitized_build
unset CFLAGS
unset CXXFLAGS
unset LDFLAGS
unset PKG_CONFIG_PATH
unset TEST_WITH_VALGRIND
unset CC
unset CXX

# Sanitized build. This is the one that also runs its tests over fuse-io-uring:
# the two builds the old "sanitized with io-uring" pass produced were
# byte-identical, and only the transport the tests use differs.
export CC=clang
export CXX=clang++
TEST_WITH_VALGRIND=false
TEST_IO_URING=1 sanitized_build

# Sanitized build without libc versioned symbols
export CC=clang
export CXX=clang++
VARIANT=nosymver sanitized_build "-Ddisable-libc-symbol-version=true"

# Sanitized build without fuse-io-uring
export CC=clang
export CXX=clang++
VARIANT=noiouring sanitized_build "-Denable-io-uring=false"

# Build without any sanitizer
non_sanitized_build

# Documentation.
(cd "${SOURCE_DIR}"; doxygen doc/Doxyfile)
