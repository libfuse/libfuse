#!/bin/bash -x

set -e

TEST_CMD="pytest -v --maxfail=1 --log-level=INFO --log-cli-level=INFO test/"
SAN="-Db_sanitize=address,undefined"

# not default
export UBSAN_OPTIONS=halt_on_error=1

# Make sure binaries can be accessed when invoked by root.
umask 0022

# There are tests that run as root but without CAP_DAC_OVERRIDE. To allow these
# to launch built binaries, the directory tree must be accessible to the root
# user. Since the source directory isn't necessarily accessible to root, we
# build and run tests in a temporary directory that we can set up to be world
# readable/executable.
SOURCE_DIR="$(readlink -f .)"
TEST_DIR="$(mktemp -dt libfuse-build-XXXXXX)"

PREFIX_DIR="$(mktemp -dt libfuse-install-XXXXXXX)"

chmod 0755 "${TEST_DIR}"
cd "${TEST_DIR}"
echo "Running in ${TEST_DIR}"

cp -v "${SOURCE_DIR}/test/lsan_suppress.txt" .
export LSAN_OPTIONS="suppressions=$(pwd)/lsan_suppress.txt"
export ASAN_OPTIONS="detect_leaks=1"
export CC

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

        meson setup -Dprefix=${PREFIX_DIR} -D werror=true ${build_opts} "${SOURCE_DIR}" || (cat meson-logs/meson-log.txt; false)
        ninja
        sudo env PATH=$PATH ninja install

        # libfuse will first try the install path and then system defaults
        sudo chmod 4755 ${PREFIX_DIR}/bin/fusermount3

        # also needed for some of the tests
        sudo chown root:root util/fusermount3
        sudo chmod 4755 util/fusermount3

        ${TEST_CMD}
        popd
        rm -fr build-${CC}
        sudo rm -fr ${PREFIX_DIR}

    done
)

sanitized_build()
(
    echo "=== Building with clang and sanitizers"

    mkdir build-san; pushd build-san

    meson setup -Dprefix=${PREFIX_DIR} -D werror=true\
           "${SOURCE_DIR}" \
           || (ct meson-logs/meson-log.txt; false)
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

    # also needed for some of the tests
    sudo chown root:root util/fusermount3
    sudo chmod 4755 util/fusermount3

    # Test as root and regular user
    sudo env PATH=$PATH ${TEST_CMD}
    # Cleanup temporary files (since they are now owned by root)
    sudo rm -rf test/.pytest_cache/ test/__pycache__

    ${TEST_CMD}
    
    popd
    rm -fr build-san
    sudo rm -fr ${PREFIX_DIR}
)

# Sanitized build
export CC=clang
export CXX=clang++
TEST_WITH_VALGRIND=false
sanitized_build

# Sanitized build without libc versioned symbols
export CC=clang
export CXX=clang++
sanitized_build "-Ddisable-libc-symbol-version=true"

non_sanitized_build

# Documentation.
(cd "${SOURCE_DIR}"; doxygen doc/Doxyfile)

# Clean up.
rm -rf "${TEST_DIR}"
