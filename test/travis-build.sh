#!/bin/bash

set -e

export CFLAGS="-Werror"
export CC

# Standard build
for CC in gcc gcc-6 clang; do
    mkdir build-${CC}; cd build-${CC}
    if [ ${CC} == 'gcc-6' ]; then
        build_opts='-D b_lundef=false'
    else
        build_opts=''
    fi
    meson ${build_opts} ../
    ninja

    sudo chown root:root util/fusermount3
    sudo chmod 4755 util/fusermount3
    ninja tests
    cd ..
done
(cd build-$CC; sudo ninja install)

# Sanitized build
CC=clang
for san in undefined; do
    mkdir build-${san}; cd build-${san}
    # b_lundef=false is required to work around clang
    # bug, cf. https://groups.google.com/forum/#!topic/mesonbuild/tgEdAXIIdC4
    meson -D b_sanitize=${san} -D b_lundef=false ..
    ninja

    # Test as root and regular user
    sudo ninja tests
    sudo chown root:root util/fusermount3
    sudo chmod 4755 util/fusermount3
    ninja tests
    cd ..
done

# Autotools build
CC=gcc
./makeconf.sh
./configure
make
sudo python3 -m pytest test/
sudo make install

# Documentation
doxygen doc/Doxyfile

