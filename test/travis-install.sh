#!/bin/sh

set -e

# Meson 0.45 requires Python 3.5 or newer
sudo python3 -m pip install pytest meson==0.44
wget https://github.com/ninja-build/ninja/releases/download/v1.7.2/ninja-linux.zip
unzip ninja-linux.zip
chmod 755 ninja
sudo chown root:root ninja
sudo mv -fv ninja /usr/local/bin
valgrind --version
ninja --version
meson --version
