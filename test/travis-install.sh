#!/bin/sh

set -e

sudo python3 -m pip install --upgrade pip
# Meson 0.45 requires Python 3.5 or newer
sudo python3 -m pip install pytest meson==0.44
valgrind --version
ninja --version
meson --version
