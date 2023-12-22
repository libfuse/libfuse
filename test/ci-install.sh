#!/bin/sh

set -e

sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install pytest meson==1.0.1 looseversion
valgrind --version
ninja --version
meson --version
