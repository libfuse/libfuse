#!/bin/bash
# The API documentation build. Not a build configuration: it needs no compiler
# of its own and none of them has to have run first.

set -e

cd "$(readlink -f "$(dirname "$0")/../..")"
doxygen doc/Doxyfile
