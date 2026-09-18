#!/bin/sh
#
# Pack HEAD as a release tarball and build and test what it ships.
#
# This is a script of its own so the workflow is one command.  That command
# runs by hand too, and the release test does not depend on GitHub.
#
# usage: release-tarball.sh <output-dir> [work-dir]

set -e

OUTPUT_DIR="${1:?usage: release-tarball.sh <output-dir> [work-dir]}"
WORK_DIR="$2"
RELEASE_PY="$(dirname "$0")/release.py"

tarball="$("${RELEASE_PY}" tarball HEAD --output-dir "${OUTPUT_DIR}")"

if [ -n "${WORK_DIR}" ]; then
    "${RELEASE_PY}" test "${tarball}" --work-dir "${WORK_DIR}"
else
    "${RELEASE_PY}" test "${tarball}"
fi
