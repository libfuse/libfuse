#!/bin/bash

set -e

# Script to find the previous major release tag for libfuse
# Usage: ./find_previous_release_tag.sh

# Get current version from meson.build
# Pattern matches: version : "3.18.0" or version: '3.18.0'
VERSION_PATTERN="version\s*:\s*['\"]"
VERSION_EXTRACT="s/.*version\s*:\s*['\"]([^'\"]+)['\"].*/\1/"

CURRENT_VERSION=$(grep -E "$VERSION_PATTERN" meson.build | \
                  sed -E "$VERSION_EXTRACT")
echo "Current version: $CURRENT_VERSION" >&2

# Extract major.minor version (e.g., 3.18 from 3.18.0)
# Pattern captures first two numbers separated by dot
MAJOR_MINOR_PATTERN='s/^([0-9]+\.[0-9]+).*/\1/'

CURRENT_MAJOR_MINOR=$(echo "$CURRENT_VERSION" | \
                      sed -E "$MAJOR_MINOR_PATTERN")
echo "Current major.minor: $CURRENT_MAJOR_MINOR" >&2

# Get all major.minor versions from tags, sort them, and find the one before
# current
# Pattern matches tags like: fuse-3.17.0, fuse-3.18.1, etc.
FUSE_TAG_PATTERN="^fuse-[0-9]+\.[0-9]+"
# Pattern extracts major.minor from version strings
TAG_MAJOR_MINOR_PATTERN='s/^([0-9]+\.[0-9]+).*/\1/'

ALL_MAJOR_MINOR=$(git tag --list | \
                  grep -E "$FUSE_TAG_PATTERN" | \
                  sed 's/fuse-//' | \
                  sed -E "$TAG_MAJOR_MINOR_PATTERN" | \
                  sort -V -u)
echo "All major.minor versions found:" >&2
echo "$ALL_MAJOR_MINOR" >&2

# Find the previous major.minor version
PREV_MAJOR_MINOR=$(echo "$ALL_MAJOR_MINOR" | \
                   grep -B1 "^${CURRENT_MAJOR_MINOR}$" | \
                   head -1)

if [ -z "$PREV_MAJOR_MINOR" ] || [ "$PREV_MAJOR_MINOR" = "$CURRENT_MAJOR_MINOR" ]; then
    echo "Error: No previous major.minor version found before $CURRENT_MAJOR_MINOR" >&2
    exit 1
fi

echo "Previous major.minor: $PREV_MAJOR_MINOR" >&2

# Get the latest tag for the previous major.minor version
# Pattern matches tags like: fuse-3.17.0, fuse-3.17.1, fuse-3.17.2, etc.
PREV_TAG_PATTERN="^fuse-${PREV_MAJOR_MINOR}\.[0-9]+"

PREV_TAG=$(git tag --list | \
           grep -E "$PREV_TAG_PATTERN" | \
           sort -V | \
           tail -1)

if [ -z "$PREV_TAG" ]; then
    echo "Error: No previous major release tag found for version $PREV_MAJOR_MINOR" >&2
    exit 1
fi

echo "Previous release tag: $PREV_TAG" >&2

# Output the tag to stdout (this is what the workflow will capture)
echo "$PREV_TAG"
