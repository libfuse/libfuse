#!/bin/bash
# ABI compatibility check script for libfuse

set -e

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Check ABI compatibility between two versions of libfuse.

OPTIONS:
    --prev-tag <tag>        Previous release tag/hash to compare against
                           (default: auto-detect latest release tag)

    --current-dir <path>    Path to current version checkout
                           (default: create temporary checkout from current directory)

    --previous-dir <path>   Path to previous version checkout
                           (default: create temporary checkout at --prev-tag)

    -h, --help             Show this help message and exit

EXAMPLES:
    # Auto-detect previous release and create temporary checkouts
    $0

    # Compare against a specific tag
    $0 --prev-tag fuse-3.16.2

    # Use existing checkout directories (useful in CI)
    $0 --current-dir ./current --previous-dir ./previous

NOTES:
    - If both --current-dir and --previous-dir are provided, the script will use
      those directories directly without creating temporary checkouts.

    - If only --prev-tag is provided (or auto-detected), the script will create
      temporary checkouts in /tmp for both versions.

EOF
}

PREV_TAG=""
CURRENT_DIR=""
PREVIOUS_DIR=""
WORK_DIR="/tmp/libfuse-abicheck-$$"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --prev-tag)
            PREV_TAG="$2"
            shift 2
            ;;
        --current-dir)
            CURRENT_DIR="$2"
            shift 2
            ;;
        --previous-dir)
            PREVIOUS_DIR="$2"
            shift 2
            ;;
        *)
            # Support old positional argument format
            PREV_TAG="$1"
            shift
            ;;
    esac
done

# If directories are provided, use them; otherwise create our own
if [ -n "$CURRENT_DIR" ] && [ -n "$PREVIOUS_DIR" ]; then
    # Use provided directories - convert to absolute paths
    CURRENT_PATH="$(cd "$CURRENT_DIR" && pwd)"
    PREVIOUS_PATH="$(cd "$PREVIOUS_DIR" && pwd)"
    echo "Using provided directories:"
    echo "  Current: $CURRENT_PATH"
    echo "  Previous: $PREVIOUS_PATH"
    CLEANUP_WORK_DIR=false
else
    # Auto-detect previous release tag if not provided
    if [ -z "$PREV_TAG" ]; then
        PREV_TAG=$(.github/workflows/find_previous_release_tag.sh)
    fi

    echo "Previous release: $PREV_TAG"

    # Create working directory
    mkdir -p "$WORK_DIR"
    trap "rm -rf $WORK_DIR" EXIT
    CLEANUP_WORK_DIR=true

    # Checkout current version
    cp -r . "$WORK_DIR/current"

    # Checkout previous version
    git clone . "$WORK_DIR/previous"
    (cd "$WORK_DIR/previous" && git checkout "$PREV_TAG")

    CURRENT_PATH="$WORK_DIR/current"
    PREVIOUS_PATH="$WORK_DIR/previous"
fi

# Build current version
cd "$CURRENT_PATH"
meson setup build --buildtype=debug
meson compile -C build

# Build previous version
cd "$PREVIOUS_PATH"
meson setup build --buildtype=debug
meson compile -C build

# Run abidiff
abidiff \
    --no-added-syms \
    --suppressions "$CURRENT_PATH/.github/workflows/abidiff_suppressions.abignore" \
    --headers-dir1 "$PREVIOUS_PATH/include/" \
    --headers-dir2 "$CURRENT_PATH/include/" \
    "$PREVIOUS_PATH/build/lib/libfuse3.so" \
    "$CURRENT_PATH/build/lib/libfuse3.so"
