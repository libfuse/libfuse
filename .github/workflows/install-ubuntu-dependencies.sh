#!/bin/bash
# Install Ubuntu dependencies for libfuse
# Based on dependencies from .github/workflows/pr-ci.yml and codechecker.yml

set -e

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Install Ubuntu dependencies for libfuse development and testing.

OPTIONS:
    --minimal       Install only minimal build dependencies
    --full          Install all dependencies including multilib and testing tools (default)
    --codechecker   Install dependencies for CodeChecker analysis
    --cppcheck      Install cppcheck for static analysis
    --abicheck      Install dependencies for ABI compatibility checks
    --codeql        Install dependencies for CodeQL analysis
    -h, --help      Show this help message

EXAMPLES:
    $0                    # Install full dependencies
    $0 --minimal          # Install minimal build dependencies
    $0 --codechecker      # Install CodeChecker dependencies
    $0 --cppcheck         # Install cppcheck
    $0 --abicheck         # Install ABI check dependencies
    $0 --codeql           # Install CodeQL dependencies

EOF
    exit 0
}

install_minimal() {
    echo "Installing minimal build dependencies..."
    sudo apt-get update
    sudo apt-get install -y \
        gcc \
        meson \
        ninja-build \
        python3 \
        python3-pip \
        libudev-dev \
        pkg-config
}

install_full() {
    echo "Installing full dependencies (including multilib and testing tools)..."

    # Add i386 architecture for 32-bit support
    echo "Adding i386 architecture..."
    sudo dpkg --add-architecture i386

    sudo apt-get update
    sudo apt-get install -y \
        clang \
        doxygen \
        gcc \
        gcc-10 \
        gcc-9 \
        valgrind \
        gcc-multilib \
        g++-multilib \
        libc6-dev-i386 \
        libpcap0.8-dev:i386 \
        libudev-dev:i386 \
        pkg-config:i386 \
        liburing-dev \
        libnuma-dev \
        meson \
        ninja-build \
        python3 \
        python3-pip

    echo "Installing Python test dependencies..."
    pip install -r requirements.txt
}

install_codechecker() {
    echo "Installing CodeChecker dependencies..."
    sudo apt-get update
    sudo apt-get install -y \
        gcc \
        meson \
        ninja-build \
        python3 \
        python3-pip \
        libudev-dev \
        jq

    echo "Installing Python packages for CodeChecker..."
    pip install -r requirements.txt
}

install_abicheck() {
    echo "Installing ABI check dependencies..."
    sudo apt-get update
    sudo apt-get install -y \
        abigail-tools \
        clang \
        gcc \
        liburing-dev \
        libnuma-dev \
        meson \
        ninja-build \
        python3 \
        python3-pip
}

install_codeql() {
    echo "Installing CodeQL dependencies..."
    sudo apt-get update
    sudo apt-get install -y \
        meson \
        ninja-build \
        python3-pytest \
        liburing-dev \
        libnuma-dev
}

install_cppcheck() {
    echo "Installing cppcheck..."
    sudo apt-get update
    sudo apt-get install -y cppcheck
}

# Default to full installation
MODE="full"
INSTALL_CPPCHECK=0

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal)
            MODE="minimal"
            shift
            ;;
        --full)
            MODE="full"
            shift
            ;;
        --codechecker)
            MODE="codechecker"
            shift
            ;;
        --cppcheck)
            INSTALL_CPPCHECK=1
            shift
            ;;
        --abicheck)
            MODE="abicheck"
            shift
            ;;
        --codeql)
            MODE="codeql"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information."
            exit 1
            ;;
    esac
done

# Execute the appropriate installation
case $MODE in
    minimal)
        install_minimal
        ;;
    full)
        install_full
        ;;
    codechecker)
        install_codechecker
        ;;
    abicheck)
        install_abicheck
        ;;
    codeql)
        install_codeql
        ;;
esac

# Install cppcheck if requested
if [ $INSTALL_CPPCHECK -eq 1 ]; then
    install_cppcheck
fi

echo ""
echo "✓ Dependencies installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Build: meson setup builddir && ninja -C builddir"
echo "  2. Test:  meson test -C builddir"
echo ""
