#!/bin/bash
# Install Ubuntu dependencies for libfuse
# Based on dependencies from .github/workflows/pr-ci.yml and codechecker.yml

set -e

# Package lists - define once, reuse everywhere
PACKAGES_CORE=(
    gcc
    meson
    ninja-build
    libudev-dev
    liburing-dev
    libnuma-dev
    pkg-config
    python3
    python3-pip
    libsystemd-dev
    systemd-dev
)

PACKAGES_FULL=(
    "${PACKAGES_CORE[@]}"
    clang
    doxygen
    gcc-10
    gcc-9
    valgrind
    gcc-multilib
    g++-multilib
    libc6-dev-i386
    libpcap0.8-dev:i386
    libudev-dev:i386
    pkg-config:i386
    python3-pytest
    libsystemd-dev
    systemd-dev
)

PACKAGES_CODECHECKER=(
    "${PACKAGES_CORE[@]}"
    jq
)

PACKAGES_ABICHECK=(
    "${PACKAGES_CORE[@]}"
    abigail-tools
    clang
)

PACKAGES_CODEQL=(
    "${PACKAGES_CORE[@]}"
)

PACKAGES_CPPCHECK=(
    cppcheck
)

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
    --infer         Install Facebook Infer static analyzer
    -h, --help      Show this help message

EXAMPLES:
    $0                    # Install full dependencies
    $0 --minimal          # Install minimal build dependencies
    $0 --codechecker      # Install CodeChecker dependencies
    $0 --cppcheck         # Install cppcheck
    $0 --abicheck         # Install ABI check dependencies
    $0 --codeql           # Install CodeQL dependencies
    $0 --infer            # Install Infer static analyzer

EOF
    exit 0
}

install_packages() {
    local packages=("$@")
    if [ ${#packages[@]} -eq 0 ]; then
        echo "No packages to install"
        return 0
    fi

    sudo apt-get update
    sudo apt-get install -y "${packages[@]}"
}

install_minimal() {
    echo "Installing minimal build dependencies..."
    install_packages "${PACKAGES_CORE[@]}"
}

install_full() {
    echo "Installing full dependencies (including multilib and testing tools)..."

    # Add i386 architecture for 32-bit support
    echo "Adding i386 architecture..."
    sudo dpkg --add-architecture i386

    install_packages "${PACKAGES_FULL[@]}"

    echo "Installing Python test dependencies..."
    pip install -r requirements.txt
}

install_codechecker() {
    echo "Installing CodeChecker dependencies..."
    install_packages "${PACKAGES_CODECHECKER[@]}"

    echo "Installing Python packages for CodeChecker..."
    pip install -r requirements.txt
}

install_abicheck() {
    echo "Installing ABI check dependencies..."
    install_packages "${PACKAGES_ABICHECK[@]}"
}

install_codeql() {
    echo "Installing CodeQL dependencies..."
    install_packages "${PACKAGES_CODEQL[@]}"
}

install_cppcheck() {
    echo "Installing cppcheck..."
    install_packages "${PACKAGES_CPPCHECK[@]}"
}

install_infer() {
    echo "Installing Facebook Infer..."
    INFER_VERSION="1.2.0"
    INFER_TAR="infer-linux-x86_64-v${INFER_VERSION}.tar.xz"
    curl -sSL \
        "https://github.com/facebook/infer/releases/download/v${INFER_VERSION}/${INFER_TAR}" \
        -o /tmp/infer.tar.xz
    sudo tar -xJf /tmp/infer.tar.xz -C /opt
    sudo ln -sf "/opt/infer-linux-x86_64-v${INFER_VERSION}/bin/infer" /usr/local/bin/infer
    rm /tmp/infer.tar.xz
}

# Default to full installation
MODE="full"
INSTALL_CPPCHECK=0
INSTALL_INFER=0

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
        --infer)
            INSTALL_INFER=1
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

# Install optional tools if requested
if [ $INSTALL_CPPCHECK -eq 1 ]; then
    install_cppcheck
fi
if [ $INSTALL_INFER -eq 1 ]; then
    install_infer
fi

echo ""
echo "✓ Dependencies installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Build: meson setup builddir && ninja -C builddir"
echo "  2. Test:  meson test -C builddir"
echo ""
