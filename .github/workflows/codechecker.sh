#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
# Codechecker analysis script for libfuse
#
# Usage:
#   ./clang-ctu.sh [OPTIONS]
#
# Options:
#   --build-dir DIR         Path to Meson build directory (required)
#   --clang-only            Use only clang scan-build for CTU analysis
#   --codechecker           Use CodeChecker for advanced CTU analysis (default)
#   --github-workflow       Generate SARIF output for GitHub Code Scanning
#   --no-ctu                Disable CTU analysis (faster, intra-file analysis only)
#   --gcc                   Enable GCC static analyzer (requires GCC 13+, CodeChecker only)
#   --cppcheck              Enable cppcheck analyzer (CodeChecker only)

set -e

# Defaults
USE_CODECHECKER=1
BUILD_DIR=""
GITHUB_WORKFLOW=0
ENABLE_CTU=1
ENABLE_GCC=0
ENABLE_CPPCHECK=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --clang-only)
            USE_CODECHECKER=0
            shift
            ;;
        --codechecker)
            USE_CODECHECKER=1
            shift
            ;;
        --github-workflow)
            GITHUB_WORKFLOW=1
            shift
            ;;
        --no-ctu)
            ENABLE_CTU=0
            shift
            ;;
        --gcc)
            ENABLE_GCC=1
            shift
            ;;
        --cppcheck)
            ENABLE_CPPCHECK=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo \
"  --build-dir DIR         Path to Meson build directory (required)"
            echo \
"  --clang-only            Use only clang scan-build for CTU analysis"
            echo \
"  --codechecker           Use CodeChecker for advanced CTU analysis (default)"
            echo \
"  --github-workflow       Generate SARIF output for GitHub Code Scanning"
            echo \
"  --no-ctu                Disable CTU analysis (faster, intra-file analysis only)"
            echo \
"  --gcc                   Enable GCC static analyzer (requires GCC 13+, CodeChecker only)"
            echo \
"  --cppcheck              Enable cppcheck analyzer (CodeChecker only)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate options
if [ $ENABLE_GCC -eq 1 ] && [ $USE_CODECHECKER -eq 0 ]; then
    echo "[ERROR] --gcc option requires --codechecker"
    exit 1
fi

if [ $ENABLE_CPPCHECK -eq 1 ] && [ $USE_CODECHECKER -eq 0 ]; then
    echo "[ERROR] --cppcheck option requires --codechecker"
    exit 1
fi

if [ $ENABLE_GCC -eq 1 ] && [ $ENABLE_CPPCHECK -eq 1 ]; then
    echo "[ERROR] Cannot use both --gcc and --cppcheck at the same time"
    exit 1
fi

echo_info()
{
    echo "[INFO] $1"
}

echo_error()
{
    echo "[ERROR] $1"
}

# Validate build directory and compile_commands.json
setup_build_dir()
{
    if [ -z "$BUILD_DIR" ]; then
        echo_error "--build-dir is required. Please specify the Meson build directory"
        exit 1
    fi

    if [ ! -d "$BUILD_DIR" ]; then
        echo_error "Build directory not found: $BUILD_DIR"
        exit 1
    fi

    if [ ! -f "$BUILD_DIR/compile_commands.json" ]; then
        echo_error "compile_commands.json not found in $BUILD_DIR"
        echo_error "Make sure you have run 'meson setup' with the build directory"
        exit 1
    fi

    # Convert to absolute path
    BUILD_DIR=$(cd "$BUILD_DIR" && pwd)

    echo_info "Using build directory: $BUILD_DIR"
}

# Run analysis with clang tools
run_clang_ctu()
{
    local mode_msg="Clang analysis"
    if [ $ENABLE_CTU -eq 1 ]; then
        mode_msg="$mode_msg with CTU"
    else
        mode_msg="$mode_msg (no CTU)"
    fi
    echo_info "Running $mode_msg..."

    # Work in build directory
    cd "$BUILD_DIR"

    rm -rf ctu-dir scan-results

    if [ $ENABLE_CTU -eq 1 ]; then
        mkdir -p ctu-dir
        echo_info "Generating CTU index..."
        clang-extdef-mapping -p . > ctu-dir/externalDefMap.txt
        echo_info "Found $(wc -l < ctu-dir/externalDefMap.txt) external definitions"
    fi

    if [ $GITHUB_WORKFLOW -eq 1 ]; then
        echo_info "Running scan-build with SARIF output..."
        mkdir -p scan-results

        # Build scan-build command conditionally
        local scan_build_cmd="scan-build --use-cc=clang --use-c++=clang++ --status-bugs"

        if [ $ENABLE_CTU -eq 1 ]; then
            scan_build_cmd=\
                "$scan_build_cmd -analyzer-config experimental-enable-naive-ctu-analysis=true"
            scan_build_cmd="$scan_build_cmd -analyzer-config ctu-dir=ctu-dir"
            scan_build_cmd="$scan_build_cmd -analyzer-config ctu-index-name=externalDefMap.txt"
        fi

        scan_build_cmd="$scan_build_cmd --sarif -o scan-results"

        # Run scan-build with meson compile to analyze all files
        echo_info "Running scan-build meson compile..."
        eval $scan_build_cmd meson compile

        # Find and consolidate SARIF files
        find scan-results -name "*.sarif" -exec cat {} \; > results.sarif 2>/dev/null || true
        echo_info "SARIF output saved to results.sarif"
    else
        echo_info "Running clang-check analysis..."

        # Build clang-check command conditionally
        local clang_check_cmd="clang-check -analyze -p ."

        local ctu_args="-extra-arg=-Xclang -extra-arg=-analyzer-config"
        ctu_args="$ctu_args -extra-arg=-Xclang "
        ctu_args="$ctu_args -extra-arg=experimental-enable-naive-ctu-analysis=true"
        ctu_args="$ctu_args -extra-arg=-Xclang -extra-arg=-analyzer-config"
        ctu_args="$ctu_args -extra-arg=-Xclang -extra-arg=ctu-dir=ctu-dir"

        if [ $ENABLE_CTU -eq 1 ]; then
            clang_check_cmd="$clang_check_cmd $ctu_args"
        fi

        if ! eval $clang_check_cmd $(jq -r '.[].file' compile_commands.json | sort -u); then
            echo_error "Analysis found issues"
            return 1
        fi
        echo_info "No issues found"
    fi

    return 0
}

# Detect CodeChecker command (pip package vs snap package)
detect_codechecker()
{
    if command -v CodeChecker &> /dev/null; then
        echo "CodeChecker"
    elif command -v codechecker &> /dev/null; then
        echo "codechecker"
    else
        echo_error "CodeChecker not found (tried 'CodeChecker' and 'codechecker')"
        exit 1
    fi
}

# Parse and output CodeChecker results
parse_codechecker_results()
{
    local codechecker="$1"

    echo_info "Parsing results..."
    local has_issues=0
    if $codechecker parse codechecker-reports | grep -q "found"; then
        has_issues=1
        $codechecker parse codechecker-reports
    fi

    # Generate output based on mode
    if [ $GITHUB_WORKFLOW -eq 1 ]; then
        echo_info "Generating SARIF output for GitHub..."
        $codechecker parse codechecker-reports -e sarif -o results.sarif
        echo_info "SARIF output saved to results.sarif"
    else
        echo_info "Generating HTML reports..."
        $codechecker parse codechecker-reports -e html -o codechecker-html
        echo_info "HTML reports saved to codechecker-html/"
    fi

    if [ $has_issues -eq 1 ]; then
        return 1
    fi

    echo_info "No issues found"
    return 0
}

# Run analysis with CodeChecker using Clang Static Analyzer
run_codechecker_clang()
{
    local mode_msg="CodeChecker with Clang Static Analyzer"
    if [ $ENABLE_CTU -eq 1 ]; then
        mode_msg="$mode_msg with CTU"
    else
        mode_msg="$mode_msg (no CTU)"
    fi
    echo_info "Running $mode_msg..."

    local codechecker=$(detect_codechecker)

    # Work in build directory
    cd "$BUILD_DIR"

    rm -rf codechecker-reports codechecker-html
    mkdir -p codechecker-reports

    # Build CodeChecker analyze command for Clang
    local cc_analyze_cmd="$codechecker analyze compile_commands.json -o codechecker-reports"
    cc_analyze_cmd="$cc_analyze_cmd --analyzers clangsa"

    # Add CTU flag if enabled
    if [ $ENABLE_CTU -eq 1 ]; then
        cc_analyze_cmd="$cc_analyze_cmd --ctu"
    fi

    # Enable Clang-specific checkers
    cc_analyze_cmd="$cc_analyze_cmd --enable core --enable unix --enable profile:security"
    cc_analyze_cmd="$cc_analyze_cmd --enable alpha.unix.Stream --enable alpha.core.PointerArithm"

    # Note: cert-dcl37-c and cert-dcl51-cpp checkers (reserved identifiers) are not
    # available in Clang Static Analyzer. We use _function() in the exported API but
    # this won't be flagged by the available checkers.

    eval $cc_analyze_cmd

    parse_codechecker_results "$codechecker"
}

# Run analysis with CodeChecker using GCC Static Analyzer
run_codechecker_gcc()
{
    echo_info "Running CodeChecker with GCC Static Analyzer (CTU not supported)..."

    # Check GCC version
    if ! command -v gcc &> /dev/null; then
        echo_error "GCC not found but --gcc was specified"
        exit 1
    fi

    local gcc_version=$(gcc -dumpversion | cut -d. -f1)
    if [ "$gcc_version" -lt 13 ]; then
        echo_error "GCC version $gcc_version found, but GCC 13+ is required for static analyzer"
        exit 1
    fi
    echo_info "Found GCC version $gcc_version"

    local codechecker=$(detect_codechecker)

    # Work in build directory
    cd "$BUILD_DIR"

    rm -rf codechecker-reports codechecker-html
    mkdir -p codechecker-reports

    # Build CodeChecker analyze command for GCC
    local cmd="$codechecker analyze compile_commands.json -o codechecker-reports"
    cmd="$cmd --analyzers gcc"

    # Enable GCC checkers, disable malloc-leak, due to too many false positives
    cmd="$cmd --enable gcc --disable gcc-malloc-leak"

    eval $cmd

    parse_codechecker_results "$codechecker"
}

# Run analysis with CodeChecker using cppcheck
run_codechecker_cppcheck()
{
    echo_info "Running CodeChecker with cppcheck analyzer..."

    # Check if cppcheck is available
    if ! command -v cppcheck &> /dev/null; then
        echo_error "cppcheck not found but --cppcheck was specified"
        exit 1
    fi

    local cppcheck_version=$(cppcheck --version | awk '{print $2}')
    echo_info "Found cppcheck version $cppcheck_version"

    local codechecker=$(detect_codechecker)

    # Work in build directory
    cd "$BUILD_DIR"

    rm -rf codechecker-reports codechecker-html
    mkdir -p codechecker-reports

    # Build CodeChecker analyze command for cppcheck
    local cmd="$codechecker analyze compile_commands.json -o codechecker-reports"
    cmd="$cmd --analyzers cppcheck"

    # Enable cppcheck checkers
    cmd="$cmd --enable cppcheck"

    # Disable checkers with excessive false positives
    cmd="$cmd --disable cppcheck-missingIncludeSystem"
    cmd="$cmd --disable cppcheck-constParameterCallback"
    cmd="$cmd --disable cppcheck-knownConditionTrueFalse"
    cmd="$cmd --disable cppcheck-unusedStructMember"

    eval $cmd

    parse_codechecker_results "$codechecker"
}

echo_info "Static Analysis Configuration"

# Display tool selection
if [ $USE_CODECHECKER -eq 1 ]; then
    echo_info "Tool: CodeChecker"
else
    echo_info "Tool: clang-check"
fi

# Display CTU status
if [ $ENABLE_CTU -eq 1 ]; then
    echo_info "CTU: Enabled"
else
    echo_info "CTU: Disabled"
fi

# Display analyzer selection (for CodeChecker only)
if [ $USE_CODECHECKER -eq 1 ]; then
    if [ $ENABLE_GCC -eq 1 ]; then
        echo_info "Analyzer: GCC"
    elif [ $ENABLE_CPPCHECK -eq 1 ]; then
        echo_info "Analyzer: cppcheck"
    else
        echo_info "Analyzer: Clang"
    fi
fi

setup_build_dir

if [ $USE_CODECHECKER -eq 1 ]; then
    if [ $ENABLE_GCC -eq 1 ]; then
        run_codechecker_gcc
    elif [ $ENABLE_CPPCHECK -eq 1 ]; then
        run_codechecker_cppcheck
    else
        run_codechecker_clang
    fi
else
    run_clang_ctu
fi
