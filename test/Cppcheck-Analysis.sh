#!/bin/bash -e
# @copyright
#                               --- WARNING ---
#
#     This work contains trade secrets of DataDirect Networks, Inc.  Any
#     unauthorized use or disclosure of the work, or any part thereof, is
#     strictly prohibited. Any use of this work without an express license
#     or permission is in violation of applicable laws.
#
# @copyright DataDirect Networks, Inc. CONFIDENTIAL AND PROPRIETARY
# @copyright DataDirect Networks Copyright, Inc. (c) 2021-2024. All rights reserved.
# script: Cppcheck-Analysis
#
#    Arguments: list of files to check:
#               To check all files use 'src include'

CPPVERSION=$(cppcheck --version)
echo $CPPVERSION

which cppcheck

BASE_DIR=$(pwd)
REPORT_DIR="$BASE_DIR/cppcheck_report"
OUTXML="$REPORT_DIR/cppcheck.xml"
BUILD_CACHE="$REPORT_DIR/build_cache"

rm -f $OUTXML $REPORT_DIR/*.html
mkdir -p $BUILD_CACHE $REPORT_DIR

changed_files="$@"

if [ -z "$changed_files" ]; then
    changed_files="lib include util"
    echo $changed_files
fi

# make concurrency
if [ -z "$CONCURRENCY" ]; then
    CONCURRENCY="-j$(nproc)"
fi

echo "CONCURRENCY=$CONCURRENCY"

TESTS="--enable=performance,portability,information,missingInclude,warning,style"
if [ -n "$CPPCHECK_TESTS" ]; then
    TESTS="--enable=$CPPCHECK_TESTS"
fi

set +e
echo "Checking if --check-level=exhaustive is supported"
cppcheck -q --check-config --check-level=exhaustive include/fuse.h
if [ $? -eq 0 ]; then
    echo "--check-level=exhaustive supported"
    TESTS+=" --check-level=exhaustive"
else
    echo "--check-level=exhaustive not supported"
fi
set -e

# This list tells Cppcheck to ignore these preprocessor combinations
# that do no not require analysis
DEFINES="-D__CPPCHECK__ \
        -DMAXHOSTNAMELEN=64 \
        -Dstatic_assert \
        -DRED_MEMORY_PROFILER \
        -DFUSE_USE_VERSION=312 \
        -UGCOV_BUILD \
        -UDEBUG_PARSER \
        -URED_ADDRESS_SANITIZER"


SUPPRESSIONS="--suppress=unmatchedSuppression \
              --suppress=readdirCalled \
              --suppress=ctuOneDefinitionRuleViolation \
              --suppress=uninitMemberVar \
              --suppress=premium-uninitMemberVar \
              --suppress=missingIncludeSystem \
              --suppress=*:3rdparty/* \
              --suppress=useStlAlgorithm \
              --suppress=cstyleCast \
              --suppress=variableScope \
              --suppress=unusedPrivateFunction \
              --suppress=unusedStructMember \
              --suppress=constVariable \
              --suppress=constVariablePointer \
              --suppress=constVariableReference \
              --suppress=constParameter \
              --suppress=constParameterCallback \
              --suppress=constParameterPointer \
              --suppress=constParameterReference \
              --suppress=duplInheritedMember \
              --suppress=knownConditionTrueFalse \
              --suppress=checkersReport"

set +e
set -x

set -o pipefail

cppcheck $CONCURRENCY \
         --inline-suppr \
         $TESTS \
         $SUPPRESSIONS \
         --verbose \
         --std=c++11 \
         --language=c++ \
         --platform=unix64 \
         --library=posix,gnu \
         --xml --xml-version=2 \
         --error-exitcode=2 \
         -I . \
         -I include/ \
         --cppcheck-build-dir=$BUILD_CACHE \
         $DEFINES \
         $changed_files 2> >(tee $OUTXML)

CPPCHECK_STATUS=$?

if [ $CPPCHECK_STATUS -eq 1 ]; then
    echo "Error calling cppcheck"
    exit "$CPPCHECK_STATUS"
fi

set +x
set -e
cppcheck-htmlreport --source-encoding="iso8859-1" \
                    --title="Cppcheck" \
                    --source-dir="$BASE_DIR" \
                    --report-dir="$REPORT_DIR" \
                    --blame-options=M \
                    --file="$OUTXML"

# Check if there are any errors remaining
# Remove unmatchedSuppression
CPPCHECK_PARSE_RSLT=`test/cppcheck_parse.py -c -f $OUTXML`
if [ $CPPCHECK_STATUS -ne 0 ] ; then
    if [ $CPPCHECK_PARSE_RSLT == "0" ] ; then
        # Did not find any errors
        echo "Ignoring unmatchedSuppression"
        CPPCHECK_STATUS=0
    else 
        echo ""
        echo "===================================================================="
        echo "CPPCHECK found ${CPPCHECK_PARSE_RSLT} defects that must be corrected"
        echo "according to RED code quality guidelines:"
        echo "--------------------------------------------------------------------"
        test/cppcheck_parse.py -f $OUTXML -v
        echo "===================================================================="
        echo ""
    fi
fi

if [ $CPPCHECK_STATUS -eq 0 ]; then
    echo "Cppcheck passed"
    exit 0
else
    echo "Cppcheck errors reported"
    exit "$CPPCHECK_STATUS"
fi
