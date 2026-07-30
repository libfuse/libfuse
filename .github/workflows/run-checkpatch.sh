#!/bin/sh

if [ -n "$1" ]; then
    commit="$1"
else
    commit="HEAD"
fi

IGNORES="MAINTAINERS,SPDX_LICENSE_TAG,COMMIT_MESSAGE,FILE_PATH_CHANGES"
IGNORES="${IGNORES},EMAIL_SUBJECT,AVOID_EXTERNS,GIT_COMMIT_ID,ENOSYS_SYSCALL"
IGNORES="${IGNORES},ENOSYS,FROM_SIGN_OFF_MISMATCH,QUOTED_COMMIT_ID,"
IGNORES="${IGNORES},PREFER_ATTRIBUTE_ALWAYS_UNUSED,PREFER_DEFINED_ATTRIBUTE_MACRO"
IGNORES="${IGNORES},STRCPY,STRNCPY,COMPLEX_MACRO,LINE_SPACING"

# checkpatch is a C/kernel-style checker; a YAML key like "cc:" reads as a
# malformed Signed-off-by/Cc trailer to its BAD_SIGN_OFF check, so YAML is
# kept out of the diff it sees rather than silencing that check.
git format-patch -1 --stdout "$commit" -- . ':!*.yml' ':!*.yaml' |
    ./checkpatch.pl --show-types --max-line-length=100 --no-tree --ignore ${IGNORES} -
