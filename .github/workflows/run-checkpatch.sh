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
IGNORES="${IGNORES},STRCPY,STRNCPY,COMPLEX_MACRO,LINE_SPACING,SYMBOLIC_PERMS"
# version checks read as "FUSE_USE_VERSION >= FUSE_MAKE_VERSION(3, 19)"
IGNORES="${IGNORES},CONSTANT_COMPARISON"

# checkpatch is a C/kernel-style checker; a YAML key like "cc:" reads as a
# malformed Signed-off-by/Cc trailer to its BAD_SIGN_OFF check, so YAML is
# kept out of the diff it sees rather than silencing that check.
# -c diff.algorithm=default: histogram (a common user gitconfig default)
# aligns some hunks differently than myers, which can turn an unrelated
# pre-existing line into a "+" line or vice versa; pin so local runs match CI.
# <commit>^..<commit> rather than -1 <commit>: with a pathspec, -1 means "one
# commit reachable from here that touches it", so a YAML-only commit would
# hand checkpatch its predecessor and report on the wrong patch. The range
# emits nothing instead, which is the right answer for such a commit.
git -c diff.algorithm=default format-patch --stdout "${commit}^..${commit}" \
    -- . ':!*.yml' ':!*.yaml' |
    ./checkpatch.pl --show-types --max-line-length=100 --no-tree --ignore ${IGNORES} -
