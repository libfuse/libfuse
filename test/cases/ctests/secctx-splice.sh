#!/usr/bin/env bash
# GROUP: ctests
# A request carrying a security context extension that is too large for the
# fixed header the splice path copies out of the pipe first. Under valgrind or
# ASan this catches an extension parse that reads past that allocation.

. "$TEST_LIB/common.sh"

_require_cap FUSE_CAP_SPLICE_READ
_require_cap FUSE_CAP_SECURITY_CTX

"$FUSE_TEST_BIN_DIR/test_secctx_splice" "$TEST_MNT"
