#!/usr/bin/env bash
# GROUP: examples passthrough
# In passthrough mode the daemon never sees the write, so clearing setuid and
# setgid can only come from the kernel side of the handoff. A backing file needs
# CAP_SYS_ADMIN, hence the root daemon; --debug is what makes passthrough_hp
# name the backing file it installs.

. "$TEST_LIB/common.sh"

_require_cap FUSE_CAP_PASSTHROUGH
_require_root

FS_ARGS="--foreground --debug"
PT_WANT_BACKING=1

. "$TEST_LIB/passthrough-suid.sh"
