"""Helper functions about what this build supports and the host can run"""

import ctypes
import os
import platform
import subprocess
from pathlib import Path

IS_LINUX = platform.system() == 'Linux'

IO_URING_CAP = 'FUSE_CAP_OVER_IO_URING'
# What -Dsync-init=always/never leave in fuse_config.h; auto writes neither.
SYNC_INIT_ENABLED = '#define FUSE_SYNC_INIT_DEFAULT FUSE_SYNC_INIT_ENABLED'
SYNC_INIT_DISABLED = '#define FUSE_SYNC_INIT_DEFAULT FUSE_SYNC_INIT_DISABLED'
FUSE_URING_PARAM = Path('/sys/module/fuse/parameters/enable_uring')
# glibc has no io_uring_setup() wrapper, so this goes through syscall(2), the
# way liburing does it. 425 on every architecture but alpha.
IO_URING_SETUP = 425
IO_URING_PARAMS_SIZE = 120      # sizeof(struct io_uring_params)


def read_fuse_caps(build_dir: Path, path: str) -> frozenset:
    """The FUSE_CAP_* names printcap reports, read once per run.

    printcap mounts to negotiate, so it needs the test's $PATH; with the
    ambient one every _require_cap test silently skips.
    """
    printcap = build_dir / 'example' / 'printcap'
    if not os.access(printcap, os.X_OK):
        print(f'note: {printcap} not built; no capability is available '
              'and every _require_cap test will skip')
        return frozenset()
    proc = subprocess.run([str(printcap)], capture_output=True, text=True,
                          timeout=30, check=False,
                          env=dict(os.environ, PATH=path))
    if proc.returncode != 0:
        print(f'note: printcap failed ({proc.returncode}); '
              'every _require_cap test will skip')
        return frozenset()
    return frozenset(line.strip() for line in proc.stdout.splitlines()
                     if line.startswith('\t'))


def read_sync_init(build_dir: Path) -> str:
    """Which -Dsync-init the library was built with: auto, always, never.

    A property of the build, so it comes from fuse_config.h rather than
    the command line.
    """
    try:
        config = (build_dir / 'fuse_config.h').read_text()
    except OSError:
        return 'unknown'
    for define, mode in ((SYNC_INIT_ENABLED, 'always'),
                         (SYNC_INIT_DISABLED, 'never')):
        if define in config:
            return mode
    return 'auto'


def preflight_io_uring(build_dir: Path, fuse_caps: frozenset) -> str:
    """The reason the io-uring transport cannot be exercised, else "".

    Checked in this order, so the message names the first thing actually
    wrong; a non-empty reason skips the invocation with exit 77.
    """
    if not IS_LINUX:
        return f'fuse-io-uring is Linux-only, this is {platform.system()}'
    try:
        config = (build_dir / 'fuse_config.h').read_text()
    except OSError:
        return f'{build_dir}/fuse_config.h is unreadable'
    if 'HAVE_URING' not in config:
        return 'the library was built with -Denable-io-uring=false'
    if IO_URING_CAP in fuse_caps:
        return ''
    # printcap reports capable_ext, so absence is the kernel's answer; the
    # module parameter only separates the two reasons.
    try:
        enabled = FUSE_URING_PARAM.read_text().strip()
    except OSError:
        return 'this kernel has no fuse io-uring support'
    if enabled in ('N', '0'):
        return ('io-uring is disabled in the fuse module\n'
                f'      echo Y | sudo tee {FUSE_URING_PARAM}')
    return f'the kernel did not offer {IO_URING_CAP}'


def io_uring_setup_error() -> str:
    """The errno text when io_uring_setup() is refused, else "".

    Asked as the user the daemons will run as, so it answers for them.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ring = libc.syscall(IO_URING_SETUP, 1,
                        ctypes.create_string_buffer(IO_URING_PARAMS_SIZE))
    if ring < 0:
        return os.strerror(ctypes.get_errno())
    os.close(ring)
    return ''
