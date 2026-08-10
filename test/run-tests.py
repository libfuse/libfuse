#!/usr/bin/env python3
"""Run the libfuse shell test suite.

Every executable cases/**/*.sh outside cases/lib is a test, as is every entry
in a directory is_shell_exception_dir() names, where the file name is a
build-tree binary to run instead. A test's name is the path below cases/
without the extension. Exit code 0 is a pass, 77 a self-declared skip and
anything else a failure.

The runner knows nothing about FUSE: it owns discovery, working directories,
containment, timeouts, parallelism, logs, core dumps and the summary. The FUSE
verbs live in cases/lib/common.sh.
"""

import argparse
import ctypes
import fnmatch
import os
import platform
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path

# Everything the suite reads lives beside this file in the source tree; the
# build directory supplies binaries and nothing else, so a test edited in the
# source tree runs without a rebuild.
TEST_DIR = Path(__file__).resolve().parent
CASES_DIR = TEST_DIR / 'cases'
# What the cases source, beside them rather than above them; discovery skips it.
LIB_DIR = CASES_DIR / 'lib'
EXCLUDE_FILE = TEST_DIR / 'exclude'

DEFAULT_TIMEOUT = 60.0          # seconds; per-script "# TIMEOUT:" overrides
SKIP_EXIT_CODE = 77             # automake convention
LAUNCH_FAILED_EXIT_CODE = 125   # launcher could not establish containment
LAUNCH_FAILED_MARKER = 'run-tests: containment failed'

# util/install_helper.sh installs exactly these setuid; nothing else in util/
# needs the bit.
SETUID_HELPERS = ('fusermount3', 'fuservicemount3')

GDB_TIMEOUT = 120.0             # gdb can wedge on a huge core or absent symbols
GDB_TOP_FRAMES = 12             # frames inlined into the summary

# A task wedged in an uninterruptible FUSE request does not die on SIGKILL, so
# waiting for one without a bound hangs the run itself.
REAP_TIMEOUT = 30.0             # seconds to wait for a killed test to be gone

# A daemon under valgrind is an order of magnitude slower, so every timeout is
# scaled by one constant rather than each script carrying a second number for a
# mode most runs do not use.
VALGRIND_TIMEOUT_FACTOR = 10
# --error-exitcode is what makes a finding fail the test: the daemon exits 99
# and fuse_umount's existing status check catches it. Leak checking stays off;
# turning it on is a separate decision with its own noise budget.
VALGRIND_PREFIX = 'valgrind -q --error-exitcode=99 --'
# ==PID== is valgrind's standard output, --PID-- its warnings; the report is
# not the verdict, the daemon's exit status is.
_VALGRIND_LINE_RE = re.compile(r'^(?:==|--)[0-9]+(?:==|--) .*$', re.MULTILINE)

# Test output must land somewhere predictable, so this is the default base for
# everything the suite writes. /var/tmp rather than /tmp because it survives a
# reboot and no tmpfiles cleaner walks it mid-run, and a fixed name rather than
# a mktemp directory because a path you cannot predict is a path you cannot
# look in after CI hands you a red build.
DEFAULT_BASE_DIR = Path('/var/tmp/fuse-tests')

# Tests declaring this group cannot run concurrently with a copy of themselves:
# they bind a fixed path, name a device node globally, or take the first free
# loop device. They run first, with one job, before the rest fan out.
SERIAL_GROUP = 'serial'

_CONFIG_SECTION = 'tests'
_CONFIG_BASE_DIR_KEY = 'base_dir'

IS_LINUX = platform.system() == 'Linux'

# FreeBSD's default kern.corefile is "%N.core"; CI sets "core.%N.%P" to get the
# shape Linux's "core.%e.%p" produces. Glob those plus the bare "core" and
# "core.%p" a stock Linux box writes, so an unconfigured developer machine
# still yields a core.
CORE_GLOBS = ('core', 'core.*', '*.core')

# A daemon writing any of these to its stderr fails the test even when it
# exited 0.
SUSPICIOUS_WORDS = ('exception', 'error', 'warning', 'fatal', 'traceback',
                    'fault', 'crash(?:ed)?', 'abort(?:ed)?',
                    'uninitiali[zs]ed')

# libfuse logs this at FUSE_LOG_INFO and then carries on over /dev/fuse, so an
# io-uring run that nobody checks passes green while testing the transport it
# was meant to replace.
IO_URING_FALLBACK = 'failed to start io-uring'
IO_URING_CAP = 'FUSE_CAP_OVER_IO_URING'
# Every session states its transport on its own stderr, which is a log the
# suite keeps either way. off:custom_io is the only refusal a daemon cannot
# help: no /dev/fuse fd of its own, so no ring to issue against.
IO_URING_STATE_KEY = 'FUSE_INIT: io_uring='
IO_URING_STATES_OK = ('FUSE_INIT: io_uring=on',
                      'FUSE_INIT: io_uring=off:custom_io')
# What -Dsync-init=always/never leave in fuse_config.h; auto writes neither.
SYNC_INIT_ENABLED = '#define FUSE_SYNC_INIT_DEFAULT FUSE_SYNC_INIT_ENABLED'
SYNC_INIT_DISABLED = '#define FUSE_SYNC_INIT_DEFAULT FUSE_SYNC_INIT_DISABLED'
FUSE_URING_PARAM = Path('/sys/module/fuse/parameters/enable_uring')
# glibc has no io_uring_setup() wrapper, so this goes through syscall(2), the
# way liburing does it. 425 on every architecture but alpha.
IO_URING_SETUP = 425
IO_URING_PARAMS_SIZE = 120      # sizeof(struct io_uring_params)

# FUSE debug messages "unique: X, error: -Y (...), outsize: Z" contain the word
# "error" but only report a request's return code.
_FUSE_DEBUG_RE = re.compile(
    r'^.*unique: \d+, error: -\d+ \(.*\), outsize: \d+.*$', re.MULTILINE)

_HEADER_RE = re.compile(r'^#\s*(TIMEOUT|GROUP):\s*(.+?)\s*$')

# Two things must happen in the child before the test runs: it must enter its
# cgroup leaf and raise its soft core limit. Neither can be done with a
# preexec_fn -- run_all() is threaded, and Python between fork() and exec() can
# deadlock inside Popen(), where no timeout is watching yet. Only builtins run
# here, so nothing forks before the leaf is joined and a daemon the script
# spawns cannot escape it.
#
# `ulimit -H -c` rather than a limit computed in Python: ulimit counts 512-byte
# blocks in dash and 1024-byte blocks in bash, and RLIM_INFINITY is -1 in
# CPython, which every shell parses as an option. Only the soft limit is raised;
# raising a finite hard limit needs privilege.
#
# The command to exec is passed in rather than built here: the runner decides
# whether a test is a script or a binary, and both the spawn and repro.sh must
# name the same one.
LAUNCHER = f'''
[ -z "$1" ] || printf '%s\\n' "$$" >"$1" || {{
	echo "{LAUNCH_FAILED_MARKER}: cgroup" >&2; exit {LAUNCH_FAILED_EXIT_CODE}
}}
ulimit -S -c "$(ulimit -H -c)" || {{
	echo "{LAUNCH_FAILED_MARKER}: core limit" >&2
	exit {LAUNCH_FAILED_EXIT_CODE}
}}
shift
exec "$@"
'''


@dataclass(frozen=True)
class TestSpec:
    """One discovered test and the two facts parsed from its header."""

    name: str          # "examples/hello-ll-direct" -- path under cases/, no .sh
    script: Path       # absolute path to the script, or to the binary marker
    timeout: float     # seconds; DEFAULT_TIMEOUT unless "# TIMEOUT:" overrides
    groups: frozenset  # from "# GROUP:"; used by -g/--group selection
    binary: str = ''   # marker: the build-tree binary to run; "" for a script


@dataclass
class CoreDump:
    """One core file found in a test's log directory."""

    path: Path
    executable: str        # %e from the file name, e.g. "passthrough_ll"
    pid: int               # %p from the file name
    binary: Path | None = None      # resolved build-tree binary
    # logs/backtrace.<exe>.<pid>.txt -- deliberately not sharing the "core."
    # prefix, so CI can upload backtraces while excluding the huge cores with a
    # single "!**/core.*" pattern.
    backtrace: Path | None = None   # None if gdb is absent
    top_frames: str = ''            # first GDB_TOP_FRAMES frames


@dataclass
class TestResult:
    """Outcome of one test script run."""

    name: str
    status: str            # "PASS" | "FAIL" | "SKIP"
    duration: float        # wall clock seconds, monotonic
    exit_code: int         # script exit status; negative == killed by signal
    reason: str            # skip reason, kill reason, or "" on a clean pass
    workdir: Path
    cores: list = field(default_factory=list)   # list[CoreDump], backtraced
    suspicious: str = ''   # first offending log line found by scan_logs()


def parse_spec(script: Path, cases_dir: Path) -> TestSpec:
    """Read the leading comment block of *script* for TIMEOUT and GROUP."""
    timeout, groups = DEFAULT_TIMEOUT, set()
    with script.open() as fh:
        for line in fh:
            if not line.startswith('#'):
                if line.strip():        # first non-comment line ends the header
                    break
                continue
            hit = _HEADER_RE.match(line)
            if not hit:
                continue
            if hit.group(1) == 'TIMEOUT':
                timeout = float(hit.group(2))
            else:
                groups.update(hit.group(2).split())
    return TestSpec(name=str(script.relative_to(cases_dir).with_suffix('')),
                    script=script, timeout=timeout, groups=frozenset(groups),
                    # discover() collects nothing else without a suffix
                    binary='' if script.suffix else script.name)


def read_core_pattern() -> str:
    """The kernel's core-file pattern, Linux and FreeBSD spelling alike."""
    if IS_LINUX:
        try:
            return Path('/proc/sys/kernel/core_pattern').read_text().strip()
        except OSError:
            return ''
    proc = subprocess.run(['sysctl', '-n', 'kern.corefile'],
                          capture_output=True, text=True, check=False)
    return proc.stdout.strip()


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


def raise_nofile_limit() -> None:
    """Raise RLIMIT_NOFILE to the hard limit; -j multiplies fd pressure."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft >= hard:
        return
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except (ValueError, OSError):
        return
    if hard != resource.RLIM_INFINITY and hard < 1024:
        print(f'note: RLIMIT_NOFILE hard limit is only {hard}; '
              'reduce -j if tests fail with EMFILE')


def setuid_helpers(build_dir: Path) -> None:
    """chown root:root + chmod 4755 the build tree's mount helpers.

    Opt-in because it needs sudo and mutates the build tree; without it an
    unprivileged run skips every test that mounts.
    """
    sudo = [] if os.geteuid() == 0 else ['sudo']
    for name in SETUID_HELPERS:
        helper = build_dir / 'util' / name
        if not helper.exists():   # fuservicemount3 is not always built
            continue
        info = helper.stat()
        if info.st_uid == 0 and info.st_mode & stat.S_ISUID:
            continue
        for cmd in (['chown', 'root:root', str(helper)],
                    ['chmod', '4755', str(helper)]):
            if subprocess.run(sudo + cmd, check=False).returncode:
                sys.exit(f'{" ".join(sudo + cmd)} failed')


class CgroupManager:
    """A cgroup-v2 tree for the run, one leaf per test.

    The launcher puts itself into its leaf before it execs the test, so each
    descendant the script spawns -- the fs daemon, fusermount3, anything a
    helper backgrounds -- inherits it. Writing "1" to the leaf's cgroup.kill
    reaps the whole subtree atomically, which is the only reliable way to stop
    a wedged FUSE daemon that has already been reparented to init.

    cgroup-v2 is Linux-only, and FreeBSD does not mount /proc at all by
    default, so every method here is disabled off Linux and the runner falls
    back to killpg().
    """

    def __init__(self, root: Path | None):
        self.root = root
        self._counter = 0
        self._lock = threading.Lock()

    @classmethod
    def create(cls, tag: str) -> "CgroupManager":
        """Create the run root under the delegated base; disabled on failure."""
        base = cls.delegated_base()
        if base is None:
            if IS_LINUX:
                print('note: no writable delegated cgroup; containing tests '
                      'with killpg() instead of cgroup.kill')
            else:
                print(f'note: cgroups are Linux-only; containing tests with '
                      f'killpg() on {platform.system()}')
            return cls(None)
        root = base / f'fuse-tests-{tag}'
        try:
            root.mkdir(exist_ok=True)
        except OSError as exc:
            print(f'note: cannot create {root} ({exc}); containing tests with '
                  'killpg() instead of cgroup.kill')
            return cls(None)
        return cls(root)

    @staticmethod
    def delegated_base() -> Path | None:
        """Parent of this process's own cgroup, if it is writable."""
        if not IS_LINUX:
            return None
        try:
            for line in Path('/proc/self/cgroup').read_text().splitlines():
                if not line.startswith('0::'):
                    continue
                own = Path('/sys/fs/cgroup') / line[3:].lstrip('/')
                base = own.parent
                if os.access(base, os.W_OK):
                    return base
        except OSError:
            pass
        return None

    def new_leaf(self) -> Path | None:
        """mkdir one leaf; None when disabled."""
        if self.root is None:
            return None
        with self._lock:
            self._counter += 1
            leaf = self.root / f'test-{self._counter}'
        try:
            leaf.mkdir(exist_ok=True)
        except OSError:
            return None
        return leaf

    def procs_path(self, leaf: Path | None) -> str:
        """leaf/cgroup.procs for the launcher to write itself into, or "".

        The runner never writes it: a process moving *itself* needs write
        access to the destination cgroup.procs alone, while moving another
        process also needs it on the common ancestor -- so the launcher works
        under strictly more delegation setups than the runner would.
        """
        return '' if leaf is None else str(leaf / 'cgroup.procs')

    def kill_leaf(self, leaf: Path | None) -> None:
        """echo 1 > leaf/cgroup.kill, then rmdir. No-op when disabled."""
        if leaf is None:
            return
        try:
            (leaf / 'cgroup.kill').write_text('1\n')
        except OSError:
            pass
        # The kill is asynchronous; a leaf with a process still in it cannot be
        # removed, so give it a moment rather than leaking the directory.
        for _ in range(50):
            try:
                leaf.rmdir()
                return
            except OSError:
                time.sleep(0.1)

    def cleanup(self) -> None:
        """Kill and remove every remaining leaf, then the root."""
        if self.root is None:
            return
        for leaf in sorted(self.root.glob('test-*')):
            self.kill_leaf(leaf)
        try:
            self.root.rmdir()
        except OSError:
            pass


REEXEC_SENTINEL = 'FUSE_TESTS_UNDER_SCOPE'   # set on the re-exec'd child


def reexec_under_user_scope_if_needed() -> None:
    """Re-exec under a systemd user scope so cgroup leaves have a writable
    parent. Returns unchanged when already delegated or when systemd-run is
    unavailable; replaces this process otherwise."""
    if not IS_LINUX or os.environ.get(REEXEC_SENTINEL):
        return
    if CgroupManager.delegated_base() is not None:
        return
    systemd_run = shutil.which('systemd-run')
    if systemd_run is None:
        return
    os.environ[REEXEC_SENTINEL] = '1'
    argv = [systemd_run, '--user', '--scope', '--quiet',
            sys.executable, os.path.abspath(__file__)] + sys.argv[1:]
    try:
        os.execv(systemd_run, argv)
    except OSError:
        return


def config_path() -> Path:
    """Path to the persisted runner config."""
    return Path.home() / '.config' / 'libfuse' / 'tests.conf'


def read_configured_base_dir() -> str | None:
    """Return the persisted base_dir, or None if unset or unreadable."""
    import configparser

    parser = configparser.ConfigParser()
    try:
        parser.read(config_path())
    except (OSError, configparser.Error):
        return None
    return parser.get(_CONFIG_SECTION, _CONFIG_BASE_DIR_KEY, fallback=None)


def write_configured_base_dir(base_dir: str) -> None:
    """Persist base_dir, preserving any other keys already in the file."""
    import configparser

    parser = configparser.ConfigParser()
    path = config_path()
    try:
        parser.read(path)
    except (OSError, configparser.Error):
        pass
    if not parser.has_section(_CONFIG_SECTION):
        parser.add_section(_CONFIG_SECTION)
    parser.set(_CONFIG_SECTION, _CONFIG_BASE_DIR_KEY, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as fh:
        parser.write(fh)


def resolve_base_dir() -> Path:
    """The base a per-run leaf is appended to."""
    return Path(read_configured_base_dir() or str(DEFAULT_BASE_DIR))


def resolve_run_dir(args: argparse.Namespace) -> Path:
    """Pick the run directory: --run-dir, $FUSE_TEST_RUN_DIR, config, default.

    --run-dir and $FUSE_TEST_RUN_DIR are used verbatim, because a caller that
    names a directory means that directory: CI has to hand the path to a later
    upload step, and `meson test` cannot pass arguments to a registered test,
    so the env var is the only channel it has.

    The persisted config value and DEFAULT_BASE_DIR are *bases*: a
    run-<user>-<timestamp>-<pid> leaf is appended so two runs on one machine
    -- or two users sharing /var/tmp -- cannot land in the same directory.
    """
    if args.run_dir:
        return Path(args.run_dir)
    env_run_dir = os.environ.get('FUSE_TEST_RUN_DIR')
    if env_run_dir:
        return Path(env_run_dir)
    return resolve_base_dir() / run_leaf_name(args)


def make_run_dir(run_dir: Path) -> bool:
    """mkdir the run directory, and say whether this call created it.

    Which matters at the end: a directory the runner made is its own to
    delete, one it merely found is not.
    """
    try:
        run_dir.mkdir(parents=True)
    except FileExistsError:
        return False
    return True


def resolve_valgrind() -> str:
    """The command prefix every daemon launch gets, or "" when off.

    Resolved once here and exported, so the policy lives in one place and no
    test re-implements the no/false/0 spellings.
    """
    value = os.environ.get('TEST_WITH_VALGRIND', 'no').lower().strip()
    return '' if value in ('no', 'false', '0') else VALGRIND_PREFIX


def run_leaf_name(args: argparse.Namespace) -> str:
    """The per-run leaf appended to a base directory.

    The timestamp is second-resolution, so the pid is what keeps two runs
    started in the same second apart: a shared leaf is a shared work
    directory, log and pid file for every test, and the first run to finish
    clean deletes them all.

    The io-uring invocation gets its own suffix, so which transport a kept
    directory holds is visible without opening it. A verbatim --run-dir stays
    verbatim; the caller chose that path.
    """
    user = os.environ.get('USER') or os.environ.get('LOGNAME') or 'unknown'
    mode = '-iouring' if getattr(args, 'io_uring', False) else ''
    return f'run-{user}-{time.strftime("%y%m%d%H%M%S")}-{os.getpid()}{mode}'


def as_test_name(pattern: str, cases_dir: Path) -> str:
    """A -t pattern as a discovery name, so shell completion can supply it:
    "test/cases/examples/cuse.sh" and "examples/cuse" name the same test.

    Resolved as a path rather than matched as text, against the cwd first so a
    completed path works from wherever it was completed, then against cases/ so
    a bare "examples" means the same thing from every directory. A directory
    selects what is under it. Anything that is not a path into cases/ is
    returned as given and stays an fnmatch pattern.
    """
    for base in (Path.cwd(), cases_dir):
        resolved = (base / pattern).resolve()
        if not resolved.is_relative_to(cases_dir):
            continue
        rel = resolved.relative_to(cases_dir)
        if resolved.is_dir():
            return str(rel / '*')
        return str(rel.with_suffix('')) if rel.suffix == '.sh' else str(rel)
    return pattern


def is_shell_exception_dir(directory: Path) -> bool:
    """True when the cases/**/*.sh rule does not apply inside *directory*.

    The runner decides what a file is by where it sits, so the exceptions are
    listed once here. Today every one of them holds binary markers.
    """
    return directory.name in ('unit',)


def shell_scripts(cases_dir: Path) -> list:
    """Executable cases/**/*.sh, outside cases/lib and the shell-exception
    directories."""
    return [path for path in cases_dir.rglob('*.sh')
            if LIB_DIR not in path.parents
            and not is_shell_exception_dir(path.parent)
            and os.access(path, os.X_OK)]


def binary_markers(cases_dir: Path) -> list:
    """<dir>/<binary-name> -- one marker per C test that needs no script.

    A binary name has no suffix, so a suffixed entry is malformed and is said
    so rather than skipped. Only .md is allowed, for documentation.
    """
    markers = []
    for directory in sorted(cases_dir.iterdir()):
        if not directory.is_dir() or not is_shell_exception_dir(directory):
            continue
        for path in sorted(directory.iterdir()):
            if path.name.startswith('.') or path.suffix == '.md':
                continue
            if not path.is_file() or path.suffix:
                sys.exit(f'{path}: not a binary name; '
                         f'{directory} holds markers only')
            markers.append(path)
    return markers


def discover(cases_dir: Path, patterns: list, groups: set,
             exclude: set) -> list:
    """Executable cases/**/*.sh plus the binary markers, filtered by fnmatch
    patterns, GROUP membership, and the exclude set (CLI -X plus
    test/exclude)."""
    patterns = [as_test_name(p, cases_dir) for p in patterns]
    names, specs = [], []
    for script in sorted([*shell_scripts(cases_dir),
                          *binary_markers(cases_dir)]):
        spec = parse_spec(script, cases_dir)
        names.append(spec.name)
        if spec.name in exclude:
            continue
        if patterns and not any(fnmatch.fnmatch(spec.name, p)
                                for p in patterns):
            continue
        if groups and not (groups & spec.groups):
            continue
        specs.append(spec)
    # Checked against every name rather than against the selection, so that -g
    # or -X narrowing the result to nothing is not reported as a bad pattern.
    for pattern in patterns:
        if not any(fnmatch.fnmatch(name, pattern) for name in names):
            sys.exit(f'{pattern}: matches no test')
    return specs


class TestRunner:
    """Runs TestSpecs, one worker thread each, and reports."""

    def __init__(self, build_dir: Path, run_dir: Path, run_dir_created: bool,
                 jobs: int, keep_logs: bool, verbose: bool,
                 io_uring: bool = False, io_uring_depth: int | None = None):
        self.build_dir = build_dir
        self.run_dir = run_dir
        self.run_dir_created = run_dir_created
        self.jobs = jobs
        self.keep_logs = keep_logs
        self.verbose = verbose
        self.io_uring = io_uring
        self.io_uring_depth = io_uring_depth
        self.valgrind = resolve_valgrind()
        self.core_pattern = read_core_pattern()
        self.fuse_caps = self.read_fuse_caps()
        self.sync_init = self.read_sync_init()
        self._cgroup = CgroupManager.create(str(os.getpid()))
        self._stop = threading.Event()
        self._print_lock = threading.Lock()
        self._gdb = shutil.which('gdb')
        # Overwritten per run_all() call; set here so run_one() always has a
        # reference even if it is ever driven without run_all().
        self._run_started = time.monotonic()
        self.report_environment()

    # ---------------------------------------------------------------- startup

    def read_fuse_caps(self) -> frozenset:
        """The FUSE_CAP_* names printcap reports, read once per run.

        printcap lives in example/, not util/, so this works the same way on
        every platform.
        """
        printcap = self.build_dir / 'example' / 'printcap'
        if not os.access(printcap, os.X_OK):
            print(f'note: {printcap} not built; no capability is available '
                  'and every _require_cap test will skip')
            return frozenset()
        proc = subprocess.run([str(printcap)], capture_output=True, text=True,
                              timeout=30, check=False)
        if proc.returncode != 0:
            print(f'note: printcap failed ({proc.returncode}); '
                  'every _require_cap test will skip')
            return frozenset()
        return frozenset(line.strip() for line in proc.stdout.splitlines()
                         if line.startswith('\t'))

    def read_sync_init(self) -> str:
        """Which -Dsync-init the library was built with: auto, always, never.

        A property of the build, not of the run, so it is read where the
        io-uring preflight reads HAVE_URING rather than selected on the
        command line.
        """
        try:
            config = (self.build_dir / 'fuse_config.h').read_text()
        except OSError:
            return 'unknown'
        for define, mode in ((SYNC_INIT_ENABLED, 'always'),
                             (SYNC_INIT_DISABLED, 'never')):
            if define in config:
                return mode
        return 'auto'

    def preflight_io_uring(self) -> str:
        """Return "" when the io-uring transport can actually be exercised,
        else the reason the whole invocation skips with exit 77.

        Checked in this order, so the message names the first thing that is
        actually wrong.
        """
        if not IS_LINUX:
            return f'fuse-io-uring is Linux-only, this is {platform.system()}'
        try:
            config = (self.build_dir / 'fuse_config.h').read_text()
        except OSError:
            return f'{self.build_dir}/fuse_config.h is unreadable'
        if 'HAVE_URING' not in config:
            return 'the library was built with -Denable-io-uring=false'
        if IO_URING_CAP in self.fuse_caps:
            return ''
        # printcap reports capable_ext, so the capability's absence *is* the
        # kernel's answer. The module parameter only tells the two reasons
        # apart.
        try:
            enabled = FUSE_URING_PARAM.read_text().strip()
        except OSError:
            return 'this kernel has no fuse io-uring support'
        if enabled in ('N', '0'):
            return ('io-uring is disabled in the fuse module\n'
                    f'      echo Y | sudo tee {FUSE_URING_PARAM}')
        return f'the kernel did not offer {IO_URING_CAP}'

    def report_environment(self) -> None:
        """Say what will silently degrade before any test runs."""
        if self.core_pattern.startswith('|'):
            print('note: core_pattern is piped to systemd-coredump; cores '
                  'will be fetched via coredumpctl. For in-workdir cores run:')
            print('      sudo sysctl -w kernel.core_pattern=core.%e.%p')
        if self._gdb is None:
            print('note: gdb not found; cores will be kept but not backtraced')

    # ------------------------------------------------------------ preparation

    def prepare(self, spec: TestSpec):
        """Create the workdir tree, build the env dict, allocate the cgroup
        leaf. Returns (workdir, env, leaf)."""
        workdir = self.run_dir / spec.name
        logs = workdir / 'logs'
        for sub in ('mnt', 'src', 'tmp', 'logs'):
            (workdir / sub).mkdir(parents=True, exist_ok=True)

        util_dir = self.build_dir / 'util'
        example_dir = self.build_dir / 'example'
        env = dict(os.environ)
        env.update({
            'TEST_NAME': spec.name,
            'TEST_SCRIPT': str(spec.script),
            'TEST_DIR': str(TEST_DIR),
            'TEST_LIB': str(LIB_DIR),
            'TEST_WORKDIR': str(workdir),
            'TEST_MNT': str(workdir / 'mnt'),
            'TEST_SRC': str(workdir / 'src'),
            'TEST_TMP': str(workdir / 'tmp'),
            'TEST_LOGDIR': str(logs),
            'BUILD_DIR': str(self.build_dir),
            'FUSE_EXAMPLE_DIR': str(example_dir),
            'FUSE_TEST_BIN_DIR': str(self.build_dir / 'test'),
            'FUSE_UTIL_DIR': str(util_dir),
            'FUSE_CAPS': ' '.join(sorted(self.fuse_caps)),
            'FUSE_UID': str(os.geteuid()),
            'FUSE_OS': platform.system(),
            # Exported as 0 rather than left unset: fuse_session_new() reads it
            # from the environment, so a value in the developer's shell would
            # otherwise change what the default run tests without saying so.
            'FUSE_URING_ENABLE': '1' if self.io_uring else '0',
            # Asked of every session, not only the ones a mount verb started,
            # so the transport a test never launched through the shell -- a
            # self-mounting C test, a daemon the script backgrounded itself --
            # is on the record too. It lands in that daemon's log, because
            # none of them redirects fuse_log() anywhere else.
            'FUSE_INIT_STATUS': '1',
            'FUSE_VALGRIND': self.valgrind,
        })
        if self.io_uring_depth is not None:
            env['FUSE_URING_QUEUE_DEPTH'] = str(self.io_uring_depth)
        # $FUSE_UTIL_DIR first: an installed fusermount3 older than the build
        # tree makes printcap emit "unrecognized option '--sync-init'", which
        # is both wrong and would trip the output scanner.
        env['PATH'] = os.pathsep.join(
            [str(util_dir), str(example_dir), env.get('PATH', '')])
        return workdir, env, self._cgroup.new_leaf()

    def child_argv(self, spec: TestSpec) -> list:
        """The command the launcher execs for *spec*.

        bash -e for a script: errexit is the runner's rule, not something 88
        files have to remember. A marker names a binary, which the launcher
        execs itself; there is no shell in between to impose errexit on, and
        none is wanted -- the binary's exit status is already the verdict.
        """
        if spec.binary:
            return [str(self.build_dir / 'test' / spec.binary)]
        return ['bash', '-e', str(spec.script)]

    def write_repro(self, spec: TestSpec, workdir: Path, env: dict) -> None:
        """Write logs/repro.sh: the env deltas, the cd, and the command.

        It execs what the launcher execs, so the reproducer cannot pass where
        the run failed.
        """
        import shlex

        lines = ['#!/bin/sh',
                 '# Re-run this one test by hand, with the environment the',
                 '# runner built for it.',
                 '']
        for key, value in sorted(env.items()):
            if os.environ.get(key) == value and key != 'PATH':
                continue
            lines.append(f'export {key}={shlex.quote(value)}')
        lines += ['',
                  f'cd {shlex.quote(str(workdir / "logs"))}',
                  'exec ' + shlex.join(self.child_argv(spec)),
                  '']
        repro = workdir / 'logs' / 'repro.sh'
        repro.write_text('\n'.join(lines))
        repro.chmod(0o755)

    # -------------------------------------------------------------- execution

    def _stream(self, proc: subprocess.Popen, logs: Path, name: str,
                started: float) -> None:
        """Copy the script's merged output to logs/script.out until EOF, and
        a copy prefixed with elapsed time to logs/timestamps.out.

        A timed-out test's script.out has no way to tell "stalled right
        after the last line" from "was still grinding right up to the
        kill" -- the CI step that prints it afterwards timestamps when it
        printed, not when the test produced it. timestamps.out is named to
        pick up the same "*.out" glob so CI shows it for free.
        """
        with (logs / 'script.out').open('wb') as out, \
                (logs / 'timestamps.out').open('wb') as timestamps:
            for line in proc.stdout:
                out.write(line)
                out.flush()
                elapsed = time.monotonic() - started
                timestamps.write(f'+{elapsed:8.3f}s '.encode() + line)
                timestamps.flush()
                if self.verbose:
                    text = line.decode('utf8', errors='replace').rstrip('\n')
                    with self._print_lock:
                        print(f'[{name}] {text}')
        proc.stdout.close()

    def _kill(self, proc: subprocess.Popen, leaf: Path | None) -> None:
        """Stop a timed-out or interrupted test: cgroup.kill on the leaf when
        there is one, else killpg() on the session the script leads."""
        if leaf is not None:
            try:
                (leaf / 'cgroup.kill').write_text('1\n')
                return
            except OSError:
                pass
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except OSError:
                return
            try:
                proc.wait(timeout=5.0)
                return
            except subprocess.TimeoutExpired:
                continue

    def dump_stacks(self, proc: subprocess.Popen, leaf: Path | None,
                    logs: Path) -> None:
        """On a timeout, before _kill() tears the containment down, write a
        snapshot of the whole process table, plus every thread's kernel stack
        and (when gdb is available) user backtrace for every process still in
        the containment.

        A thread blocked in an uninterruptible syscall never answers
        PTRACE_ATTACH, so the kernel stack is taken first -- it needs no
        attach and is often the only trace such a thread ever yields. The
        process table is taken before either, while nothing has stopped a
        thread yet.
        """
        self._dump_process_table(logs)
        for pid in self._containment_pids(proc, leaf):
            self._dump_kernel_stacks(pid, logs)
            if self._gdb is not None:
                self._dump_gdb_backtrace(pid, logs)

    @staticmethod
    def _dump_process_table(logs: Path) -> None:
        """ps auxwww, so a hang that involves a process outside the test's own
        containment -- a daemon an earlier test leaked, say -- is still
        visible in the report.
        """
        result = subprocess.run(['ps', 'auxwww'], capture_output=True,
                                text=True, check=False)
        (logs / 'ps.txt').write_text(result.stdout + result.stderr)

    @staticmethod
    def _proc_identity(pid: int) -> str:
        """A "<pid> (<comm>): <cmdline>" header line for a dump.

        Which pid was the daemon and which the client blocked on it is the
        first question asked of a stack dump, and a bare pid answers it for
        nobody reading the report minutes or days later.
        """
        try:
            comm = Path(f'/proc/{pid}/comm').read_text().strip()
        except OSError:
            comm = '?'
        try:
            raw = Path(f'/proc/{pid}/cmdline').read_bytes()
            cmdline = raw.decode('utf8', errors='replace').replace('\0', ' ')
        except OSError:
            cmdline = ''
        # An argument may hold a newline; a header that is not one line
        # breaks every reader that greps the dump for its pid.
        return f'=== pid {pid} ({comm}): {" ".join(cmdline.split())} ==='

    @staticmethod
    def _as_text(data) -> str:
        """TimeoutExpired carries its partial output undecoded even when the
        run was in text mode."""
        if data is None:
            return ''
        return data if isinstance(data, str) \
            else data.decode('utf8', errors='replace')

    @staticmethod
    def _containment_pids(proc: subprocess.Popen, leaf: Path | None) -> list:
        """Every pid sharing the test's cgroup leaf, or just proc.pid when
        cgroups are disabled."""
        if leaf is not None:
            try:
                pids = [int(line) for line in
                        (leaf / 'cgroup.procs').read_text().split()]
                if pids:
                    return pids
            except OSError:
                pass
        return [proc.pid]

    @staticmethod
    def _dump_kernel_stacks(pid: int, logs: Path) -> None:
        """sudo cat /proc/<pid>/task/*/stack for every thread of *pid*.

        /proc/<pid>/task/<tid>/stack is gated on CAP_SYS_ADMIN unconditionally
        -- unlike ptrace, ownership and Yama's exceptions are not enough --
        to keep it from leaking kernel addresses. sudo is what gets it on a
        non-root run; -n so a runner without passwordless sudo fails the read
        immediately instead of blocking on a password prompt nothing answers.
        """
        task_dir = Path(f'/proc/{pid}/task')
        try:
            tids = sorted(int(tid) for tid in os.listdir(task_dir))
        except OSError:
            return
        lines = [TestRunner._proc_identity(pid)]
        for tid in tids:
            stack_path = task_dir / str(tid) / 'stack'
            result = subprocess.run(['sudo', '-n', 'cat', str(stack_path)],
                                    capture_output=True, text=True,
                                    check=False)
            stack = result.stdout if result.returncode == 0 else \
                f'(unreadable: {result.stderr.strip() or result.returncode})\n'
            lines.append(f'=== tid {tid} ===\n{stack}')
        (logs / f'kstack.{pid}.txt').write_text('\n'.join(lines))

    def _dump_gdb_backtrace(self, pid: int, logs: Path) -> None:
        """sudo gdb -p <pid> backtraces, written beside the kernel stacks.

        Bare "bt" for every thread first and "bt full" only after it: the
        locals are worth having, but they bury the frame list they belong to
        under pages of struct dumps, and the frame list is what is read first.

        sudo, not a Yama prctl exception: the wedged pid is as likely to be a
        daemon the test forked after launch as the test's own exec-chain, and
        an exception only covers the specific task that calls it, not
        children it forks afterwards. Root's CAP_SYS_PTRACE reaches either
        one uniformly. Best-effort: a thread ptrace cannot stop, or a runner
        without passwordless sudo, just leaves gdb's or sudo's own error text
        in the file.
        """
        argv = ['sudo', '-n', self._gdb, '--batch', '--nx',
                '-ex', 'set pagination off',
                '-ex', 'thread apply all bt',
                '-ex', 'set print pretty on',
                '-ex', 'thread apply all bt full',
                '-p', str(pid)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=GDB_TIMEOUT, check=False)
            out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired as expired:
            # A pid gdb cannot finish with is the interesting one often
            # enough that whatever it did print has to be kept.
            out = (self._as_text(expired.stdout) +
                   self._as_text(expired.stderr) +
                   f'\n(gdb killed after {GDB_TIMEOUT:.0f}s)\n')
        (logs / f'gdbstack.{pid}.txt').write_text(
            f'{self._proc_identity(pid)}\n{out}')

    def _log_started(self, name: str) -> None:
        """A "test X is now running" line, timestamped against the whole
        run's own start rather than the test's -- so under -j the console
        log (which CI keeps regardless of pass/fail) shows what was in
        flight and since when, not only what has finished.
        """
        elapsed = time.monotonic() - self._run_started
        with self._print_lock:
            print(f'+{elapsed:8.3f}s START {name}')
            sys.stdout.flush()

    def run_one(self, spec: TestSpec) -> TestResult:
        """Spawn the test, enforce spec.timeout, collect the result."""
        workdir, env, leaf = self.prepare(spec)
        self.write_repro(spec, workdir, env)
        logs = workdir / 'logs'
        timeout = self.effective_timeout(spec)
        started = time.monotonic()
        self._log_started(spec.name)

        proc = subprocess.Popen(
            ['/bin/sh', '-c', LAUNCHER, 'run-tests',
             self._cgroup.procs_path(leaf), *self.child_argv(spec)],
            env=env, cwd=str(logs),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True)
        # exec keeps the pid, so this is still the script and still the group
        # leader that "kill -- -$(cat pid)" targets.
        (workdir / 'pid').write_text(f'{proc.pid}\n')
        if leaf is not None:
            (workdir / 'cgroup').write_text(f'{leaf}\n')

        # _stream blocks until EOF, so read in a thread and wait with a
        # deadline here; that is what makes the timeout a hard wall-clock bound.
        reader = threading.Thread(target=self._stream,
                                  args=(proc, logs, spec.name, started),
                                  daemon=True)
        reader.start()
        reader.join(timeout=timeout)
        reason = ''
        if reader.is_alive():
            reason = f'timeout after {timeout:.0f}s'
            self.dump_stacks(proc, leaf, logs)
            self._kill(proc, leaf)
            reader.join(timeout=5.0)
        try:
            proc.wait(timeout=REAP_TIMEOUT)
        except subprocess.TimeoutExpired:
            # Report it and carry on: the run is worth more than this one
            # process, and everything worth reading is already on disk.
            unkillable = f'unkillable after {REAP_TIMEOUT:.0f}s'
            reason = f'{reason}, {unkillable}' if reason else unkillable
        # Always reap the subtree: a passing script may still have leaked a
        # daemon, and that would wedge the next test on the same mountpoint.
        self._cgroup.kill_leaf(leaf)

        duration = time.monotonic() - started
        cores = self.collect_cores(workdir, leaf)
        suspicious = self.scan_logs(workdir) if proc.returncode == 0 else ''
        result = self.classify(spec, workdir, proc.returncode, duration,
                               reason, cores, suspicious)
        (workdir / 'status').write_text(
            f'{result.status} {result.duration:.3f} {result.reason}\n'.rstrip()
            + '\n')
        return result

    def effective_timeout(self, spec: TestSpec) -> float:
        """The wall-clock bound actually enforced for *spec*."""
        if self.valgrind:
            return spec.timeout * VALGRIND_TIMEOUT_FACTOR
        return spec.timeout

    def classify(self, spec: TestSpec, workdir: Path, code: int,
                 duration: float, reason: str, cores: list,
                 suspicious: str) -> TestResult:
        """Turn an exit status plus the collected evidence into a verdict."""
        unexpected = [c for c in cores
                      if not self.core_is_allowed(workdir, c)]
        transport = self.wrong_transport(workdir)
        if reason:                       # killed by the runner
            status = 'FAIL'
        elif code == SKIP_EXIT_CODE:
            status, reason = 'SKIP', self.skip_reason(workdir)
        elif code == LAUNCH_FAILED_EXIT_CODE and self.launch_failed(workdir):
            status, reason = 'FAIL', 'could not establish containment'
        elif code != 0:
            status = 'FAIL'
            reason = (f'killed by signal {-code}' if code < 0
                      else f'exit {code}')
        elif unexpected:
            core = unexpected[0]
            status = 'FAIL'
            reason = f'core: {core.executable} (pid {core.pid})'
        elif suspicious:
            status, reason = 'FAIL', f'suspicious output: {suspicious}'
        elif transport:
            status, reason = 'FAIL', transport
        else:
            status = 'PASS'
        return TestResult(name=spec.name, status=status, duration=duration,
                          exit_code=code, reason=reason, workdir=workdir,
                          cores=unexpected, suspicious=suspicious)

    @staticmethod
    def skip_reason(workdir: Path) -> str:
        """The reason _notrun printed, taken from the script's own output."""
        try:
            text = (workdir / 'logs' / 'script.out').read_text(errors='replace')
        except OSError:
            return ''
        for line in reversed(text.splitlines()):
            if line.startswith('SKIP: '):
                return line[len('SKIP: '):]
        return ''

    def wrong_transport(self, workdir: Path) -> str:
        """Under --io-uring, the first session that did not get a ring, or "".

        A test that started no session reports nothing and so has nothing to
        prove. off:custom_io is the one refusal a daemon cannot avoid: the
        ring is issued against the session's own /dev/fuse fd, which a
        custom-io session does not have.

        timestamps.out holds the same lines behind an elapsed-time prefix, so
        matching on the start of the line reports each session once.
        """
        if not self.io_uring:
            return ''
        for out in sorted((workdir / 'logs').glob('*.out')):
            try:
                text = out.read_text(errors='replace')
            except OSError:
                continue
            for line in text.splitlines():
                if (line.startswith(IO_URING_STATE_KEY)
                        and line not in IO_URING_STATES_OK):
                    return f'{out.name}: {line}'
        return ''

    @staticmethod
    def launch_failed(workdir: Path) -> bool:
        """True when exit 125 came from the launcher, not from the test."""
        try:
            text = (workdir / 'logs' / 'script.out').read_text(errors='replace')
        except OSError:
            return False
        return LAUNCH_FAILED_MARKER in text

    # ----------------------------------------------------------- log scanning

    def scan_logs(self, workdir: Path) -> str:
        """Strip logs/.allow patterns, then look for suspicious words in every
        logs/*.out. Returns the first offending line, or ""."""
        logs = workdir / 'logs'
        allow = []
        try:
            for line in (logs / '.allow').read_text().splitlines():
                if line.strip():
                    allow.append(re.compile(line, re.MULTILINE))
        except OSError:
            pass
        words = [re.compile(r'\b{}\b'.format(w), re.IGNORECASE | re.MULTILINE)
                 for w in self.suspicious_words()]
        for out in sorted(logs.glob('*.out')):
            try:
                buf = out.read_text(errors='replace')
            except OSError:
                continue
            for pattern in allow:
                buf = pattern.sub('', buf)
            buf = _FUSE_DEBUG_RE.sub('', buf)
            buf = self.strip_extra(buf)
            for word in words:
                hit = word.search(buf)
                if hit:
                    line_start = buf.rfind('\n', 0, hit.start()) + 1
                    line_end = buf.find('\n', hit.end())
                    if line_end == -1:
                        line_end = len(buf)
                    return f'{out.name}: {buf[line_start:line_end].strip()}'
        return ''

    def suspicious_words(self) -> tuple:
        """The word list scan_logs() looks for.

        Under --io-uring it gains the message libfuse prints before falling
        back to /dev/fuse. The status file keeps only the last session of a
        binary that runs several, so the log stays the backstop for the
        earlier ones.
        """
        if self.io_uring:
            return SUSPICIOUS_WORDS + (re.escape(IO_URING_FALLBACK),)
        return SUSPICIOUS_WORDS

    def strip_extra(self, buf: str) -> str:
        """Drop the noise a mode adds to every daemon's log.

        Valgrind's own lines go before the word scan. Built in rather than a
        per-test fuse_allow_output, because it applies to every test whenever
        valgrind is on.
        """
        if self.valgrind:
            return _VALGRIND_LINE_RE.sub('', buf)
        return buf

    # ---------------------------------------------------------- core handling

    @staticmethod
    def core_is_allowed(workdir: Path, core: CoreDump) -> bool:
        """True when the test declared a core from this executable expected."""
        try:
            names = (workdir / 'logs' / '.allow-core').read_text().split()
        except OSError:
            return False
        return core.executable in names

    def resolve_binary(self, executable: str) -> Path | None:
        """Map a core's %e back to the build-tree binary that produced it.

        %e is a bare basename, so search the three directories the suite runs
        binaries from. An unrecognised name (a system tool, or %e truncated at
        16 chars) yields None; gdb still produces a usable backtrace from the
        core alone, just without symbol names for the main executable.
        """
        for directory in (self.build_dir / 'example',
                          self.build_dir / 'test',
                          self.build_dir / 'util'):
            candidate = directory / executable
            if candidate.is_file():
                return candidate
        return None

    def collect_cores(self, workdir: Path, leaf: Path | None) -> list:
        """Every core matching CORE_GLOBS in logs/, backtraced.

        When core_pattern is a pipe, nothing lands in logs/ at all. The
        fallback then asks the journal for cores recorded against *this test's*
        cgroup -- COREDUMP_CGROUP, which is exactly the leaf written to
        $TEST_WORKDIR/cgroup. A time-window query is deliberately not used:
        under -j the test intervals overlap, so one crash would be handed to
        every worker whose window contains it and fail unrelated tests.

        With no leaf to match on -- cgroups disabled, or not Linux -- the
        fallback yields nothing and the startup note is the only signal. CI
        sets a relative pattern on both platforms, so this costs no CI
        coverage.
        """
        logs = workdir / 'logs'
        found = []
        for glob in CORE_GLOBS:
            for path in sorted(logs.glob(glob)):
                found.append(self._core_from_name(path))
        if not found and self.core_pattern.startswith('|'):
            found = self._cores_from_journal(logs, leaf)
        for core in found:
            core.binary = self.resolve_binary(core.executable)
            self.backtrace(core)
        return found

    @staticmethod
    def _core_from_name(path: Path) -> CoreDump:
        """Parse a core file name into the %e and %p the pattern encoded.

        core.<exe>.<pid> is what CI configures and <exe>.core is FreeBSD's
        default, but a developer machine often has a bare "core" or "core.<pid>"
        pattern, which names no executable at all. Every shape still yields a
        CoreDump -- the executable is only used to find symbols for gdb.
        """
        parts = path.name.split('.')
        if parts[0] == 'core':
            if len(parts) >= 3 and parts[-1].isdigit():
                return CoreDump(path=path, executable='.'.join(parts[1:-1]),
                                pid=int(parts[-1]))
            if len(parts) == 2 and parts[1].isdigit():
                return CoreDump(path=path, executable='unknown',
                                pid=int(parts[1]))
            if len(parts) == 1:
                return CoreDump(path=path, executable='unknown', pid=0)
        if path.name.endswith('.core'):
            return CoreDump(path=path, executable=path.name[:-len('.core')],
                            pid=0)
        return CoreDump(path=path, executable=path.name, pid=0)

    def _cores_from_journal(self, logs: Path, leaf: Path | None) -> list:
        """Cores systemd-coredump captured for this test's cgroup."""
        if leaf is None or not IS_LINUX or shutil.which('coredumpctl') is None:
            return []
        import json

        proc = subprocess.run(
            ['journalctl', '-t', 'systemd-coredump',
             f'COREDUMP_CGROUP={self._cgroup_relative(leaf)}', '-o', 'json'],
            capture_output=True, text=True, check=False)
        cores = []
        for line in proc.stdout.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            pid = int(entry.get('COREDUMP_PID', 0))
            exe = os.path.basename(entry.get('COREDUMP_COMM', '') or '')
            if not pid:
                continue
            path = logs / f'core.{exe}.{pid}'
            dumped = subprocess.run(
                ['coredumpctl', 'dump', str(pid), '--output', str(path)],
                capture_output=True, check=False)
            if dumped.returncode == 0 and path.exists():
                cores.append(CoreDump(path=path, executable=exe, pid=pid))
        return cores

    @staticmethod
    def _cgroup_relative(leaf: Path) -> str:
        """The leaf path as the journal records it (without the mount point)."""
        return '/' + str(leaf.relative_to('/sys/fs/cgroup'))

    def backtrace(self, core: CoreDump) -> None:
        """Run gdb on *core*, write the full backtrace beside it as
        backtrace.<exe>.<pid>.txt, and keep the top frames for the summary.

        "thread apply all bt full" rather than a plain bt: a FUSE daemon is
        multi-threaded and the crashing thread is rarely the only interesting
        one. --nx so a developer's ~/.gdbinit cannot change the output.
        """
        if self._gdb is None:
            return
        argv = [self._gdb, '--batch', '--nx',
                '-ex', 'set pagination off',
                '-ex', 'set print pretty on',
                '-ex', 'thread apply all bt full']
        argv += ['--', str(core.binary)] if core.binary else []
        argv += [str(core.path)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=GDB_TIMEOUT, check=False)
        except subprocess.TimeoutExpired:
            return
        out = core.path.parent / f'backtrace.{core.executable}.{core.pid}.txt'
        out.write_text(proc.stdout + proc.stderr)
        core.backtrace = out
        frames = [line for line in proc.stdout.splitlines()
                  if line.startswith('#')]
        core.top_frames = '\n'.join(frames[:GDB_TOP_FRAMES])
        if len(frames) > GDB_TOP_FRAMES:
            core.top_frames += (f'\n    ... {len(frames) - GDB_TOP_FRAMES} '
                                f'more frames, full: {out}')

    # ------------------------------------------------------------- scheduling

    def run_all(self, specs: list) -> int:
        """Run the serial group first with one job, then fan the rest out.
        Returns 0 when nothing failed."""
        self._run_started = time.monotonic()
        serial = [s for s in specs if SERIAL_GROUP in s.groups]
        parallel = [s for s in specs if SERIAL_GROUP not in s.groups]
        results = self._run_batch(serial, 1) + \
            self._run_batch(parallel, self.jobs)
        return self.summarise(results, time.monotonic() - self._run_started)

    def _run_batch(self, specs: list, jobs: int) -> list:
        """ThreadPoolExecutor over specs; print a live line per finished test."""
        results = []
        if not specs:
            return results
        # as_completed() rather than map(): map yields in submission order, so
        # a finished test would be reported -- and its workdir freed -- only
        # once every test submitted before it has landed.
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = [pool.submit(self._run_guarded, spec) for spec in specs]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
                    self.report(result)
                    self.discard_workdir(result)
        return results

    def _run_guarded(self, spec: TestSpec):
        """run_one(), unless SIGINT already asked the run to stop."""
        if self._stop.is_set():
            return None
        return self.run_one(spec)

    def report(self, result: TestResult) -> None:
        """One line per finished test, plus where to look when it failed."""
        elapsed = time.monotonic() - self._run_started
        with self._print_lock:
            line = (f'+{elapsed:8.3f}s {result.status:<5} {result.name:<50} '
                    f'{result.duration:6.2f}s')
            if result.reason:
                line += f'  {result.reason}'
            print(line)
            if result.status == 'FAIL':
                print(f'      logs: {result.workdir / "logs"}')
            sys.stdout.flush()

    def discard_workdir(self, result: TestResult) -> None:
        """Drop a finished test's directory unless it failed.

        Only a failure is ever read, and deleting as each test lands keeps the
        run's disk use flat instead of holding all of them to the end.
        """
        if self.keep_logs or result.status == 'FAIL':
            return
        shutil.rmtree(result.workdir, ignore_errors=True)

    def discard_run_dir(self, results: list) -> None:
        """Drop the run directory after a clean run, but only what this run
        made.

        --run-dir is used verbatim, so it can name a directory that was
        already there holding anything at all; rmtree on that is data loss,
        not cleanup. discard_workdir() has taken each test's own directory
        by now, so all that is left of this run are the empty parents the
        test names needed.
        """
        if self.run_dir_created:
            shutil.rmtree(self.run_dir, ignore_errors=True)
            return
        for result in results:
            directory = result.workdir.parent
            while directory != self.run_dir:
                try:
                    directory.rmdir()   # empty only; never recursive
                except OSError:
                    break
                directory = directory.parent

    def mode_note(self) -> str:
        """Extra text for the summary header naming a non-default mode.

        The io-uring invocation selects nothing, so its counts must match the
        default run's; without the label the two are indistinguishable in a CI
        log. A -Dsync-init build is invisible for the same reason.
        """
        note = ', io-uring' if self.io_uring else ''
        if self.sync_init != 'auto':
            note += f', sync-init={self.sync_init}'
        return note

    def summarise(self, results: list, elapsed: float) -> int:
        """Print the counts, the slowest tests and every failure."""
        passed = [r for r in results if r.status == 'PASS']
        failed = [r for r in results if r.status == 'FAIL']
        skipped = [r for r in results if r.status == 'SKIP']
        print()
        print(f'{len(results)} tests: {len(passed)} passed, {len(failed)} '
              f'failed, {len(skipped)} skipped in {elapsed:.1f}s '
              f'(-j{self.jobs}{self.mode_note()})')

        slowest = sorted(results, key=lambda r: r.duration, reverse=True)[:5]
        if slowest:
            print()
            print('slowest:')
            for result in slowest:
                print(f'  {result.duration:5.1f}s  {result.name}')

        if failed:
            print()
            print('failed:')
            for result in failed:
                print(f'  {result.name}   {result.reason}')
                print(f'    logs: {result.workdir / "logs" / "script.out"}')
                for core in result.cores:
                    if core.top_frames:
                        for frame in core.top_frames.splitlines():
                            print(f'    {frame}')
                    elif core.backtrace is None:
                        print(f'    core kept, not backtraced: {core.path}')
                print(f'    repro: sh {result.workdir / "logs" / "repro.sh"}')

        if not failed and not self.keep_logs:
            self.discard_run_dir(results)
        else:
            print()
            print(f'test output kept in {self.run_dir}')
        return 1 if failed else 0

    def stop(self) -> None:
        """Ask the workers to stop launching new tests."""
        self._stop.set()

    def stopping(self) -> bool:
        """True once stop() has been asked for."""
        return self._stop.is_set()

    def cleanup(self) -> None:
        self._cgroup.cleanup()


def read_exclude_file() -> set:
    """One test name per line; blank lines and #-comments ignored, missing
    file is fine."""
    try:
        text = EXCLUDE_FILE.read_text()
    except OSError:
        return set()
    names = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            names.add(line)
    return names


def parse_args(argv: list) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run the libfuse shell test suite.')
    parser.add_argument('-j', '--jobs', type=int,
                        default=max(1, (os.cpu_count() or 2) // 2),
                        help='parallel tests (default: cpu_count // 2)')
    parser.add_argument('-t', '--test', action='append', default=[],
                        metavar='PATTERN',
                        help='fnmatch against the test name, or the path to '
                             'a case; repeatable')
    parser.add_argument('-g', '--group', action='append', default=[],
                        help='only tests declaring "# GROUP: <group>"')
    parser.add_argument('-X', '--exclude', action='append', default=[],
                        metavar='NAME',
                        help='skip this test; repeatable, adds to test/exclude')
    parser.add_argument('--build-dir', default='.',
                        help='meson build root (default: .)')
    parser.add_argument('--setuid-helpers', action='store_true',
                        help="chown root:root + chmod 4755 the build tree's "
                             'fusermount3 (needs sudo); without it an '
                             'unprivileged run skips every mounting test')
    parser.add_argument('--run-dir', default=None,
                        help='where to write per-test output, verbatim')
    parser.add_argument('--persist-base-dir', default=None, metavar='DIR',
                        help='write DIR to ~/.config/libfuse/tests.conf '
                             'and exit')
    parser.add_argument('--print-base-dir', action='store_true',
                        help='print the resolved base directory and exit')
    parser.add_argument('--timeout', type=float, default=None,
                        metavar='SECS', help="override every script's timeout")
    parser.add_argument('--io-uring', action='store_true',
                        help='run every test over fuse-io-uring; exits 77 '
                             'when the kernel or the build does not offer it')
    parser.add_argument('--io-uring-queue-depth', type=int, default=None,
                        metavar='N',
                        help="export FUSE_URING_QUEUE_DEPTH; default is "
                             "libfuse's 8")
    parser.add_argument('-l', '--list', action='store_true',
                        help='print the selected tests and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="stream each script's output live")
    parser.add_argument('--keep-logs', action='store_true',
                        help="keep every test's output, not just the failures'")
    parser.add_argument('--repeat', type=int, default=1, metavar='N',
                        help='run the selection N times')
    return parser.parse_args(argv)


def main(argv: list) -> int:
    args = parse_args(argv)

    if args.persist_base_dir:
        write_configured_base_dir(args.persist_base_dir)
        return 0
    if args.print_base_dir:
        print(resolve_base_dir())
        return 0

    build_dir = Path(args.build_dir).resolve()
    exclude = read_exclude_file() | set(args.exclude)

    if args.list:
        for spec in discover(CASES_DIR, args.test, set(args.group), exclude):
            print(spec.name)
        return 0

    if args.setuid_helpers:
        setuid_helpers(build_dir)

    reexec_under_user_scope_if_needed()
    raise_nofile_limit()

    run_dir = resolve_run_dir(args)
    runner = TestRunner(build_dir=build_dir, run_dir=run_dir,
                        run_dir_created=make_run_dir(run_dir), jobs=args.jobs,
                        keep_logs=args.keep_logs, verbose=args.verbose,
                        io_uring=args.io_uring,
                        io_uring_depth=args.io_uring_queue_depth)
    if args.io_uring:
        # A missing precondition skips the whole invocation rather than
        # failing it, so a plain `meson test` on a machine that never enabled
        # the module parameter reports one SKIP instead of 88 failures. CI does
        # not rely on that: ci-build.sh enables the parameter itself.
        reason = runner.preflight_io_uring()
        if reason:
            print(f'SKIP: {reason}')
            runner.cleanup()
            return SKIP_EXIT_CODE
        # The capability says the kernel offers the transport, not that this
        # user may open a ring. Asked here rather than skipped on, because a
        # run that then fails every ring check is the honest report.
        refused = io_uring_setup_error()
        if refused:
            print(f'warning: io_uring_setup() failed with {refused}; the '
                  'daemons will fall back to /dev/fuse')
            print('      sudo sysctl -w kernel.io_uring_disabled=0')
    specs = discover(CASES_DIR, args.test, set(args.group), exclude)
    if args.timeout is not None:
        specs = [replace(s, timeout=args.timeout) for s in specs]

    def on_signal(signum, frame):
        # The first one lets the tests already running finish, which is
        # usually what an interrupt means. Asking twice means the test in
        # flight is the problem, so take the containment down with us --
        # otherwise the run sits out its full timeout before it can react.
        if runner.stopping():
            print('\ninterrupted again: killing the tests still running')
            runner.cleanup()
            os._exit(128 + signum)
        print('\ninterrupted: waiting for the running tests to finish')
        runner.stop()
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print(f'running {len(specs)} tests from {CASES_DIR} in {run_dir}')
    rc = 0
    try:
        for _ in range(args.repeat):
            rc |= runner.run_all(specs)
    finally:
        runner.cleanup()
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
