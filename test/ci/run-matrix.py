#!/usr/bin/env python3
"""Run the CI build matrix from a checkout.

test/ci/matrix.yml spells every build parameter out, and the workflows run
each job through this script, so a job run by hand builds the same
test/ci-build.sh command line as in CI.

Configurations run one after another: the suite has tests that cannot run
beside a copy of themselves, and the io-uring ones put a global module
parameter back on exit.
"""

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent.parent.parent
MATRIX = SOURCE_DIR / 'test/ci/matrix.yml'
CI_BUILD = SOURCE_DIR / 'test/ci-build.sh'
RUN_TESTS = SOURCE_DIR / 'test/run-tests.py'
VM_RUN = SOURCE_DIR / 'test/ci/vm-run.sh'


def load_matrix() -> list[dict]:
    """Return one dict per configuration, in the order matrix.yml lists them."""
    try:
        import yaml
    except ImportError:
        sys.exit('run-matrix.py needs PyYAML to read the matrix; '
                 'install python3-yaml')

    with open(MATRIX) as matrix_file:
        document = yaml.safe_load(matrix_file)
    return document['configs']


def github_matrix(entries: list[dict], workflow: str) -> dict:
    """The jobs of one workflow, as a strategy.matrix."""
    jobs = []
    for entry in entries:
        workflows = entry.get('workflows', [])
        if workflow in workflows:
            jobs.append({'config': entry['config'], 'bufpool': False})
        if f'{workflow}-bufpool' in workflows:
            jobs.append({'config': entry['config'], 'bufpool': True})
    return {'include': jobs}


def ci_build_argv(entry: dict, work_dir: str | None) -> list[str]:
    """Spell the ci-build.sh command line pr-ci.yml expands this entry to.

    A work_dir of None leaves --work-dir off, for vm-run.sh to append: the
    guest needs one of its own.
    """
    argv = [str(CI_BUILD), '--name', entry['config'], '--cc', entry['cc']]

    cxx = entry.get('cxx')
    if cxx is not None:
        argv += ['--cxx', cxx]
    if entry.get('sanitize'):
        argv.append('--sanitize')
    if entry.get('valgrind'):
        argv.append('--valgrind')
    for meson_opt in entry.get('meson_opts', []):
        argv += ['--meson-opt', meson_opt]
    if entry.get('root'):
        argv.append('--root')
    if entry.get('io_uring'):
        argv.append('--io-uring')
    if entry.get('io_uring_bufpool'):
        argv.append('--io-uring-bufpool')

    if work_dir is not None:
        argv += ['--work-dir', work_dir]
    return argv


def vm_run_argv(kernel: str, logs_out: str, ci_argv: list[str]) -> list[str]:
    """Wrap a ci-build.sh command line in a virtme-ng guest."""
    return [str(VM_RUN), '--kernel', kernel,
            '--logs-out', logs_out, '--'] + ci_argv


def config_argv(entry: dict, work_dir: str, kernel: str | None) -> list[str]:
    """The command line that runs one configuration."""
    if kernel is None:
        return ci_build_argv(entry, work_dir)
    return vm_run_argv(kernel, work_dir, ci_build_argv(entry, None))


def missing_tools(entry: dict) -> list[str]:
    """Names of the tools this entry needs that are not on PATH."""
    needed = [entry['cc']]
    cxx = entry.get('cxx')
    if cxx is not None:
        needed.append(cxx)
    if entry.get('valgrind'):
        needed.append('valgrind')

    missing = []
    for tool in needed:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def select(entries: list[dict], patterns: list[str],
           excludes: list[str]) -> list[dict]:
    """The entries whose name matches a pattern and no exclude."""
    selected = []
    for entry in entries:
        name = entry['config']
        if patterns and not matches_any(name, patterns):
            continue
        if matches_any(name, excludes):
            continue
        selected.append(entry)
    return selected


def with_bufpool(entries: list[dict]) -> list[dict]:
    """The io-uring entries, each renamed <config>-bufpool and given a pool."""
    pooled = []
    for entry in entries:
        if not entry.get('io_uring'):
            continue
        pooled_entry = dict(entry)
        pooled_entry['config'] = entry['config'] + '-bufpool'
        pooled_entry['io_uring_bufpool'] = True
        pooled.append(pooled_entry)
    return pooled


def matches_any(name: str, patterns: list[str]) -> bool:
    """True when name matches one of the fnmatch patterns."""
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def default_work_dir() -> str:
    """A work directory under the base run-tests.py reports."""
    # Asking the runner keeps the precedence of the persisted config in one
    # place instead of parsing an INI here as well.
    base = subprocess.check_output(
        [sys.executable, str(RUN_TESTS), '--print-base-dir'],
        text=True).strip()
    user = os.environ.get('USER', 'unknown')
    return f'{base}/matrix-{user}-{time.strftime("%y%m%d%H%M%S")}'


def run_and_tee(argv: list[str], log_path: Path) -> int:
    """Run argv, copy its output to the terminal and to log_path, return rc."""
    with open(log_path, 'w') as log_file:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log_file.write(line)
        return process.wait()


def print_summary(results: list[tuple]) -> None:
    """Print one line per configuration and the totals."""
    width = 0
    for name, status, seconds, detail in results:
        if len(name) > width:
            width = len(name)

    print()
    print('=== summary ===')
    for name, status, seconds, detail in results:
        print(f'{status:5s} {name:{width}s} {seconds:7.1f}s  {detail}')

    counts = {'PASS': 0, 'FAIL': 0, 'SKIP': 0}
    for name, status, seconds, detail in results:
        counts[status] += 1
    print(f'{len(results)} configurations: {counts["PASS"]} passed, '
          f'{counts["FAIL"]} failed, {counts["SKIP"]} skipped')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-c', '--config', action='append', default=[],
                        metavar='PATTERN',
                        help='configuration to run; fnmatch pattern, '
                             'repeatable (default: all of them)')
    parser.add_argument('-X', '--exclude', action='append', default=[],
                        metavar='PATTERN',
                        help='configuration to skip; repeatable')
    parser.add_argument('--github-matrix', default=None, metavar='WORKFLOW',
                        help='print the jobs matrix.yml assigns to WORKFLOW '
                             'as JSON for strategy.matrix, and exit')
    parser.add_argument('-l', '--list', action='store_true',
                        help='print the command line of each configuration '
                             'and exit')
    parser.add_argument('--kernel', default=None, metavar='KERNEL',
                        help='run every configuration in a virtme-ng guest '
                             'booting this kernel: "latest-rc" or "latest" '
                             'for the newest release candidate or release in '
                             'the Ubuntu mainline archive at '
                             'kernel.ubuntu.com/mainline, an exact version '
                             'from it ("v7.3-rc2"), a kernel deb or a '
                             'directory of kernel debs, or the path of a '
                             'kernel image or of a directory holding a '
                             'kernel built from source. Archive kernels are '
                             'downloaded once and cached under '
                             '~/.cache/virtme-ng')
    parser.add_argument('--io-uring-bufpool', action='store_true',
                        help='run only the selected io-uring configurations, '
                             'each with a buffer pool and named '
                             '<config>-bufpool; needs Linux 7.3')
    parser.add_argument('--work-dir', default=None, metavar='DIR',
                        help='where to build and log; one directory for the '
                             'whole run, as ci-build.sh names its own '
                             'subdirectories after the configuration')
    args = parser.parse_args()

    if args.github_matrix is not None:
        print(json.dumps(github_matrix(load_matrix(), args.github_matrix)))
        return 0

    entries = select(load_matrix(), args.config, args.exclude)
    if args.io_uring_bufpool:
        entries = with_bufpool(entries)
    if not entries:
        sys.exit('no configuration matches')

    work_dir = args.work_dir
    if work_dir is None:
        work_dir = default_work_dir()

    if args.list:
        for entry in entries:
            print(' '.join(config_argv(entry, work_dir, args.kernel)))
        return 0

    # test/ci/prepare-runner.sh is deliberately not run here: it rewrites
    # kernel.core_pattern, which a CI runner needs and a workstation must not
    # get.
    Path(work_dir).mkdir(parents=True, exist_ok=True)
    print(f'{len(entries)} configurations, work directory {work_dir}')

    results = []
    for entry in entries:
        name = entry['config']
        missing = missing_tools(entry)
        if missing:
            print(f'SKIP  {name}: no {", ".join(missing)} on PATH')
            results.append((name, 'SKIP', 0.0, f'no {", ".join(missing)}'))
            continue

        log_path = Path(work_dir) / f'{name}.log'
        print(f'=== {name} ===')
        started = time.time()
        returncode = run_and_tee(config_argv(entry, work_dir, args.kernel),
                                 log_path)
        seconds = time.time() - started

        status = 'PASS' if returncode == 0 else 'FAIL'
        results.append((name, status, seconds, str(log_path)))

    print_summary(results)
    for name, status, seconds, detail in results:
        if status == 'FAIL':
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
