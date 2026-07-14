#!/usr/bin/env python3

import sys
import pytest
import time
import re
import os
import shlex
import subprocess
import threading


# The dirs util.py prepends to PATH so the build's binaries resolve: example/
# (for the fs daemons, e.g. 'hello') and util/ (for fusermount3/mount.fuse3).
# example/ ends up first because util.py prepends it last. A reproducer only
# needs these two in front of the caller's own $PATH, so we print them instead
# of the whole (often massively duplicated) inherited PATH.
_ADDED_PATH_DIRS = [os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 '..', d) for d in ('example', 'util')]


# If a test fails, wait a moment before retrieving the captured
# stdout/stderr. When using a server process, this makes sure that we capture
# any potential output of the server that comes *after* a test has failed. For
# example, if a request handler raises an exception, the server first signals an
# error to FUSE (causing the test to fail), and then logs the exception. Without
# the extra delay, the exception will go into nowhere.
@pytest.hookimpl(hookwrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    outcome = yield
    failed = outcome.excinfo is not None
    if failed:
        time.sleep(1)


class OutputChecker:
    '''Check output data for suspicious patterns.

    Everything written to check_output.fd will be scanned for suspicious
    messages and then written to sys.stdout.
    '''

    def __init__(self):
        (fd_r, fd_w) = os.pipe()
        self.fd = fd_w
        self._false_positives = []
        self._commands = []
        self._buf = bytearray()
        self._thread = threading.Thread(target=self._loop, daemon=True, args=(fd_r,))
        self._thread.start()

    def register_output(self, pattern, count=1, flags=re.MULTILINE):
        '''Register *pattern* as false positive for output checking

        This prevents the test from failing because the output otherwise
        appears suspicious.
        '''

        self._false_positives.append((pattern, flags, count))

    def _record(self, args, kwargs):
        '''Remember a command so a failure can print a *runnable* reproducer.

        The tests spawn subprocesses that inherit os.environ (notably a PATH
        that util.py prepends the build's example/ and util/ dirs to) and the
        current directory, so the bare argv alone is not reproducible. Capture
        the cwd and PATH in effect at spawn time as well.'''
        if isinstance(args, (list, tuple)):
            cmd = ' '.join(shlex.quote(str(a)) for a in args)
        else:
            cmd = str(args)
        env = kwargs.get('env') or os.environ
        self._commands.append({
            'cmd': cmd,
            'cwd': kwargs.get('cwd') or os.getcwd(),
            'path': env.get('PATH', ''),
        })

    @staticmethod
    def _runnable(cmd):
        '''Format a recorded command as a copy-pasteable shell line.

        Rather than dump the whole inherited PATH (which the user's shell
        already provides, often duplicated many times over), print only the
        build dirs the harness prepended and reference $PATH for the rest.
        Fall back to the full captured PATH if it doesn't start with that
        prefix (e.g. the command was spawned with a custom env=).'''
        prefix = ':'.join(_ADDED_PATH_DIRS)
        if cmd["path"] == prefix or cmd["path"].startswith(prefix + ':'):
            path = ':'.join(shlex.quote(d) for d in _ADDED_PATH_DIRS) + ':$PATH'
        else:
            path = shlex.quote(cmd["path"])
        return (f'(cd {shlex.quote(cmd["cwd"])} && '
                f'PATH={path} \\\n'
                f'     {cmd["cmd"]})')

    def _io_kwargs(self, kwargs):
        kwargs.setdefault('stdout', self.fd)
        kwargs.setdefault('stderr', self.fd)
        return kwargs

    def run(self, args, **kwargs):
        '''subprocess.run() with stdout/stderr wired to this checker and the
        command line recorded for failure reporting.'''
        self._record(args, kwargs)
        return subprocess.run(args, **self._io_kwargs(kwargs))

    def check_call(self, args, **kwargs):
        '''subprocess.check_call() variant, see run().'''
        self._record(args, kwargs)
        return subprocess.check_call(args, **self._io_kwargs(kwargs))

    def Popen(self, args, **kwargs):
        '''subprocess.Popen() variant, see run().'''
        self._record(args, kwargs)
        return subprocess.Popen(args, **self._io_kwargs(kwargs))

    def _loop(self, ifd):
        BUFSIZE = 128*1024
        ofd = sys.stdout.fileno()
        while True:
            buf = os.read(ifd, BUFSIZE)
            if not buf:
                break
            os.write(ofd, buf)
            self._buf += buf

    def _finalize(self):
        '''Close the pipe, join the reader thread and return the raw captured
        output as text.'''
        os.close(self.fd)
        self._thread.join()
        return self._buf.decode('utf8', errors='replace')

    def dump_on_failure(self, raw):
        '''Print the commands run and the full captured output so a failing
        test shows *what* ran and *why* it failed, instead of nothing.'''
        out = ['', '===== output_checker: test failed, '
               f'{len(self._commands)} command(s) run (runnable reproducers) =====']
        for c in self._commands:
            out.append(f'    {self._runnable(c)}')
        out.append('----- captured subprocess output -----')
        out.append(raw if raw else '(no output captured)')
        out.append('===== end output_checker dump =====')
        sys.stdout.write('\n'.join(out) + '\n')
        sys.stdout.flush()

    def _check(self, buf):
        # Strip out false positives
        for (pattern, flags, count) in self._false_positives:
            cp = re.compile(pattern, flags)
            (buf, cnt) = cp.subn('', buf, count=count)

        # Filter out Valgrind output lines before checking for suspicious words
        # ==PID== prefix: Valgrind standard messages (errors, info)
        # --PID-- prefix: Valgrind warnings (e.g., unhandled syscalls)
        buf = re.sub(r'^==[0-9]+== .*$', '', buf, flags=re.MULTILINE)
        buf = re.sub(r'^--[0-9]+-- .*$', '', buf, flags=re.MULTILINE)

        # FUSE debug messages "unique: X, error: -Y (...), outsize: Z" contain the
        # word "error" but just report a request's return code, not a real error.
        buf = re.sub(r'^.*unique: \d+, error: -\d+ \(.*\), outsize: \d+.*$', '',
                     buf, flags=re.MULTILINE)

        patterns = [ r'\b{}\b'.format(x) for x in
                     ('exception', 'error', 'warning', 'fatal', 'traceback',
                        'fault', 'crash(?:ed)?', 'abort(?:ed)',
                        'uninitiali[zs]ed') ]

        for pattern in patterns:
            cp = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            hit = cp.search(buf)
            if hit:
                raise AssertionError(self._format_failure(hit, buf))

    def _format_failure(self, hit, buf):
        '''Build a failure message that names the offending command and the
        exact line that tripped the check, instead of just the matched word.'''
        line_start = buf.rfind('\n', 0, hit.start()) + 1
        line_end = buf.find('\n', hit.end())
        if line_end == -1:
            line_end = len(buf)
        line = buf[line_start:line_end].strip()

        lines = []
        if len(self._commands) == 1:
            lines.append(f"Command failed (runnable reproducer):\n"
                         f"    {self._runnable(self._commands[0])}")
        elif self._commands:
            lines.append("Commands run in this test (runnable reproducers, in order):")
            lines.extend(f"    {self._runnable(c)}" for c in self._commands)
        lines.append(f'Suspicious output to stderr (matched "{hit.group(0)}") in line:')
        lines.append(f"    {line}")
        return '\n'.join(lines)

@pytest.fixture()
def output_checker(request):
    checker = OutputChecker()
    yield checker
    raw = checker._finalize()
    rep = getattr(request.node, 'rep_call', None)
    # Dump the full merged buffer on *any* failure, so the captured output is
    # always visible: both when the test body already failed (rep.failed) and
    # when _check() itself trips on suspicious output. The latter is the case
    # that otherwise only showed the single matched line, hiding the context.
    try:
        checker._check(raw)
    except AssertionError:
        checker.dump_on_failure(raw)
        raise
    else:
        if rep is not None and rep.failed:
            checker.dump_on_failure(raw)


# Make test outcome available to fixtures
# (from https://github.com/pytest-dev/pytest/issues/230)
@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)
    return rep
