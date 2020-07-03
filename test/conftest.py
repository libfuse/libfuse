#!/usr/bin/env python3

import sys
import pytest
import time
import re
import os
import threading


# If a test fails, wait a moment before retrieving the captured
# stdout/stderr. When using a server process, this makes sure that we capture
# any potential output of the server that comes *after* a test has failed. For
# example, if a request handler raises an exception, the server first signals an
# error to FUSE (causing the test to fail), and then logs the exception. Without
# the extra delay, the exception will go into nowhere.
@pytest.mark.hookwrapper
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
        self._buf = bytearray()
        self._thread = threading.Thread(target=self._loop, daemon=True, args=(fd_r,))
        self._thread.start()

    def register_output(self, pattern, count=1, flags=re.MULTILINE):
        '''Register *pattern* as false positive for output checking

        This prevents the test from failing because the output otherwise
        appears suspicious.
        '''

        self._false_positives.append((pattern, flags, count))

    def _loop(self, ifd):
        BUFSIZE = 128*1024
        ofd = sys.stdout.fileno()
        while True:
            buf = os.read(ifd, BUFSIZE)
            if not buf:
                break
            os.write(ofd, buf)
            self._buf += buf

    def _check(self):
        os.close(self.fd)
        self._thread.join()

        buf = self._buf.decode('utf8', errors='replace')

        # Strip out false positives
        for (pattern, flags, count) in self._false_positives:
            cp = re.compile(pattern, flags)
            (buf, cnt) = cp.subn('', buf, count=count)

        patterns = [ r'\b{}\b'.format(x) for x in
                     ('exception', 'error', 'warning', 'fatal', 'traceback',
                        'fault', 'crash(?:ed)?', 'abort(?:ed)',
                        'uninitiali[zs]ed') ]
        patterns += ['^==[0-9]+== ']

        for pattern in patterns:
            cp = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            hit = cp.search(buf)
            if hit:
                raise AssertionError('Suspicious output to stderr (matched "%s")'
                                     % hit.group(0))

@pytest.fixture()
def output_checker(request):
    checker = OutputChecker()
    yield checker
    checker._check()


# Make test outcome available to fixtures
# (from https://github.com/pytest-dev/pytest/issues/230)
@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)
    return rep
