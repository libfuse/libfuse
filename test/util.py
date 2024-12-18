#!/usr/bin/env python3
import subprocess
import pytest
import os
import stat
import time
from os.path import join as pjoin
import sys
import re
import itertools
from packaging import version
import logging

basename = pjoin(os.path.dirname(__file__), '..')

def parse_kernel_version(release):
    # Extract the first three numbers from the kernel version string
    match = re.match(r'^(\d+\.\d+\.\d+)', release)
    if match:
        return version.parse(match.group(1))
    return version.parse('0')

def get_printcap():
    cmdline = base_cmdline + [ pjoin(basename, 'example', 'printcap') ]
    proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                            universal_newlines=True)
    (stdout, _) = proc.communicate(30)
    assert proc.returncode == 0

    proto = None
    caps = set()
    for line in stdout.split('\n'):
        if line.startswith('\t'):
            caps.add(line.strip())
            continue

        hit = re.match(r'Protocol version: (\d+)\.(\d+)$', line) 
        if hit:
            proto = (int(hit.group(1)), int(hit.group(2)))

    return (proto, caps)

def test_printcap():
    get_printcap()

def wait_for_mount(mount_process, mnt_dir,
                   test_fn=os.path.ismount):
    elapsed = 0
    while elapsed < 30:
        if test_fn(mnt_dir):
            return True
        if mount_process.poll() is not None:
            pytest.fail('file system process terminated prematurely')
        time.sleep(0.1)
        elapsed += 0.1
    pytest.fail("mountpoint failed to come up")

def cleanup(mount_process, mnt_dir):
    # Don't bother trying Valgrind if things already went wrong

    if 'bsd' in sys.platform or 'dragonfly' in sys.platform:
        cmd = [ 'umount', '-f', mnt_dir ]
    else:
        cmd = [pjoin(basename, 'util', 'fusermount3'),
                         '-z', '-u', mnt_dir]
    subprocess.call(cmd, stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT)
    mount_process.terminate()
    try:
        mount_process.wait(1)
    except subprocess.TimeoutExpired:
        mount_process.kill()

def umount(mount_process, mnt_dir):
    logger = logging.getLogger(__name__)
    logger.debug(f"Unmounting {mnt_dir}")

    if 'bsd' in sys.platform or 'dragonfly' in sys.platform:
        cmdline = [ 'umount', mnt_dir ]
        logger.debug("Using BSD-style umount command")
    else:
        logger.debug("Using fusermount3 for unmounting")
        # fusermount3 will be setuid root, so we can only trace it with
        # valgrind if we're root
        if os.getuid() == 0:
            cmdline = base_cmdline
            logger.debug("Running as root, using valgrind if configured")
        else:
            cmdline = []
            logger.debug("Not running as root, skipping valgrind for fusermount3")
        cmdline = cmdline + [ pjoin(basename, 'util', 'fusermount3'),
                              '-z', '-u', mnt_dir ]

    logger.debug(f"Unmount command: {' '.join(cmdline)}")
    try:
        result = subprocess.run(cmdline, capture_output=True, text=True, check=True)
        if result.stdout:
            logger.debug(f"Unmount command stdout: {result.stdout}")
        if result.stderr:
            logger.debug(f"Unmount command stderr: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Unmount command failed with return code {e.returncode}\nStdout: {e.stdout}\nStderr: {e.stderr}")
        raise

    if not os.path.ismount(mnt_dir):
        logger.debug(f"{mnt_dir} is no longer a mount point")
    else:
        logger.warning(f"{mnt_dir} is still a mount point after unmount command")

    # Give mount process a little while to terminate. Popen.wait(timeout)
    # was only added in 3.3...
    elapsed = 0
    while elapsed < 30:
        code = mount_process.poll()
        if code is not None:
            if code == 0:
                return
            logger.error(f"File system process terminated with code {code}")
            pytest.fail(f'file system process terminated with code {code}')
        time.sleep(0.1)
        elapsed += 0.1
    logger.error("Mount process did not terminate within 30 seconds")
    pytest.fail('mount process did not terminate')


def safe_sleep(secs):
    '''Like time.sleep(), but sleep for at least *secs*

    `time.sleep` may sleep less than the given period if a signal is
    received. This function ensures that we sleep for at least the
    desired time.
    '''

    now = time.time()
    end = now + secs
    while now < end:
        time.sleep(end - now)
        now = time.time()

def fuse_test_marker():
    '''Return a pytest.marker that indicates FUSE availability

    If system/user/environment does not support FUSE, return
    a `pytest.mark.skip` object with more details. If FUSE is
    supported, return `pytest.mark.uses_fuse()`.
    '''

    skip = lambda x: pytest.mark.skip(reason=x)

    if 'bsd' in sys.platform or 'dragonfly' in sys.platform:
        return pytest.mark.uses_fuse()

    with subprocess.Popen(['which', 'fusermount3'], stdout=subprocess.PIPE,
                          universal_newlines=True) as which:
        fusermount_path = which.communicate()[0].strip()

    if not fusermount_path or which.returncode != 0:
        return skip("Can't find fusermount executable")

    if not os.path.exists('/dev/fuse'):
        return skip("FUSE kernel module does not seem to be loaded")

    if os.getuid() == 0:
        return pytest.mark.uses_fuse()

    mode = os.stat(fusermount_path).st_mode
    if mode & stat.S_ISUID == 0:
        return skip('fusermount executable not setuid, and we are not root.')

    try:
        fd = os.open('/dev/fuse', os.O_RDWR)
    except OSError as exc:
        return skip('Unable to open /dev/fuse: %s' % exc.strerror)
    else:
        os.close(fd)

    return pytest.mark.uses_fuse()

def powerset(iterable):
  s = list(iterable)
  return itertools.chain.from_iterable(
      itertools.combinations(s, r) for r in range(len(s)+1))

def create_tmpdir(mnt_dir):
    if not os.path.exists(mnt_dir):
        print("makedirs: '" + mnt_dir + "'")
        os.makedirs(mnt_dir)
    else:
        print("mnt_dir exists: '" + mnt_dir + "'")

# Use valgrind if requested
if os.environ.get('TEST_WITH_VALGRIND', 'no').lower().strip() \
   not in ('no', 'false', '0'):
    base_cmdline = [ 'valgrind', '-q', '--' ]
else:
    base_cmdline = []

# Try to use local fusermount3
os.environ['PATH'] = '%s:%s' % (pjoin(basename, 'util'), os.environ['PATH'])
# Put example binaries on PATH
os.environ['PATH'] = '%s:%s' % (pjoin(basename, 'example'), os.environ['PATH'])

try:
    (fuse_proto, fuse_caps) = get_printcap()
except:
    # Rely on test to raise error
    fuse_proto = (0,0)
    fuse_caps = set()

