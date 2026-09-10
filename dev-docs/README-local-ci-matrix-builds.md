Running the CI build matrix locally
===================================

`.github/workflows/pr-ci.yml` builds libfuse in many configurations on every
pull request: several compilers, the sanitizers, valgrind, root and
unprivileged runs, fuse-over-io-uring, a 32-bit build, and various sets of
meson options. `test/ci/run-matrix.py` runs the same ones from a checkout, so
a red job can be reproduced without pushing.

The matrix keeps one definition
-------------------------------

* Every build parameter is spelled out in `pr-ci.yml`, under
  `jobs.build.strategy.matrix`.
* `run-matrix.py` reads that file and produces the same `test/ci-build.sh`
  command line the workflow's expression expansion does. A configuration
  added there needs no change here.
* Needs PyYAML -- `python3-yaml` on Debian and Ubuntu.

Running it
----------

* `test/ci/run-matrix.py` -- every configuration, in the order `pr-ci.yml`
  lists them.
* `-c PATTERN` -- run only the configurations matching. fnmatch, repeatable.
* `-X PATTERN` -- skip the configurations matching. fnmatch, repeatable.
* `--list` -- print the command lines and exit, running nothing.
* `--kernel KERNEL` -- run each configuration in a VM booting that kernel
  instead of on this one. See README-kernel-vm-tests.md.
* `--work-dir DIR` -- build and log there instead of the default below.

```
test/ci/run-matrix.py                      # every configuration
test/ci/run-matrix.py -c clang-san-m32     # one of them
test/ci/run-matrix.py -c 'gcc*' -X '*valgrind*'
test/ci/run-matrix.py --list               # print, do not run
```

What to expect
--------------

* Configurations run one after another. Not a limitation waiting to be
  lifted: the suite has tests that cannot run beside a copy of themselves --
  they bind a fixed path, name a device node globally, or take the first free
  loop device -- and the io-uring configurations put a global module
  parameter back on exit.
* A configuration whose compiler or valgrind is not installed is reported as
  a skip, not a failure, naming what is missing. An older `gcc` the matrix
  names may not be packaged for the distribution at all.
* `ci-build.sh` calls `sudo` for `ninja install` and for the setuid bits, so
  a run prompts for a password unless sudo is passwordless.
* Exit status is non-zero when any configuration failed.

Where the output goes
---------------------

* `--work-dir` when given. Otherwise the base `test/run-tests.py
  --print-base-dir` reports -- `/var/tmp/fuse-tests` unless configured --
  with a `matrix-<user>-<timestamp>` directory below it.
* `<work-dir>/<config>.log` -- everything that configuration printed.
* `<work-dir>/run/<config>/` -- the suite's own per-test logs, as CI uploads
  them. A test that passed deletes its own directory.
* `test/ci/prepare-runner.sh` is deliberately not run: it rewrites
  `kernel.core_pattern`, which a CI runner needs and a workstation must not
  get.
