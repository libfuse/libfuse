# Writing a libfuse test

## The runner

`test/run-tests.py` is the suite. A plain Python program with no test framework
under it — run it directly; `meson test` only wraps it. Per run it

- discovers every executable `cases/**/*.sh`, then narrows by `-t`, `-g`, `-X`
  and `test/exclude`;
- runs `printcap` once, so every script sees the same `$FUSE_CAPS`;
- gives each test a private work directory and its own cgroup;
- launches the script as `bash -e`, cwd its own log directory, and enforces
  `# TIMEOUT:` as a wall-clock bound;
- kills that cgroup afterwards, pass or fail, so a leaked daemon cannot wedge
  the next test;
- turns the exit status plus what it collected — cores, suspicious log lines —
  into PASS/SKIP/FAIL, prints the counts and the slowest five, and exits
  non-zero if anything failed.

`-j` tests run at once, so nothing may depend on a global name.

One run, end to end — `->` calls or execs, `=>` spawns and waits, `..>` writes a
file, `[ ]` a process of its own:

```text
meson test -C build            (two entries: fuse-tests, fuse-tests-io-uring)
  -> test/run-tests.py --build-dir <build>
       -> discover()           cases/**/*.sh + cases/unit/<binary> markers
       -> TestRunner.run_all()
            -> _run_batch(serial group, jobs=1)
            -> _run_batch(rest, jobs=N)
                 -> run_one(spec)
                      -> prepare()        mnt/ src/ tmp/ logs/ + env contract
                      -> write_repro()    ..> logs/repro.sh
                      => [ /bin/sh -c LAUNCHER ]
                           ..> <leaf>/cgroup.procs     (self-move)
                           -> ulimit -S -c "$(ulimit -H -c)"
                           -> exec bash -e cases/<name>.sh
                                -> . cases/lib/common.sh
                                     -> fuse_mount_at
                                          => [ fs daemon ] ..> logs/fs-N-*.out
                                          -> fuse_wait_mount
                                          -> _fuse_assert_uring
                                     -> _check <op>  -> python3 cases/lib/checks.py
                                     -> fuse_umount  -> fusermount3 -u
                      -> _stream()        ..> logs/script.out, logs/timestamps.out
                      -- timeout?  -> dump_stacks() ..> ps.txt kstack.N.txt gdbstack.N.txt
                                   -> _kill()       ..> <leaf>/cgroup.kill
                      -> collect_cores()  -> gdb ..> backtrace.<exe>.<pid>.txt
                      -> scan_logs()      suspicious words, minus logs/.allow
                      -> classify()       PASS | FAIL | SKIP(77)
                 -> report() / discard_workdir()
            -> summarise()
```

## What a test is

An executable `*.sh` anywhere under `test/cases/`. Its **name** is the path
below `cases/` without the extension, so `cases/examples/hello-direct.sh` is
`examples/hello-direct`.

| exit code     | meaning                            |
|---------------|------------------------------------|
| 0             | PASS                               |
| 77            | SKIP — the script called `_notrun` |
| anything else | FAIL                               |

Nothing registers a test anywhere. Dropping the file in and making it
executable is the whole step; `test/run-tests.py` discovers it.

`test/cases/unit/` is the exception to all of the above. A C test that needs
neither a mount nor a gate has no script there — only a file named after the
binary, which the runner execs from `$FUSE_TEST_BIN_DIR` with no shell in
between. It carries no exec bit, and its content is a header block or nothing
at all.

## The skeleton

```sh
#!/usr/bin/env bash
# GROUP: examples quick

. "$TEST_LIB/common.sh"

_require_cap FUSE_CAP_WRITEBACK_CACHE     # skip (77) if unsupported

fuse_mount passthrough_ll -o writeback,source="$TEST_SRC"
_check fuse_test_open_write "$TEST_SRC" "$TEST_MNT"
fuse_umount
```

`#!/usr/bin/env bash`, not `#!/bin/bash`: FreeBSD has no bash in base, and
`common.sh` needs bash for the `FUSE_FS_*` arrays and `$SECONDS`.

A case that sources a body from `lib/` gets `common.sh` with it and does not
name it itself. Source it directly only when there is no body, or when the case
gates before one — a gate has to run before the body, which is the whole test.

## The environment you get

The runner exports all of this into every script:

```sh
TEST_NAME=examples/hello-ll-direct     # discovery name
TEST_SCRIPT=/…/test/cases/examples/hello-ll-direct.sh
TEST_DIR=/…/test                       # source tree, never the build dir
TEST_LIB=/…/test/cases/lib             # what tests source from
TEST_WORKDIR=/…/run/examples/hello-ll-direct
TEST_MNT=$TEST_WORKDIR/mnt
TEST_SRC=$TEST_WORKDIR/src
TEST_TMP=$TEST_WORKDIR/tmp
TEST_LOGDIR=$TEST_WORKDIR/logs         # also the cwd of your script
BUILD_DIR=/…/build                     # meson build root
FUSE_EXAMPLE_DIR=$BUILD_DIR/example
FUSE_TEST_BIN_DIR=$BUILD_DIR/test
FUSE_UTIL_DIR=$BUILD_DIR/util
FUSE_CAPS="FUSE_CAP_ASYNC_READ FUSE_CAP_POSIX_LOCKS …"   # printcap, run once
FUSE_UID=1000                          # effective uid
FUSE_OS=Linux                          # platform.system()
FUSE_INIT_STATUS=1                     # every session logs its FUSE_INIT result
PATH=$FUSE_UTIL_DIR:$FUSE_EXAMPLE_DIR:$PATH
```

`$TEST_MNT`, `$TEST_SRC` and `$TEST_TMP` already exist and are yours alone, so
a test never invents a temporary directory or worries about colliding with a
concurrent test. `$FUSE_OS` is exported so no script shells out to `uname -s`.

## Header directives

Only two exist. Anything else in the leading comment block is an ordinary
comment.

```sh
# TIMEOUT: 180      # seconds; the default is 60
# GROUP: examples serial
```

`# GROUP:` names are used by `run-tests.py -g`.

## Errexit is on

The runner runs your script as `bash -e`, so any command that fails and is not
checked ends the test there. Nothing to add to the script. What it means when
writing one is that a command you *expect* to fail must say so — `cmd || true`,
or an `if`, or `_assert_errno`.

The same applies to a test you write as a bare condition: `[ -n "$x" ] && cmd`
returns non-zero when `$x` is empty and ends the test. Write
`[ -z "$x" ] || cmd` instead.

Run a test by hand the same way (`bash -e cases/…`, or the `repro.sh` the
runner writes) or it will behave differently from CI.

## Skipping

> Gate on a feature, never on a version. `_require_cap FUSE_CAP_X` asks the
> running kernel what it supports; `_require_binary`, `_require_root` and
> `_require_prog` ask about the environment. There is deliberately no
> `_require_kernel_version`: a version comparison is wrong the moment the fix
> is backported. If a feature has no capability flag, grep the filesystem's own
> log for whatever it prints when the kernel refuses
> (`_require_fs_marker_absent`), or let the test fail on old kernels and have
> those targets exclude it by name via `test/exclude` or `-X`.
>
> A *platform* is the one exception, because it is not a version:
> `/proc/self/mountinfo` will not be backported to FreeBSD. `_require_linux
> <what>` states which Linux-only facility the test needs. Put it in the shared
> body when a whole family is affected, not in each caller.

```sh
_fail <msg...>                  # exit 1 with a message
_notrun <reason...>             # exit 77; the runner records the reason
_require_root                   # / _require_nonroot
_is_linux                       # true/false, for a conditional section
_require_linux <what>           # skip off Linux, naming the facility
_require_cap FUSE_CAP_NAME      # skip unless printcap reported it
_require_binary example/null    # skip unless $BUILD_DIR/<path> is executable
_require_prog losetup           # skip unless it is on $PATH
_require_not_32bit_on_64 <path>
_require_reachable_without_caps <fs-name>
_require_fs_marker_absent <regex> [fs-index]
```

Sourcing `common.sh` also gates the case on FUSE being usable at all — the
module loaded, and a setuid `fusermount3` when you are not root — because
every case that mounts needs both. A case that never mounts says so *before*
sourcing, and runs anyway:

```sh
_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"
```

## Mounting

```sh
fuse_mount <fs-name> [args...]          # $TEST_MNT, foreground (-f)
fuse_mount_at <mnt> <fs-name> [args...] # explicit mountpoint, no -f
fuse_mount_helper <fs-name> [args...]   # via mount.fuse3
fuse_umount [idx]                       # and require the daemon to exit 0
fuse_umount_lazy [idx]                  # the give-up path; the trap uses it
fuse_wait_mount <path> [predicate]
fuse_fs_pid [idx]  /  fuse_fs_log [idx]
```

A filesystem name is resolved under `$FUSE_EXAMPLE_DIR`, or under
`$FUSE_TEST_BIN_DIR` when it is prefixed `test/` (so `test/hello` is the
`hello` built in `test/`). Each mount gets an index, and every one of them is
unmounted and killed by an EXIT trap, so an aborting test never leaks a mount.
Register your own cleanup with `_at_exit <command>` rather than `trap`, or you
will replace that trap.

### Daemons run in the foreground

`fuse_mount` passes `-f`, and a case that launches a filesystem itself is
expected to do the same. The runner owns the process: the daemon has to stay
in the test's cgroup for the timeout to reach it, and its stderr has to stay
attached to `logs/fs-N-*.out`.

That leaves the backgrounded path — `fuse_daemonize_early_start()`, the parent
waiting for the mount, `stdout`/`stderr` closed once FUSE_INIT is answered —
covered only by the `mount.fuse3` cases, which is where synchronous FUSE_INIT
is reached as well. Covering it properly needs foreground and background
variants of the existing cases; that has not been done.

## Assertions

> Shell owns mounting, sequencing and skipping. It does not own checks.
> `_assert_eq`, `_assert_ne`, `_assert_file_eq` and `_wait_for` exist because
> shell expresses them exactly. Everything else is a `checks.py` subcommand —
> and if what you need is not there, **add a subcommand rather than
> approximating it in shell**. An `errno` compared against `strerror` text, a
> timestamp rounded by `touch -d`, an option set split by `awk`: each is a
> weaker test than the Python one line of `checks.py` would have been.

A check is a subcommand of `test/cases/lib/checks.py`, not a command and not a
shell function. `_check` runs it:

```sh
_check fuse_test_open_write "$TEST_SRC" "$TEST_MNT"
# runs: python3 test/cases/lib/checks.py fuse_test_open_write <src> <mnt>
```

Every name is prefixed `fuse_test_` so a reader never has to wonder whether
`unlink` in a test script means coreutils or a check. The list below is all
of them; if what you need is missing, add it to `checks.py`.

```sh
# file and directory operations
fuse_test_unlink <mnt> [--src <dir>] # create, unlink, require ENOENT
fuse_test_mkdir <mnt>                # directory create
fuse_test_rmdir <mnt> [--src <dir>]  # directory remove
fuse_test_symlink <mnt>              # symlink and read it back
fuse_test_create <mnt>               # O_CREAT, then mode/nlink/size
fuse_test_link <mnt>                 # hard link, nlink, unlink
fuse_test_chown <mnt>                # chown uid then gid separately
fuse_test_utimens <mnt> [--ns-tol N] # nanosecond timestamps
fuse_test_xattr <path>               # set/get/remove
fuse_test_statvfs <mnt>              # statvfs succeeds

# reading and writing
fuse_test_open_read <src> <mnt>  # write via src, read through the mount
fuse_test_open_write <src> <mnt> # create via src, write through the mount
fuse_test_append <src> <mnt>     # O_APPEND writes
fuse_test_seek <src> <mnt>       # lseek writes
fuse_test_open_unlink <mnt>      # write to an unlinked fd
fuse_test_truncate_path <mnt>    # grow and shrink by path
fuse_test_truncate_fd <mnt>      # grow and shrink by fd

# listing and comparison
fuse_test_listdir <dir>                             # print the entries
fuse_test_listdir_first <dir>                       # print the first entry
fuse_test_assert_listdir <dir> <name>...            # exactly these entries
fuse_test_readdir <src> <mnt> [--inode-check M]     # listing and inodes
fuse_test_readdir_big <src> <mnt> [--inode-check M] # 500 entries
fuse_test_passthrough <src> <mnt> [--inode-check M] # both sides agree

# predicates and errno
fuse_test_size <path>                         # print st_size
fuse_test_ismount <path>                      # is it a mountpoint
fuse_test_isbigger <path> <size>              # is it bigger than that
fuse_test_expect_errno <ERRNO> <op> [args...] # require exactly that errno

# mount state
fuse_test_mountinfo <mnt> <field>              # one /proc/self/mountinfo field
fuse_test_assert_mount_opt <mnt> <opt>...      # present in mount_options
fuse_test_refute_mount_opt <mnt> <opt>...      # absent from mount_options
fuse_test_assert_super_opt <mnt> <opt>...      # present in super_options
fuse_test_assert_super_opt_prefix <mnt> <p>... # e.g. user_id=
fuse_test_assert_fstype <mnt> <fstype>...      # any one is acceptable
fuse_test_assert_source <mnt> <source>...      # any one is acceptable

# the remainder
fuse_test_printcap_caps <src-root>          # every FUSE_CAP_* is in the header
fuse_test_reachable_without_caps <path>     # mode-bit walk up the tree
fuse_test_elf_class <path>                  # 32 or 64, from e_ident
fuse_test_null_roundtrip <path>             # read zeros, then write
fuse_test_cuse_roundtrip <devpath> <client> # read/write/offset exchange
fuse_test_uds_init <sockpath>               # a FUSE INIT handshake
```

`--inode-check M` is `exact` (the default) or `nonzero`. `<op>` for
`fuse_test_expect_errno` is one of `fuse_test_open_rw`, `fuse_test_open_ro`
or `fuse_test_stat`.

`common.sh` wraps the common ones in shell functions, which keep the
underscore-prefixed naming shell uses elsewhere: `_assert_errno`,
`_assert_listdir`, `_assert_xattr_roundtrip`, `mountinfo_field`,
`_assert_mount_opt`, `_refute_mount_opt`, `_assert_super_opt`,
`_assert_super_opt_prefix`, `_assert_fstype`, `_assert_source`.

## Adding a variant of an existing test

A parametrized case becomes a real file, so it gets its own duration, log
directory and name in the summary. The variant sets a few variables and sources
a shared body from `lib/`:

```sh
#!/usr/bin/env bash
# cases/examples/hello-ll-mount-fuse-clone_fd.sh
# GROUP: examples quick

FS_NAME=hello_ll          # which example to mount
FS_OPTS=clone_fd          # -o option list, empty for none
LAUNCH=mount_fuse         # direct | mount_fuse | mount_fuse_dropcaps

. "$TEST_LIB/hello.sh"
```

The shared body carries the gates for the whole family — one
`_require_linux "the clone_fd mount option"` in `lib/hello.sh` covers every
`clone_fd` variant — so a new caller inherits them.

## Suspicious output fails a test

Anything a daemon writes matching `error`, `warning`, `fatal`, `crash`,
`abort`, `exception`, `traceback`, `fault` or `uninitialised` fails the test
even when it exited 0. If that is a false positive for your test, exempt the
exact line:

```sh
fuse_allow_output '^ \d\d \[[^]]+ message: .No error: 0.\]'
```

A core dump fails the test the same way. A test that deliberately crashes
something opts out per executable with `fuse_allow_core <executable-name>`.

## When a test fails

```
$TEST_WORKDIR/logs/script.out    what the test printed
$TEST_WORKDIR/logs/fs-0-*.out    what the filesystem daemon printed
$TEST_WORKDIR/logs/fs-0-*.status its exit status
$TEST_WORKDIR/logs/core.<exe>.<pid>            core, one per crashed process
$TEST_WORKDIR/logs/backtrace.<exe>.<pid>.txt   its gdb backtrace
$TEST_WORKDIR/logs/repro.sh      re-run this one test, same env, by hand
```

On a CI failure this whole tree is downloadable from the job's `test-logs`
artifact, minus the raw cores — the backtraces the runner already resolved are
what is worth keeping.

A test's directory is removed as soon as it passes or skips, and the run
directory itself when nothing failed at all — so what is left afterwards is
exactly what is worth looking at (and uploading). `--keep-logs` keeps
everything anyway.

## Running them

`--build-dir` is the only option a run normally needs; it defaults to `.`.

```sh
./test/run-tests.py --build-dir build      # everything
./test/run-tests.py -t 'examples/hello-*'  # fnmatch on the name, repeatable
./test/run-tests.py -g quick               # only this GROUP, repeatable
./test/run-tests.py -X misc/hello-uds      # skip one, repeatable
./test/run-tests.py -l                     # list the selection, run nothing
./test/run-tests.py -j1 -v                 # serially, output live
./test/run-tests.py -j8                    # default is cpu_count // 2
./test/run-tests.py --repeat 20 -t misc/x  # chase a flake
./test/run-tests.py --timeout 300          # override every # TIMEOUT:
./test/run-tests.py --keep-logs            # keep passing tests' output too
```

`-t` and `-g` narrow; `-X` and `test/exclude` remove from what is left.

A `-t` pattern may also be the path to a case, so it can be tab-completed:
`test/cases/examples/cuse.sh` and `examples/cuse` name the same test, from any
directory. A directory selects everything under it, by path or by bare name —
`-t examples` and `-t test/cases/examples` are the same selection. A pattern
that matches no test is an error rather than an empty run.

Where the output lands:

```sh
--run-dir DIR           # this directory, verbatim; so does $FUSE_TEST_RUN_DIR
--print-base-dir        # print where a run would land, and exit
--persist-base-dir DIR  # remember DIR in ~/.config/libfuse/tests.conf
```

Without `--run-dir`, a run gets a `run-<user>-<timestamp>-<pid>` leaf under the
base, and the leaf is deleted when nothing failed.

Unprivileged, without a setuid `fusermount3`, everything that mounts skips
itself. `--setuid-helpers` makes the build tree's helpers setuid root (with
`sudo`) before the run; it is a no-op once they are.

`test/exclude` holds one test name per line for a host that cannot support a
test; `-X <name>` adds to it for one run.

`TEST_WITH_VALGRIND=1` traces every daemon and scales every timeout by ten to
match. A valgrind finding fails the test through the daemon's exit status
(`--error-exitcode=99`), with the report sitting in that daemon's own log;
valgrind's `==pid==` lines are stripped before the suspicious-output scan.
`fusermount3` is traced only when the test runs as root, because it is setuid,
and the give-up umount on the failure path is not traced at all.

## Running them over fuse-io-uring

```sh
echo Y | sudo tee /sys/module/fuse/parameters/enable_uring
./test/run-tests.py --build-dir build --io-uring
```

The same tests run again with `FUSE_URING_ENABLE=1` in the environment. Without
the module parameter the whole invocation skips and says so, rather than
reporting 88 failures.

`kernel.io_uring_disabled` is the other half, and only warns: the runner opens a
ring of its own first, and where that fails it prints the errno and runs anyway,
because the failure then lands on the tests that were supposed to use one.

A test neither opts in nor out: every test runs over both transports, and it
says nothing about io-uring anywhere in its script. Because setting the
variable is not evidence the transport was used, the run proves it three ways —
the kernel has to have offered `FUSE_CAP_OVER_IO_URING`, no daemon may log
`failed to start io-uring`, and every session that answered FUSE_INIT has to
have printed `FUSE_INIT: io_uring=on` on its stderr.

That last line is the session's own account of its transport, and every daemon
the suite starts has its stderr captured, so it covers the ones a mount verb
never started too — `mount.fuse3`, the self-mounting C tests, a daemon a script
launched itself:

```text
FUSE_INIT: io_uring=on                        the ring is up
FUSE_INIT: io_uring=off:custom_io             no /dev/fuse fd, so no ring
FUSE_INIT: io_uring=off:start_failed:<errno>  asked for a ring, did not get one
FUSE_INIT: io_uring=off:disabled              nobody asked
FUSE_INIT: io_uring=off:not_offered           the kernel did not offer the cap
```

Only the first two pass. `off:custom_io` is the one refusal a daemon cannot
help, so it needs no declaration from the test: `hello_ll_uds` serves the
protocol over an `AF_UNIX` socket and says so itself. A test that starts no
session reports nothing and has nothing to prove, which is also how
`cuse` passes — it answers `CUSE_INIT` in `lib/cuse_lowlevel.c` and never
reaches this reporting at all.

## What breaks under -j

A test that binds a fixed path, names a device node globally, or takes the
first free loop device cannot run concurrently with a copy of itself and must
declare `# GROUP: serial`. The three existing cases are `misc/hello-uds`
(`hello_ll_uds` hard-codes a socket path in /tmp), `examples/cuse` (it names a
device node globally) and `mount/blkdev-fsname-*` (`losetup -f` races).
