Testing against another kernel in a VM
======================================

`test/ci/vm-run.sh` boots a chosen kernel under virtme-ng and runs a
`test/ci-build.sh` command line inside it. `test/ci/run-matrix.py --kernel`
does that for a whole matrix configuration. Both are meant to be run by hand
as much as by CI:

* On a workstation -- run the suite against a release candidate, or against a
  kernel just built, without rebooting into it and without a test filesystem
  of its own.
* In CI -- a GitHub runner boots the kernel its image ships and cannot be
  rebooted, so fuse-over-io-uring went untested on anything newer.

Running it
----------

* `test/ci/run-matrix.py --kernel latest-rc` -- every configuration, each in a
  guest booting the newest release candidate in the Ubuntu mainline archive,
  kernel.ubuntu.com/mainline.
* `--kernel latest` -- the newest release there instead.
* `--kernel v7.3-rc2` -- that exact version from the same archive.
* `--kernel FILE.deb` -- a kernel deb, unpacked into a temporary directory for
  the run and thrown away afterwards. A `make bindeb-pkg` deb carries the
  image and its modules together.
* `--kernel DIR` where DIR holds debs -- all of them are unpacked into one
  tree, the `linux-headers` ones skipped. This is how an Ubuntu
  `linux-image` deb meets the separate `linux-modules` deb it needs; on its
  own it is rejected, naming the modules it lacks.
* `--kernel PATH` -- a kernel image, or a directory holding a kernel built
  from source. Nothing is downloaded.
* Archive kernels are Ubuntu builds of the mainline tree, shipped as debs.
  virtme-ng fetches the ones it needs and unpacks them under
  `~/.cache/virtme-ng`, so a version is downloaded once and every later run
  boots it out of the cache.
* `-c` and `-X` select configurations as they do without a kernel. See
  README-local-ci-matrix-builds.md.
* Needs the virtme-ng, qemu, virtiofsd and busybox packages:
  `.github/workflows/install-ubuntu-dependencies.sh --kernel-vm`.
* Needs to open `/dev/kvm`. Without it qemu emulates the guest and the suite
  takes hours.

```
test/ci/run-matrix.py --kernel latest-rc -c 'gcc*io-uring*'
test/ci/run-matrix.py --kernel ~/linux -c gcc-io-uring
```

What the guest is
-----------------

* virtme-ng boots the kernel on the host's own filesystem over virtiofs: the
  same checkout, the same toolchain, the same uid. Only the kernel differs.
* Nothing is installed and no disk image is built. The guest dies with the
  command it ran, and its exit status is the one reported.
* `latest-rc` and `latest` are resolved when the run starts, and vm-run.sh
  prints the version it picked -- a failure cannot be repeated otherwise. A
  version whose build failed is listed in the archive with no packages, so
  the newest one carrying packages for this architecture wins.
* The guest has no systemd and no init past virtme's own, so vm-run.sh mounts
  fusectl, loads the cuse module and writes the sudo rule itself before the
  tests start. Each is a test that hangs or fails without it.
* Guest cpus default to the host's, capped at 8. An io-uring daemon takes ring
  memory per core and the suite runs many daemons at once, so handing a guest
  every core of a big host runs it out of memory rather than making it faster.
  `vm-run.sh --cpus` and `--memory` override, `run-matrix.py` does not pass
  them through.

Where the output goes
---------------------

* The guest builds and tests under `/var/tmp/fuse-tests`, on its own tmpfs.
  The host directory will not do: files written over 9p land owned by the qemu
  user, which is who the setuid `fusermount3` would then elevate to, and a
  build there did not finish at all.
* `run-matrix.py --work-dir` reaches vm-run.sh as `--logs-out`. The guest
  copies its `run/` logs there before it exits, so the per-test logs survive
  the VM.

In CI
-----

* `.github/workflows/pr-ci.yml` runs every configuration with `vm: true` in
  `test/ci/matrix.yml` this way, on every push and pull request. These are
  the io-uring configurations.
* They name `kernel: latest-rc`, so the jobs follow the current release
  candidate with no version for anyone to bump.
* These jobs do not block a merge: a release candidate can break on its own.
* Logs upload as `test-logs-<config>`.

Buffer pools
------------

* A configuration with `io_uring_bufpool: true` runs with a buffer pool. Its
  name ends in `-bufpool`.
* Buffer pools need Linux 7.3 and no GitHub runner image ships a kernel that
  new, so every bufpool configuration in `matrix.yml` runs in a VM booting
  `latest-rc`.
* On a kernel without pools run-tests.py skips the whole invocation and
  prints the reason on its `SKIP:` line. ci-build.sh fails on that exit,
  as on every non-zero exit of run-tests.py.

```
test/ci/run-matrix.py -c gcc-io-uring-bufpool
test/ci/run-matrix.py --kernel ~/linux -c gcc-io-uring-bufpool
```
