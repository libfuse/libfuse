Release Process
===============

`scripts/release.py` does the work. Run it from a libfuse checkout. Every
command takes `--dry-run`: it prints the exact commands and changes nothing.
X.Y.Z is the release being cut.

Step 1 -- prepare the release commit
------------------------------------

* `scripts/release.py prepare X.Y.Z`
* Sets the version in `meson.build`.
* Renames the `Unreleased Changes` section of `ChangeLog.rst` to this release.
* Appends every author who is not in `AUTHORS` yet.
* Generates a signing key only when the next release has none, which is a new
  minor or major version. A patch release inherits the keys of its `.0`.
* Leaves one commit, `Released fuse-X.Y.Z`.
* Offers to push the branch, and prints the URL that opens a pull request for
  it. `--remote` names the remote it is pushed to, `origin` by default.
  `--base` names the branch that pull request merges into, `master` by
  default.

Step 2 -- get the pull request merged
-------------------------------------

* Open the pull request at the printed URL, and get it merged. Neither is
  scriptable without `gh`.
* `git checkout master`. `publish` reads the signing keys from the checkout,
  so it releases another branch only from master.
* Pulling master is not needed. `publish` offers the fast-forward itself.

Step 3 -- publish
-----------------

* `scripts/release.py publish`
* Each action is shown with the commands it runs and confirmed on its own:

  * update -- `git pull --ff-only`, when the branch is behind the remote
  * pack -- `git archive`, `doxygen`, `tar -czf`
  * test -- `tar -xzf` into `verify/`, `test/ci-build.sh --name release`
  * the `Release tarball` workflow -- run it, answer whether it passed
  * tag -- `git tag -s`
  * sign -- `signify-openbsd -S`, then `-V`
  * write -- `fuse-X.Y.Z-notes.md`, `fuse-X.Y.Z-announce.txt`
  * push -- `git push origin refs/tags/fuse-X.Y.Z`
  * publish `doxygen/` in `../libfuse.github.io`

* A no before the tag ends the release with nothing to take back.
* A no to one of the two pushes skips it; the rest still runs.
* The tarball and the tree it is packed from are built again on every run, so
  a repeated one cannot ship an earlier commit under the same version.
* Released is the branch `--branch` names, the checked-out one by default. The
  version and the ChangeLog are read out of its commit, not out of the
  checkout. Another branch than the checked-out one needs master checked out.
  Every `signify/*.pub` is on master, a release branch only has the ones that
  existed when it forked.
* That branch has to point at what `origin` has it point at, so what is
  released is what everyone else can see.
* A `fuse-X.Y.Z` tag `origin` carries already has to point at that same
  commit. Publishing stops when it points elsewhere; the tag out there is a
  release of its own, and this one needs another version.
* The options not named above:

  * `--remote` -- the name of a git remote, `origin` by default. `publish`
    asks it where the release branch and the release tag point, and pushes
    the new tag to it.
  * `--pages-dir` -- a checkout of the libfuse.github.io repository, the one
    the website is served from. `../libfuse.github.io`, next to the libfuse
    checkout, by default. Its `doxygen/` is deleted and replaced with the
    `doc/html` of the packed tree, committed and pushed. `publish` clones the
    repository from `git@github.com:libfuse/libfuse.github.io.git` when the
    directory does not exist, and stops when the checkout it finds has
    uncommitted changes.
  * `--skip-test` -- do not build and test the tarball.
  * `--skip-workflow` -- do not ask about the release workflow run.
  * `--skip-docs` -- do not update the API documentation.
  * `--work-dir` -- passed to `test/ci-build.sh` as its build and log
    directory.

Step 4 -- create the GitHub release
-----------------------------------

* Open the URL `publish` printed.
* Title, notes file and the two attachments: `publish` names them.
* GitHub is never written to by the script.

Step 5 -- send the announcement
-------------------------------

* Send `fuse-X.Y.Z-announce.txt` to fuse-devel@lists.linux.dev.

The tarball
-----------

* `git archive` of the commit: an uncommitted source file builds here and is
  missing for everyone who downloads.
* Extracted tree: every `.gitignore` deleted, `.github` and `.cirrus.yml`
  removed, `doxygen doc/Doxyfile` writes `doc/html`.
* Named after the version the packed `meson.build` declares, so
  `release.py tarball HEAD` and `release.py tarball fuse-X.Y.Z` agree.
* The extracted tree stays next to the tarball, `doxygen/` is copied from its
  `doc/html`.
* All of it lands in `/var/tmp/fuse-release`, `--output-dir` elsewhere: the
  tree, the tarball, its signature, the notes and the announcement would
  otherwise sit untracked in the checkout, and only `*.gz` is gitignored.

The test build
--------------

* `release.py test fuse-X.Y.Z.tar.gz` unpacks it into `verify/` next to
  itself and runs `test/ci-build.sh --name release` in there.
* Unpacked rather than built where it was packed: the build has to see what a
  downloader gets, so a file `git archive` leaves out fails the release
  instead of the download.
* `publish` runs it before the tag exists, so a failure costs nothing.
* `test/ci-build.sh` calls `sudo` for its install prefix and the suite takes a
  while -- `--skip-test` when it has already been run.
* `test/ci/prepare-runner.sh` is not part of this. It rewrites
  `kernel.core_pattern`, which a CI runner needs and a workstation must not
  get.

The same test on GitHub
-----------------------

* `publish` prints the Actions URL for the branch it releases after the
  local test, and waits for the answer whether that run passed.
* Start it there with `Run workflow` on that branch. It is a
  `workflow_dispatch`, so nothing else ever starts it.
* `.github/workflows/release.yml` calls `scripts/release-tarball.sh` and
  nothing else.  The whole job is that one command, and it runs by hand.
* A `workflow_dispatch` is only listed when the file is on the default
  branch, and the run uses the file from the selected branch.  A release
  branch has to carry `release.yml`, `release.py` and
  `release-tarball.sh`.
* Answering anything but yes ends `publish` before the tag exists, so nothing
  has to be deleted. Fix, push, run `publish` again.
* Once the tag is on the remote it was let out by a run that passed, so a
  repeated `publish` does not ask again.
* The workflow packs its own tarball, so it needs no key; signing stays here.

Signing keys
------------

* `signify/fuse-<major>.<minor>.sec` signs every release of that minor and is
  gitignored -- back it up.
* `prepare X.Y.0` generates the keys of `X.<Y+1>` and `<X+1>.0` and commits
  their `.pub`, so this release carries the key of whichever comes next.
* `prepare X.Y.Z` refuses when one of them is gone: it may be published
  already, and a second key of that name is indistinguishable to whoever
  verifies with the first. `--new-key` generates it anyway.
