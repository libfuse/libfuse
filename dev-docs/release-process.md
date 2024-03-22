Release Process
===============

* `set TAG fuse-A.B.C`
* Update version in
  * `ChangeLog.rst`
  * `meson.build`
  * `include/fuse_common.h` (`#define FUSE_{MINOR/MAJOR}_VERSION`)
* When creating new minor release:
  * Create signing key for the next release: `P=fuse-<A.B+1> signify-openbsd -G -n -p signify/$P.pub -s
  signify/$P.sec; git add signify/$P.pub`
  * Expire old release signing keys (keep one around just in case)
* Update authors: `git log --all --pretty="format:%an <%aE>" | sort -u >> AUTHORS`
* `git commit --all -m "Released $TAG"`
* `git tag $TAG`
* Build tarball, `./make_release_tarball.sh`
* Test build:
  * `cd fuse-x.y.z`
  * `md build && (cd build && meson .. && ninja)`
  * `sudo sudo chown root:root build/util/fusermount3`
  * `sudo chmod 4755 build/util/fusermount3`
  * `(cd build; python3 -m pytest test/)`
* Upload API docs:
  * `rm -r ../libfuse.github.io/doxygen && cp -a doc/html ../libfuse.github.io/doxygen`
  * `git -C ../libfuse.github.io add doxygen/`
  * `git -C ../libfuse.github.io commit --all -m "Re-generated doxygen documentation"`
  * `git -C ../libfuse.github.io push`
* `git checkout master && git push && git push --tags`
* Create release on Github
* Write announcement to fuse-devel


Announcement email template

```
To: fuse-devel@lists.sourceforge.net
Subject: [ANNOUNCE] libfuse XXXX has been released

Dear all,

I am pleased to announce the release of libfuse XXX.

The source code is available for download at https://github.com/libfuse/libfuse/releases.

Please report any issues on this mailing list or the GitHub issue
tracker at https://github.com/libfuse/libfuse/issues.

From ChangeLog.rst:

[INSERT NEW ENTRIES]

The following people have contributed code to this release:

[INSERT CONTRIBUTORS]

(a full list of credits containing all known contributors is included in
the `AUTHORS` file).

Best,
-Nikolaus
```
