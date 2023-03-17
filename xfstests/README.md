To test FUSE with xfstests¹:

1.  copy the `mount.fuse.passthrough` file into
  `/sbin` and edit the `PASSTHROUGH_PATH`, `SCRATCH_SOURCE` and `TEST_SOURCE` variables as needed.

2.  Make sure that the `SCRATCH_SOURCE` and `TEST_SOURCE` directories
exist.

3. Copy `local.config` into your xfstests directory

Tests can then be run with e.g.:

```sh
# make
# sudo ./check -fuse -b
```

¹https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/about/
