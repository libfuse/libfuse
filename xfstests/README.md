To test FUSE with xfstests¹:

1.  copy the `mount.fuse.passthrough` file into `/sbin`.

2.  Edit the `local.config` file, change the `PASSTHROUGH_PATH`,
  `SCRATCH_DEV`, `SCRATCH_MNT`, `TEST_DEV` and `TEST_DIR` variables as needed.
  Make sure that the directories exist.

3. Copy `local.config` into your xfstests directory

Tests can then be run with e.g.:

```sh
# make
# sudo ./check -fuse -b
```

¹https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/about/
