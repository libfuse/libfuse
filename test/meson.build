# Compile helper programs
td = []
foreach prog: [ 'test_write_cache', 'test_setattr', 'test_api_30', 'hello' ]
    td += executable(prog, prog + '.c',
                     include_directories: include_dirs,
                     link_with: [ libfuse ],
                     dependencies: thread_dep,
                     install: false)
endforeach
td += executable('test_syscalls', 'test_syscalls.c',
                 include_directories: include_dirs,
                 install: false)
td += executable('readdir_inode', 'readdir_inode.c',
                 include_directories: include_dirs,
                 install: false)
td += executable('release_unlink_race', 'release_unlink_race.c',
                 dependencies: [ libfuse_dep ],
                 install: false)
td += executable('test_want_conversion', 'test_want_conversion.c',
                 dependencies: [ libfuse_dep ],
                 install: false)
td += executable('test_signals', 'test_signals.c',
                 dependencies: [ libfuse_dep, thread_dep ],
                 install: false)
td += executable('test_teardown_watchdog', 'test_teardown_watchdog.c',
                 dependencies: [ libfuse_dep, thread_dep ],
                 install: false)
td += executable('test_abi', 'test_abi.c',
                 dependencies: [ libfuse_dep ],
                 install: false)
td += executable('test_loop_config', 'test_loop_config.c',
                 include_directories: include_dirs,
                 link_with: [ libfuse ],
                 dependencies: thread_dep,
                 install: false)
td += executable('test_mount_flags',
                 ['test_mount_flags.c', '../lib/mount_util.c',
                  '../lib/fuse_log.c'],
                 include_directories: include_dirs,
                 install: false)

if meson.is_subproject()
	# Skipped rather than run: the tests mount filesystems, which is not
	# something a parent project's `meson test` should do. Exit 77 is how a
	# test tells meson SKIP. python3 is optional here because nothing else
	# in this branch needs it, and a parent must still be able to configure.
	python3 = find_program('python3', required: false)
	if python3.found()
		test('libfuse is a subproject, skipping tests', python3,
		     args: ['-c',
		            'import sys; print("run them with test/run-tests.py ' +
		            '--build-dir <builddir>", file=sys.stderr); sys.exit(77)'])
	endif
else
	# The same definition works both as a regular user and under sudo:
	# invoke 'meson test -C build' for the unprivileged subset, or
	# 'sudo -E meson test -C build' to also exercise the tests that require
	# root (they pick the uid up at runtime).
	#
	# Nothing is copied into the build tree: the runner,
	# its library and the test scripts are read from the source dir, and
	# the only build artefacts a test needs are the binaries, which it
	# reaches through --build-dir. That also means no custom_target and no
	# rebuild after editing a test.
	#
	# No --run-dir: it defaults under /var/tmp/fuse-tests, and CI redirects
	# it with $FUSE_TEST_RUN_DIR so the logs outlive the build tree.
	runner = find_program('run-tests.py')
	test('fuse-tests', runner,
	     args: ['--build-dir', meson.project_build_root()],
	     depends: td,
	     timeout: 1800,
	     is_parallel: false)   # the runner does its own -j

	# The same tests over the other transport. Its own suite so a caller
	# can ask for exactly one of the two: `meson test --suite io-uring`
	# and `meson test --no-suite io-uring`. Plain `meson test` runs both,
	# and the io-uring one exits 77 -- meson reports SKIP -- where the
	# fuse module has io-uring disabled.
	test('fuse-tests-io-uring', runner,
	     args: ['--build-dir', meson.project_build_root(), '--io-uring'],
	     suite: 'io-uring',
	     depends: td,
	     timeout: 1800,
	     is_parallel: false)
endif
