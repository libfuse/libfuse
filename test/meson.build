# Compile helper programs
td = []
foreach prog: [ 'test_write_cache', 'test_setattr' ]
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

test_scripts = [ 'conftest.py', 'pytest.ini', 'test_examples.py',
                 'util.py', 'test_ctests.py', 'test_custom_io.py' ]
td += custom_target('test_scripts', input: test_scripts,
                      output: test_scripts, build_by_default: true,
                      command: ['cp', '-fPp',
                                '@INPUT@', meson.current_build_dir() ])


if meson.is_subproject()

	message('libfuse tests will be skipped because it is a meson subproject.')

else

	python3 = find_program('python3', required: false)

	if python3.found()
		test(
			'run tests',
			python3,
			args: ['-m', 'pytest'],
			workdir: meson.current_source_dir()
		)
	else
		message('libfuse tests will be skipped because python3 is missing')
	endif

endif
