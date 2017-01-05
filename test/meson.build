# Attention, emacs, please use -*- mode: python -*-
# (even though this isn't actually Python code)

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

# Actual tests are written in Python and can simply be copied.
foreach fname : [ 'conftest.py', 'pytest.ini', 'test_examples.py',
                  'util.py' ]
    td += custom_target(fname, input: fname, output: fname,
                        command: ['cp', '-fP', '--preserve=mode',
                                  '@INPUT@', '@OUTPUT@'])
endforeach

# Create a new 'tests' target that we can run with Ninja
run_target('tests', depends: td,
           command: [ 'python3', '-m', 'pytest',
                      meson.current_build_dir() ])


# Provide something helpful when running 'ninja test'
wrong_cmd = executable('wrong_command', 'wrong_command.c',
                       install: false)
test('wrong_cmd', wrong_cmd)

